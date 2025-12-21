//! PCAP Replay Module
//!
//! Provides the ability to replay captured PCAP files for offline analysis.
//! Supports time-based replay with configurable speed multiplier.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::Capture;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, info, trace};

use crate::capture::{FlowEvent, FlowKey, Protocol};
use crate::dns_detector::is_dns_port;
// Note: is_tls_port removed since we now extract TLS from all TCP ports

/// Configuration for PCAP replay
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// Speed multiplier (1.0 = realtime, 10.0 = 10x faster, 0.0 = as fast as possible)
    pub speed: f64,
    /// Maximum events to replay (0 = unlimited)
    pub max_events: usize,
    /// Channel buffer size
    pub channel_size: usize,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            speed: 0.0, // As fast as possible by default
            channel_size: 10_000,
            max_events: 0,
        }
    }
}

/// PCAP file replayer
pub struct PcapReplay {
    config: ReplayConfig,
    file_path: String,
}

impl PcapReplay {
    pub fn new(file_path: &str, config: ReplayConfig) -> Self {
        Self {
            config,
            file_path: file_path.to_string(),
        }
    }

    /// Starts replay in a background task, returning a receiver for events.
    pub fn start(self) -> Result<mpsc::Receiver<FlowEvent>> {
        let (tx, rx) = mpsc::channel(self.config.channel_size);

        let file_path = self.file_path.clone();
        let config = self.config.clone();

        // Spawn replay task
        tokio::spawn(async move {
            if let Err(e) = replay_file(&file_path, tx, config).await {
                tracing::error!("Replay error: {}", e);
            }
        });

        Ok(rx)
    }

    /// Replays the PCAP file synchronously, sending events to the provided sender.
    #[allow(dead_code)] // Alternative API for custom replay handling
    pub async fn replay_to_sender(self, tx: mpsc::Sender<FlowEvent>) -> Result<ReplayStats> {
        replay_file(&self.file_path, tx, self.config).await
    }
}

/// Statistics from a replay session
#[derive(Debug, Clone, Default)]
pub struct ReplayStats {
    pub packets_processed: usize,
    pub events_sent: usize,
    pub packets_skipped: usize,
    pub duration_ms: u64,
}

/// Replays a PCAP file, parsing packets and sending FlowEvents.
async fn replay_file(
    file_path: &str,
    tx: mpsc::Sender<FlowEvent>,
    config: ReplayConfig,
) -> Result<ReplayStats> {
    let path = Path::new(file_path);
    if !path.exists() {
        anyhow::bail!("PCAP file not found: {}", file_path);
    }

    info!("Opening PCAP file: {}", file_path);

    let mut cap = Capture::from_file(file_path).context("Failed to open PCAP file")?;

    let start_time = std::time::Instant::now();
    let mut stats = ReplayStats::default();
    let mut last_packet_time: Option<DateTime<Utc>> = None;
    let mut first_packet_time: Option<DateTime<Utc>> = None;

    while let Ok(packet) = cap.next_packet() {
        stats.packets_processed += 1;

        // Check max events limit
        if config.max_events > 0 && stats.events_sent >= config.max_events {
            info!("Reached max events limit: {}", config.max_events);
            break;
        }

        // Parse packet timestamp
        let packet_time = DateTime::from_timestamp(
            packet.header.ts.tv_sec,
            (packet.header.ts.tv_usec as u32).saturating_mul(1000),
        );

        let Some(timestamp) = packet_time else {
            stats.packets_skipped += 1;
            continue;
        };

        // Track first packet time for speed calculation
        if first_packet_time.is_none() {
            first_packet_time = Some(timestamp);
        }

        // Apply speed-based delay if configured
        if config.speed > 0.0 {
            if let Some(last_ts) = last_packet_time {
                let delta = timestamp.signed_duration_since(last_ts);
                if delta.num_milliseconds() > 0 {
                    let delay_ms = (delta.num_milliseconds() as f64 / config.speed) as u64;
                    if delay_ms > 0 {
                        sleep(Duration::from_millis(delay_ms)).await;
                    }
                }
            }
        }
        last_packet_time = Some(timestamp);

        // Parse the packet
        if let Some(event) = parse_pcap_packet(packet.data, timestamp) {
            trace!(
                "Replaying: {} -> {}:{} ({})",
                event.flow_key.src_ip,
                event.flow_key.dst_ip,
                event.flow_key.dst_port,
                event.flow_key.protocol
            );

            if tx.send(event).await.is_err() {
                debug!("Receiver dropped, stopping replay");
                break;
            }
            stats.events_sent += 1;
        } else {
            stats.packets_skipped += 1;
        }
    }

    stats.duration_ms = start_time.elapsed().as_millis() as u64;

    info!(
        "Replay complete: {} packets processed, {} events sent, {} skipped in {}ms",
        stats.packets_processed, stats.events_sent, stats.packets_skipped, stats.duration_ms
    );

    Ok(stats)
}

/// Parses a raw packet from PCAP and creates a FlowEvent.
fn parse_pcap_packet(data: &[u8], timestamp: DateTime<Utc>) -> Option<FlowEvent> {
    let sliced = SlicedPacket::from_ethernet(data).ok()?;

    // Extract IP addresses
    let (src_ip, dst_ip) = match &sliced.net {
        Some(NetSlice::Ipv4(ipv4)) => {
            let header = ipv4.header();
            (
                std::net::IpAddr::from(header.source()),
                std::net::IpAddr::from(header.destination()),
            )
        }
        Some(NetSlice::Ipv6(ipv6)) => {
            let header = ipv6.header();
            (
                std::net::IpAddr::from(header.source()),
                std::net::IpAddr::from(header.destination()),
            )
        }
        _ => return None,
    };

    // Extract transport layer info and payloads
    let (dst_port, protocol, tcp_payload, udp_payload): (
        u16,
        Protocol,
        Option<&[u8]>,
        Option<&[u8]>,
    ) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            let port = tcp.destination_port();
            let eth_len = 14;
            let ip_len = match &sliced.net {
                Some(NetSlice::Ipv4(ipv4)) => (ipv4.header().ihl() as usize) * 4,
                Some(NetSlice::Ipv6(_)) => 40,
                _ => 0,
            };
            let tcp_header_len = tcp.data_offset() as usize * 4;
            let payload_offset = eth_len + ip_len + tcp_header_len;

            if payload_offset < data.len() {
                (port, Protocol::Tcp, Some(&data[payload_offset..]), None)
            } else {
                (port, Protocol::Tcp, None, None)
            }
        }
        Some(TransportSlice::Udp(udp)) => {
            let port = udp.destination_port();
            let eth_len = 14;
            let ip_len = match &sliced.net {
                Some(NetSlice::Ipv4(ipv4)) => (ipv4.header().ihl() as usize) * 4,
                Some(NetSlice::Ipv6(_)) => 40,
                _ => 0,
            };
            let udp_header_len = 8;
            let payload_offset = eth_len + ip_len + udp_header_len;

            let payload = if payload_offset < data.len() {
                Some(&data[payload_offset..])
            } else {
                None
            };

            (port, Protocol::Udp, None, payload)
        }
        _ => return None,
    };

    // Extract TLS payload (check all TCP ports for protocol mismatch detection)
    let tls_payload: Option<Vec<u8>> = if protocol == Protocol::Tcp {
        tcp_payload.and_then(|p| {
            if !p.is_empty() && p[0] == 0x16 {
                let len = p.len().min(512);
                Some(p[..len].to_vec())
            } else {
                None
            }
        })
    } else {
        None
    };

    // Extract DNS payload
    let dns_payload: Option<Vec<u8>> = if protocol == Protocol::Udp && is_dns_port(dst_port) {
        udp_payload.and_then(|p| {
            if p.len() >= 12 {
                let len = p.len().min(512);
                Some(p[..len].to_vec())
            } else {
                None
            }
        })
    } else {
        None
    };

    let flow_key = FlowKey::new(src_ip, dst_ip, dst_port, protocol);

    Some(FlowEvent {
        flow_key,
        timestamp,
        packet_size: data.len() as u32,
        tls_payload,
        dns_payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_config_default() {
        let config = ReplayConfig::default();
        assert_eq!(config.speed, 0.0);
        assert_eq!(config.channel_size, 10_000);
        assert_eq!(config.max_events, 0);
    }

    #[test]
    fn test_replay_stats_default() {
        let stats = ReplayStats::default();
        assert_eq!(stats.packets_processed, 0);
        assert_eq!(stats.events_sent, 0);
        assert_eq!(stats.packets_skipped, 0);
        assert_eq!(stats.duration_ms, 0);
    }
}
