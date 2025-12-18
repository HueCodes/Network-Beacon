//! Packet capture module - The Producer in our Producer-Consumer architecture.
//!
//! This module handles raw packet capture using libpcap and extracts minimal
//! flow metadata (FlowKey + timestamp) for downstream analysis.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use chrono::{DateTime, Utc};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Device};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::error::{CaptureError, Result};

/// Unique identifier for a network flow.
/// Composed of source IP, destination IP, and destination port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: Protocol,
}

impl FlowKey {
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, dst_port: u16, protocol: Protocol) -> Self {
        Self {
            src_ip,
            dst_ip,
            dst_port,
            protocol,
        }
    }

    /// Returns a display-friendly string representation.
    pub fn display(&self) -> String {
        format!(
            "{}:{} -> {}:{} ({})",
            self.src_ip, "*", self.dst_ip, self.dst_port, self.protocol
        )
    }
}

impl std::fmt::Display for FlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display())
    }
}

/// Transport layer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Other(u8),
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Other(n) => write!(f, "PROTO:{}", n),
        }
    }
}

/// Minimal metadata extracted from each packet.
/// This is what gets sent over the channel to the analyzer.
#[derive(Debug, Clone)]
pub struct FlowEvent {
    pub flow_key: FlowKey,
    pub timestamp: DateTime<Utc>,
    pub packet_size: u32,
}

/// Configuration for the packet capture.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Network interface to capture on (None = auto-detect).
    pub device: Option<String>,
    /// BPF filter expression (e.g., "tcp port 443").
    pub filter: Option<String>,
    /// Channel buffer size for flow events.
    pub channel_capacity: usize,
    /// Promiscuous mode.
    pub promiscuous: bool,
    /// Capture timeout in milliseconds.
    pub timeout_ms: i32,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            device: None,
            filter: None,
            channel_capacity: 10_000,
            promiscuous: true,
            timeout_ms: 100,
        }
    }
}

/// The packet capture producer.
/// Runs in a dedicated thread and sends FlowEvents to the analyzer.
pub struct PacketCapture {
    config: CaptureConfig,
    shutdown: Arc<AtomicBool>,
}

impl PacketCapture {
    pub fn new(config: CaptureConfig) -> Self {
        Self {
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns a handle to signal shutdown.
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Starts packet capture in a background thread.
    /// Returns a receiver for FlowEvents.
    pub fn start(self) -> Result<mpsc::Receiver<FlowEvent>> {
        let (tx, rx) = mpsc::channel(self.config.channel_capacity);
        let shutdown = Arc::clone(&self.shutdown);
        let config = self.config.clone();

        thread::Builder::new()
            .name("packet-capture".into())
            .spawn(move || {
                if let Err(e) = Self::capture_loop(config, tx, shutdown) {
                    error!("Capture thread error: {}", e);
                }
                info!("Capture thread terminated");
            })?;

        Ok(rx)
    }

    /// The main capture loop - runs in a dedicated thread.
    fn capture_loop(
        config: CaptureConfig,
        tx: mpsc::Sender<FlowEvent>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<()> {
        // Select capture device
        let device = match &config.device {
            Some(name) => Device::from(name.as_str()),
            None => Device::lookup()
                .map_err(|e| CaptureError::DeviceOpen {
                    device: "default".into(),
                    source: e,
                })?
                .ok_or(CaptureError::NoDeviceFound)?,
        };

        info!("Opening capture on device: {}", device.name);

        // Open capture handle
        let mut cap = Capture::from_device(device.clone())
            .map_err(|e| CaptureError::DeviceOpen {
                device: device.name.clone(),
                source: e,
            })?
            .promisc(config.promiscuous)
            .timeout(config.timeout_ms)
            .open()
            .map_err(|e| CaptureError::DeviceOpen {
                device: device.name.clone(),
                source: e,
            })?;

        // Apply BPF filter if specified
        if let Some(ref filter) = config.filter {
            cap.filter(filter, true).map_err(|e| CaptureError::FilterSet {
                filter: filter.clone(),
                source: e,
            })?;
            info!("Applied capture filter: {}", filter);
        }

        // Main capture loop
        while !shutdown.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(packet) => {
                    if let Some(event) = Self::parse_packet(packet.data, packet.header.ts) {
                        // Non-blocking send - drop if channel is full
                        if tx.try_send(event).is_err() {
                            warn!("Channel full, dropping packet");
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Normal timeout, continue loop
                    continue;
                }
                Err(e) => {
                    error!("Packet read error: {}", e);
                    // Brief backoff on error
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }

        Ok(())
    }

    /// Parses a raw packet and extracts flow metadata.
    /// Returns None if the packet cannot be parsed or is not IP-based.
    fn parse_packet(data: &[u8], ts: libc::timeval) -> Option<FlowEvent> {
        let sliced = SlicedPacket::from_ethernet(data).ok()?;

        // Extract IP addresses
        let (src_ip, dst_ip) = match sliced.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                let header = ipv4.header();
                (
                    IpAddr::from(header.source()),
                    IpAddr::from(header.destination()),
                )
            }
            Some(NetSlice::Ipv6(ipv6)) => {
                let header = ipv6.header();
                (
                    IpAddr::from(header.source()),
                    IpAddr::from(header.destination()),
                )
            }
            _ => return None,
        };

        // Extract transport layer info
        let (dst_port, protocol) = match sliced.transport {
            Some(TransportSlice::Tcp(tcp)) => (tcp.destination_port(), Protocol::Tcp),
            Some(TransportSlice::Udp(udp)) => (udp.destination_port(), Protocol::Udp),
            _ => return None,
        };

        // Convert pcap timestamp to chrono DateTime
        let timestamp = DateTime::from_timestamp(ts.tv_sec, (ts.tv_usec * 1000) as u32)?;

        let flow_key = FlowKey::new(src_ip, dst_ip, dst_port, protocol);

        debug!(
            "Captured: {} -> {}:{} ({})",
            src_ip, dst_ip, dst_port, protocol
        );

        Some(FlowEvent {
            flow_key,
            timestamp,
            packet_size: data.len() as u32,
        })
    }
}

/// Lists available network devices for capture.
pub fn list_devices() -> Result<Vec<Device>> {
    Ok(Device::list()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_key_equality() {
        let key1 = FlowKey::new(
            "192.168.1.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            443,
            Protocol::Tcp,
        );

        let key2 = FlowKey::new(
            "192.168.1.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            443,
            Protocol::Tcp,
        );

        let key3 = FlowKey::new(
            "192.168.1.2".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            443,
            Protocol::Tcp,
        );

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_flow_key_display() {
        let key = FlowKey::new(
            "192.168.1.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            443,
            Protocol::Tcp,
        );

        let display = key.display();
        assert!(display.contains("192.168.1.1"));
        assert!(display.contains("10.0.0.1"));
        assert!(display.contains("443"));
        assert!(display.contains("TCP"));
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(format!("{}", Protocol::Tcp), "TCP");
        assert_eq!(format!("{}", Protocol::Udp), "UDP");
        assert_eq!(format!("{}", Protocol::Other(17)), "PROTO:17");
    }
}
