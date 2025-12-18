//! Network-Beacon: High-performance C2 beacon detection tool.
//!
//! This tool captures network traffic and analyzes flow patterns to detect
//! Command & Control (C2) beaconing behavior using statistical analysis
//! of packet timing intervals.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//! │   Capture   │────>│  Analyzer   │────>│     UI      │
//! │  (pcap)     │ ch1 │ (consumer)  │ ch2 │  (ratatui)  │
//! └─────────────┘     └─────────────┘     └─────────────┘
//!     Thread              Async               Async
//! ```
//!
//! - **Capture**: Background thread using libpcap for packet sniffing
//! - **Analyzer**: Async task aggregating flows and computing CV metrics
//! - **UI**: Real-time TUI dashboard showing suspicious flows

mod analyzer;
mod capture;
mod error;
mod ui;

use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::sync::mpsc;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::analyzer::{run_analyzer, AnalyzerConfig};
use crate::capture::{list_devices, CaptureConfig, PacketCapture};
use crate::ui::run_ui;

/// Network-Beacon: C2 beacon detection through network flow analysis.
#[derive(Parser, Debug)]
#[command(name = "network-beacon")]
#[command(author = "Security Team")]
#[command(version = "0.1.0")]
#[command(about = "Detect C2 beaconing behavior via statistical analysis of network flows")]
#[command(long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start capturing and analyzing network traffic.
    Capture {
        /// Network interface to capture on (default: auto-detect).
        #[arg(short, long)]
        interface: Option<String>,

        /// BPF filter expression (e.g., "tcp port 443").
        #[arg(short, long)]
        filter: Option<String>,

        /// Analysis interval in seconds.
        #[arg(short = 'n', long, default_value = "10")]
        analysis_interval: u64,

        /// Minimum samples required for CV calculation.
        #[arg(short, long, default_value = "5")]
        min_samples: usize,

        /// Maximum flows to track.
        #[arg(long, default_value = "10000")]
        max_flows: usize,

        /// Flow TTL in seconds (inactive flows are evicted).
        #[arg(long, default_value = "300")]
        flow_ttl: u64,

        /// Channel buffer size for flow events.
        #[arg(long, default_value = "10000")]
        channel_size: usize,

        /// Enable verbose logging (writes to stderr).
        #[arg(short, long)]
        verbose: bool,

        /// Disable TUI and output to stdout instead.
        #[arg(long)]
        no_ui: bool,
    },

    /// List available network interfaces.
    ListInterfaces,

    /// Run analysis on a PCAP file (offline mode).
    Analyze {
        /// Path to the PCAP file.
        #[arg(short, long)]
        file: String,

        /// Minimum samples required for CV calculation.
        #[arg(short, long, default_value = "5")]
        min_samples: usize,

        /// Output format: text, json.
        #[arg(short, long, default_value = "text")]
        output: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Capture {
            interface,
            filter,
            analysis_interval,
            min_samples,
            max_flows,
            flow_ttl,
            channel_size,
            verbose,
            no_ui,
        } => {
            // Initialize logging
            let log_level = if verbose { Level::DEBUG } else { Level::INFO };

            // If using UI, we need to be careful with logging
            if no_ui {
                let subscriber = FmtSubscriber::builder()
                    .with_max_level(log_level)
                    .with_target(false)
                    .finish();
                tracing::subscriber::set_global_default(subscriber)
                    .context("Failed to set tracing subscriber")?;
            }

            run_capture(
                interface,
                filter,
                analysis_interval,
                min_samples,
                max_flows,
                flow_ttl,
                channel_size,
                no_ui,
            )
            .await
        }

        Commands::ListInterfaces => {
            let devices = list_devices()?;
            println!("Available network interfaces:\n");
            for device in devices {
                let desc = device
                    .desc
                    .as_ref()
                    .map(|d| format!(" ({})", d))
                    .unwrap_or_default();
                println!("  {}{}", device.name, desc);

                for addr in &device.addresses {
                    println!("    - {}", addr.addr);
                }
            }
            Ok(())
        }

        Commands::Analyze {
            file,
            min_samples,
            output,
        } => {
            run_offline_analysis(&file, min_samples, &output).await
        }
    }
}

async fn run_capture(
    interface: Option<String>,
    filter: Option<String>,
    analysis_interval: u64,
    min_samples: usize,
    max_flows: usize,
    flow_ttl: u64,
    channel_size: usize,
    no_ui: bool,
) -> Result<()> {
    info!("Starting Network-Beacon capture...");

    // Configure capture
    let capture_config = CaptureConfig {
        device: interface,
        filter,
        channel_capacity: channel_size,
        promiscuous: true,
        timeout_ms: 100,
    };

    // Configure analyzer
    let analyzer_config = AnalyzerConfig {
        max_flows,
        max_timestamps_per_flow: 1000,
        analysis_interval_secs: analysis_interval,
        min_samples,
        flow_ttl_secs: flow_ttl,
    };

    // Create channels
    let (report_tx, report_rx) = mpsc::channel(100);

    // Start packet capture (producer)
    let capture = PacketCapture::new(capture_config);
    let shutdown_handle = capture.shutdown_handle();
    let event_rx = capture
        .start()
        .context("Failed to start packet capture")?;

    info!("Packet capture started");

    // Start analyzer (consumer)
    let analyzer_handle = tokio::spawn(async move {
        if let Err(e) = run_analyzer(event_rx, report_tx, analyzer_config).await {
            error!("Analyzer error: {}", e);
        }
    });

    // Run UI or console output
    if no_ui {
        run_console_output(report_rx, shutdown_handle.clone()).await?;
    } else {
        // Run TUI - this blocks until user quits
        run_ui(report_rx).await?;
    }

    // Signal shutdown
    shutdown_handle.store(true, Ordering::Relaxed);
    info!("Shutdown signal sent");

    // Wait for analyzer to finish
    let _ = analyzer_handle.await;

    info!("Network-Beacon stopped");
    Ok(())
}

async fn run_console_output(
    mut report_rx: mpsc::Receiver<analyzer::AnalysisReport>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    use tokio::signal;

    println!("Network-Beacon - Console Mode");
    println!("Press Ctrl+C to stop\n");

    loop {
        tokio::select! {
            Some(report) = report_rx.recv() => {
                println!("--- Analysis Report ---");
                println!("Time: {}", report.timestamp.format("%Y-%m-%d %H:%M:%S"));
                println!("Total Flows: {}", report.total_flows);
                println!("Active Flows: {}", report.active_flows);
                println!("Events Processed: {}", report.events_processed);

                if report.suspicious_flows.is_empty() {
                    println!("Suspicious Flows: None detected");
                } else {
                    println!("\nSuspicious Flows ({}):", report.suspicious_flows.len());
                    for flow in &report.suspicious_flows {
                        println!(
                            "  [{:8}] {} -> {}:{} | CV: {:.4} | Interval: {:.1}ms | Packets: {}",
                            flow.classification.severity(),
                            flow.flow_key.src_ip,
                            flow.flow_key.dst_ip,
                            flow.flow_key.dst_port,
                            flow.cv.unwrap_or(0.0),
                            flow.mean_interval_ms.unwrap_or(0.0),
                            flow.packet_count,
                        );
                    }
                }
                println!();
            }

            _ = signal::ctrl_c() => {
                println!("\nReceived Ctrl+C, shutting down...");
                shutdown.store(true, Ordering::Relaxed);
                break;
            }
        }
    }

    Ok(())
}

async fn run_offline_analysis(file: &str, min_samples: usize, output: &str) -> Result<()> {
    use pcap::Capture;
    use std::collections::HashMap;

    use crate::analyzer::{calculate_statistics, timestamps_to_deltas, FlowClassification};
    use crate::capture::{FlowKey, Protocol};

    println!("Analyzing PCAP file: {}", file);

    let mut cap = Capture::from_file(file).context("Failed to open PCAP file")?;

    let mut flows: HashMap<FlowKey, Vec<chrono::DateTime<chrono::Utc>>> = HashMap::new();

    // Process all packets
    while let Ok(packet) = cap.next_packet() {
        if let Ok(sliced) = etherparse::SlicedPacket::from_ethernet(packet.data) {
            let (src_ip, dst_ip) = match sliced.net {
                Some(etherparse::NetSlice::Ipv4(ipv4)) => {
                    let h = ipv4.header();
                    (
                        std::net::IpAddr::from(h.source()),
                        std::net::IpAddr::from(h.destination()),
                    )
                }
                Some(etherparse::NetSlice::Ipv6(ipv6)) => {
                    let h = ipv6.header();
                    (
                        std::net::IpAddr::from(h.source()),
                        std::net::IpAddr::from(h.destination()),
                    )
                }
                _ => continue,
            };

            let (dst_port, protocol) = match sliced.transport {
                Some(etherparse::TransportSlice::Tcp(tcp)) => (tcp.destination_port(), Protocol::Tcp),
                Some(etherparse::TransportSlice::Udp(udp)) => (udp.destination_port(), Protocol::Udp),
                _ => continue,
            };

            let ts = chrono::DateTime::from_timestamp(
                packet.header.ts.tv_sec,
                (packet.header.ts.tv_usec * 1000) as u32,
            );

            if let Some(timestamp) = ts {
                let key = FlowKey::new(src_ip, dst_ip, dst_port, protocol);
                flows.entry(key).or_default().push(timestamp);
            }
        }
    }

    // Analyze flows
    let mut results: Vec<_> = flows
        .iter()
        .filter(|(_, timestamps)| timestamps.len() >= min_samples)
        .map(|(key, timestamps)| {
            let deltas = timestamps_to_deltas(timestamps);
            let stats = calculate_statistics(&deltas);
            let classification = FlowClassification::from_cv(stats.cv);
            (key.clone(), classification, stats, timestamps.len())
        })
        .collect();

    // Sort by CV (most suspicious first)
    results.sort_by(|a, b| {
        a.2.cv
            .partial_cmp(&b.2.cv)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Output results
    match output {
        "json" => {
            let json_results: Vec<_> = results
                .iter()
                .map(|(key, class, stats, count)| {
                    serde_json::json!({
                        "flow": key.to_string(),
                        "classification": format!("{}", class),
                        "severity": class.severity(),
                        "cv": stats.cv,
                        "mean_interval_ms": stats.mean,
                        "std_dev_ms": stats.std_dev,
                        "sample_count": count,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_results)?);
        }
        _ => {
            println!("\nAnalysis Results ({} flows):\n", results.len());
            println!(
                "{:<50} {:>10} {:>8} {:>12} {:>8}",
                "Flow", "Class", "CV", "Interval", "Samples"
            );
            println!("{}", "-".repeat(92));

            for (key, classification, stats, count) in results {
                let interval_str = if stats.mean >= 1000.0 {
                    format!("{:.1}s", stats.mean / 1000.0)
                } else {
                    format!("{:.0}ms", stats.mean)
                };

                println!(
                    "{:<50} {:>10} {:>8.4} {:>12} {:>8}",
                    key.to_string(),
                    classification.severity(),
                    stats.cv,
                    interval_str,
                    count,
                );
            }
        }
    }

    Ok(())
}
