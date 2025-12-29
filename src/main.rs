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
mod config;
mod dns_detector;
mod error;
mod export;
mod http_detector;
mod metrics;
mod replay;
mod tls_fingerprint;
mod ui;

use std::path::PathBuf;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use tokio::sync::mpsc;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::analyzer::{run_analyzer, AnalyzerConfig};
use crate::capture::{list_devices, CaptureConfig, PacketCapture};
use crate::config::Config;
use crate::export::{export_report, OutputFormat};
use crate::replay::{PcapReplay, ReplayConfig};
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

/// CLI output format (used by clap)
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum CliOutputFormat {
    #[default]
    Text,
    Json,
    Jsonl,
}

impl From<CliOutputFormat> for OutputFormat {
    fn from(f: CliOutputFormat) -> Self {
        match f {
            CliOutputFormat::Text => OutputFormat::Text,
            CliOutputFormat::Json => OutputFormat::Json,
            CliOutputFormat::Jsonl => OutputFormat::JsonLines,
        }
    }
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

        /// Path to TOML configuration file.
        #[arg(short, long)]
        config: Option<PathBuf>,

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

        /// Output format when --no-ui is used.
        #[arg(long, value_enum, default_value = "text")]
        output: CliOutputFormat,
    },

    /// Replay a PCAP file for analysis.
    Replay {
        /// Path to the PCAP file.
        #[arg(short, long)]
        file: PathBuf,

        /// Replay speed multiplier (0 = as fast as possible, 1 = realtime).
        #[arg(short, long, default_value = "0")]
        speed: f64,

        /// Maximum events to replay (0 = unlimited).
        #[arg(long, default_value = "0")]
        max_events: usize,

        /// Minimum samples required for CV calculation.
        #[arg(short, long, default_value = "5")]
        min_samples: usize,

        /// Output format.
        #[arg(short, long, value_enum, default_value = "text")]
        output: CliOutputFormat,

        /// Enable verbose logging.
        #[arg(short, long)]
        verbose: bool,
    },

    /// List available network interfaces.
    ListInterfaces,

    /// Analyze a PCAP file (legacy command, use 'replay' for more options).
    Analyze {
        /// Path to the PCAP file.
        #[arg(short, long)]
        file: String,

        /// Minimum samples required for CV calculation.
        #[arg(short, long, default_value = "5")]
        min_samples: usize,

        /// Output format.
        #[arg(short, long, value_enum, default_value = "text")]
        output: CliOutputFormat,
    },

    /// Generate a default configuration file.
    GenerateConfig {
        /// Output file path (default: network-beacon.toml).
        #[arg(short, long, default_value = "network-beacon.toml")]
        output: PathBuf,

        /// Print to stdout instead of writing to file.
        #[arg(long)]
        stdout: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Capture {
            interface,
            filter,
            config,
            analysis_interval,
            min_samples,
            max_flows,
            flow_ttl,
            channel_size,
            verbose,
            no_ui,
            output,
        } => {
            // Load config file if provided
            let file_config = Config::load_or_default(config.as_deref());

            // Validate configuration
            file_config.validate().context("Invalid configuration")?;

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

            // CLI args override config file
            let interface = interface.or(file_config.capture.interface);
            let filter = filter.or(file_config.capture.filter);

            run_capture(
                interface,
                filter,
                analysis_interval,
                min_samples,
                max_flows,
                flow_ttl,
                channel_size,
                no_ui,
                output.into(),
            )
            .await
        }

        Commands::Replay {
            file,
            speed,
            max_events,
            min_samples,
            output,
            verbose,
        } => {
            // Initialize logging
            let log_level = if verbose { Level::DEBUG } else { Level::INFO };
            let subscriber = FmtSubscriber::builder()
                .with_max_level(log_level)
                .with_target(false)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .context("Failed to set tracing subscriber")?;

            run_replay(&file, speed, max_events, min_samples, output.into()).await
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
        } => run_offline_analysis(&file, min_samples, output.into()).await,

        Commands::GenerateConfig { output, stdout } => {
            let config_content = Config::generate_default();
            if stdout {
                println!("{}", config_content);
            } else {
                std::fs::write(&output, &config_content)
                    .with_context(|| format!("Failed to write config to {}", output.display()))?;
                println!("Configuration written to: {}", output.display());
            }
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_capture(
    interface: Option<String>,
    filter: Option<String>,
    analysis_interval: u64,
    min_samples: usize,
    max_flows: usize,
    flow_ttl: u64,
    channel_size: usize,
    no_ui: bool,
    output_format: OutputFormat,
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
    let event_rx = capture.start().context("Failed to start packet capture")?;

    info!("Packet capture started");

    // Start analyzer (consumer)
    let analyzer_handle = tokio::spawn(async move {
        if let Err(e) = run_analyzer(event_rx, report_tx, analyzer_config).await {
            error!("Analyzer error: {}", e);
        }
    });

    // Run UI or console output
    if no_ui {
        run_console_output(report_rx, shutdown_handle.clone(), output_format).await?;
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

async fn run_replay(
    file: &PathBuf,
    speed: f64,
    max_events: usize,
    min_samples: usize,
    output_format: OutputFormat,
) -> Result<()> {
    info!("Starting PCAP replay: {:?}", file);

    let replay_config = ReplayConfig {
        speed,
        max_events,
        channel_size: 10_000,
    };

    // Configure analyzer
    let analyzer_config = AnalyzerConfig {
        max_flows: 10_000,
        max_timestamps_per_flow: 1000,
        analysis_interval_secs: 5, // Faster for replay
        min_samples,
        flow_ttl_secs: 300,
    };

    // Create channels
    let (report_tx, mut report_rx) = mpsc::channel(100);

    // Start replay
    let replay = PcapReplay::new(file.to_str().unwrap_or(""), replay_config);
    let event_rx = replay.start()?;

    // Start analyzer
    let analyzer_handle = tokio::spawn(async move {
        if let Err(e) = run_analyzer(event_rx, report_tx, analyzer_config).await {
            error!("Analyzer error: {}", e);
        }
    });

    // Collect reports
    let mut last_report = None;
    while let Some(report) = report_rx.recv().await {
        last_report = Some(report);
    }

    // Wait for analyzer
    let _ = analyzer_handle.await;

    // Output final report
    if let Some(report) = last_report {
        println!("{}", export_report(&report, output_format));
    } else {
        println!("No data analyzed");
    }

    info!("Replay complete");
    Ok(())
}

async fn run_console_output(
    mut report_rx: mpsc::Receiver<analyzer::AnalysisReport>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    output_format: OutputFormat,
) -> Result<()> {
    use tokio::signal;

    if output_format == OutputFormat::Text {
        println!("Network-Beacon - Console Mode");
        println!("Press Ctrl+C to stop\n");
    }

    loop {
        tokio::select! {
            Some(report) = report_rx.recv() => {
                println!("{}", export_report(&report, output_format));
            }

            _ = signal::ctrl_c() => {
                if output_format == OutputFormat::Text {
                    println!("\nReceived Ctrl+C, shutting down...");
                }
                shutdown.store(true, Ordering::Relaxed);
                break;
            }
        }
    }

    Ok(())
}

async fn run_offline_analysis(
    file: &str,
    min_samples: usize,
    output_format: OutputFormat,
) -> Result<()> {
    use pcap::Capture;
    use std::collections::HashMap;

    use crate::analyzer::{calculate_statistics, timestamps_to_deltas, FlowClassification};
    use crate::capture::{FlowKey, Protocol};

    if output_format == OutputFormat::Text {
        println!("Analyzing PCAP file: {}", file);
    }

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
                Some(etherparse::TransportSlice::Tcp(tcp)) => {
                    (tcp.destination_port(), Protocol::Tcp)
                }
                Some(etherparse::TransportSlice::Udp(udp)) => {
                    (udp.destination_port(), Protocol::Udp)
                }
                _ => continue,
            };

            let ts = chrono::DateTime::from_timestamp(
                packet.header.ts.tv_sec,
                (packet.header.ts.tv_usec as u32).saturating_mul(1000),
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
    match output_format {
        OutputFormat::Json => {
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
        OutputFormat::JsonLines => {
            for (key, class, stats, count) in &results {
                let json_obj = serde_json::json!({
                    "flow": key.to_string(),
                    "classification": format!("{}", class),
                    "severity": class.severity(),
                    "cv": stats.cv,
                    "mean_interval_ms": stats.mean,
                    "std_dev_ms": stats.std_dev,
                    "sample_count": count,
                });
                println!("{}", serde_json::to_string(&json_obj)?);
            }
        }
        OutputFormat::Text => {
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
