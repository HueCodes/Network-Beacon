# Network-Beacon

Network-Beacon is a Rust-based security utility designed to identify Command & Control (C2) beaconing patterns through statistical traffic analysis and passive TLS fingerprinting.

## Features

* **Flow Analysis**: Real-time packet ingestion using `pcap` to track source/destination metadata.
* **Jitter Detection**: Calculates the Coefficient of Variation (CV) to identify automated heartbeats.
* **TLS Fingerprinting**: Inspects Client Hello packets to generate JA4-style signatures for identifying non-browser traffic.
* **Async Engine**: Multi-threaded architecture utilizing `Tokio` for high-throughput packet processing.
* **Terminal UI**: Live dashboard built with `Ratatui` for real-time monitoring.

## Detection Logic

The tool classifies network traffic based on the timing interval between packets:

* **Periodic (CV < 0.1)**: High probability of C2 beaconing or automated scripts.
* **Jittered (CV 0.1 - 0.5)**: Suspicious traffic with randomized delays.
* **Stochastic (CV > 1.0)**: Characteristic of organic human activity.

## Installation

### Prerequisites
* Rust toolchain
* libpcap-dev (Linux) or WinPcap/Npcap (Windows)

### Build
```bash
cargo build --release
