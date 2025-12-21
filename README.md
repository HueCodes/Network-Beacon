# Network-Beacon

Network-Beacon is a Rust-based security utility designed to identify Command & Control (C2) beaconing patterns through statistical traffic analysis, passive TLS fingerprinting, and DNS tunneling detection.

## Features

* **Flow Analysis**: Real-time packet ingestion using `pcap` to track source/destination metadata
* **Jitter Detection**: Calculates the Coefficient of Variation (CV) to identify automated heartbeats
* **TLS Fingerprinting**: Inspects Client Hello packets to generate JA4-style signatures for identifying non-browser traffic
* **DNS Tunneling Detection**: Analyzes DNS traffic for high-entropy subdomains, unusual query patterns, and data exfiltration indicators
* **Protocol Mismatch Detection**: Detects TLS traffic on non-standard ports (potential C2 evasion)
* **Async Engine**: Multi-threaded architecture utilizing `Tokio` for high-throughput packet processing
* **Terminal UI**: Live dashboard built with `Ratatui` for real-time monitoring
* **Multiple Output Formats**: Text, JSON, and JSON Lines for integration with SIEM systems
* **PCAP Replay**: Analyze captured traffic files offline
* **TOML Configuration**: Flexible configuration file support

## Detection Logic

### CV-Based Detection

The tool classifies network traffic based on the timing interval between packets:

| Classification | CV Range | Description |
|----------------|----------|-------------|
| CRITICAL | < 0.1 | Highly Periodic - Probable C2 beacon |
| HIGH | 0.1 - 0.5 | Jittered Periodic - Suspicious automated traffic |
| MEDIUM | 0.5 - 1.0 | Moderate Variation |
| LOW | > 1.0 | Stochastic - Likely organic human activity |

### DNS Tunneling Detection

DNS tunneling is detected through multiple indicators:

* **High Entropy**: Subdomain labels with entropy > 3.5 bits/char (base64/hex encoded data)
* **Long Labels**: DNS labels exceeding 50 characters
* **Suspicious Record Types**: TXT, NULL, and other record types commonly used for tunneling
* **High Query Rate**: Abnormally frequent queries to the same domain
* **Many Unique Subdomains**: Pattern indicating data encoding in DNS queries

### Protocol Mismatch

* TLS traffic detected on non-standard ports (not 443, 8443, etc.)
* Indicates potential C2 channels using encrypted communication on unusual ports

## Installation

### Prerequisites
* Rust toolchain (1.70+)
* libpcap-dev (Linux/macOS) or Npcap (Windows)

### macOS
```bash
brew install libpcap
```

### Ubuntu/Debian
```bash
sudo apt-get install libpcap-dev
```

### Build
```bash
cargo build --release
```

The binary will be at `target/release/network-beacon`.

## Usage

### Live Capture (TUI Mode)
```bash
# Auto-detect interface
sudo ./network-beacon capture

# Specify interface
sudo ./network-beacon capture -i en0

# With BPF filter
sudo ./network-beacon capture -i en0 -f "tcp port 443"
```

### Live Capture (Console Mode)
```bash
# Text output
sudo ./network-beacon capture --no-ui

# JSON output for SIEM integration
sudo ./network-beacon capture --no-ui --output json

# JSON Lines (one JSON object per line)
sudo ./network-beacon capture --no-ui --output jsonl
```

### PCAP Replay
```bash
# Analyze a PCAP file
./network-beacon replay -f capture.pcap

# With speed control (1.0 = realtime, 0 = as fast as possible)
./network-beacon replay -f capture.pcap -s 1.0

# JSON output
./network-beacon replay -f capture.pcap -o json
```

### Legacy PCAP Analysis
```bash
./network-beacon analyze -f capture.pcap
```

### List Interfaces
```bash
./network-beacon list-interfaces
```

### Generate Configuration
```bash
# Write default config to file
./network-beacon generate-config -o config.toml

# Print to stdout
./network-beacon generate-config --stdout
```

## Configuration

Network-Beacon can be configured via TOML file:

```bash
./network-beacon capture -c config.toml
```

Example configuration:

```toml
[capture]
interface = "en0"
promiscuous = true
timeout_ms = 100

[analyzer]
max_flows = 10000
max_timestamps_per_flow = 1000
analysis_interval_secs = 10
min_samples = 5
flow_ttl_secs = 300

[detection]
cv_enabled = true
dns_tunneling_enabled = true
cv_threshold_periodic = 0.1
cv_threshold_jittered = 0.5
entropy_threshold = 3.5
max_dns_label_length = 50
profile = "balanced"  # paranoid, balanced, or relaxed

[output]
format = "text"
verbose = false
```

### Detection Profiles

* **paranoid**: Higher sensitivity, more false positives
* **balanced**: Default settings
* **relaxed**: Lower sensitivity, fewer alerts

## TUI Keyboard Shortcuts

| Key | Action |
|-----|--------|
| q / Esc | Quit |
| ↑ / k | Move up |
| ↓ / j | Move down |
| Enter | Show flow details |
| Home | Jump to first |
| End | Jump to last |
| ? / h | Toggle help |

## Detection Indicators

The TUI displays detection indicators for each suspicious flow:

| Indicator | Description |
|-----------|-------------|
| BEACON | Periodic timing pattern detected |
| DNS-TUN | DNS tunneling indicators present |
| PROTO-MIS | Protocol mismatch (e.g., TLS on non-443) |
| UNK-TLS | Unknown TLS client fingerprint |

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Capture   │────>│  Analyzer   │────>│     UI      │
│  (pcap)     │ ch1 │ (consumer)  │ ch2 │  (ratatui)  │
└─────────────┘     └─────────────┘     └─────────────┘
    Thread              Async               Async
```

* **Capture**: Background thread using libpcap for packet sniffing
* **Analyzer**: Async task aggregating flows and computing metrics
* **UI**: Real-time TUI dashboard or console output

## License

MIT License - See LICENSE file for details.
