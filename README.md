# Network-Beacon

Network-Beacon is a high-performance Rust CLI tool for detecting Command & Control (C2) beaconing patterns through statistical traffic analysis, passive TLS fingerprinting, DNS tunneling detection, and HTTP beacon analysis.

## Features

* **Flow Analysis**: Real-time packet ingestion using `pcap` to track source/destination metadata
* **Jitter Detection**: Calculates the Coefficient of Variation (CV) to identify automated heartbeats
* **TLS Fingerprinting**: Inspects Client Hello packets to generate JA4-style signatures for identifying non-browser traffic
* **DNS Tunneling Detection**: Analyzes DNS traffic for high-entropy subdomains, unusual query patterns, and data exfiltration indicators
* **HTTP Beacon Detection**: Identifies HTTP-based C2 patterns including POST beaconing, suspicious User-Agents, and payload size consistency
* **Protocol Mismatch Detection**: Detects TLS traffic on non-standard ports (potential C2 evasion)
* **GeoIP Enrichment**: Enrich flows with geographic and ASN data via MaxMind databases
* **Alerting**: Webhook and syslog alerting with throttling, deduplication, and retry
* **Prometheus Metrics**: Built-in `/metrics` endpoint for monitoring
* **Async Engine**: Multi-threaded architecture utilizing `Tokio` for high-throughput packet processing
* **Terminal UI**: Live dashboard built with `Ratatui` for real-time monitoring
* **Multiple Output Formats**: Text, JSON, and JSON Lines for integration with SIEM systems
* **PCAP Replay**: Analyze captured traffic files offline
* **TOML Configuration**: Flexible configuration file with detection profiles
* **Benchmarking**: Built-in synthetic throughput benchmarks

## Detection Logic

### CV-Based Detection

The tool classifies network traffic based on the timing interval between packets:

| Classification | CV Range | Description |
|----------------|----------|-------------|
| CRITICAL | < 0.1 | Highly Periodic — Probable C2 beacon |
| HIGH | 0.1 - 0.5 | Jittered Periodic — Suspicious automated traffic |
| MEDIUM | 0.5 - 1.0 | Moderate Variation |
| LOW | > 1.0 | Stochastic — Likely organic human activity |

### DNS Tunneling Detection

DNS tunneling is detected through multiple indicators:

* **High Entropy**: Subdomain labels with entropy > 3.5 bits/char (base64/hex encoded data)
* **Long Labels**: DNS labels exceeding 50 characters
* **Suspicious Record Types**: TXT, NULL, and other record types commonly used for tunneling
* **High Query Rate**: Abnormally frequent queries to the same domain
* **Many Unique Subdomains**: Pattern indicating data encoding in DNS queries

### HTTP Beacon Detection

* **POST Beaconing**: Repeated HTTP POST requests to the same endpoint
* **Suspicious User-Agents**: Known C2 framework User-Agent strings
* **Payload Size Consistency**: Low variance in request/response sizes indicating automated communication
* **High Request Rate**: Abnormally frequent HTTP requests

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

### Docker
```bash
docker build -t network-beacon .
docker run --net=host --cap-add=NET_RAW network-beacon capture -i eth0
```

## Usage

### Live Capture (TUI Mode)
```bash
# Auto-detect interface
sudo ./network-beacon capture

# Specify interface
sudo ./network-beacon capture -i en0

# With BPF filter
sudo ./network-beacon capture -i en0 -f "tcp port 443"

# With config file
sudo ./network-beacon capture -c config.toml
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

### Benchmark
```bash
# Default: 1000 flows, 100 events each
./network-beacon benchmark

# Custom parameters
./network-beacon benchmark --flows 5000 --events-per-flow 200
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
channel_capacity = 10000

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
dns_ports = [53, 5353]
http_ports = [80, 8080, 8888]
tls_ports = [443, 8443, 993, 995, 465]
profile = "balanced"  # paranoid, balanced, or relaxed

[detection.dns]
unique_subdomains_threshold = 10

[detection.http]
high_request_rate_threshold = 30

[alerting]
enabled = false
webhook_timeout_secs = 10

[[alerting.webhooks]]
url = "https://hooks.example.com/alert"
min_severity = "high"

[metrics]
enabled = false
bind_address = "127.0.0.1:9090"

[geo]
enabled = false
city_db_path = "/path/to/GeoLite2-City.mmdb"
asn_db_path = "/path/to/GeoLite2-ASN.mmdb"

[output]
format = "text"
verbose = false
```

### Detection Profiles

* **paranoid**: Higher sensitivity, more false positives
* **balanced**: Default settings
* **relaxed**: Lower sensitivity, fewer alerts

### Environment Variable Overrides

Key parameters can be overridden via environment variables:

| Variable | Description |
|----------|-------------|
| `NETWORK_BEACON_ANALYSIS_INTERVAL` | Analysis interval in seconds |
| `NETWORK_BEACON_MIN_SAMPLES` | Minimum samples for detection |
| `NETWORK_BEACON_MAX_FLOWS` | Maximum tracked flows |
| `NETWORK_BEACON_FLOW_TTL` | Flow TTL in seconds |

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
| HTTP-BCN | HTTP beacon pattern detected |
| PROTO-MIS | Protocol mismatch (e.g., TLS on non-443) |
| UNK-TLS | Unknown TLS client fingerprint |

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Capture   │────>│  Analyzer   │────>│     UI      │
│  (pcap)     │ ch1 │ (consumer)  │ ch2 │  (ratatui)  │
└─────────────┘     └─────────────┘     └─────────────┘
    Thread              Async               Async
                          │
                    ┌─────┴──────┐
                    │            │
              ┌─────┴───┐  ┌────┴─────┐
              │ GeoIP   │  │ Alerting │
              │ Enricher│  │ (webhook/│
              └─────────┘  │  syslog) │
                           └──────────┘
```

* **Capture**: Background thread using libpcap for packet sniffing
* **Analyzer**: Async task aggregating flows and computing detection metrics
* **UI**: Real-time TUI dashboard or console output
* **GeoIP**: Optional geographic enrichment of flow endpoints
* **Alerting**: Optional webhook/syslog notifications for high-severity detections

### Module Overview

| Module | Description |
|--------|-------------|
| `capture` | Packet capture and flow event creation |
| `analyzer` | Flow aggregation and detection orchestration |
| `config` | TOML configuration parsing and validation |
| `dns_detector` | DNS tunneling detection (entropy, query patterns) |
| `http_detector` | HTTP beacon detection (POST patterns, User-Agents) |
| `tls_fingerprint` | TLS Client Hello parsing and JA4 fingerprinting |
| `geo` | MaxMind GeoIP/ASN enrichment |
| `alerting` | Webhook and syslog alert delivery |
| `metrics` | Prometheus metrics exposition |
| `export` | Report formatting (text, JSON, JSONL) |
| `replay` | PCAP file replay for offline analysis |
| `ui` | Ratatui TUI dashboard |
| `error` | Error types |

## License

MIT License — See LICENSE file for details.
