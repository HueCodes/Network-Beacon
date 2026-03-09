# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-03-08

### Added
- HTTP beacon detection (POST patterns, User-Agent analysis, payload size consistency)
- GeoIP enrichment via MaxMind databases (city + ASN)
- Webhook and syslog alerting with throttling, dedup, and retry
- Prometheus metrics endpoint (`/metrics`)
- PCAP file validation (magic byte checks before replay)
- `benchmark` subcommand for synthetic throughput testing
- `generate-config` subcommand to emit default TOML configuration
- TOML configuration file support with detection profiles (paranoid/balanced/relaxed)
- Configurable port lists for DNS, HTTP, and TLS detection
- Configurable payload limits, thresholds, and timeouts
- Environment variable overrides for key parameters
- GitHub Actions CI pipeline (fmt, clippy, test, release build)
- Dockerfile with multi-stage build
- justfile for common development tasks
- 142 unit tests covering all detection modules

### Changed
- Replaced all hardcoded detection thresholds with configurable values
- Webhook delivery now retries on 5xx errors with exponential backoff
- Improved error handling across all modules (replaced unwrap/expect with proper error propagation)
- Removed dead code and unused imports

### Fixed
- DNS `query_rate()` no longer panics on empty query times
- PCAP replay validates file before attempting parse

## [0.1.0] - 2024-12-01

### Added
- Initial release
- CV-based beacon detection
- TLS fingerprinting (JA3/JA4)
- DNS tunneling detection
- Protocol mismatch detection
- Ratatui TUI dashboard
- PCAP replay support
- Text, JSON, and JSONL output formats
