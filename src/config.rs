//! Configuration Module
//!
//! Provides TOML-based configuration for Network-Beacon.
//! Configuration is optional - CLI arguments can override file settings.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::alerting::AlertingConfig;
use crate::dns_detector::DnsDetectorConfig;
use crate::export::OutputFormat;
use crate::geo::GeoConfig;
use crate::http_detector::HttpDetectorConfig;

/// Main configuration structure
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub capture: CaptureConfig,
    pub analyzer: AnalyzerConfig,
    pub detection: DetectionConfig,
    pub output: OutputConfig,
    pub geo: GeoConfig,
    pub alerting: AlertingConfig,
    pub metrics: MetricsConfig,
}

impl Config {
    /// Loads configuration from a TOML file
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        Ok(config)
    }

    /// Loads configuration from file if it exists, otherwise returns defaults
    pub fn load_or_default(path: Option<&Path>) -> Self {
        match path {
            Some(p) => Self::load(p).unwrap_or_else(|e| {
                tracing::warn!("Failed to load config: {}, using defaults", e);
                Self::default()
            }),
            None => Self::default(),
        }
    }

    /// Generates a default configuration file content
    pub fn generate_default() -> String {
        let config = Config::default();
        toml::to_string_pretty(&config)
            .unwrap_or_else(|_| "# Failed to generate config".to_string())
    }

    /// Validates the configuration
    pub fn validate(&self) -> Result<()> {
        if self.analyzer.max_flows == 0 {
            anyhow::bail!("max_flows must be greater than 0");
        }
        if self.analyzer.min_samples == 0 {
            anyhow::bail!("min_samples must be greater than 0");
        }
        if self.detection.cv_threshold_periodic <= 0.0
            || self.detection.cv_threshold_periodic >= 1.0
        {
            anyhow::bail!("cv_threshold_periodic must be between 0.0 and 1.0");
        }
        if self.detection.entropy_threshold <= 0.0 || self.detection.entropy_threshold >= 8.0 {
            anyhow::bail!("entropy_threshold must be between 0.0 and 8.0 (bits per char)");
        }
        if self.detection.dns_ports.is_empty() {
            anyhow::bail!("dns_ports must not be empty");
        }
        if self.detection.http_ports.is_empty() {
            anyhow::bail!("http_ports must not be empty");
        }
        if self.detection.tls_ports.is_empty() {
            anyhow::bail!("tls_ports must not be empty");
        }
        if self.capture.tls_payload_limit == 0 {
            anyhow::bail!("tls_payload_limit must be greater than 0");
        }
        if self.capture.dns_payload_limit == 0 {
            anyhow::bail!("dns_payload_limit must be greater than 0");
        }
        if self.capture.http_payload_limit == 0 {
            anyhow::bail!("http_payload_limit must be greater than 0");
        }
        if self.detection.dns.unique_subdomains_threshold == 0 {
            anyhow::bail!("unique_subdomains_threshold must be greater than 0");
        }
        if self.alerting.webhook_timeout_secs == 0 {
            anyhow::bail!("webhook_timeout_secs must be greater than 0");
        }
        Ok(())
    }
}

/// Capture-related configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CaptureConfig {
    /// Network interface to capture on (None = auto-detect)
    pub interface: Option<String>,
    /// BPF filter expression
    pub filter: Option<String>,
    /// Enable promiscuous mode
    pub promiscuous: bool,
    /// Capture timeout in milliseconds
    pub timeout_ms: i32,
    /// Channel buffer size for flow events
    pub channel_capacity: usize,
    /// Maximum bytes to capture from TLS Client Hello payloads
    pub tls_payload_limit: usize,
    /// Maximum bytes to capture from DNS payloads
    pub dns_payload_limit: usize,
    /// Maximum bytes to capture from HTTP request payloads
    pub http_payload_limit: usize,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: None,
            filter: None,
            promiscuous: true,
            timeout_ms: 100,
            channel_capacity: 10_000,
            tls_payload_limit: 512,
            dns_payload_limit: 512,
            http_payload_limit: 2048,
        }
    }
}

/// Analyzer-related configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AnalyzerConfig {
    /// Maximum number of flows to track (LRU eviction)
    pub max_flows: usize,
    /// Maximum timestamps to retain per flow
    pub max_timestamps_per_flow: usize,
    /// Analysis interval in seconds
    pub analysis_interval_secs: u64,
    /// Minimum samples required for CV calculation
    pub min_samples: usize,
    /// TTL for inactive flows in seconds
    pub flow_ttl_secs: u64,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            max_flows: 10_000,
            max_timestamps_per_flow: 1_000,
            analysis_interval_secs: 10,
            min_samples: 5,
            flow_ttl_secs: 300,
        }
    }
}

/// Detection-related configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DetectionConfig {
    /// Enable CV-based beacon detection
    pub cv_enabled: bool,
    /// Enable DNS tunneling detection
    pub dns_tunneling_enabled: bool,
    /// CV threshold for highly periodic (CRITICAL)
    pub cv_threshold_periodic: f64,
    /// CV threshold for jittered periodic (HIGH)
    pub cv_threshold_jittered: f64,
    /// Entropy threshold for DNS tunneling detection
    pub entropy_threshold: f64,
    /// Maximum normal DNS label length
    pub max_dns_label_length: usize,
    /// Detection profile (affects sensitivity)
    pub profile: DetectionProfile,
    /// Ports considered DNS traffic
    pub dns_ports: Vec<u16>,
    /// Ports considered HTTP traffic
    pub http_ports: Vec<u16>,
    /// Ports considered TLS traffic
    pub tls_ports: Vec<u16>,
    /// DNS tunneling detection sub-config
    pub dns: DnsDetectorConfig,
    /// HTTP beacon detection sub-config
    pub http: HttpDetectorConfig,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            cv_enabled: true,
            dns_tunneling_enabled: true,
            cv_threshold_periodic: 0.1,
            cv_threshold_jittered: 0.5,
            entropy_threshold: 3.5,
            max_dns_label_length: 50,
            profile: DetectionProfile::Balanced,
            dns_ports: vec![53, 5353, 5355],
            http_ports: vec![80, 8080, 8000, 8008, 8888, 3000, 3128, 9000],
            tls_ports: vec![443, 8443, 993, 995, 465, 636, 989, 990, 5061],
            dns: DnsDetectorConfig::default(),
            http: HttpDetectorConfig::default(),
        }
    }
}

/// Detection sensitivity profile
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DetectionProfile {
    /// High sensitivity, more false positives
    Paranoid,
    /// Default balanced profile
    #[default]
    Balanced,
    /// Low sensitivity, fewer alerts
    Relaxed,
}

impl DetectionProfile {
    /// Returns adjusted thresholds based on profile
    #[allow(dead_code)]
    pub fn adjust_cv_threshold(&self, base: f64) -> f64 {
        match self {
            Self::Paranoid => base * 1.5, // More lenient = more detections
            Self::Balanced => base,
            Self::Relaxed => base * 0.5, // Stricter = fewer detections
        }
    }

    /// Returns adjusted min_samples based on profile
    #[allow(dead_code)]
    pub fn adjust_min_samples(&self, base: usize) -> usize {
        match self {
            Self::Paranoid => base.saturating_sub(2).max(2),
            Self::Balanced => base,
            Self::Relaxed => base + 3,
        }
    }
}

impl std::fmt::Display for DetectionProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Paranoid => write!(f, "paranoid"),
            Self::Balanced => write!(f, "balanced"),
            Self::Relaxed => write!(f, "relaxed"),
        }
    }
}

/// Output-related configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct OutputConfig {
    /// Output format (text, json, jsonl)
    #[serde(with = "output_format_serde")]
    pub format: OutputFormat,
    /// Output file path (None = stdout)
    pub file: Option<String>,
    /// Enable verbose logging
    pub verbose: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Text,
            file: None,
            verbose: false,
        }
    }
}

/// Prometheus metrics configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// Enable Prometheus metrics endpoint.
    pub enabled: bool,
    /// Bind address for the metrics HTTP server.
    pub bind_address: String,
    /// Metrics endpoint path.
    pub metrics_path: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "127.0.0.1:9090".to_string(),
            metrics_path: "/metrics".to_string(),
        }
    }
}

/// Custom serde implementation for OutputFormat
mod output_format_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(format: &OutputFormat, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OutputFormat, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert!(config.detection.cv_enabled);
        assert!(config.detection.dns_tunneling_enabled);
        assert_eq!(config.analyzer.max_flows, 10_000);
    }

    #[test]
    fn test_config_validate() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());

        config.analyzer.max_flows = 0;
        assert!(config.validate().is_err());

        // Reset and test other validations
        let mut config = Config::default();
        config.detection.dns_ports = vec![];
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.capture.tls_payload_limit = 0;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.alerting.webhook_timeout_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_detection_profile_adjust() {
        let paranoid = DetectionProfile::Paranoid;
        let balanced = DetectionProfile::Balanced;
        let relaxed = DetectionProfile::Relaxed;

        assert!(paranoid.adjust_cv_threshold(0.1) > balanced.adjust_cv_threshold(0.1));
        assert!(relaxed.adjust_cv_threshold(0.1) < balanced.adjust_cv_threshold(0.1));
    }

    #[test]
    fn test_generate_default_config() {
        let config_str = Config::generate_default();
        assert!(config_str.contains("[capture]"));
        assert!(config_str.contains("[analyzer]"));
        assert!(config_str.contains("[detection]"));
        assert!(config_str.contains("[output]"));
    }

    #[test]
    fn test_parse_config() {
        let toml_str = r#"
[capture]
interface = "en0"
promiscuous = true

[analyzer]
max_flows = 5000
min_samples = 3

[detection]
cv_enabled = true
dns_tunneling_enabled = true
profile = "paranoid"

[output]
format = "json"
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.capture.interface, Some("en0".to_string()));
        assert_eq!(config.analyzer.max_flows, 5000);
        assert_eq!(config.detection.profile, DetectionProfile::Paranoid);
        assert_eq!(config.output.format, OutputFormat::Json);
    }

    #[test]
    fn test_validate_empty_http_ports() {
        let mut config = Config::default();
        config.detection.http_ports = vec![];
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("http_ports"));
    }

    #[test]
    fn test_validate_empty_tls_ports() {
        let mut config = Config::default();
        config.detection.tls_ports = vec![];
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("tls_ports"));
    }

    #[test]
    fn test_validate_zero_dns_payload_limit() {
        let mut config = Config::default();
        config.capture.dns_payload_limit = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_zero_http_payload_limit() {
        let mut config = Config::default();
        config.capture.http_payload_limit = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_zero_min_samples() {
        let mut config = Config::default();
        config.analyzer.min_samples = 0;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("min_samples"));
    }

    #[test]
    fn test_validate_cv_threshold_out_of_range() {
        let mut config = Config::default();
        config.detection.cv_threshold_periodic = 0.0;
        assert!(config.validate().is_err());

        config.detection.cv_threshold_periodic = 1.0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_entropy_threshold_out_of_range() {
        let mut config = Config::default();
        config.detection.entropy_threshold = 0.0;
        assert!(config.validate().is_err());

        config.detection.entropy_threshold = 8.0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_zero_unique_subdomains_threshold() {
        let mut config = Config::default();
        config.detection.dns.unique_subdomains_threshold = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_parse_config_with_nested_dns_config() {
        let toml_str = r#"
[detection.dns]
entropy_threshold = 4.0
max_label_length = 30
unique_subdomains_threshold = 20

[detection.http]
min_requests = 10
high_request_rate_threshold = 60
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.detection.dns.entropy_threshold, 4.0);
        assert_eq!(config.detection.dns.max_label_length, 30);
        assert_eq!(config.detection.dns.unique_subdomains_threshold, 20);
        assert_eq!(config.detection.http.min_requests, 10);
        assert_eq!(config.detection.http.high_request_rate_threshold, 60);
    }

    #[test]
    fn test_detection_profile_display() {
        assert_eq!(DetectionProfile::Paranoid.to_string(), "paranoid");
        assert_eq!(DetectionProfile::Balanced.to_string(), "balanced");
        assert_eq!(DetectionProfile::Relaxed.to_string(), "relaxed");
    }

    #[test]
    fn test_detection_profile_adjust_min_samples() {
        assert_eq!(DetectionProfile::Paranoid.adjust_min_samples(5), 3);
        assert_eq!(DetectionProfile::Balanced.adjust_min_samples(5), 5);
        assert_eq!(DetectionProfile::Relaxed.adjust_min_samples(5), 8);
    }

    #[test]
    fn test_load_or_default_with_none() {
        let config = Config::load_or_default(None);
        assert_eq!(config.analyzer.max_flows, 10_000);
    }

    #[test]
    fn test_metrics_config_default() {
        let config = MetricsConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.bind_address, "127.0.0.1:9090");
        assert_eq!(config.metrics_path, "/metrics");
    }
}
