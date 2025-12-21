//! Configuration Module
//!
//! Provides TOML-based configuration for Network-Beacon.
//! Configuration is optional - CLI arguments can override file settings.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::export::OutputFormat;

/// Main configuration structure
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub capture: CaptureConfig,
    pub analyzer: AnalyzerConfig,
    pub detection: DetectionConfig,
    pub output: OutputConfig,
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
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: None,
            filter: None,
            promiscuous: true,
            timeout_ms: 100,
            channel_capacity: 10_000,
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
    #[allow(dead_code)] // For future config-based threshold adjustment
    pub fn adjust_cv_threshold(&self, base: f64) -> f64 {
        match self {
            Self::Paranoid => base * 1.5, // More lenient = more detections
            Self::Balanced => base,
            Self::Relaxed => base * 0.5, // Stricter = fewer detections
        }
    }

    /// Returns adjusted min_samples based on profile
    #[allow(dead_code)] // For future config-based threshold adjustment
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
}
