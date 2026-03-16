//! Alerting module for real-time notifications.
//!
//! Supports webhook (HTTP POST) and syslog destinations for security alerts.

use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, trace, warn};

use crate::analyzer::FlowAnalysis;
use crate::geo::GeoInfo;

/// Sanitizes a string for safe inclusion in log messages by replacing
/// control characters (newlines, carriage returns, tabs, null bytes, etc.)
/// with underscores to prevent log injection attacks.
fn sanitize_log_field(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect()
}

/// Severity level for alerts.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    /// Low severity alert.
    Low,
    /// Medium severity alert (default).
    #[default]
    Medium,
    /// High severity alert.
    High,
    /// Critical severity alert.
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for AlertSeverity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(format!("Invalid severity: {}", s)),
        }
    }
}

/// Type of detection that triggered the alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionType {
    /// Periodic beaconing behavior detected.
    Beacon,
    /// DNS tunneling detected.
    DnsTunneling,
    /// Known malicious JA3 fingerprint matched.
    MaliciousJa3,
    /// Destination in a high-risk geographic region.
    HighRiskGeo,
    /// Protocol running on a nonstandard port.
    ProtocolMismatch,
}

impl std::fmt::Display for DetectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Beacon => write!(f, "beacon"),
            Self::DnsTunneling => write!(f, "dns_tunneling"),
            Self::MaliciousJa3 => write!(f, "malicious_ja3"),
            Self::HighRiskGeo => write!(f, "high_risk_geo"),
            Self::ProtocolMismatch => write!(f, "protocol_mismatch"),
        }
    }
}

/// Alert payload sent to webhooks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Timestamp when the alert was generated.
    pub timestamp: DateTime<Utc>,
    /// Severity level of the alert.
    pub severity: AlertSeverity,
    /// Type of detection that triggered this alert.
    pub detection_type: DetectionType,
    /// Source IP address of the suspicious flow.
    pub source_ip: String,
    /// Destination IP address of the suspicious flow.
    pub dest_ip: String,
    /// Destination port of the suspicious flow.
    pub dest_port: u16,
    /// Destination country code (if GeoIP available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_country: Option<String>,
    /// Destination ASN (if GeoIP available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_asn: Option<u32>,
    /// Destination ASN organization (if GeoIP available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_org: Option<String>,
    /// Geographic risk level (if GeoIP available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_risk: Option<String>,
    /// Coefficient of variation of inter-packet intervals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cv_value: Option<f64>,
    /// JA3 fingerprint hash (if TLS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3_hash: Option<String>,
    /// Matched malicious JA3 description (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3_match: Option<String>,
    /// Total packets in the flow.
    pub packet_count: u64,
    /// Duration of the flow in seconds.
    pub flow_duration_secs: i64,
    /// Detection indicators for this flow.
    pub indicators: Vec<String>,
}

impl Alert {
    /// Creates an alert from a flow analysis.
    pub fn from_flow(
        flow: &FlowAnalysis,
        detection_type: DetectionType,
        severity: AlertSeverity,
        geo_info: Option<&GeoInfo>,
    ) -> Self {
        let (ja3_hash, ja3_match) = flow
            .tls_fingerprint
            .as_ref()
            .map(|fp| (Some(fp.ja3_hash.clone()), fp.malicious_match.clone()))
            .unwrap_or((None, None));

        Self {
            timestamp: Utc::now(),
            severity,
            detection_type,
            source_ip: flow.flow_key.src_ip.to_string(),
            dest_ip: flow.flow_key.dst_ip.to_string(),
            dest_port: flow.flow_key.dst_port,
            dest_country: geo_info.and_then(|g| g.country_code.clone()),
            dest_asn: geo_info.and_then(|g| g.asn),
            dest_org: geo_info.and_then(|g| g.asn_org.clone()),
            geo_risk: geo_info.map(|g| g.risk.to_string()),
            cv_value: flow.cv,
            ja3_hash,
            ja3_match,
            packet_count: flow.packet_count,
            flow_duration_secs: flow.duration_secs,
            indicators: flow.indicators.clone(),
        }
    }

    /// Converts the alert to a syslog message.
    ///
    /// All variable fields are sanitized to prevent log injection attacks.
    pub fn to_syslog_message(&self) -> String {
        let sanitized_indicators: Vec<String> = self
            .indicators
            .iter()
            .map(|i| sanitize_log_field(i))
            .collect();
        format!(
            "network-beacon: severity={} type={} src={} dst={}:{} packets={} indicators={}",
            self.severity,
            self.detection_type,
            sanitize_log_field(&self.source_ip),
            sanitize_log_field(&self.dest_ip),
            self.dest_port,
            self.packet_count,
            sanitized_indicators.join(",")
        )
    }
}

/// Configuration for a webhook destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL.
    pub url: String,
    /// Minimum severity to send to this webhook.
    #[serde(default)]
    pub min_severity: AlertSeverity,
    /// Optional custom headers.
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

/// Configuration for syslog destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SyslogConfig {
    /// Enable syslog output.
    pub enabled: bool,
    /// Syslog host.
    pub host: String,
    /// Syslog port.
    pub port: u16,
    /// Protocol (udp or tcp).
    pub protocol: String,
    /// Syslog facility.
    pub facility: String,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: "localhost".to_string(),
            port: 514,
            protocol: "udp".to_string(),
            facility: "local0".to_string(),
        }
    }
}

/// Main alerting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertingConfig {
    /// Enable alerting.
    pub enabled: bool,
    /// Per-flow cooldown in seconds.
    pub throttle_seconds: u64,
    /// Maximum alerts per minute (global rate limit).
    pub max_alerts_per_minute: u32,
    /// HTTP client timeout for webhook requests (seconds).
    pub webhook_timeout_secs: u64,
    /// Webhook destinations.
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
    /// Syslog configuration.
    #[serde(default)]
    pub syslog: SyslogConfig,
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            throttle_seconds: 300,
            max_alerts_per_minute: 30,
            webhook_timeout_secs: 10,
            webhooks: vec![],
            syslog: SyslogConfig::default(),
        }
    }
}

/// Flow key for throttling.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ThrottleKey {
    src_ip: String,
    dst_ip: String,
    dst_port: u16,
}

/// The alerting service.
pub struct AlertService {
    config: AlertingConfig,
    http_client: reqwest::Client,
    /// Per-flow last alert time for throttling.
    flow_throttle: RwLock<HashMap<ThrottleKey, Instant>>,
    /// Global alert count for rate limiting.
    alerts_this_minute: RwLock<(Instant, u32)>,
    /// Syslog socket.
    syslog_socket: Option<UdpSocket>,
}

impl AlertService {
    /// Creates a new alert service.
    pub fn new(config: AlertingConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.webhook_timeout_secs))
            .build()
            .unwrap_or_default();

        let syslog_socket = if config.syslog.enabled && config.syslog.protocol == "udp" {
            match UdpSocket::bind("0.0.0.0:0") {
                Ok(socket) => {
                    debug!(
                        "Syslog UDP socket bound for {}:{}",
                        config.syslog.host, config.syslog.port
                    );
                    Some(socket)
                }
                Err(e) => {
                    warn!("Failed to bind syslog UDP socket: {}", e);
                    None
                }
            }
        } else {
            None
        };

        if config.enabled {
            info!(
                "Alerting enabled: {} webhooks, syslog={}",
                config.webhooks.len(),
                config.syslog.enabled
            );
        }

        Self {
            config,
            http_client,
            flow_throttle: RwLock::new(HashMap::new()),
            alerts_this_minute: RwLock::new((Instant::now(), 0)),
            syslog_socket,
        }
    }

    /// Checks if alerting is enabled.
    #[allow(dead_code)]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Sends an alert if not throttled.
    pub async fn send_alert(&self, alert: Alert) -> bool {
        if !self.config.enabled {
            return false;
        }

        // Check per-flow throttle
        let throttle_key = ThrottleKey {
            src_ip: alert.source_ip.clone(),
            dst_ip: alert.dest_ip.clone(),
            dst_port: alert.dest_port,
        };

        {
            let throttle = self.flow_throttle.read().await;
            if let Some(last_alert) = throttle.get(&throttle_key) {
                if last_alert.elapsed() < Duration::from_secs(self.config.throttle_seconds) {
                    trace!(
                        "Alert throttled for {}:{} -> {}:{}",
                        alert.source_ip,
                        alert.dest_port,
                        alert.dest_ip,
                        alert.dest_port
                    );
                    return false;
                }
            }
        }

        // Check global rate limit
        {
            let mut rate_limit = self.alerts_this_minute.write().await;
            let (window_start, count) = &mut *rate_limit;

            if window_start.elapsed() >= Duration::from_secs(60) {
                *window_start = Instant::now();
                *count = 0;
            }

            if *count >= self.config.max_alerts_per_minute {
                warn!(
                    "Global alert rate limit reached ({}/min)",
                    self.config.max_alerts_per_minute
                );
                return false;
            }

            *count += 1;
        }

        // Update throttle
        {
            let mut throttle = self.flow_throttle.write().await;
            throttle.insert(throttle_key, Instant::now());

            // Clean up old entries
            throttle
                .retain(|_, v| v.elapsed() < Duration::from_secs(self.config.throttle_seconds * 2));
        }

        debug!(
            "Sending alert: {} {} {}:{} -> {}:{}",
            alert.severity,
            alert.detection_type,
            alert.source_ip,
            alert.dest_port,
            alert.dest_ip,
            alert.dest_port
        );

        // Send to webhooks
        for webhook in &self.config.webhooks {
            if alert.severity >= webhook.min_severity {
                self.send_webhook(webhook, &alert).await;
            }
        }

        // Send to syslog
        if self.config.syslog.enabled {
            self.send_syslog(&alert);
        }

        true
    }

    /// Maximum number of retry attempts for webhook delivery.
    const WEBHOOK_MAX_RETRIES: u32 = 3;
    /// Base delay between retries (doubled each attempt).
    const WEBHOOK_RETRY_BASE_DELAY_MS: u64 = 500;

    /// Sends an alert to a webhook with retry logic.
    async fn send_webhook(&self, webhook: &WebhookConfig, alert: &Alert) {
        for attempt in 0..=Self::WEBHOOK_MAX_RETRIES {
            let mut request = self.http_client.post(&webhook.url).json(alert);

            for (key, value) in &webhook.headers {
                request = request.header(key, value);
            }

            match request.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        debug!("Webhook sent successfully to {}", webhook.url);
                        return;
                    }
                    let status = response.status();
                    if status.is_server_error() && attempt < Self::WEBHOOK_MAX_RETRIES {
                        let delay = Self::WEBHOOK_RETRY_BASE_DELAY_MS * 2u64.pow(attempt);
                        warn!(
                            "Webhook returned {} from {}, retrying in {}ms (attempt {}/{})",
                            status,
                            webhook.url,
                            delay,
                            attempt + 1,
                            Self::WEBHOOK_MAX_RETRIES
                        );
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        continue;
                    }
                    warn!(
                        "Webhook returned error status {} from {}",
                        status, webhook.url
                    );
                    return;
                }
                Err(e) => {
                    if attempt < Self::WEBHOOK_MAX_RETRIES {
                        let delay = Self::WEBHOOK_RETRY_BASE_DELAY_MS * 2u64.pow(attempt);
                        warn!(
                            "Webhook to {} failed: {}, retrying in {}ms (attempt {}/{})",
                            webhook.url,
                            e,
                            delay,
                            attempt + 1,
                            Self::WEBHOOK_MAX_RETRIES
                        );
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        continue;
                    }
                    error!(
                        "Failed to send webhook to {} after {} attempts: {}",
                        webhook.url,
                        Self::WEBHOOK_MAX_RETRIES + 1,
                        e
                    );
                    return;
                }
            }
        }
    }

    /// Sends an alert to syslog.
    fn send_syslog(&self, alert: &Alert) {
        let Some(ref socket) = self.syslog_socket else {
            return;
        };

        let message = alert.to_syslog_message();
        let target = format!("{}:{}", self.config.syslog.host, self.config.syslog.port);

        // RFC 5424 priority: facility * 8 + severity
        // local0 = 16, warning = 4, so priority = 16 * 8 + 4 = 132
        let priority = match alert.severity {
            AlertSeverity::Critical => 128 + 2, // local0.crit
            AlertSeverity::High => 128 + 3,     // local0.err
            AlertSeverity::Medium => 128 + 4,   // local0.warning
            AlertSeverity::Low => 128 + 6,      // local0.info
        };

        let syslog_msg = format!("<{}>{}", priority, message);

        match socket.send_to(syslog_msg.as_bytes(), &target) {
            Ok(_) => trace!("Syslog message sent to {}", target),
            Err(e) => warn!("Failed to send syslog message to {}: {}", target, e),
        }
    }

    /// Determines the severity based on flow analysis.
    pub fn determine_severity(flow: &FlowAnalysis, geo_info: Option<&GeoInfo>) -> AlertSeverity {
        // Check for malicious JA3 - always critical
        if let Some(ref fp) = flow.tls_fingerprint {
            if fp.is_known_malicious {
                return AlertSeverity::Critical;
            }
        }

        // Check CV-based classification
        let cv_severity = match flow.classification {
            crate::analyzer::FlowClassification::HighlyPeriodic => AlertSeverity::Critical,
            crate::analyzer::FlowClassification::JitteredPeriodic => AlertSeverity::High,
            crate::analyzer::FlowClassification::Moderate => AlertSeverity::Medium,
            _ => AlertSeverity::Low,
        };

        // Check geo risk
        let geo_severity = match geo_info.map(|g| g.risk) {
            Some(crate::geo::GeoRisk::High) => AlertSeverity::High,
            Some(crate::geo::GeoRisk::Elevated) => AlertSeverity::Medium,
            _ => AlertSeverity::Low,
        };

        // Check DNS tunneling
        let dns_severity = if flow
            .dns_analysis
            .as_ref()
            .map(|d| d.is_suspicious)
            .unwrap_or(false)
        {
            AlertSeverity::High
        } else {
            AlertSeverity::Low
        };

        // Return highest severity
        [cv_severity, geo_severity, dns_severity]
            .into_iter()
            .max()
            .unwrap_or(AlertSeverity::Low)
    }

    /// Determines the primary detection type for a flow.
    pub fn determine_detection_type(flow: &FlowAnalysis) -> DetectionType {
        // Check for malicious JA3 first
        if let Some(ref fp) = flow.tls_fingerprint {
            if fp.is_known_malicious {
                return DetectionType::MaliciousJa3;
            }
        }

        // Check for DNS tunneling
        if flow
            .dns_analysis
            .as_ref()
            .map(|d| d.is_suspicious)
            .unwrap_or(false)
        {
            return DetectionType::DnsTunneling;
        }

        // Check for protocol mismatch
        if flow
            .indicators
            .iter()
            .any(|i| i.contains("nonstandard_port"))
        {
            return DetectionType::ProtocolMismatch;
        }

        // Default to beacon
        DetectionType::Beacon
    }
}

/// Thread-safe shared alert service.
pub type SharedAlertService = Arc<AlertService>;

/// Creates a shared alert service.
pub fn new_shared_alert_service(config: AlertingConfig) -> SharedAlertService {
    Arc::new(AlertService::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::FlowClassification;
    use crate::capture::{FlowKey, Protocol};
    use crate::dns_detector::DnsAnalysisResult;
    use crate::tls_fingerprint::{ThreatCategory, TlsFingerprint, TlsStatus, TlsVersionInfo};
    use std::net::IpAddr;

    /// Helper to create a minimal FlowAnalysis for testing.
    fn make_test_flow() -> FlowAnalysis {
        let flow_key = FlowKey::new(
            "192.168.1.1".parse::<IpAddr>().unwrap(),
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            443,
            Protocol::Tcp,
        );
        FlowAnalysis {
            flow_key,
            classification: FlowClassification::Moderate,
            cv: Some(0.5),
            mean_interval_ms: Some(60000.0),
            packet_count: 100,
            total_bytes: 50000,
            duration_secs: 3600,
            tls_fingerprint: None,
            tls_status: TlsStatus::Plaintext,
            dns_analysis: None,
            http_analysis: None,
            indicators: vec![],
            geo_info: None,
        }
    }

    #[test]
    fn test_alert_severity_ordering() {
        assert!(AlertSeverity::Critical > AlertSeverity::High);
        assert!(AlertSeverity::High > AlertSeverity::Medium);
        assert!(AlertSeverity::Medium > AlertSeverity::Low);
    }

    #[test]
    fn test_alert_severity_parse() {
        assert_eq!(
            "critical".parse::<AlertSeverity>().unwrap(),
            AlertSeverity::Critical
        );
        assert_eq!(
            "HIGH".parse::<AlertSeverity>().unwrap(),
            AlertSeverity::High
        );
        assert_eq!(
            "Medium".parse::<AlertSeverity>().unwrap(),
            AlertSeverity::Medium
        );
        assert_eq!("low".parse::<AlertSeverity>().unwrap(), AlertSeverity::Low);
    }

    #[test]
    fn test_detection_type_display() {
        assert_eq!(format!("{}", DetectionType::Beacon), "beacon");
        assert_eq!(format!("{}", DetectionType::DnsTunneling), "dns_tunneling");
        assert_eq!(format!("{}", DetectionType::MaliciousJa3), "malicious_ja3");
    }

    #[test]
    fn test_alert_to_syslog_message() {
        let alert = Alert {
            timestamp: Utc::now(),
            severity: AlertSeverity::High,
            detection_type: DetectionType::Beacon,
            source_ip: "192.168.1.100".to_string(),
            dest_ip: "45.33.32.156".to_string(),
            dest_port: 443,
            dest_country: Some("RU".to_string()),
            dest_asn: None,
            dest_org: None,
            geo_risk: Some("high".to_string()),
            cv_value: Some(0.05),
            ja3_hash: None,
            ja3_match: None,
            packet_count: 100,
            flow_duration_secs: 3600,
            indicators: vec!["periodic_beacon".to_string()],
        };

        let msg = alert.to_syslog_message();
        assert!(msg.contains("network-beacon"));
        assert!(msg.contains("severity=high"));
        assert!(msg.contains("type=beacon"));
        assert!(msg.contains("192.168.1.100"));
    }

    #[test]
    fn test_alerting_config_default() {
        let config = AlertingConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.throttle_seconds, 300);
        assert_eq!(config.max_alerts_per_minute, 30);
        assert!(config.webhooks.is_empty());
    }

    #[test]
    fn test_syslog_config_default() {
        let config = SyslogConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 514);
        assert_eq!(config.protocol, "udp");
    }

    #[test]
    fn test_alert_service_construction_disabled() {
        let config = AlertingConfig::default();
        let service = AlertService::new(config);
        assert!(!service.is_enabled());
    }

    #[test]
    fn test_alert_service_construction_with_webhook() {
        let config = AlertingConfig {
            enabled: true,
            webhook_timeout_secs: 5,
            webhooks: vec![WebhookConfig {
                url: "https://example.com/hook".to_string(),
                min_severity: AlertSeverity::High,
                headers: std::collections::HashMap::new(),
            }],
            ..AlertingConfig::default()
        };
        let service = AlertService::new(config);
        assert!(service.is_enabled());
    }

    #[test]
    fn test_alert_severity_display() {
        assert_eq!(format!("{}", AlertSeverity::Low), "low");
        assert_eq!(format!("{}", AlertSeverity::Medium), "medium");
        assert_eq!(format!("{}", AlertSeverity::High), "high");
        assert_eq!(format!("{}", AlertSeverity::Critical), "critical");
    }

    #[test]
    fn test_alert_severity_invalid_parse() {
        assert!("invalid".parse::<AlertSeverity>().is_err());
    }

    #[test]
    fn test_detection_type_all_variants_display() {
        assert_eq!(format!("{}", DetectionType::HighRiskGeo), "high_risk_geo");
        assert_eq!(
            format!("{}", DetectionType::ProtocolMismatch),
            "protocol_mismatch"
        );
    }

    #[test]
    fn test_syslog_message_sanitizes_control_chars() {
        let alert = Alert {
            timestamp: Utc::now(),
            severity: AlertSeverity::High,
            detection_type: DetectionType::Beacon,
            source_ip: "192.168.1.1".to_string(),
            dest_ip: "10.0.0.1".to_string(),
            dest_port: 443,
            dest_country: None,
            dest_asn: None,
            dest_org: None,
            geo_risk: None,
            cv_value: None,
            ja3_hash: None,
            ja3_match: None,
            packet_count: 10,
            flow_duration_secs: 60,
            indicators: vec![
                "indicator\nwith_newline".to_string(),
                "indicator\rwith_cr".to_string(),
                "indicator\twith_tab".to_string(),
            ],
        };

        let msg = alert.to_syslog_message();
        assert!(!msg.contains('\n'));
        assert!(!msg.contains('\r'));
        assert!(!msg.contains('\t'));
        assert!(msg.contains("indicator_with_newline"));
        assert!(msg.contains("indicator_with_cr"));
        assert!(msg.contains("indicator_with_tab"));
    }

    #[test]
    fn test_determine_severity_malicious_ja3() {
        let mut flow = make_test_flow();
        flow.tls_fingerprint = Some(TlsFingerprint {
            fingerprint: "test".to_string(),
            ja3_hash: "abc123".to_string(),
            ja3_string: "test".to_string(),
            tls_version: TlsVersionInfo::Tls12,
            cipher_count: 5,
            extension_count: 3,
            sni: None,
            is_known_good: false,
            known_match: None,
            is_known_malicious: true,
            malicious_match: Some("CobaltStrike".to_string()),
            threat_category: Some(ThreatCategory::C2Framework),
        });

        let severity = AlertService::determine_severity(&flow, None);
        assert_eq!(severity, AlertSeverity::Critical);
    }

    #[test]
    fn test_determine_severity_highly_periodic() {
        let mut flow = make_test_flow();
        flow.classification = FlowClassification::HighlyPeriodic;

        let severity = AlertService::determine_severity(&flow, None);
        assert_eq!(severity, AlertSeverity::Critical);
    }

    #[test]
    fn test_determine_detection_type_dns() {
        let mut flow = make_test_flow();
        flow.dns_analysis = Some(DnsAnalysisResult {
            is_suspicious: true,
            max_entropy: 4.5,
            max_label_length: 60,
            query_rate: 10.0,
            indicators: vec![],
            query_count: 100,
        });

        let dt = AlertService::determine_detection_type(&flow);
        assert!(matches!(dt, DetectionType::DnsTunneling));
    }

    #[test]
    fn test_determine_detection_type_protocol_mismatch() {
        let mut flow = make_test_flow();
        flow.indicators = vec!["tls_on_nonstandard_port".to_string()];

        let dt = AlertService::determine_detection_type(&flow);
        assert!(matches!(dt, DetectionType::ProtocolMismatch));
    }

    #[test]
    fn test_alert_from_flow() {
        let flow = make_test_flow();
        let alert = Alert::from_flow(&flow, DetectionType::Beacon, AlertSeverity::High, None);

        assert_eq!(alert.source_ip, "192.168.1.1");
        assert_eq!(alert.dest_ip, "10.0.0.1");
        assert_eq!(alert.dest_port, 443);
        assert_eq!(alert.severity, AlertSeverity::High);
        assert!(matches!(alert.detection_type, DetectionType::Beacon));
        assert_eq!(alert.packet_count, 100);
        assert_eq!(alert.flow_duration_secs, 3600);
        assert!(alert.dest_country.is_none());
        assert!(alert.ja3_hash.is_none());
    }
}
