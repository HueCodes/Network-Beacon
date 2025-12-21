//! Export Module
//!
//! Provides functionality to export analysis reports in various formats,
//! including JSON for integration with other security tools.

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::analyzer::{AnalysisReport, FlowAnalysis, FlowClassification};
use crate::dns_detector::DnsAnalysisResult;

/// Output format for exports
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    JsonLines, // One JSON object per line (JSONL)
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "jsonl" | "jsonlines" => Ok(Self::JsonLines),
            _ => Err(format!("Unknown output format: {}", s)),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::Json => write!(f, "json"),
            Self::JsonLines => write!(f, "jsonl"),
        }
    }
}

/// JSON-serializable analysis report
#[derive(Serialize)]
pub struct JsonReport {
    pub version: &'static str,
    pub timestamp: String,
    pub total_flows: usize,
    pub active_flows: usize,
    pub suspicious_count: usize,
    pub events_processed: u64,
    pub suspicious_flows: Vec<JsonFlow>,
}

impl From<&AnalysisReport> for JsonReport {
    fn from(report: &AnalysisReport) -> Self {
        Self {
            version: "1.0",
            timestamp: report.timestamp.to_rfc3339(),
            total_flows: report.total_flows,
            active_flows: report.active_flows,
            suspicious_count: report.suspicious_flows.len(),
            events_processed: report.events_processed,
            suspicious_flows: report.suspicious_flows.iter().map(JsonFlow::from).collect(),
        }
    }
}

/// JSON-serializable flow analysis
#[derive(Serialize)]
pub struct JsonFlow {
    pub flow_key: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub classification: String,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cv: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_interval_ms: Option<f64>,
    pub packet_count: u64,
    pub total_bytes: u64,
    pub duration_secs: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_fingerprint: Option<JsonTlsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_analysis: Option<JsonDnsAnalysis>,
    pub indicators: Vec<String>,
}

impl From<&FlowAnalysis> for JsonFlow {
    fn from(flow: &FlowAnalysis) -> Self {
        Self {
            flow_key: flow.flow_key.to_string(),
            src_ip: flow.flow_key.src_ip.to_string(),
            dst_ip: flow.flow_key.dst_ip.to_string(),
            dst_port: flow.flow_key.dst_port,
            protocol: format!("{}", flow.flow_key.protocol),
            classification: format!("{}", flow.classification),
            severity: flow.classification.severity().to_string(),
            cv: flow.cv,
            mean_interval_ms: flow.mean_interval_ms,
            packet_count: flow.packet_count,
            total_bytes: flow.total_bytes,
            duration_secs: flow.duration_secs,
            tls_fingerprint: flow.tls_fingerprint.as_ref().map(|fp| JsonTlsInfo {
                fingerprint: fp.fingerprint.clone(),
                tls_version: format!("{}", fp.tls_version),
                cipher_count: fp.cipher_count,
                extension_count: fp.extension_count,
                sni: fp.sni.clone(),
                is_known_good: fp.is_known_good,
                known_match: fp.known_match.clone(),
            }),
            dns_analysis: flow.dns_analysis.as_ref().map(JsonDnsAnalysis::from),
            indicators: flow.indicators.clone(),
        }
    }
}

/// JSON-serializable TLS fingerprint info
#[derive(Serialize)]
pub struct JsonTlsInfo {
    pub fingerprint: String,
    pub tls_version: String,
    pub cipher_count: usize,
    pub extension_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    pub is_known_good: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_match: Option<String>,
}

/// JSON-serializable DNS analysis result
#[derive(Serialize)]
pub struct JsonDnsAnalysis {
    pub is_suspicious: bool,
    pub max_entropy: f64,
    pub max_label_length: usize,
    pub query_rate: f64,
    pub query_count: usize,
    pub indicators: Vec<String>,
}

impl From<&DnsAnalysisResult> for JsonDnsAnalysis {
    fn from(dns: &DnsAnalysisResult) -> Self {
        Self {
            is_suspicious: dns.is_suspicious,
            max_entropy: dns.max_entropy,
            max_label_length: dns.max_label_length,
            query_rate: dns.query_rate,
            query_count: dns.query_count,
            indicators: dns.indicators.iter().map(|i| format!("{:?}", i)).collect(),
        }
    }
}

/// Exports a report in the specified format
pub fn export_report(report: &AnalysisReport, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => export_text(report),
        OutputFormat::Json => export_json(report),
        OutputFormat::JsonLines => export_jsonl(report),
    }
}

/// Exports report as pretty-printed JSON
pub fn export_json(report: &AnalysisReport) -> String {
    let json_report = JsonReport::from(report);
    serde_json::to_string_pretty(&json_report)
        .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
}

/// Exports report as JSON Lines (one flow per line)
pub fn export_jsonl(report: &AnalysisReport) -> String {
    let mut lines = Vec::new();

    // First line is the summary
    let summary = serde_json::json!({
        "type": "summary",
        "timestamp": report.timestamp.to_rfc3339(),
        "total_flows": report.total_flows,
        "active_flows": report.active_flows,
        "suspicious_count": report.suspicious_flows.len(),
        "events_processed": report.events_processed,
    });
    lines.push(serde_json::to_string(&summary).unwrap_or_default());

    // Each flow is a separate line
    for flow in &report.suspicious_flows {
        let json_flow = JsonFlow::from(flow);
        if let Ok(line) = serde_json::to_string(&json_flow) {
            lines.push(line);
        }
    }

    lines.join("\n")
}

/// Exports report as formatted text
pub fn export_text(report: &AnalysisReport) -> String {
    let mut output = String::new();

    output.push_str(&format!(
        "--- Analysis Report ---\nTime: {}\nTotal Flows: {}\nActive Flows: {}\nEvents Processed: {}\n",
        report.timestamp.format("%Y-%m-%d %H:%M:%S"),
        report.total_flows,
        report.active_flows,
        report.events_processed
    ));

    if report.suspicious_flows.is_empty() {
        output.push_str("Suspicious Flows: None detected\n");
    } else {
        output.push_str(&format!(
            "\nSuspicious Flows ({}):\n",
            report.suspicious_flows.len()
        ));
        output.push_str(&"-".repeat(100));
        output.push('\n');

        for flow in &report.suspicious_flows {
            output.push_str(&format!(
                "[{:8}] {} -> {}:{} | CV: {:.4} | Interval: {} | Packets: {} | Indicators: [{}]\n",
                flow.classification.severity(),
                flow.flow_key.src_ip,
                flow.flow_key.dst_ip,
                flow.flow_key.dst_port,
                flow.cv.unwrap_or(0.0),
                format_interval(flow.mean_interval_ms),
                flow.packet_count,
                flow.indicators.join(", "),
            ));
        }
    }

    output
}

/// Formats an interval in a human-readable way
fn format_interval(ms: Option<f64>) -> String {
    match ms {
        Some(ms) if ms >= 1000.0 => format!("{:.1}s", ms / 1000.0),
        Some(ms) => format!("{:.0}ms", ms),
        None => "N/A".to_string(),
    }
}

/// Exports a single flow as JSON (for streaming output)
#[allow(dead_code)] // Available for streaming JSON output
pub fn export_flow_json(flow: &FlowAnalysis) -> String {
    let json_flow = JsonFlow::from(flow);
    serde_json::to_string(&json_flow).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
}

/// Creates a detection event for SIEM integration
#[allow(dead_code)] // Available for SIEM integration
#[derive(Serialize)]
pub struct DetectionEvent {
    pub event_type: &'static str,
    pub timestamp: String,
    pub source_ip: String,
    pub destination_ip: String,
    pub destination_port: u16,
    pub protocol: String,
    pub severity: String,
    pub detection_type: String,
    pub confidence: f64,
    pub indicators: Vec<String>,
    pub metadata: serde_json::Value,
}

impl DetectionEvent {
    #[allow(dead_code)] // Available for SIEM integration
    pub fn from_flow(flow: &FlowAnalysis, timestamp: DateTime<Utc>) -> Self {
        // Calculate confidence based on indicators
        let base_confidence = match flow.classification {
            FlowClassification::HighlyPeriodic => 0.9,
            FlowClassification::JitteredPeriodic => 0.7,
            FlowClassification::Moderate => 0.5,
            _ => 0.3,
        };

        let dns_boost = if flow
            .dns_analysis
            .as_ref()
            .map(|d| d.is_suspicious)
            .unwrap_or(false)
        {
            0.1
        } else {
            0.0
        };

        let tls_boost = if flow
            .tls_fingerprint
            .as_ref()
            .map(|t| !t.is_known_good)
            .unwrap_or(false)
        {
            0.05
        } else {
            0.0
        };

        let confidence = f64::min(base_confidence + dns_boost + tls_boost, 1.0);

        let detection_type = if flow
            .dns_analysis
            .as_ref()
            .map(|d| d.is_suspicious)
            .unwrap_or(false)
        {
            "dns_tunneling"
        } else {
            "periodic_beacon"
        };

        Self {
            event_type: "detection",
            timestamp: timestamp.to_rfc3339(),
            source_ip: flow.flow_key.src_ip.to_string(),
            destination_ip: flow.flow_key.dst_ip.to_string(),
            destination_port: flow.flow_key.dst_port,
            protocol: format!("{}", flow.flow_key.protocol),
            severity: flow.classification.severity().to_string(),
            detection_type: detection_type.to_string(),
            confidence,
            indicators: flow.indicators.clone(),
            metadata: serde_json::json!({
                "cv": flow.cv,
                "mean_interval_ms": flow.mean_interval_ms,
                "packet_count": flow.packet_count,
                "total_bytes": flow.total_bytes,
                "duration_secs": flow.duration_secs,
            }),
        }
    }

    #[allow(dead_code)] // Available for SIEM integration
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_format_parse() {
        assert_eq!("text".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!(
            "jsonl".parse::<OutputFormat>().unwrap(),
            OutputFormat::JsonLines
        );
        assert!("invalid".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn test_output_format_display() {
        assert_eq!(OutputFormat::Text.to_string(), "text");
        assert_eq!(OutputFormat::Json.to_string(), "json");
        assert_eq!(OutputFormat::JsonLines.to_string(), "jsonl");
    }

    #[test]
    fn test_format_interval() {
        assert_eq!(format_interval(Some(500.0)), "500ms");
        assert_eq!(format_interval(Some(1500.0)), "1.5s");
        assert_eq!(format_interval(Some(60000.0)), "60.0s");
        assert_eq!(format_interval(None), "N/A");
    }
}
