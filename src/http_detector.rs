//! HTTP Beacon Detection Module
//!
//! Detects potential C2 beaconing over HTTP/HTTPS by analyzing:
//! - Periodic POST request patterns
//! - Suspicious or non-standard User-Agent strings
//! - Consistent payload sizes (indicates structured C2 protocol)
//! - URL patterns common in C2 communications
//!
//! # Detection Methodology
//!
//! HTTP-based C2 frameworks (Cobalt Strike, Metasploit, etc.) often exhibit:
//! - Regular check-in intervals via POST requests
//! - Custom or default User-Agents that don't match browsers
//! - Fixed-size payloads for command/response framing
//! - Predictable URL patterns (/api/, /beacon/, base64 encoded paths)

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tracing::{debug, trace};

/// HTTP beacon detection configuration thresholds.
#[derive(Debug, Clone)]
pub struct HttpDetectorConfig {
    /// Minimum requests to analyze for patterns.
    pub min_requests: usize,
    /// Threshold for payload size consistency (0.0-1.0, lower = more consistent).
    pub payload_consistency_threshold: f64,
    /// Maximum variance in Content-Length to be considered consistent.
    pub max_size_variance: f64,
    /// Minimum POST request ratio to be suspicious.
    pub min_post_ratio: f64,
}

impl Default for HttpDetectorConfig {
    fn default() -> Self {
        Self {
            min_requests: 5,
            payload_consistency_threshold: 0.1,
            max_size_variance: 50.0, // bytes
            min_post_ratio: 0.8,     // 80% POST requests
        }
    }
}

/// Known suspicious User-Agent patterns.
/// These are commonly used by C2 frameworks or indicate automated tools.
pub static SUSPICIOUS_USER_AGENTS: &[SuspiciousUserAgent] = &[
    SuspiciousUserAgent {
        pattern: "Mozilla/5.0 (compatible; MSIE",
        description: "Legacy IE - often spoofed by C2",
        severity: Severity::Medium,
    },
    SuspiciousUserAgent {
        pattern: "Mozilla/4.0 (compatible; MSIE 6.0",
        description: "Ancient IE - Cobalt Strike default",
        severity: Severity::High,
    },
    SuspiciousUserAgent {
        pattern: "Mozilla/4.0 (compatible; MSIE 7.0",
        description: "Old IE - common C2 default",
        severity: Severity::High,
    },
    SuspiciousUserAgent {
        pattern: "Mozilla/4.0 (compatible; MSIE 8.0",
        description: "Old IE - common C2 default",
        severity: Severity::Medium,
    },
    SuspiciousUserAgent {
        pattern: "Java/",
        description: "Java HTTP client",
        severity: Severity::Medium,
    },
    SuspiciousUserAgent {
        pattern: "python-requests",
        description: "Python Requests library",
        severity: Severity::Low,
    },
    SuspiciousUserAgent {
        pattern: "Python-urllib",
        description: "Python urllib",
        severity: Severity::Low,
    },
    SuspiciousUserAgent {
        pattern: "Go-http-client",
        description: "Go HTTP client",
        severity: Severity::Low,
    },
    SuspiciousUserAgent {
        pattern: "curl/",
        description: "curl command-line tool",
        severity: Severity::Low,
    },
    SuspiciousUserAgent {
        pattern: "Wget/",
        description: "wget command-line tool",
        severity: Severity::Low,
    },
    SuspiciousUserAgent {
        pattern: "PowerShell/",
        description: "PowerShell web request",
        severity: Severity::High,
    },
    SuspiciousUserAgent {
        pattern: "WindowsPowerShell/",
        description: "Windows PowerShell",
        severity: Severity::High,
    },
];

/// Known suspicious URL patterns used by C2 frameworks.
pub static SUSPICIOUS_URL_PATTERNS: &[SuspiciousUrlPattern] = &[
    SuspiciousUrlPattern {
        pattern: "/api/",
        description: "Generic API endpoint",
        severity: Severity::Low,
    },
    SuspiciousUrlPattern {
        pattern: "/beacon",
        description: "Cobalt Strike beacon endpoint",
        severity: Severity::High,
    },
    SuspiciousUrlPattern {
        pattern: "/submit.php",
        description: "Generic submission endpoint",
        severity: Severity::Medium,
    },
    SuspiciousUrlPattern {
        pattern: "/login.php",
        description: "Login endpoint (often abused)",
        severity: Severity::Low,
    },
    SuspiciousUrlPattern {
        pattern: "/admin",
        description: "Admin endpoint",
        severity: Severity::Low,
    },
    SuspiciousUrlPattern {
        pattern: "/updates",
        description: "Update endpoint (C2 masquerading)",
        severity: Severity::Low,
    },
    SuspiciousUrlPattern {
        pattern: "/pixel",
        description: "Tracking pixel (data exfil)",
        severity: Severity::Medium,
    },
    SuspiciousUrlPattern {
        pattern: "/__",
        description: "Hidden/internal endpoint pattern",
        severity: Severity::Medium,
    },
    SuspiciousUrlPattern {
        pattern: "/static/",
        description: "Static files (may hide C2)",
        severity: Severity::Low,
    },
];

/// Severity level for detection indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A suspicious User-Agent pattern entry.
#[derive(Debug, Clone)]
pub struct SuspiciousUserAgent {
    pub pattern: &'static str,
    pub description: &'static str,
    pub severity: Severity,
}

/// A suspicious URL pattern entry.
#[derive(Debug, Clone)]
pub struct SuspiciousUrlPattern {
    pub pattern: &'static str,
    pub description: &'static str,
    pub severity: Severity,
}

/// HTTP method for request classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Other,
}

impl HttpMethod {
    /// Parse HTTP method from string.
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            "PATCH" => Self::Patch,
            _ => Self::Other,
        }
    }
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Post => write!(f, "POST"),
            Self::Put => write!(f, "PUT"),
            Self::Delete => write!(f, "DELETE"),
            Self::Head => write!(f, "HEAD"),
            Self::Options => write!(f, "OPTIONS"),
            Self::Patch => write!(f, "PATCH"),
            Self::Other => write!(f, "OTHER"),
        }
    }
}

/// Parsed HTTP request metadata for analysis.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// HTTP method (GET, POST, etc.)
    pub method: HttpMethod,
    /// Request URI/path
    pub uri: String,
    /// User-Agent header if present
    pub user_agent: Option<String>,
    /// Content-Length if present
    pub content_length: Option<usize>,
    /// Host header
    pub host: Option<String>,
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
}

/// Tracks HTTP requests for a specific flow/destination.
#[derive(Debug, Clone)]
pub struct HttpFlowTracker {
    /// All requests in this flow
    pub requests: Vec<HttpRequest>,
    /// Method distribution
    pub method_counts: HashMap<HttpMethod, u32>,
    /// User-Agent seen (first one)
    pub primary_user_agent: Option<String>,
    /// Content-Length values for POST requests
    pub post_content_lengths: Vec<usize>,
    /// URIs accessed
    pub uris: Vec<String>,
    /// First request timestamp
    pub first_seen: Option<DateTime<Utc>>,
    /// Last request timestamp
    pub last_seen: Option<DateTime<Utc>>,
}

impl HttpFlowTracker {
    pub fn new() -> Self {
        Self {
            requests: Vec::new(),
            method_counts: HashMap::new(),
            primary_user_agent: None,
            post_content_lengths: Vec::new(),
            uris: Vec::new(),
            first_seen: None,
            last_seen: None,
        }
    }

    /// Add an HTTP request to the tracker.
    pub fn add_request(&mut self, request: HttpRequest) {
        // Update timestamps
        if self.first_seen.is_none() {
            self.first_seen = Some(request.timestamp);
        }
        self.last_seen = Some(request.timestamp);

        // Track method distribution
        *self.method_counts.entry(request.method).or_insert(0) += 1;

        // Track User-Agent (use first one seen)
        if self.primary_user_agent.is_none() {
            self.primary_user_agent = request.user_agent.clone();
        }

        // Track POST content lengths for consistency analysis
        if request.method == HttpMethod::Post {
            if let Some(len) = request.content_length {
                self.post_content_lengths.push(len);
            }
        }

        // Track URIs
        self.uris.push(request.uri.clone());

        self.requests.push(request);
    }

    /// Calculate the ratio of POST requests.
    pub fn post_ratio(&self) -> f64 {
        let total: u32 = self.method_counts.values().sum();
        if total == 0 {
            return 0.0;
        }
        let post_count = self.method_counts.get(&HttpMethod::Post).unwrap_or(&0);
        *post_count as f64 / total as f64
    }

    /// Calculate Content-Length consistency (coefficient of variation).
    pub fn content_length_cv(&self) -> Option<f64> {
        if self.post_content_lengths.len() < 2 {
            return None;
        }

        let lengths: Vec<f64> = self.post_content_lengths.iter().map(|&l| l as f64).collect();
        let mean: f64 = lengths.iter().sum::<f64>() / lengths.len() as f64;

        if mean == 0.0 {
            return None;
        }

        let variance: f64 = lengths.iter().map(|l| (l - mean).powi(2)).sum::<f64>()
            / lengths.len() as f64;
        let std_dev = variance.sqrt();

        Some(std_dev / mean)
    }

    /// Get request rate (requests per second).
    pub fn request_rate(&self) -> f64 {
        if self.requests.len() < 2 {
            return 0.0;
        }

        if let (Some(first), Some(last)) = (self.first_seen, self.last_seen) {
            let duration_secs =
                last.signed_duration_since(first).num_milliseconds() as f64 / 1000.0;
            if duration_secs > 0.0 {
                return self.requests.len() as f64 / duration_secs;
            }
        }

        0.0
    }
}

impl Default for HttpFlowTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTP beacon detection indicators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpIndicator {
    /// Suspicious User-Agent detected
    SuspiciousUserAgent {
        pattern: String,
        severity: Severity,
    },
    /// High ratio of POST requests
    HighPostRatio { ratio: u32 }, // Stored as percentage
    /// Consistent Content-Length in POST requests
    ConsistentPayloadSize { cv: u32 }, // CV * 1000 for integer storage
    /// Suspicious URL pattern
    SuspiciousUrl { pattern: String, severity: Severity },
    /// High request rate (potential automated)
    HighRequestRate { rate: u32 }, // Requests per minute
    /// Periodic request pattern detected
    PeriodicRequests,
}

impl std::fmt::Display for HttpIndicator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SuspiciousUserAgent { pattern, severity } => {
                write!(f, "Suspicious UA '{}' [{}]", pattern, severity)
            }
            Self::HighPostRatio { ratio } => {
                write!(f, "High POST ratio ({}%)", ratio)
            }
            Self::ConsistentPayloadSize { cv } => {
                write!(f, "Consistent payload size (CV={:.3})", *cv as f64 / 1000.0)
            }
            Self::SuspiciousUrl { pattern, severity } => {
                write!(f, "Suspicious URL '{}' [{}]", pattern, severity)
            }
            Self::HighRequestRate { rate } => {
                write!(f, "High request rate ({}/min)", rate)
            }
            Self::PeriodicRequests => {
                write!(f, "Periodic request pattern")
            }
        }
    }
}

/// Result of HTTP beacon analysis.
#[derive(Debug, Clone)]
pub struct HttpAnalysisResult {
    /// Whether beacon-like behavior was detected.
    pub is_suspicious: bool,
    /// Overall severity (highest of all indicators).
    pub severity: Severity,
    /// Total requests analyzed.
    pub request_count: usize,
    /// POST request ratio (0.0-1.0).
    pub post_ratio: f64,
    /// Content-Length coefficient of variation.
    pub content_length_cv: Option<f64>,
    /// Request rate (per second).
    pub request_rate: f64,
    /// Detection indicators.
    pub indicators: Vec<HttpIndicator>,
    /// Primary User-Agent.
    pub user_agent: Option<String>,
}

impl HttpAnalysisResult {
    /// Create a non-suspicious result.
    pub fn not_suspicious() -> Self {
        Self {
            is_suspicious: false,
            severity: Severity::Low,
            request_count: 0,
            post_ratio: 0.0,
            content_length_cv: None,
            request_rate: 0.0,
            indicators: Vec::new(),
            user_agent: None,
        }
    }
}

/// HTTP beacon detector.
#[derive(Debug, Clone)]
pub struct HttpDetector {
    config: HttpDetectorConfig,
}

impl HttpDetector {
    pub fn new(config: HttpDetectorConfig) -> Self {
        Self { config }
    }

    /// Analyze an HTTP flow tracker for beacon-like behavior.
    pub fn analyze(&self, tracker: &HttpFlowTracker) -> HttpAnalysisResult {
        if tracker.requests.len() < self.config.min_requests {
            return HttpAnalysisResult::not_suspicious();
        }

        let mut indicators = Vec::new();
        let mut max_severity = Severity::Low;

        // Check User-Agent
        if let Some(ref ua) = tracker.primary_user_agent {
            for suspicious in SUSPICIOUS_USER_AGENTS {
                if ua.contains(suspicious.pattern) {
                    indicators.push(HttpIndicator::SuspiciousUserAgent {
                        pattern: suspicious.pattern.to_string(),
                        severity: suspicious.severity,
                    });
                    if Self::severity_rank(suspicious.severity) > Self::severity_rank(max_severity)
                    {
                        max_severity = suspicious.severity;
                    }
                    debug!(
                        "Suspicious User-Agent detected: {} ({})",
                        suspicious.pattern, suspicious.severity
                    );
                    break; // Only report first match
                }
            }
        }

        // Check POST ratio
        let post_ratio = tracker.post_ratio();
        if post_ratio >= self.config.min_post_ratio {
            indicators.push(HttpIndicator::HighPostRatio {
                ratio: (post_ratio * 100.0) as u32,
            });
            if Self::severity_rank(Severity::Medium) > Self::severity_rank(max_severity) {
                max_severity = Severity::Medium;
            }
            debug!("High POST ratio: {:.1}%", post_ratio * 100.0);
        }

        // Check Content-Length consistency
        let content_length_cv = tracker.content_length_cv();
        if let Some(cv) = content_length_cv {
            if cv < self.config.payload_consistency_threshold {
                indicators.push(HttpIndicator::ConsistentPayloadSize {
                    cv: (cv * 1000.0) as u32,
                });
                if Self::severity_rank(Severity::High) > Self::severity_rank(max_severity) {
                    max_severity = Severity::High;
                }
                debug!("Consistent payload size detected: CV={:.4}", cv);
            }
        }

        // Check URL patterns
        for uri in &tracker.uris {
            for suspicious in SUSPICIOUS_URL_PATTERNS {
                if uri.contains(suspicious.pattern) {
                    // Avoid duplicates
                    let indicator = HttpIndicator::SuspiciousUrl {
                        pattern: suspicious.pattern.to_string(),
                        severity: suspicious.severity,
                    };
                    if !indicators.contains(&indicator) {
                        indicators.push(indicator);
                        if Self::severity_rank(suspicious.severity)
                            > Self::severity_rank(max_severity)
                        {
                            max_severity = suspicious.severity;
                        }
                        trace!("Suspicious URL pattern: {}", suspicious.pattern);
                    }
                    break;
                }
            }
        }

        // Check request rate (high rate indicates automation)
        let request_rate = tracker.request_rate();
        let requests_per_minute = (request_rate * 60.0) as u32;
        if requests_per_minute > 30 {
            // More than 30 requests/minute
            indicators.push(HttpIndicator::HighRequestRate {
                rate: requests_per_minute,
            });
            if Self::severity_rank(Severity::Medium) > Self::severity_rank(max_severity) {
                max_severity = Severity::Medium;
            }
            debug!("High request rate: {} req/min", requests_per_minute);
        }

        let is_suspicious = !indicators.is_empty();

        HttpAnalysisResult {
            is_suspicious,
            severity: max_severity,
            request_count: tracker.requests.len(),
            post_ratio,
            content_length_cv,
            request_rate,
            indicators,
            user_agent: tracker.primary_user_agent.clone(),
        }
    }

    /// Rank severity for comparison.
    fn severity_rank(severity: Severity) -> u8 {
        match severity {
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

impl Default for HttpDetector {
    fn default() -> Self {
        Self::new(HttpDetectorConfig::default())
    }
}

/// Parse HTTP request from raw TCP payload.
/// Returns None if the payload is not a valid HTTP request.
pub fn parse_http_request(payload: &[u8], timestamp: DateTime<Utc>) -> Option<HttpRequest> {
    // HTTP requests must be at least a few bytes
    if payload.len() < 10 {
        return None;
    }

    // Convert to string (HTTP is text-based)
    let text = std::str::from_utf8(payload).ok()?;

    // Parse request line (first line)
    let mut lines = text.lines();
    let request_line = lines.next()?;

    // Request line format: METHOD URI HTTP/VERSION
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    // Validate HTTP version
    if !parts[2].starts_with("HTTP/") {
        return None;
    }

    let method = HttpMethod::from_str(parts[0]);
    let uri = parts[1].to_string();

    // Parse headers
    let mut user_agent = None;
    let mut content_length = None;
    let mut host = None;

    for line in lines {
        if line.is_empty() {
            break; // End of headers
        }

        if let Some((name, value)) = line.split_once(':') {
            let name_lower = name.trim().to_lowercase();
            let value_trimmed = value.trim();

            match name_lower.as_str() {
                "user-agent" => {
                    user_agent = Some(value_trimmed.to_string());
                }
                "content-length" => {
                    content_length = value_trimmed.parse().ok();
                }
                "host" => {
                    host = Some(value_trimmed.to_string());
                }
                _ => {}
            }
        }
    }

    trace!(
        "Parsed HTTP request: {} {} (UA: {:?})",
        method,
        uri,
        user_agent
    );

    Some(HttpRequest {
        method,
        uri,
        user_agent,
        content_length,
        host,
        timestamp,
    })
}

/// Check if a port is commonly used for HTTP traffic.
pub fn is_http_port(port: u16) -> bool {
    matches!(port, 80 | 8080 | 8000 | 8008 | 8888 | 3000 | 3128 | 9000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_request_get() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
        let timestamp = Utc::now();

        let request = parse_http_request(payload, timestamp);
        assert!(request.is_some());

        let req = request.unwrap();
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.uri, "/index.html");
        assert_eq!(req.host, Some("example.com".to_string()));
        assert!(req.user_agent.unwrap().contains("Mozilla"));
    }

    #[test]
    fn test_parse_http_request_post() {
        let payload = b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 42\r\nUser-Agent: curl/7.68.0\r\n\r\n";
        let timestamp = Utc::now();

        let request = parse_http_request(payload, timestamp);
        assert!(request.is_some());

        let req = request.unwrap();
        assert_eq!(req.method, HttpMethod::Post);
        assert_eq!(req.uri, "/api/data");
        assert_eq!(req.content_length, Some(42));
    }

    #[test]
    fn test_parse_http_request_invalid() {
        let payload = b"Not an HTTP request";
        let timestamp = Utc::now();

        let request = parse_http_request(payload, timestamp);
        assert!(request.is_none());
    }

    #[test]
    fn test_http_flow_tracker_post_ratio() {
        let mut tracker = HttpFlowTracker::new();
        let timestamp = Utc::now();

        // Add 3 POST and 1 GET
        for i in 0..3 {
            tracker.add_request(HttpRequest {
                method: HttpMethod::Post,
                uri: format!("/api/{}", i),
                user_agent: None,
                content_length: Some(100),
                host: None,
                timestamp,
            });
        }
        tracker.add_request(HttpRequest {
            method: HttpMethod::Get,
            uri: "/status".to_string(),
            user_agent: None,
            content_length: None,
            host: None,
            timestamp,
        });

        let ratio = tracker.post_ratio();
        assert!((ratio - 0.75).abs() < 0.01, "POST ratio should be 75%");
    }

    #[test]
    fn test_content_length_cv() {
        let mut tracker = HttpFlowTracker::new();
        let timestamp = Utc::now();

        // Add POST requests with identical content lengths (CV should be 0)
        for _ in 0..5 {
            tracker.add_request(HttpRequest {
                method: HttpMethod::Post,
                uri: "/beacon".to_string(),
                user_agent: None,
                content_length: Some(256),
                host: None,
                timestamp,
            });
        }

        let cv = tracker.content_length_cv();
        assert!(cv.is_some());
        assert!(cv.unwrap() < 0.01, "CV should be near 0 for identical sizes");
    }

    #[test]
    fn test_suspicious_user_agent_detection() {
        let detector = HttpDetector::default();
        let mut tracker = HttpFlowTracker::new();
        let timestamp = Utc::now();

        // Add requests with suspicious User-Agent
        for i in 0..5 {
            tracker.add_request(HttpRequest {
                method: HttpMethod::Post,
                uri: format!("/api/{}", i),
                user_agent: Some("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)".to_string()),
                content_length: Some(100),
                host: None,
                timestamp,
            });
        }

        let result = detector.analyze(&tracker);
        assert!(result.is_suspicious);
        assert!(result.indicators.iter().any(|i| {
            matches!(i, HttpIndicator::SuspiciousUserAgent { .. })
        }));
    }

    #[test]
    fn test_beacon_pattern_detection() {
        let detector = HttpDetector::default();
        let mut tracker = HttpFlowTracker::new();
        let timestamp = Utc::now();

        // Simulate beacon-like behavior: all POST, consistent size
        for i in 0..10 {
            tracker.add_request(HttpRequest {
                method: HttpMethod::Post,
                uri: "/beacon".to_string(),
                user_agent: Some("PowerShell/7.0".to_string()),
                content_length: Some(128), // Consistent size
                host: Some("c2.example.com".to_string()),
                timestamp: timestamp + chrono::Duration::seconds(i * 60), // Every minute
            });
        }

        let result = detector.analyze(&tracker);
        assert!(result.is_suspicious);
        assert!(result.post_ratio >= 0.8);

        // Should have multiple indicators
        assert!(result.indicators.len() >= 2);
    }

    #[test]
    fn test_is_http_port() {
        assert!(is_http_port(80));
        assert!(is_http_port(8080));
        assert!(is_http_port(8000));
        assert!(!is_http_port(443)); // HTTPS
        assert!(!is_http_port(22));  // SSH
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", Severity::Low), "LOW");
        assert_eq!(format!("{}", Severity::Medium), "MEDIUM");
        assert_eq!(format!("{}", Severity::High), "HIGH");
        assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
    }

    #[test]
    fn test_http_method_parsing() {
        assert_eq!(HttpMethod::from_str("GET"), HttpMethod::Get);
        assert_eq!(HttpMethod::from_str("post"), HttpMethod::Post);
        assert_eq!(HttpMethod::from_str("PUT"), HttpMethod::Put);
        assert_eq!(HttpMethod::from_str("unknown"), HttpMethod::Other);
    }
}
