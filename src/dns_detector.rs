//! DNS Tunneling Detection Module
//!
//! Detects potential DNS tunneling activity by analyzing DNS queries for:
//! - High entropy in subdomain labels (indicates encoded data)
//! - Unusually long DNS labels (data exfiltration)
//! - High query rates to single domains
//! - Suspicious record types (TXT, NULL)
//!
//! # Detection Methodology
//!
//! DNS tunneling encodes data in DNS queries/responses. Common indicators:
//! - Base64/hex encoded subdomains have entropy > 3.5 bits/char
//! - Normal subdomains typically have entropy < 3.0 bits/char
//! - Labels > 50 chars suggest data encoding
//! - Rapid queries to same domain indicate command/control channel

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tracing::{debug, trace};

/// DNS tunneling detection thresholds
#[derive(Debug, Clone)]
pub struct DnsDetectorConfig {
    /// Entropy threshold for suspicious labels (default: 3.5 bits/char)
    pub entropy_threshold: f64,
    /// Maximum normal label length (default: 50 chars)
    pub max_label_length: usize,
    /// Minimum queries to trigger rate analysis (default: 5)
    pub min_queries_for_rate: usize,
    /// Query rate threshold in queries/second (default: 1.0)
    pub query_rate_threshold: f64,
}

impl Default for DnsDetectorConfig {
    fn default() -> Self {
        Self {
            entropy_threshold: 3.5,
            max_label_length: 50,
            min_queries_for_rate: 5,
            query_rate_threshold: 1.0,
        }
    }
}

/// Result of DNS tunneling analysis
#[derive(Debug, Clone)]
pub struct DnsAnalysisResult {
    /// Whether tunneling was detected
    pub is_suspicious: bool,
    /// Maximum entropy found in any label
    pub max_entropy: f64,
    /// Longest label length found
    pub max_label_length: usize,
    /// Query rate (queries per second)
    pub query_rate: f64,
    /// Suspicious indicators found
    pub indicators: Vec<DnsIndicator>,
    /// Number of queries analyzed
    pub query_count: usize,
}

impl DnsAnalysisResult {
    #[allow(dead_code)] // Factory for non-suspicious results
    pub fn not_suspicious() -> Self {
        Self {
            is_suspicious: false,
            max_entropy: 0.0,
            max_label_length: 0,
            query_rate: 0.0,
            indicators: Vec::new(),
            query_count: 0,
        }
    }
}

/// Specific indicators of DNS tunneling
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsIndicator {
    /// High entropy in subdomain (> threshold)
    HighEntropy { entropy: u32 }, // Stored as entropy * 100 for comparison
    /// Long subdomain label
    LongLabel { length: usize },
    /// High query rate to domain
    HighQueryRate,
    /// Suspicious record type (TXT, NULL, etc.)
    SuspiciousRecordType { qtype: u16 },
    /// Many unique subdomains (data encoding pattern)
    ManySubdomains { count: usize },
}

/// Parsed DNS query information
#[derive(Debug, Clone)]
pub struct DnsQuery {
    /// Full query name (e.g., "encoded-data.evil.com")
    #[allow(dead_code)] // Available for detailed logging
    pub qname: String,
    /// Individual labels (e.g., ["encoded-data", "evil", "com"])
    pub labels: Vec<String>,
    /// Query type (A=1, TXT=16, NULL=10, etc.)
    pub qtype: u16,
    /// Query class (usually IN=1)
    #[allow(dead_code)] // Available for detailed logging
    pub qclass: u16,
}

/// DNS query types that are commonly used for tunneling
pub fn is_suspicious_qtype(qtype: u16) -> bool {
    matches!(
        qtype,
        16 |    // TXT - most common for tunneling
        10 |    // NULL - can carry arbitrary data
        99 |    // SPF (deprecated, but abused)
        255 |   // ANY - information gathering
        28 // AAAA - sometimes abused for data
    )
}

/// Tracks DNS queries for a specific flow/domain
#[derive(Debug, Clone)]
pub struct DnsFlowTracker {
    /// Timestamps of queries
    pub query_times: Vec<DateTime<Utc>>,
    /// Unique subdomains seen
    pub unique_subdomains: HashMap<String, u32>,
    /// Query types seen
    pub query_types: HashMap<u16, u32>,
    /// Base domain (e.g., "evil.com")
    pub base_domain: Option<String>,
    /// Highest entropy seen
    pub max_entropy: f64,
    /// Longest label seen
    pub max_label_length: usize,
}

impl DnsFlowTracker {
    pub fn new() -> Self {
        Self {
            query_times: Vec::new(),
            unique_subdomains: HashMap::new(),
            query_types: HashMap::new(),
            base_domain: None,
            max_entropy: 0.0,
            max_label_length: 0,
        }
    }

    /// Adds a DNS query to the tracker
    pub fn add_query(&mut self, query: &DnsQuery, timestamp: DateTime<Utc>) {
        self.query_times.push(timestamp);

        // Track query type
        *self.query_types.entry(query.qtype).or_insert(0) += 1;

        // Extract base domain (last 2 labels for .com/.net, last 3 for .co.uk etc.)
        if self.base_domain.is_none() && query.labels.len() >= 2 {
            let base = query.labels[query.labels.len().saturating_sub(2)..].join(".");
            self.base_domain = Some(base);
        }

        // Track subdomains (everything except base domain)
        if query.labels.len() > 2 {
            let subdomain = query.labels[..query.labels.len() - 2].join(".");
            *self.unique_subdomains.entry(subdomain.clone()).or_insert(0) += 1;

            // Calculate entropy for non-TLD labels
            for label in &query.labels[..query.labels.len() - 2] {
                let entropy = calculate_entropy(label);
                if entropy > self.max_entropy {
                    self.max_entropy = entropy;
                }
                if label.len() > self.max_label_length {
                    self.max_label_length = label.len();
                }
            }
        }
    }

    /// Calculates query rate (queries per second)
    pub fn query_rate(&self) -> f64 {
        if self.query_times.len() < 2 {
            return 0.0;
        }

        let first = self.query_times.first().unwrap();
        let last = self.query_times.last().unwrap();
        let duration_secs = last.signed_duration_since(*first).num_milliseconds() as f64 / 1000.0;

        if duration_secs > 0.0 {
            self.query_times.len() as f64 / duration_secs
        } else {
            0.0
        }
    }
}

impl Default for DnsFlowTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS Tunneling Detector
#[derive(Debug, Clone)]
pub struct DnsDetector {
    config: DnsDetectorConfig,
}

impl DnsDetector {
    pub fn new(config: DnsDetectorConfig) -> Self {
        Self { config }
    }

    /// Analyzes a DNS flow tracker for tunneling indicators
    pub fn analyze(&self, tracker: &DnsFlowTracker) -> DnsAnalysisResult {
        let mut indicators = Vec::new();
        let mut is_suspicious = false;

        // Check entropy
        if tracker.max_entropy > self.config.entropy_threshold {
            is_suspicious = true;
            indicators.push(DnsIndicator::HighEntropy {
                entropy: (tracker.max_entropy * 100.0) as u32,
            });
            debug!(
                "High entropy detected: {:.2} (threshold: {:.2})",
                tracker.max_entropy, self.config.entropy_threshold
            );
        }

        // Check label length
        if tracker.max_label_length > self.config.max_label_length {
            is_suspicious = true;
            indicators.push(DnsIndicator::LongLabel {
                length: tracker.max_label_length,
            });
            debug!(
                "Long label detected: {} chars (threshold: {})",
                tracker.max_label_length, self.config.max_label_length
            );
        }

        // Check query rate
        let query_rate = tracker.query_rate();
        if tracker.query_times.len() >= self.config.min_queries_for_rate
            && query_rate > self.config.query_rate_threshold
        {
            is_suspicious = true;
            indicators.push(DnsIndicator::HighQueryRate);
            debug!(
                "High query rate: {:.2} q/s (threshold: {:.2})",
                query_rate, self.config.query_rate_threshold
            );
        }

        // Check for suspicious record types
        for (&qtype, &count) in &tracker.query_types {
            if is_suspicious_qtype(qtype) && count > 2 {
                is_suspicious = true;
                indicators.push(DnsIndicator::SuspiciousRecordType { qtype });
                debug!("Suspicious record type: {} (count: {})", qtype, count);
            }
        }

        // Check for many unique subdomains (data encoding pattern)
        let unique_count = tracker.unique_subdomains.len();
        if unique_count > 10 {
            is_suspicious = true;
            indicators.push(DnsIndicator::ManySubdomains {
                count: unique_count,
            });
            debug!("Many unique subdomains: {}", unique_count);
        }

        DnsAnalysisResult {
            is_suspicious,
            max_entropy: tracker.max_entropy,
            max_label_length: tracker.max_label_length,
            query_rate,
            indicators,
            query_count: tracker.query_times.len(),
        }
    }
}

impl Default for DnsDetector {
    fn default() -> Self {
        Self::new(DnsDetectorConfig::default())
    }
}

/// Calculate Shannon entropy of a string (bits per character).
///
/// Normal text has entropy around 2.5-3.5 bits/char.
/// Base64 encoded data has entropy around 4.5-5.5 bits/char.
/// Hex encoded data has entropy around 3.5-4.0 bits/char.
///
/// # Example
/// ```
/// use network_beacon::dns_detector::calculate_entropy;
/// let entropy = calculate_entropy("aGVsbG8gd29ybGQ=");
/// assert!(entropy > 3.0);
/// ```
pub fn calculate_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    let len = data.len() as f64;

    for byte in data.bytes() {
        freq[byte as usize] += 1;
    }

    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Parse a DNS query from raw UDP payload.
///
/// DNS packet structure:
/// - Header: 12 bytes
/// - Question section: variable
///   - QNAME: sequence of length-prefixed labels, terminated by 0
///   - QTYPE: 2 bytes
///   - QCLASS: 2 bytes
pub fn parse_dns_query(payload: &[u8]) -> Option<DnsQuery> {
    // DNS header is 12 bytes minimum
    if payload.len() < 12 {
        trace!("DNS payload too short: {} bytes", payload.len());
        return None;
    }

    // Check QR bit (byte 2, bit 7) - 0 = query, 1 = response
    // We want queries
    if (payload[2] & 0x80) != 0 {
        trace!("DNS packet is a response, skipping");
        return None;
    }

    // Parse question count from header (bytes 4-5)
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        trace!("No questions in DNS packet");
        return None;
    }

    // Parse QNAME starting at byte 12
    let mut pos = 12;
    let mut labels = Vec::new();

    loop {
        if pos >= payload.len() {
            trace!("Unexpected end of DNS packet while parsing QNAME");
            return None;
        }

        let label_len = payload[pos] as usize;
        if label_len == 0 {
            pos += 1; // Skip null terminator
            break;
        }

        // Check for compression pointer (top 2 bits set)
        if label_len >= 0xC0 {
            // Compression not typically used in queries, skip for now
            trace!("DNS compression pointer found, skipping");
            return None;
        }

        // Validate label length (max 63 per RFC 1035)
        if label_len > 63 {
            trace!("Invalid DNS label length: {}", label_len);
            return None;
        }

        pos += 1;
        if pos + label_len > payload.len() {
            trace!("Label extends beyond packet");
            return None;
        }

        // Extract label as string (DNS is case-insensitive)
        let label_bytes = &payload[pos..pos + label_len];
        if let Ok(label) = std::str::from_utf8(label_bytes) {
            labels.push(label.to_lowercase());
        } else {
            // Non-UTF8 label - could be binary data
            labels.push(hex::encode(label_bytes));
        }

        pos += label_len;
    }

    if labels.is_empty() {
        trace!("Empty QNAME in DNS query");
        return None;
    }

    // Parse QTYPE and QCLASS (2 bytes each)
    if pos + 4 > payload.len() {
        trace!("Missing QTYPE/QCLASS");
        return None;
    }

    let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
    let qclass = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]);

    let qname = labels.join(".");

    debug!(
        "Parsed DNS query: {} (type={}, class={})",
        qname, qtype, qclass
    );

    Some(DnsQuery {
        qname,
        labels,
        qtype,
        qclass,
    })
}

/// Check if a port is a DNS port
pub fn is_dns_port(port: u16) -> bool {
    matches!(port, 53 | 5353 | 5355)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert_eq!(calculate_entropy(""), 0.0);
    }

    #[test]
    fn test_entropy_single_char() {
        // Single character repeated has 0 entropy
        assert!(calculate_entropy("aaaaaaaaaa") < 0.1);
    }

    #[test]
    fn test_entropy_random_looking() {
        // Base64-like string should have higher entropy
        let entropy = calculate_entropy("aGVsbG8gd29ybGQ=");
        assert!(
            entropy > 3.0,
            "Base64 entropy should be > 3.0, got {}",
            entropy
        );
    }

    #[test]
    fn test_entropy_normal_domain() {
        // Normal domain names have moderate entropy
        let entropy = calculate_entropy("www");
        assert!(
            entropy < 2.0,
            "Simple domain entropy should be < 2.0, got {}",
            entropy
        );

        let entropy2 = calculate_entropy("google");
        assert!(
            entropy2 < 3.0,
            "Normal domain entropy should be < 3.0, got {}",
            entropy2
        );
    }

    #[test]
    fn test_entropy_hex_data() {
        // Hex-encoded data
        let entropy = calculate_entropy("48656c6c6f576f726c64");
        assert!(
            entropy > 2.5,
            "Hex data entropy should be > 2.5, got {}",
            entropy
        );
    }

    #[test]
    fn test_parse_dns_query_too_short() {
        let payload = [0u8; 10];
        assert!(parse_dns_query(&payload).is_none());
    }

    #[test]
    fn test_parse_dns_query_response() {
        // DNS response (QR bit = 1)
        let mut payload = [0u8; 20];
        payload[2] = 0x80; // QR = 1 (response)
        assert!(parse_dns_query(&payload).is_none());
    }

    #[test]
    fn test_parse_dns_query_valid() {
        // Construct a valid DNS query for "test.example.com" type A
        let mut payload = Vec::new();

        // Header (12 bytes)
        payload.extend_from_slice(&[
            0x00, 0x01, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
        ]);

        // QNAME: test.example.com
        payload.push(4); // length of "test"
        payload.extend_from_slice(b"test");
        payload.push(7); // length of "example"
        payload.extend_from_slice(b"example");
        payload.push(3); // length of "com"
        payload.extend_from_slice(b"com");
        payload.push(0); // null terminator

        // QTYPE: A (1)
        payload.extend_from_slice(&[0x00, 0x01]);
        // QCLASS: IN (1)
        payload.extend_from_slice(&[0x00, 0x01]);

        let result = parse_dns_query(&payload);
        assert!(result.is_some(), "Should parse valid DNS query");

        let query = result.unwrap();
        assert_eq!(query.qname, "test.example.com");
        assert_eq!(query.labels, vec!["test", "example", "com"]);
        assert_eq!(query.qtype, 1);
        assert_eq!(query.qclass, 1);
    }

    #[test]
    fn test_dns_detector_high_entropy() {
        let config = DnsDetectorConfig::default();
        let detector = DnsDetector::new(config);

        let mut tracker = DnsFlowTracker::new();

        // Simulate high-entropy subdomain
        let query = DnsQuery {
            qname: "aGVsbG8gd29ybGQgdGhpcyBpcyBlbmNvZGVk.evil.com".to_string(),
            labels: vec![
                "aGVsbG8gd29ybGQgdGhpcyBpcyBlbmNvZGVk".to_string(),
                "evil".to_string(),
                "com".to_string(),
            ],
            qtype: 1,
            qclass: 1,
        };

        tracker.add_query(&query, Utc::now());

        let result = detector.analyze(&tracker);
        assert!(
            result.is_suspicious,
            "High entropy subdomain should be suspicious"
        );
        assert!(result
            .indicators
            .iter()
            .any(|i| matches!(i, DnsIndicator::HighEntropy { .. })));
    }

    #[test]
    fn test_dns_detector_long_label() {
        let config = DnsDetectorConfig::default();
        let detector = DnsDetector::new(config);

        let mut tracker = DnsFlowTracker::new();

        // Create a very long subdomain label
        let long_label = "a".repeat(60);
        let query = DnsQuery {
            qname: format!("{}.example.com", long_label),
            labels: vec![long_label, "example".to_string(), "com".to_string()],
            qtype: 1,
            qclass: 1,
        };

        tracker.add_query(&query, Utc::now());

        let result = detector.analyze(&tracker);
        assert!(result.is_suspicious, "Long label should be suspicious");
        assert!(result
            .indicators
            .iter()
            .any(|i| matches!(i, DnsIndicator::LongLabel { .. })));
    }

    #[test]
    fn test_dns_detector_suspicious_qtype() {
        let config = DnsDetectorConfig::default();
        let detector = DnsDetector::new(config);

        let mut tracker = DnsFlowTracker::new();

        // Add multiple TXT queries
        for _ in 0..5 {
            let query = DnsQuery {
                qname: "normal.example.com".to_string(),
                labels: vec![
                    "normal".to_string(),
                    "example".to_string(),
                    "com".to_string(),
                ],
                qtype: 16, // TXT
                qclass: 1,
            };
            tracker.add_query(&query, Utc::now());
        }

        let result = detector.analyze(&tracker);
        assert!(
            result.is_suspicious,
            "Multiple TXT queries should be suspicious"
        );
        assert!(result
            .indicators
            .iter()
            .any(|i| matches!(i, DnsIndicator::SuspiciousRecordType { qtype: 16 })));
    }

    #[test]
    fn test_is_dns_port() {
        assert!(is_dns_port(53));
        assert!(is_dns_port(5353)); // mDNS
        assert!(is_dns_port(5355)); // LLMNR
        assert!(!is_dns_port(80));
        assert!(!is_dns_port(443));
    }

    #[test]
    fn test_is_suspicious_qtype() {
        assert!(is_suspicious_qtype(16)); // TXT
        assert!(is_suspicious_qtype(10)); // NULL
        assert!(is_suspicious_qtype(255)); // ANY
        assert!(!is_suspicious_qtype(1)); // A
        assert!(!is_suspicious_qtype(5)); // CNAME
    }
}
