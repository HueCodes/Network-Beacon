//! Flow analysis module - The Consumer in our Producer-Consumer architecture.
//!
//! This module aggregates flow events and performs statistical analysis to
//! detect C2 beaconing patterns based on timing periodicity.
//!
//! # Statistical Methodology
//!
//! ## Delta Calculation
//! For a series of timestamps [t₀, t₁, t₂, ..., tₙ], we calculate the intervals:
//! Δᵢ = tᵢ - tᵢ₋₁ for i ∈ [1, n]
//!
//! ## Jitter Metric (Coefficient of Variation)
//! CV = σ / μ where:
//! - σ (sigma) = standard deviation of intervals
//! - μ (mu) = mean of intervals
//!
//! The CV is dimensionless and allows comparison across flows with different
//! beacon frequencies.
//!
//! ## Classification Thresholds
//! - CV < 0.1: Highly Periodic → Probable Bot/C2
//! - 0.1 ≤ CV < 0.5: Jittered Periodicity → Suspicious
//! - CV ≥ 1.0: Stochastic → Likely Human/Organic Traffic

use std::time::Duration;

use chrono::{DateTime, Utc};
use lru::LruCache;
use statrs::statistics::{Data, Distribution, Max, Min, OrderStatistics};
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, info, trace};

use crate::capture::{FlowEvent, FlowKey, Protocol};
use crate::dns_detector::{
    is_dns_port, parse_dns_query, DnsAnalysisResult, DnsDetector, DnsDetectorConfig, DnsFlowTracker,
};
use crate::error::Result;
use crate::tls_fingerprint::{extract_fingerprint, is_tls_port, TlsFingerprint, TlsStatus};

/// Classification of flow behavior based on CV analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowClassification {
    /// CV < 0.1 - Highly regular intervals, likely automated/C2
    HighlyPeriodic,
    /// 0.1 ≤ CV < 0.5 - Some jitter but still suspicious regularity
    JitteredPeriodic,
    /// 0.5 ≤ CV < 1.0 - Moderate variation, needs monitoring
    Moderate,
    /// CV ≥ 1.0 - High variation, likely human-driven
    Stochastic,
    /// Insufficient data for classification
    Insufficient,
}

impl FlowClassification {
    /// Returns the classification based on CV value.
    pub fn from_cv(cv: f64) -> Self {
        match cv {
            cv if cv < 0.1 => Self::HighlyPeriodic,
            cv if cv < 0.5 => Self::JitteredPeriodic,
            cv if cv < 1.0 => Self::Moderate,
            _ => Self::Stochastic,
        }
    }

    /// Returns a human-readable severity level.
    pub fn severity(&self) -> &'static str {
        match self {
            Self::HighlyPeriodic => "CRITICAL",
            Self::JitteredPeriodic => "HIGH",
            Self::Moderate => "MEDIUM",
            Self::Stochastic => "LOW",
            Self::Insufficient => "UNKNOWN",
        }
    }

    /// Returns a color hint for UI rendering.
    pub fn color_hint(&self) -> &'static str {
        match self {
            Self::HighlyPeriodic => "red",
            Self::JitteredPeriodic => "yellow",
            Self::Moderate => "blue",
            Self::Stochastic => "green",
            Self::Insufficient => "gray",
        }
    }
}

impl std::fmt::Display for FlowClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HighlyPeriodic => write!(f, "Highly Periodic (Probable Bot)"),
            Self::JitteredPeriodic => write!(f, "Jittered Periodic (Suspicious)"),
            Self::Moderate => write!(f, "Moderate Variation"),
            Self::Stochastic => write!(f, "Stochastic (Likely Organic)"),
            Self::Insufficient => write!(f, "Insufficient Data"),
        }
    }
}

/// Trait for beacon detection algorithms.
/// Allows for extensibility with different detection strategies.
pub trait Detector: Send + Sync {
    /// Analyzes a series of intervals and returns a detection result.
    fn analyze(&self, intervals_ms: &[f64]) -> DetectionResult;

    /// Returns the minimum number of samples required for analysis.
    fn min_samples(&self) -> usize;
}

/// Result of beacon detection analysis.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub classification: FlowClassification,
    pub cv: Option<f64>,
    pub mean_interval_ms: Option<f64>,
    pub std_dev_ms: Option<f64>,
    pub sample_count: usize,
}

impl DetectionResult {
    /// Creates a result indicating insufficient data.
    pub fn insufficient(sample_count: usize) -> Self {
        Self {
            classification: FlowClassification::Insufficient,
            cv: None,
            mean_interval_ms: None,
            std_dev_ms: None,
            sample_count,
        }
    }
}

/// Default CV-based beacon detector.
pub struct CvDetector {
    min_samples: usize,
}

impl CvDetector {
    pub fn new(min_samples: usize) -> Self {
        Self { min_samples }
    }
}

impl Default for CvDetector {
    fn default() -> Self {
        Self { min_samples: 5 }
    }
}

impl Detector for CvDetector {
    fn analyze(&self, intervals_ms: &[f64]) -> DetectionResult {
        if intervals_ms.len() < self.min_samples {
            return DetectionResult::insufficient(intervals_ms.len());
        }

        let stats = calculate_statistics(intervals_ms);

        DetectionResult {
            classification: FlowClassification::from_cv(stats.cv),
            cv: Some(stats.cv),
            mean_interval_ms: Some(stats.mean),
            std_dev_ms: Some(stats.std_dev),
            sample_count: intervals_ms.len(),
        }
    }

    fn min_samples(&self) -> usize {
        self.min_samples
    }
}

/// Statistical summary for a set of intervals.
#[derive(Debug, Clone)]
pub struct IntervalStatistics {
    pub mean: f64,
    pub std_dev: f64,
    pub cv: f64,
    pub min: f64,
    pub max: f64,
    pub median: f64,
}

/// Calculates comprehensive statistics for a set of intervals.
/// Returns default values if the input is empty or has fewer than 2 elements.
pub fn calculate_statistics(intervals_ms: &[f64]) -> IntervalStatistics {
    // Guard against empty or single-element arrays
    if intervals_ms.is_empty() {
        return IntervalStatistics {
            mean: 0.0,
            std_dev: 0.0,
            cv: f64::INFINITY,
            min: 0.0,
            max: 0.0,
            median: 0.0,
        };
    }

    let mut data = Data::new(intervals_ms.to_vec());

    let mean = data.mean().unwrap_or(0.0);
    let std_dev = data.std_dev().unwrap_or(0.0);

    // Handle edge cases in CV calculation
    let cv = if mean > 0.0 && std_dev.is_finite() {
        let computed_cv = std_dev / mean;
        if computed_cv.is_finite() { computed_cv } else { f64::INFINITY }
    } else {
        f64::INFINITY
    };

    let min = data.min();
    let max = data.max();
    let median = data.median();

    IntervalStatistics {
        mean,
        std_dev,
        cv,
        min,
        max,
        median,
    }
}

/// Converts timestamps to interval deltas in milliseconds.
pub fn timestamps_to_deltas(timestamps: &[DateTime<Utc>]) -> Vec<f64> {
    if timestamps.len() < 2 {
        return Vec::new();
    }

    timestamps
        .windows(2)
        .map(|window| {
            let delta = window[1].signed_duration_since(window[0]);
            delta.num_milliseconds() as f64
        })
        .collect()
}

/// Aggregated data for a single flow.
#[derive(Debug, Clone)]
pub struct FlowData {
    pub flow_key: FlowKey,
    pub timestamps: Vec<DateTime<Utc>>,
    pub total_bytes: u64,
    pub packet_count: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub last_analysis: Option<DetectionResult>,
    /// TLS fingerprint extracted from Client Hello (if applicable).
    pub tls_fingerprint: Option<TlsFingerprint>,
    /// TLS status for this flow.
    pub tls_status: TlsStatus,
    /// DNS flow tracker for tunneling detection (if DNS flow).
    pub dns_tracker: Option<DnsFlowTracker>,
    /// Latest DNS analysis result.
    pub dns_analysis: Option<DnsAnalysisResult>,
}

impl FlowData {
    pub fn new(event: &FlowEvent) -> Self {
        // Determine initial TLS status based on port and protocol
        let (tls_fingerprint, tls_status) = Self::extract_tls_info(event);

        // Initialize DNS tracker if this is a DNS flow
        let dns_tracker = Self::init_dns_tracker(event);

        Self {
            flow_key: event.flow_key.clone(),
            timestamps: vec![event.timestamp],
            total_bytes: event.packet_size as u64,
            packet_count: 1,
            first_seen: event.timestamp,
            last_seen: event.timestamp,
            last_analysis: None,
            tls_fingerprint,
            tls_status,
            dns_tracker,
            dns_analysis: None,
        }
    }

    /// Initializes DNS tracker if this is a DNS flow with payload
    fn init_dns_tracker(event: &FlowEvent) -> Option<DnsFlowTracker> {
        if event.flow_key.protocol != Protocol::Udp || !is_dns_port(event.flow_key.dst_port) {
            return None;
        }

        let mut tracker = DnsFlowTracker::new();

        if let Some(ref payload) = event.dns_payload {
            if let Some(query) = parse_dns_query(payload) {
                tracker.add_query(&query, event.timestamp);
            }
        }

        Some(tracker)
    }

    /// Extracts TLS fingerprint information from a flow event.
    fn extract_tls_info(event: &FlowEvent) -> (Option<TlsFingerprint>, TlsStatus) {
        // Check if this is a TLS port
        if event.flow_key.protocol != Protocol::Tcp {
            return (None, TlsStatus::Plaintext);
        }

        if !is_tls_port(event.flow_key.dst_port) {
            return (None, TlsStatus::Plaintext);
        }

        // Try to extract TLS fingerprint from payload
        if let Some(ref payload) = event.tls_payload {
            if let Some(fingerprint) = extract_fingerprint(payload) {
                trace!(
                    "Extracted TLS fingerprint for {}: {}",
                    event.flow_key,
                    fingerprint.fingerprint
                );
                return (Some(fingerprint), TlsStatus::Fingerprinted);
            }
        }

        // TLS port but no fingerprint (could be resumed session or encrypted)
        (None, TlsStatus::TlsNoFingerprint)
    }

    /// Adds a new event to this flow's data.
    pub fn add_event(&mut self, event: &FlowEvent) {
        self.timestamps.push(event.timestamp);
        self.total_bytes += event.packet_size as u64;
        self.packet_count += 1;
        self.last_seen = event.timestamp;

        // Try to extract TLS fingerprint if we don't have one yet
        if self.tls_fingerprint.is_none() && self.tls_status != TlsStatus::Plaintext {
            let (fp, status) = Self::extract_tls_info(event);
            if fp.is_some() {
                self.tls_fingerprint = fp;
                self.tls_status = status;
            }
        }

        // Update DNS tracker if this is a DNS flow
        if let Some(ref mut tracker) = self.dns_tracker {
            if let Some(ref payload) = event.dns_payload {
                if let Some(query) = parse_dns_query(payload) {
                    tracker.add_query(&query, event.timestamp);
                }
            }
        }
    }

    /// Calculates interval deltas for this flow.
    pub fn get_deltas_ms(&self) -> Vec<f64> {
        timestamps_to_deltas(&self.timestamps)
    }

    /// Analyzes this flow using the provided detector.
    pub fn analyze(&mut self, detector: &dyn Detector) -> DetectionResult {
        let deltas = self.get_deltas_ms();
        let result = detector.analyze(&deltas);
        self.last_analysis = Some(result.clone());
        result
    }

    /// Returns the duration of this flow.
    pub fn duration(&self) -> chrono::Duration {
        self.last_seen.signed_duration_since(self.first_seen)
    }
}

/// Configuration for the flow analyzer.
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    /// Maximum number of flows to track (LRU eviction).
    pub max_flows: usize,
    /// Maximum timestamps to retain per flow.
    pub max_timestamps_per_flow: usize,
    /// Analysis interval in seconds.
    pub analysis_interval_secs: u64,
    /// Minimum samples required for CV calculation.
    pub min_samples: usize,
    /// TTL for inactive flows in seconds.
    pub flow_ttl_secs: u64,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            max_flows: 10_000,
            max_timestamps_per_flow: 1_000,
            analysis_interval_secs: 10,
            min_samples: 5,
            flow_ttl_secs: 300, // 5 minutes
        }
    }
}

/// Analysis results for reporting to the UI.
#[derive(Debug, Clone)]
pub struct AnalysisReport {
    pub timestamp: DateTime<Utc>,
    pub total_flows: usize,
    pub active_flows: usize,
    pub suspicious_flows: Vec<FlowAnalysis>,
    pub events_processed: u64,
}

/// Analysis result for a single flow.
#[derive(Debug, Clone)]
pub struct FlowAnalysis {
    pub flow_key: FlowKey,
    pub classification: FlowClassification,
    pub cv: Option<f64>,
    pub mean_interval_ms: Option<f64>,
    pub packet_count: u64,
    pub total_bytes: u64,
    pub duration_secs: i64,
    /// TLS fingerprint (if extracted).
    pub tls_fingerprint: Option<TlsFingerprint>,
    /// TLS status for display.
    pub tls_status: TlsStatus,
    /// DNS tunneling analysis result (if DNS flow).
    pub dns_analysis: Option<DnsAnalysisResult>,
    /// Detection indicators for this flow.
    pub indicators: Vec<String>,
}

/// The main flow analyzer - consumes FlowEvents and performs analysis.
pub struct FlowAnalyzer {
    config: AnalyzerConfig,
    flows: LruCache<FlowKey, FlowData>,
    detector: Box<dyn Detector>,
    dns_detector: DnsDetector,
    events_processed: u64,
}

impl FlowAnalyzer {
    pub fn new(config: AnalyzerConfig) -> Self {
        let detector = Box::new(CvDetector::new(config.min_samples));
        let dns_detector = DnsDetector::new(DnsDetectorConfig::default());
        // Ensure max_flows is at least 1 to prevent panic
        let max_flows = std::num::NonZeroUsize::new(config.max_flows.max(1))
            .expect("max(1) guarantees non-zero");

        Self {
            config,
            flows: LruCache::new(max_flows),
            detector,
            dns_detector,
            events_processed: 0,
        }
    }

    /// Processes a single flow event.
    pub fn process_event(&mut self, event: FlowEvent) {
        self.events_processed += 1;

        if let Some(flow_data) = self.flows.get_mut(&event.flow_key) {
            flow_data.add_event(&event);

            // Trim timestamps if exceeding limit
            if flow_data.timestamps.len() > self.config.max_timestamps_per_flow {
                let excess = flow_data.timestamps.len() - self.config.max_timestamps_per_flow;
                flow_data.timestamps.drain(0..excess);
            }
        } else {
            let flow_data = FlowData::new(&event);
            self.flows.put(event.flow_key, flow_data);
        }
    }

    /// Performs analysis on all active flows.
    pub fn analyze_all(&mut self) -> AnalysisReport {
        let now = Utc::now();
        let ttl = chrono::Duration::seconds(self.config.flow_ttl_secs as i64);

        let mut suspicious_flows = Vec::new();
        let mut active_count = 0;

        // Collect keys to analyze (can't modify while iterating)
        let keys: Vec<FlowKey> = self.flows.iter().map(|(k, _)| k.clone()).collect();

        for key in keys {
            if let Some(flow_data) = self.flows.get_mut(&key) {
                // Check if flow is still active (within TTL)
                let age = now.signed_duration_since(flow_data.last_seen);
                if age > ttl {
                    continue;
                }

                active_count += 1;

                // Perform CV-based analysis
                let result = flow_data.analyze(self.detector.as_ref());

                // Perform DNS tunneling analysis if applicable
                let dns_analysis = if let Some(ref tracker) = flow_data.dns_tracker {
                    let analysis = self.dns_detector.analyze(tracker);
                    flow_data.dns_analysis = Some(analysis.clone());
                    Some(analysis)
                } else {
                    None
                };

                // Build indicators list
                let mut indicators = Vec::new();

                // CV-based indicators
                let is_periodic = matches!(
                    result.classification,
                    FlowClassification::HighlyPeriodic | FlowClassification::JitteredPeriodic
                );
                if is_periodic {
                    indicators.push("periodic_beacon".to_string());
                }

                // TLS indicators
                if let Some(ref fp) = flow_data.tls_fingerprint {
                    if !fp.is_known_good {
                        indicators.push("unknown_tls_client".to_string());
                    }
                }

                // DNS tunneling indicators
                let dns_suspicious = dns_analysis.as_ref().map(|d| d.is_suspicious).unwrap_or(false);
                if dns_suspicious {
                    indicators.push("dns_tunneling".to_string());
                    if let Some(ref dns) = dns_analysis {
                        for indicator in &dns.indicators {
                            let indicator_str = match indicator {
                                crate::dns_detector::DnsIndicator::HighEntropy { .. } => "high_entropy_dns",
                                crate::dns_detector::DnsIndicator::LongLabel { .. } => "long_dns_label",
                                crate::dns_detector::DnsIndicator::HighQueryRate => "high_dns_query_rate",
                                crate::dns_detector::DnsIndicator::SuspiciousRecordType { .. } => "suspicious_dns_qtype",
                                crate::dns_detector::DnsIndicator::ManySubdomains { .. } => "many_unique_subdomains",
                            };
                            indicators.push(indicator_str.to_string());
                        }
                    }
                }

                // Report suspicious flows (periodic OR DNS tunneling)
                if is_periodic || dns_suspicious {
                    suspicious_flows.push(FlowAnalysis {
                        flow_key: flow_data.flow_key.clone(),
                        classification: result.classification,
                        cv: result.cv,
                        mean_interval_ms: result.mean_interval_ms,
                        packet_count: flow_data.packet_count,
                        total_bytes: flow_data.total_bytes,
                        duration_secs: flow_data.duration().num_seconds(),
                        tls_fingerprint: flow_data.tls_fingerprint.clone(),
                        tls_status: flow_data.tls_status,
                        dns_analysis,
                        indicators,
                    });
                }
            }
        }

        // Sort suspicious flows by CV (lowest/most periodic first)
        // DNS-only detections go last (they have no CV)
        suspicious_flows.sort_by(|a, b| {
            a.cv.unwrap_or(f64::MAX)
                .partial_cmp(&b.cv.unwrap_or(f64::MAX))
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        debug!(
            "Analysis complete: {} total flows, {} active, {} suspicious",
            self.flows.len(),
            active_count,
            suspicious_flows.len()
        );

        AnalysisReport {
            timestamp: now,
            total_flows: self.flows.len(),
            active_flows: active_count,
            suspicious_flows,
            events_processed: self.events_processed,
        }
    }

    /// Removes expired flows from the cache.
    pub fn cleanup_expired(&mut self) {
        let now = Utc::now();
        let ttl = chrono::Duration::seconds(self.config.flow_ttl_secs as i64);

        // Collect expired keys
        let expired: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, data)| now.signed_duration_since(data.last_seen) > ttl)
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired {
            self.flows.pop(&key);
        }
    }

    /// Returns current statistics.
    pub fn stats(&self) -> AnalyzerStats {
        AnalyzerStats {
            total_flows: self.flows.len(),
            events_processed: self.events_processed,
            max_flows: self.config.max_flows,
        }
    }
}

/// Runtime statistics for the analyzer.
#[derive(Debug, Clone)]
pub struct AnalyzerStats {
    pub total_flows: usize,
    pub events_processed: u64,
    pub max_flows: usize,
}

/// Async task that runs the analyzer loop.
pub async fn run_analyzer(
    mut rx: mpsc::Receiver<FlowEvent>,
    report_tx: mpsc::Sender<AnalysisReport>,
    config: AnalyzerConfig,
) -> Result<()> {
    let analysis_interval = Duration::from_secs(config.analysis_interval_secs);
    let mut analyzer = FlowAnalyzer::new(config);
    let mut interval = interval(analysis_interval);

    info!("Analyzer started, analysis interval: {:?}", analysis_interval);

    loop {
        tokio::select! {
            // Process incoming flow events
            Some(event) = rx.recv() => {
                analyzer.process_event(event);
            }

            // Periodic analysis
            _ = interval.tick() => {
                analyzer.cleanup_expired();
                let report = analyzer.analyze_all();

                if !report.suspicious_flows.is_empty() {
                    info!(
                        "Found {} suspicious flows",
                        report.suspicious_flows.len()
                    );
                }

                // Send report to UI (non-blocking)
                let _ = report_tx.try_send(report);
            }

            else => {
                info!("Analyzer channel closed, shutting down");
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cv_classification_highly_periodic() {
        // Very regular intervals - should be classified as highly periodic
        let intervals = vec![1000.0, 1000.0, 1000.0, 1000.0, 1000.0];
        let stats = calculate_statistics(&intervals);

        assert!(stats.cv < 0.1, "CV should be < 0.1 for periodic traffic");
        assert_eq!(
            FlowClassification::from_cv(stats.cv),
            FlowClassification::HighlyPeriodic
        );
    }

    #[test]
    fn test_cv_classification_jittered() {
        // Intervals with moderate jitter (±30-40%) to produce CV in 0.1-0.5 range
        let intervals = vec![1000.0, 1400.0, 800.0, 1300.0, 700.0, 1200.0, 900.0, 1100.0];
        let stats = calculate_statistics(&intervals);

        assert!(
            stats.cv >= 0.1 && stats.cv < 0.5,
            "CV should be in jittered range for moderately varying traffic: {}",
            stats.cv
        );
        assert_eq!(
            FlowClassification::from_cv(stats.cv),
            FlowClassification::JitteredPeriodic
        );
    }

    #[test]
    fn test_cv_classification_stochastic() {
        // Highly variable intervals - human-like
        let intervals = vec![500.0, 3000.0, 100.0, 5000.0, 200.0, 8000.0, 50.0];
        let stats = calculate_statistics(&intervals);

        assert!(stats.cv >= 1.0, "CV should be >= 1.0 for stochastic traffic");
        assert_eq!(
            FlowClassification::from_cv(stats.cv),
            FlowClassification::Stochastic
        );
    }

    #[test]
    fn test_timestamps_to_deltas() {
        let base = Utc::now();
        let timestamps = vec![
            base,
            base + chrono::Duration::milliseconds(1000),
            base + chrono::Duration::milliseconds(2000),
            base + chrono::Duration::milliseconds(3000),
        ];

        let deltas = timestamps_to_deltas(&timestamps);

        assert_eq!(deltas.len(), 3);
        assert_eq!(deltas[0], 1000.0);
        assert_eq!(deltas[1], 1000.0);
        assert_eq!(deltas[2], 1000.0);
    }

    #[test]
    fn test_timestamps_to_deltas_empty() {
        let deltas = timestamps_to_deltas(&[]);
        assert!(deltas.is_empty());
    }

    #[test]
    fn test_timestamps_to_deltas_single() {
        let deltas = timestamps_to_deltas(&[Utc::now()]);
        assert!(deltas.is_empty());
    }

    #[test]
    fn test_cv_detector_insufficient_data() {
        let detector = CvDetector::new(5);
        let intervals = vec![1000.0, 1000.0]; // Only 2 samples

        let result = detector.analyze(&intervals);

        assert_eq!(result.classification, FlowClassification::Insufficient);
        assert!(result.cv.is_none());
    }

    #[test]
    fn test_cv_detector_sufficient_data() {
        let detector = CvDetector::new(5);
        let intervals = vec![1000.0, 1000.0, 1000.0, 1000.0, 1000.0];

        let result = detector.analyze(&intervals);

        assert_eq!(result.classification, FlowClassification::HighlyPeriodic);
        assert!(result.cv.is_some());
        assert!(result.cv.unwrap() < 0.1);
    }

    #[test]
    fn test_statistics_calculation() {
        let intervals = vec![100.0, 200.0, 300.0, 400.0, 500.0];
        let stats = calculate_statistics(&intervals);

        // Mean should be 300
        assert!((stats.mean - 300.0).abs() < 0.01);

        // Min should be 100
        assert!((stats.min - 100.0).abs() < 0.01);

        // Max should be 500
        assert!((stats.max - 500.0).abs() < 0.01);

        // Median should be 300
        assert!((stats.median - 300.0).abs() < 0.01);
    }

    #[test]
    fn test_flow_classification_severity() {
        assert_eq!(FlowClassification::HighlyPeriodic.severity(), "CRITICAL");
        assert_eq!(FlowClassification::JitteredPeriodic.severity(), "HIGH");
        assert_eq!(FlowClassification::Moderate.severity(), "MEDIUM");
        assert_eq!(FlowClassification::Stochastic.severity(), "LOW");
        assert_eq!(FlowClassification::Insufficient.severity(), "UNKNOWN");
    }

    #[test]
    fn test_real_world_beacon_pattern() {
        // Simulate a C2 beacon with 60-second interval and ±5% jitter
        let base_interval = 60_000.0; // 60 seconds in ms
        let intervals: Vec<f64> = (0..20)
            .map(|i| {
                // Add slight deterministic jitter for reproducibility
                let jitter = ((i % 5) as f64 - 2.0) * 0.02 * base_interval;
                base_interval + jitter
            })
            .collect();

        let stats = calculate_statistics(&intervals);

        assert!(
            stats.cv < 0.1,
            "A 60-second beacon with 5% jitter should be detected as periodic: CV={}",
            stats.cv
        );
    }
}
