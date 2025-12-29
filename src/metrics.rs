//! Prometheus Metrics Export Module
//!
//! Exposes network-beacon metrics in Prometheus format for monitoring and alerting.
//! Provides an HTTP endpoint that can be scraped by Prometheus.
//!
//! # Metrics Exported
//!
//! - `network_beacon_packets_total` - Total packets captured
//! - `network_beacon_flows_total` - Total unique flows tracked
//! - `network_beacon_flows_active` - Currently active flows
//! - `network_beacon_suspicious_flows` - Number of suspicious flows detected
//! - `network_beacon_events_processed` - Total flow events processed by analyzer
//! - `network_beacon_dns_tunneling_detections` - DNS tunneling detections
//! - `network_beacon_malicious_ja3_detections` - Malicious JA3 fingerprint matches
//! - `network_beacon_http_beacon_detections` - HTTP beacon pattern detections

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::analyzer::AnalysisReport;

/// Atomic metrics counters for thread-safe updates.
#[derive(Debug)]
pub struct Metrics {
    /// Total packets captured (incremented by capture module)
    pub packets_total: AtomicU64,
    /// Total unique flows ever seen
    pub flows_total: AtomicU64,
    /// Currently active flows
    pub flows_active: AtomicU64,
    /// Suspicious flows detected
    pub suspicious_flows: AtomicU64,
    /// Total events processed by analyzer
    pub events_processed: AtomicU64,
    /// DNS tunneling detections
    pub dns_tunneling_detections: AtomicU64,
    /// Malicious JA3 fingerprint matches
    pub malicious_ja3_detections: AtomicU64,
    /// HTTP beacon pattern detections
    pub http_beacon_detections: AtomicU64,
    /// Protocol mismatch detections
    pub protocol_mismatch_detections: AtomicU64,
    /// Periodic beacon detections (CV-based)
    pub periodic_beacon_detections: AtomicU64,
    /// High-risk geographic destination flows
    pub geo_high_risk_flows: AtomicU64,
    /// Total alerts sent
    pub alerts_sent_total: AtomicU64,
    /// Last analysis timestamp (Unix epoch milliseconds)
    pub last_analysis_timestamp: AtomicU64,
}

impl Metrics {
    /// Create new metrics with all counters at zero.
    pub fn new() -> Self {
        Self {
            packets_total: AtomicU64::new(0),
            flows_total: AtomicU64::new(0),
            flows_active: AtomicU64::new(0),
            suspicious_flows: AtomicU64::new(0),
            events_processed: AtomicU64::new(0),
            dns_tunneling_detections: AtomicU64::new(0),
            malicious_ja3_detections: AtomicU64::new(0),
            http_beacon_detections: AtomicU64::new(0),
            protocol_mismatch_detections: AtomicU64::new(0),
            periodic_beacon_detections: AtomicU64::new(0),
            geo_high_risk_flows: AtomicU64::new(0),
            alerts_sent_total: AtomicU64::new(0),
            last_analysis_timestamp: AtomicU64::new(0),
        }
    }

    /// Increment packets captured counter.
    pub fn inc_packets(&self) {
        self.packets_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment packets by a specific amount.
    pub fn add_packets(&self, count: u64) {
        self.packets_total.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment alerts sent counter.
    pub fn inc_alerts(&self) {
        self.alerts_sent_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Update metrics from an analysis report.
    pub fn update_from_report(&self, report: &AnalysisReport) {
        self.flows_total
            .store(report.total_flows as u64, Ordering::Relaxed);
        self.flows_active
            .store(report.active_flows as u64, Ordering::Relaxed);
        self.suspicious_flows
            .store(report.suspicious_flows.len() as u64, Ordering::Relaxed);
        self.events_processed
            .store(report.events_processed, Ordering::Relaxed);
        self.last_analysis_timestamp
            .store(report.timestamp.timestamp_millis() as u64, Ordering::Relaxed);

        // Count specific detection types
        let mut dns_count: u64 = 0;
        let mut ja3_count: u64 = 0;
        let mut http_count: u64 = 0;
        let mut protocol_mismatch_count: u64 = 0;
        let mut periodic_count: u64 = 0;
        let mut geo_high_risk_count: u64 = 0;

        for flow in &report.suspicious_flows {
            for indicator in &flow.indicators {
                match indicator.as_str() {
                    "dns_tunneling" => dns_count += 1,
                    "malicious_ja3" => ja3_count += 1,
                    "http_beacon" => http_count += 1,
                    "tls_on_nonstandard_port" | "dns_on_nonstandard_port" => {
                        protocol_mismatch_count += 1
                    }
                    "periodic_beacon" => periodic_count += 1,
                    "high_risk_geo" => geo_high_risk_count += 1,
                    _ => {}
                }
            }

            // Check TLS fingerprint for malicious JA3
            if let Some(ref fp) = flow.tls_fingerprint {
                if fp.is_known_malicious {
                    ja3_count += 1;
                }
            }
        }

        self.dns_tunneling_detections
            .store(dns_count, Ordering::Relaxed);
        self.malicious_ja3_detections
            .store(ja3_count, Ordering::Relaxed);
        self.http_beacon_detections
            .store(http_count, Ordering::Relaxed);
        self.protocol_mismatch_detections
            .store(protocol_mismatch_count, Ordering::Relaxed);
        self.periodic_beacon_detections
            .store(periodic_count, Ordering::Relaxed);
        self.geo_high_risk_flows
            .store(geo_high_risk_count, Ordering::Relaxed);
    }

    /// Export metrics in Prometheus text format.
    pub fn to_prometheus_format(&self) -> String {
        let mut output = String::new();

        // Packets total
        output.push_str("# HELP network_beacon_packets_total Total packets captured\n");
        output.push_str("# TYPE network_beacon_packets_total counter\n");
        output.push_str(&format!(
            "network_beacon_packets_total {}\n\n",
            self.packets_total.load(Ordering::Relaxed)
        ));

        // Flows total
        output.push_str("# HELP network_beacon_flows_total Total unique flows tracked\n");
        output.push_str("# TYPE network_beacon_flows_total counter\n");
        output.push_str(&format!(
            "network_beacon_flows_total {}\n\n",
            self.flows_total.load(Ordering::Relaxed)
        ));

        // Active flows
        output.push_str("# HELP network_beacon_flows_active Currently active flows\n");
        output.push_str("# TYPE network_beacon_flows_active gauge\n");
        output.push_str(&format!(
            "network_beacon_flows_active {}\n\n",
            self.flows_active.load(Ordering::Relaxed)
        ));

        // Suspicious flows
        output.push_str("# HELP network_beacon_suspicious_flows Number of suspicious flows\n");
        output.push_str("# TYPE network_beacon_suspicious_flows gauge\n");
        output.push_str(&format!(
            "network_beacon_suspicious_flows {}\n\n",
            self.suspicious_flows.load(Ordering::Relaxed)
        ));

        // Events processed
        output.push_str("# HELP network_beacon_events_processed Total events processed\n");
        output.push_str("# TYPE network_beacon_events_processed counter\n");
        output.push_str(&format!(
            "network_beacon_events_processed {}\n\n",
            self.events_processed.load(Ordering::Relaxed)
        ));

        // DNS tunneling detections
        output
            .push_str("# HELP network_beacon_dns_tunneling_detections DNS tunneling detections\n");
        output.push_str("# TYPE network_beacon_dns_tunneling_detections gauge\n");
        output.push_str(&format!(
            "network_beacon_dns_tunneling_detections {}\n\n",
            self.dns_tunneling_detections.load(Ordering::Relaxed)
        ));

        // Malicious JA3 detections
        output.push_str(
            "# HELP network_beacon_malicious_ja3_detections Malicious JA3 fingerprint matches\n",
        );
        output.push_str("# TYPE network_beacon_malicious_ja3_detections gauge\n");
        output.push_str(&format!(
            "network_beacon_malicious_ja3_detections {}\n\n",
            self.malicious_ja3_detections.load(Ordering::Relaxed)
        ));

        // HTTP beacon detections
        output
            .push_str("# HELP network_beacon_http_beacon_detections HTTP beacon pattern matches\n");
        output.push_str("# TYPE network_beacon_http_beacon_detections gauge\n");
        output.push_str(&format!(
            "network_beacon_http_beacon_detections {}\n\n",
            self.http_beacon_detections.load(Ordering::Relaxed)
        ));

        // Protocol mismatch detections
        output.push_str(
            "# HELP network_beacon_protocol_mismatch_detections Protocol mismatch detections\n",
        );
        output.push_str("# TYPE network_beacon_protocol_mismatch_detections gauge\n");
        output.push_str(&format!(
            "network_beacon_protocol_mismatch_detections {}\n\n",
            self.protocol_mismatch_detections.load(Ordering::Relaxed)
        ));

        // Periodic beacon detections
        output
            .push_str("# HELP network_beacon_periodic_detections CV-based periodic detections\n");
        output.push_str("# TYPE network_beacon_periodic_detections gauge\n");
        output.push_str(&format!(
            "network_beacon_periodic_detections {}\n\n",
            self.periodic_beacon_detections.load(Ordering::Relaxed)
        ));

        // High-risk geo flows
        output.push_str(
            "# HELP network_beacon_geo_high_risk_flows High-risk geographic destination flows\n",
        );
        output.push_str("# TYPE network_beacon_geo_high_risk_flows gauge\n");
        output.push_str(&format!(
            "network_beacon_geo_high_risk_flows {}\n\n",
            self.geo_high_risk_flows.load(Ordering::Relaxed)
        ));

        // Alerts sent total
        output.push_str("# HELP network_beacon_alerts_sent_total Total alerts sent\n");
        output.push_str("# TYPE network_beacon_alerts_sent_total counter\n");
        output.push_str(&format!(
            "network_beacon_alerts_sent_total {}\n\n",
            self.alerts_sent_total.load(Ordering::Relaxed)
        ));

        // Last analysis timestamp
        output.push_str(
            "# HELP network_beacon_last_analysis_timestamp Last analysis Unix timestamp ms\n",
        );
        output.push_str("# TYPE network_beacon_last_analysis_timestamp gauge\n");
        output.push_str(&format!(
            "network_beacon_last_analysis_timestamp {}\n",
            self.last_analysis_timestamp.load(Ordering::Relaxed)
        ));

        output
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared metrics handle for use across threads/tasks.
pub type SharedMetrics = Arc<Metrics>;

/// Create a new shared metrics instance.
pub fn new_shared_metrics() -> SharedMetrics {
    Arc::new(Metrics::new())
}

/// Prometheus metrics server configuration.
#[derive(Debug, Clone)]
pub struct MetricsServerConfig {
    /// Address to bind the HTTP server.
    pub bind_address: SocketAddr,
    /// Metrics endpoint path.
    pub metrics_path: String,
}

impl Default for MetricsServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:9090".parse().unwrap(),
            metrics_path: "/metrics".to_string(),
        }
    }
}

/// Runs the Prometheus metrics HTTP server.
///
/// This is a minimal HTTP server that only responds to GET requests on the metrics path.
/// It's designed to be lightweight and not add external HTTP framework dependencies.
pub async fn run_metrics_server(
    config: MetricsServerConfig,
    metrics: SharedMetrics,
    shutdown: Arc<RwLock<bool>>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(&config.bind_address).await?;
    info!(
        "Prometheus metrics server listening on http://{}{}",
        config.bind_address, config.metrics_path
    );

    loop {
        // Check shutdown
        {
            let should_shutdown = shutdown.read().await;
            if *should_shutdown {
                info!("Metrics server shutting down");
                break;
            }
        }

        // Accept connections with timeout to allow shutdown checks
        let accept_result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            listener.accept(),
        )
        .await;

        let (mut socket, addr) = match accept_result {
            Ok(Ok((socket, addr))) => (socket, addr),
            Ok(Err(e)) => {
                error!("Accept error: {}", e);
                continue;
            }
            Err(_) => continue, // Timeout, check shutdown and loop
        };

        debug!("Metrics request from {}", addr);

        // Read request (we only care about GET /metrics)
        let mut buf = [0u8; 1024];
        let n = match socket.try_read(&mut buf) {
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Wait for data
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                match socket.try_read(&mut buf) {
                    Ok(n) => n,
                    Err(_) => continue,
                }
            }
            Err(_) => continue,
        };

        if n == 0 {
            continue;
        }

        let request = String::from_utf8_lossy(&buf[..n]);

        // Simple HTTP request parsing
        let is_metrics_request = request.starts_with("GET ")
            && (request.contains(&config.metrics_path)
                || request.contains("/metrics"));

        let response = if is_metrics_request {
            let body = metrics.to_prometheus_format();
            format!(
                "HTTP/1.1 200 OK\r\n\
                Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                Content-Length: {}\r\n\
                Connection: close\r\n\
                \r\n\
                {}",
                body.len(),
                body
            )
        } else if request.starts_with("GET /health") || request.starts_with("GET /") {
            let body = "OK\n";
            format!(
                "HTTP/1.1 200 OK\r\n\
                Content-Type: text/plain\r\n\
                Content-Length: {}\r\n\
                Connection: close\r\n\
                \r\n\
                {}",
                body.len(),
                body
            )
        } else {
            "HTTP/1.1 404 Not Found\r\n\
            Content-Length: 0\r\n\
            Connection: close\r\n\
            \r\n"
                .to_string()
        };

        if let Err(e) = socket.write_all(response.as_bytes()).await {
            debug!("Failed to write response: {}", e);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{FlowAnalysis, FlowClassification};
    use crate::capture::{FlowKey, Protocol};
    use crate::tls_fingerprint::TlsStatus;
    use chrono::Utc;
    use std::net::IpAddr;

    #[test]
    fn test_metrics_new() {
        let metrics = Metrics::new();
        assert_eq!(metrics.packets_total.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.flows_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_metrics_increment() {
        let metrics = Metrics::new();

        metrics.inc_packets();
        metrics.inc_packets();
        metrics.add_packets(8);

        assert_eq!(metrics.packets_total.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn test_prometheus_format() {
        let metrics = Metrics::new();
        metrics.add_packets(100);
        metrics.flows_total.store(50, Ordering::Relaxed);
        metrics.flows_active.store(25, Ordering::Relaxed);
        metrics.suspicious_flows.store(5, Ordering::Relaxed);

        let output = metrics.to_prometheus_format();

        assert!(output.contains("network_beacon_packets_total 100"));
        assert!(output.contains("network_beacon_flows_total 50"));
        assert!(output.contains("network_beacon_flows_active 25"));
        assert!(output.contains("network_beacon_suspicious_flows 5"));
        assert!(output.contains("# HELP"));
        assert!(output.contains("# TYPE"));
    }

    #[test]
    fn test_update_from_report() {
        let metrics = Metrics::new();

        let flow_key = FlowKey::new(
            "192.168.1.1".parse::<IpAddr>().unwrap(),
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            443,
            Protocol::Tcp,
        );

        let report = AnalysisReport {
            timestamp: Utc::now(),
            total_flows: 100,
            active_flows: 50,
            suspicious_flows: vec![FlowAnalysis {
                flow_key,
                classification: FlowClassification::HighlyPeriodic,
                cv: Some(0.05),
                mean_interval_ms: Some(60000.0),
                packet_count: 100,
                total_bytes: 50000,
                duration_secs: 3600,
                tls_fingerprint: None,
                tls_status: TlsStatus::Plaintext,
                dns_analysis: None,
                indicators: vec![
                    "periodic_beacon".to_string(),
                    "dns_tunneling".to_string(),
                ],
                geo_info: None,
            }],
            events_processed: 10000,
        };

        metrics.update_from_report(&report);

        assert_eq!(metrics.flows_total.load(Ordering::Relaxed), 100);
        assert_eq!(metrics.flows_active.load(Ordering::Relaxed), 50);
        assert_eq!(metrics.suspicious_flows.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.events_processed.load(Ordering::Relaxed), 10000);
        assert_eq!(
            metrics.periodic_beacon_detections.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics.dns_tunneling_detections.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_shared_metrics() {
        let shared = new_shared_metrics();
        let clone = Arc::clone(&shared);

        shared.inc_packets();
        clone.inc_packets();

        assert_eq!(shared.packets_total.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_default_config() {
        let config = MetricsServerConfig::default();
        assert_eq!(config.bind_address.port(), 9090);
        assert_eq!(config.metrics_path, "/metrics");
    }
}
