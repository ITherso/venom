use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct ProxyMetrics {
    pub total_requests: Arc<AtomicU64>,
    pub total_responses: Arc<AtomicU64>,
    pub total_bytes_sent: Arc<AtomicU64>,
    pub total_bytes_received: Arc<AtomicU64>,
    pub active_connections: Arc<AtomicU64>,
    pub errors: Arc<AtomicU64>,
    pub timeout_errors: Arc<AtomicU64>,
    pub start_time: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ScannerMetrics {
    pub total_scans: Arc<AtomicU64>,
    pub vulnerabilities_found: Arc<AtomicU64>,
    pub critical_vulns: Arc<AtomicU64>,
    pub high_vulns: Arc<AtomicU64>,
    pub medium_vulns: Arc<AtomicU64>,
    pub low_vulns: Arc<AtomicU64>,
    pub scan_errors: Arc<AtomicU64>,
    pub average_scan_time_ms: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
pub struct MetricsCollector {
    pub proxy: ProxyMetrics,
    pub scanner: ScannerMetrics,
}

impl ProxyMetrics {
    pub fn new() -> Self {
        Self {
            total_requests: Arc::new(AtomicU64::new(0)),
            total_responses: Arc::new(AtomicU64::new(0)),
            total_bytes_sent: Arc::new(AtomicU64::new(0)),
            total_bytes_received: Arc::new(AtomicU64::new(0)),
            active_connections: Arc::new(AtomicU64::new(0)),
            errors: Arc::new(AtomicU64::new(0)),
            timeout_errors: Arc::new(AtomicU64::new(0)),
            start_time: Utc::now(),
        }
    }

    pub fn record_request(&self) {
        self.total_requests.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_response(&self) {
        self.total_responses.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_bytes_sent(&self, bytes: u64) {
        self.total_bytes_sent.fetch_add(bytes, Ordering::SeqCst);
    }

    pub fn record_bytes_received(&self, bytes: u64) {
        self.total_bytes_received.fetch_add(bytes, Ordering::SeqCst);
    }

    pub fn increment_active_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::SeqCst);
    }

    pub fn decrement_active_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_timeout_error(&self) {
        self.timeout_errors.fetch_add(1, Ordering::SeqCst);
    }

    pub fn get_total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::SeqCst)
    }

    pub fn get_total_responses(&self) -> u64 {
        self.total_responses.load(Ordering::SeqCst)
    }

    pub fn get_active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::SeqCst)
    }

    pub fn get_errors(&self) -> u64 {
        self.errors.load(Ordering::SeqCst)
    }

    pub fn get_uptime_seconds(&self) -> u64 {
        let elapsed = Utc::now().signed_duration_since(self.start_time);
        elapsed.num_seconds() as u64
    }

    pub fn get_requests_per_second(&self) -> f64 {
        let uptime = self.get_uptime_seconds().max(1);
        self.get_total_requests() as f64 / uptime as f64
    }

    pub fn get_bytes_per_second(&self) -> f64 {
        let uptime = self.get_uptime_seconds().max(1);
        self.total_bytes_received.load(Ordering::SeqCst) as f64 / uptime as f64
    }
}

impl ScannerMetrics {
    pub fn new() -> Self {
        Self {
            total_scans: Arc::new(AtomicU64::new(0)),
            vulnerabilities_found: Arc::new(AtomicU64::new(0)),
            critical_vulns: Arc::new(AtomicU64::new(0)),
            high_vulns: Arc::new(AtomicU64::new(0)),
            medium_vulns: Arc::new(AtomicU64::new(0)),
            low_vulns: Arc::new(AtomicU64::new(0)),
            scan_errors: Arc::new(AtomicU64::new(0)),
            average_scan_time_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_scan(&self) {
        self.total_scans.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_vulnerability(&self, severity: &str) {
        self.vulnerabilities_found.fetch_add(1, Ordering::SeqCst);

        match severity {
            "critical" => {
                self.critical_vulns.fetch_add(1, Ordering::SeqCst);
            }
            "high" => {
                self.high_vulns.fetch_add(1, Ordering::SeqCst);
            }
            "medium" => {
                self.medium_vulns.fetch_add(1, Ordering::SeqCst);
            }
            "low" => {
                self.low_vulns.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
    }

    pub fn record_scan_error(&self) {
        self.scan_errors.fetch_add(1, Ordering::SeqCst);
    }

    pub fn set_average_scan_time(&self, ms: u64) {
        self.average_scan_time_ms.store(ms, Ordering::SeqCst);
    }

    pub fn get_total_scans(&self) -> u64 {
        self.total_scans.load(Ordering::SeqCst)
    }

    pub fn get_vulnerabilities_found(&self) -> u64 {
        self.vulnerabilities_found.load(Ordering::SeqCst)
    }

    pub fn get_critical_vulns(&self) -> u64 {
        self.critical_vulns.load(Ordering::SeqCst)
    }

    pub fn get_high_vulns(&self) -> u64 {
        self.high_vulns.load(Ordering::SeqCst)
    }

    pub fn get_scan_errors(&self) -> u64 {
        self.scan_errors.load(Ordering::SeqCst)
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            proxy: ProxyMetrics::new(),
            scanner: ScannerMetrics::new(),
        }
    }

    pub fn summary(&self) -> String {
        format!(
            r#"
╔════════════════════════════════════════════════════════════════╗
║                   VENOM Metrics Summary                         ║
╚════════════════════════════════════════════════════════════════╝

📊 PROXY METRICS
├─ Total Requests: {}
├─ Total Responses: {}
├─ Active Connections: {}
├─ Bytes Sent: {}
├─ Bytes Received: {}
├─ Errors: {}
├─ Timeout Errors: {}
├─ Uptime: {}s
├─ Requests/sec: {:.2}
└─ Bytes/sec: {:.2}

🔍 SCANNER METRICS
├─ Total Scans: {}
├─ Vulnerabilities Found: {}
├─ Critical: {}
├─ High: {}
├─ Medium: {}
├─ Low: {}
├─ Scan Errors: {}
└─ Average Scan Time: {}ms

═══════════════════════════════════════════════════════════════════
"#,
            self.proxy.get_total_requests(),
            self.proxy.get_total_responses(),
            self.proxy.get_active_connections(),
            self.proxy.total_bytes_sent.load(Ordering::SeqCst),
            self.proxy.total_bytes_received.load(Ordering::SeqCst),
            self.proxy.get_errors(),
            self.proxy.timeout_errors.load(Ordering::SeqCst),
            self.proxy.get_uptime_seconds(),
            self.proxy.get_requests_per_second(),
            self.proxy.get_bytes_per_second(),
            self.scanner.get_total_scans(),
            self.scanner.get_vulnerabilities_found(),
            self.scanner.get_critical_vulns(),
            self.scanner.get_high_vulns(),
            self.scanner.medium_vulns.load(Ordering::SeqCst),
            self.scanner.low_vulns.load(Ordering::SeqCst),
            self.scanner.get_scan_errors(),
            self.scanner.average_scan_time_ms.load(Ordering::SeqCst),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_metrics() {
        let metrics = ProxyMetrics::new();
        assert_eq!(metrics.get_total_requests(), 0);

        metrics.record_request();
        assert_eq!(metrics.get_total_requests(), 1);

        metrics.record_bytes_sent(1000);
        assert_eq!(metrics.total_bytes_sent.load(Ordering::SeqCst), 1000);
    }

    #[test]
    fn test_scanner_metrics() {
        let metrics = ScannerMetrics::new();
        assert_eq!(metrics.get_total_scans(), 0);

        metrics.record_scan();
        metrics.record_vulnerability("critical");
        metrics.record_vulnerability("high");

        assert_eq!(metrics.get_total_scans(), 1);
        assert_eq!(metrics.get_vulnerabilities_found(), 2);
        assert_eq!(metrics.get_critical_vulns(), 1);
        assert_eq!(metrics.get_high_vulns(), 1);
    }
}
