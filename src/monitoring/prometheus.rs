use super::metrics::MetricsCollector;

pub struct PrometheusExporter {
    metrics: MetricsCollector,
}

impl PrometheusExporter {
    pub fn new(metrics: MetricsCollector) -> Self {
        Self { metrics }
    }

    /// Generate Prometheus metrics output in text format
    pub fn export(&self) -> String {
        let mut output = String::new();

        // HELP comments
        output.push_str("# HELP venom_proxy_requests_total Total number of requests processed\n");
        output.push_str("# TYPE venom_proxy_requests_total counter\n");

        // Proxy metrics
        output.push_str(&format!(
            "venom_proxy_requests_total {}\n",
            self.metrics.proxy.get_total_requests()
        ));

        output.push_str("# HELP venom_proxy_responses_total Total number of responses sent\n");
        output.push_str("# TYPE venom_proxy_responses_total counter\n");
        output.push_str(&format!(
            "venom_proxy_responses_total {}\n",
            self.metrics.proxy.get_total_responses()
        ));

        output.push_str("# HELP venom_proxy_bytes_sent_total Total bytes sent\n");
        output.push_str("# TYPE venom_proxy_bytes_sent_total counter\n");
        output.push_str(&format!(
            "venom_proxy_bytes_sent_total {}\n",
            self.metrics.proxy.total_bytes_sent.load(std::sync::atomic::Ordering::SeqCst)
        ));

        output.push_str("# HELP venom_proxy_bytes_received_total Total bytes received\n");
        output.push_str("# TYPE venom_proxy_bytes_received_total counter\n");
        output.push_str(&format!(
            "venom_proxy_bytes_received_total {}\n",
            self.metrics.proxy.total_bytes_received.load(std::sync::atomic::Ordering::SeqCst)
        ));

        output.push_str("# HELP venom_proxy_active_connections Current number of active connections\n");
        output.push_str("# TYPE venom_proxy_active_connections gauge\n");
        output.push_str(&format!(
            "venom_proxy_active_connections {}\n",
            self.metrics.proxy.get_active_connections()
        ));

        output.push_str("# HELP venom_proxy_errors_total Total number of proxy errors\n");
        output.push_str("# TYPE venom_proxy_errors_total counter\n");
        output.push_str(&format!(
            "venom_proxy_errors_total {}\n",
            self.metrics.proxy.get_errors()
        ));

        output.push_str("# HELP venom_proxy_timeout_errors_total Total timeout errors\n");
        output.push_str("# TYPE venom_proxy_timeout_errors_total counter\n");
        output.push_str(&format!(
            "venom_proxy_timeout_errors_total {}\n",
            self.metrics.proxy.timeout_errors.load(std::sync::atomic::Ordering::SeqCst)
        ));

        output.push_str("# HELP venom_proxy_uptime_seconds Proxy uptime in seconds\n");
        output.push_str("# TYPE venom_proxy_uptime_seconds gauge\n");
        output.push_str(&format!(
            "venom_proxy_uptime_seconds {}\n",
            self.metrics.proxy.get_uptime_seconds()
        ));

        output.push_str("# HELP venom_proxy_requests_per_second Requests per second\n");
        output.push_str("# TYPE venom_proxy_requests_per_second gauge\n");
        output.push_str(&format!(
            "venom_proxy_requests_per_second {:.2}\n",
            self.metrics.proxy.get_requests_per_second()
        ));

        output.push_str("# HELP venom_proxy_bytes_per_second Bytes per second\n");
        output.push_str("# TYPE venom_proxy_bytes_per_second gauge\n");
        output.push_str(&format!(
            "venom_proxy_bytes_per_second {:.2}\n",
            self.metrics.proxy.get_bytes_per_second()
        ));

        // Scanner metrics
        output.push_str("# HELP venom_scanner_scans_total Total number of scans performed\n");
        output.push_str("# TYPE venom_scanner_scans_total counter\n");
        output.push_str(&format!(
            "venom_scanner_scans_total {}\n",
            self.metrics.scanner.get_total_scans()
        ));

        output.push_str("# HELP venom_scanner_vulnerabilities_total Total vulnerabilities found\n");
        output.push_str("# TYPE venom_scanner_vulnerabilities_total counter\n");
        output.push_str(&format!(
            "venom_scanner_vulnerabilities_total {}\n",
            self.metrics.scanner.get_vulnerabilities_found()
        ));

        output.push_str("# HELP venom_scanner_vulnerabilities Vulnerabilities by severity\n");
        output.push_str("# TYPE venom_scanner_vulnerabilities gauge\n");
        output.push_str(&format!(
            "venom_scanner_vulnerabilities{{severity=\"critical\"}} {}\n",
            self.metrics.scanner.get_critical_vulns()
        ));
        output.push_str(&format!(
            "venom_scanner_vulnerabilities{{severity=\"high\"}} {}\n",
            self.metrics.scanner.get_high_vulns()
        ));
        output.push_str(&format!(
            "venom_scanner_vulnerabilities{{severity=\"medium\"}} {}\n",
            self.metrics.scanner.medium_vulns.load(std::sync::atomic::Ordering::SeqCst)
        ));
        output.push_str(&format!(
            "venom_scanner_vulnerabilities{{severity=\"low\"}} {}\n",
            self.metrics.scanner.low_vulns.load(std::sync::atomic::Ordering::SeqCst)
        ));

        output.push_str("# HELP venom_scanner_errors_total Total scanner errors\n");
        output.push_str("# TYPE venom_scanner_errors_total counter\n");
        output.push_str(&format!(
            "venom_scanner_errors_total {}\n",
            self.metrics.scanner.get_scan_errors()
        ));

        output.push_str("# HELP venom_scanner_average_scan_time_ms Average scan time in milliseconds\n");
        output.push_str("# TYPE venom_scanner_average_scan_time_ms gauge\n");
        output.push_str(&format!(
            "venom_scanner_average_scan_time_ms {}\n",
            self.metrics.scanner.average_scan_time_ms.load(std::sync::atomic::Ordering::SeqCst)
        ));

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prometheus_export() {
        let collector = MetricsCollector::new();
        collector.proxy.record_request();
        collector.proxy.record_request();
        collector.scanner.record_scan();
        collector.scanner.record_vulnerability("critical");

        let exporter = PrometheusExporter::new(collector);
        let output = exporter.export();

        assert!(output.contains("venom_proxy_requests_total 2"));
        assert!(output.contains("venom_scanner_scans_total 1"));
        assert!(output.contains("venom_scanner_vulnerabilities{severity=\"critical\"} 1"));
        assert!(output.contains("# HELP venom_proxy_requests_total"));
        assert!(output.contains("# TYPE venom_proxy_requests_total counter"));
    }
}
