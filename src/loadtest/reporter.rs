use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestReport {
    pub test_name: String,
    pub target_url: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,

    // Request metrics
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub bytes_transferred: u64,

    // Latency metrics (in milliseconds)
    pub latency_min: f64,
    pub latency_max: f64,
    pub latency_mean: f64,
    pub latency_p50: f64,
    pub latency_p95: f64,
    pub latency_p99: f64,

    // Throughput
    pub requests_per_second: f64,
    pub bytes_per_second: f64,

    // Connection metrics
    pub concurrent_users: u32,
    pub duration_seconds: u32,
    pub errors_connect: u32,
    pub errors_timeout: u32,
    pub errors_other: u32,
}

impl LoadTestReport {
    pub fn new(test_name: &str, target_url: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            target_url: target_url.to_string(),
            timestamp: chrono::Utc::now(),
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            bytes_transferred: 0,
            latency_min: 0.0,
            latency_max: 0.0,
            latency_mean: 0.0,
            latency_p50: 0.0,
            latency_p95: 0.0,
            latency_p99: 0.0,
            requests_per_second: 0.0,
            bytes_per_second: 0.0,
            concurrent_users: 0,
            duration_seconds: 0,
            errors_connect: 0,
            errors_timeout: 0,
            errors_other: 0,
        }
    }

    /// Calculate success rate percentage
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            (self.successful_requests as f64 / self.total_requests as f64) * 100.0
        }
    }

    /// Calculate error rate percentage
    pub fn error_rate(&self) -> f64 {
        100.0 - self.success_rate()
    }

    /// Calculate total errors
    pub fn total_errors(&self) -> u32 {
        self.errors_connect + self.errors_timeout + self.errors_other
    }

    /// Format report as human-readable string
    pub fn format_summary(&self) -> String {
        format!(
            r#"
╔════════════════════════════════════════════════════════════════╗
║            VENOM Load Test Report - {}                        ║
╚════════════════════════════════════════════════════════════════╝

📊 TEST OVERVIEW
├─ Test Name: {}
├─ Target URL: {}
├─ Timestamp: {}
└─ Duration: {}s

📈 REQUEST METRICS
├─ Total Requests: {}
├─ Successful: {} ({:.2}%)
├─ Failed: {} ({:.2}%)
├─ Bytes Transferred: {} bytes
└─ Throughput: {:.2} req/s

⏱️  LATENCY METRICS (milliseconds)
├─ Min: {:.2}ms
├─ Max: {:.2}ms
├─ Mean: {:.2}ms
├─ P50: {:.2}ms
├─ P95: {:.2}ms
└─ P99: {:.2}ms

🔗 CONNECTION METRICS
├─ Concurrent Users: {}
├─ Bytes/sec: {:.2}
└─ Total Errors: {}
   ├─ Connection Errors: {}
   ├─ Timeout Errors: {}
   └─ Other Errors: {}

═══════════════════════════════════════════════════════════════════
"#,
            self.test_name,
            self.test_name,
            self.target_url,
            self.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            self.duration_seconds,
            self.total_requests,
            self.successful_requests,
            self.success_rate(),
            self.failed_requests,
            self.error_rate(),
            self.bytes_transferred,
            self.requests_per_second,
            self.latency_min,
            self.latency_max,
            self.latency_mean,
            self.latency_p50,
            self.latency_p95,
            self.latency_p99,
            self.concurrent_users,
            self.bytes_per_second,
            self.total_errors(),
            self.errors_connect,
            self.errors_timeout,
            self.errors_other,
        )
    }

    /// Format report as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Generate HTML report
    pub fn to_html(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Load Test Report - {}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        h1 {{ color: #d32f2f; border-bottom: 3px solid #d32f2f; padding-bottom: 10px; }}
        h2 {{ color: #333; margin-top: 30px; }}
        .metric-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }}
        .metric-card {{ background: #f9f9f9; border-left: 4px solid #d32f2f; padding: 15px; border-radius: 4px; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #d32f2f; }}
        .metric-label {{ font-size: 12px; color: #666; margin-top: 5px; }}
        .chart {{ margin: 30px 0; padding: 20px; background: #fafafa; border-radius: 4px; }}
        .success {{ color: #4caf50; }}
        .error {{ color: #f44336; }}
        .warning {{ color: #ff9800; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #d32f2f; color: white; padding: 10px; text-align: left; }}
        td {{ border-bottom: 1px solid #ddd; padding: 10px; }}
        tr:hover {{ background: #f5f5f5; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔥 VENOM Load Test Report</h1>

        <h2>Overview</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">{}</div>
                <div class="metric-label">Total Requests</div>
            </div>
            <div class="metric-card">
                <div class="metric-value success">{:.1}%</div>
                <div class="metric-label">Success Rate</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{:.2} req/s</div>
                <div class="metric-label">Throughput</div>
            </div>
        </div>

        <h2>Latency Metrics (ms)</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value (ms)</th>
            </tr>
            <tr>
                <td>Minimum</td>
                <td>{:.2}</td>
            </tr>
            <tr>
                <td>Maximum</td>
                <td>{:.2}</td>
            </tr>
            <tr>
                <td>Mean</td>
                <td>{:.2}</td>
            </tr>
            <tr>
                <td>P50 (Median)</td>
                <td>{:.2}</td>
            </tr>
            <tr>
                <td>P95</td>
                <td>{:.2}</td>
            </tr>
            <tr>
                <td>P99</td>
                <td>{:.2}</td>
            </tr>
        </table>

        <h2>Error Analysis</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value error">{}</div>
                <div class="metric-label">Total Errors</div>
            </div>
            <div class="metric-card">
                <div class="metric-value warning">{}</div>
                <div class="metric-label">Connection Errors</div>
            </div>
            <div class="metric-card">
                <div class="metric-value warning">{}</div>
                <div class="metric-label">Timeout Errors</div>
            </div>
        </div>

        <h2>Test Configuration</h2>
        <table>
            <tr>
                <th>Parameter</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Target URL</td>
                <td>{}</td>
            </tr>
            <tr>
                <td>Concurrent Users</td>
                <td>{}</td>
            </tr>
            <tr>
                <td>Duration</td>
                <td>{}s</td>
            </tr>
            <tr>
                <td>Bytes Transferred</td>
                <td>{} bytes</td>
            </tr>
            <tr>
                <td>Bytes/sec</td>
                <td>{:.2}</td>
            </tr>
            <tr>
                <td>Generated</td>
                <td>{}</td>
            </tr>
        </table>

        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px;">
            <p>Generated by VENOM v0.5.0 Load Testing Framework</p>
        </footer>
    </div>
</body>
</html>"#,
            self.test_name,
            self.total_requests,
            self.success_rate(),
            self.requests_per_second,
            self.latency_min,
            self.latency_max,
            self.latency_mean,
            self.latency_p50,
            self.latency_p95,
            self.latency_p99,
            self.total_errors(),
            self.errors_connect,
            self.errors_timeout,
            self.target_url,
            self.concurrent_users,
            self.duration_seconds,
            self.bytes_transferred,
            self.bytes_per_second,
            self.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_success_rate() {
        let mut report = LoadTestReport::new("test", "http://localhost");
        report.total_requests = 1000;
        report.successful_requests = 950;
        report.failed_requests = 50;

        assert_eq!(report.success_rate(), 95.0);
        assert_eq!(report.error_rate(), 5.0);
    }

    #[test]
    fn test_report_total_errors() {
        let mut report = LoadTestReport::new("test", "http://localhost");
        report.errors_connect = 10;
        report.errors_timeout = 5;
        report.errors_other = 3;

        assert_eq!(report.total_errors(), 18);
    }

    #[test]
    fn test_report_formatting() {
        let report = LoadTestReport::new("baseline", "http://target.com");
        let summary = report.format_summary();

        assert!(summary.contains("baseline"));
        assert!(summary.contains("http://target.com"));
        assert!(summary.contains("VENOM Load Test Report"));
    }
}
