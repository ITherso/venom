use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceTestSuite {
    pub id: String,
    pub name: String,
    pub tests: Vec<PerformanceTestCase>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceTestCase {
    pub id: String,
    pub name: String,
    pub test_type: PerformanceMetric,
    pub target_threshold: f64,
    pub actual_value: Option<f64>,
    pub unit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PerformanceMetric {
    ProxyLatency,
    ConcurrentConnections,
    ScannerThroughput,
    MemoryUsage,
    CSSRendering,
    APIResponseTime,
    DatabaseQueryTime,
    NetworkBandwidth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceResult {
    pub test_id: String,
    pub test_name: String,
    pub metric_type: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub measurements: Vec<f64>,
    pub threshold: f64,
    pub actual_avg: f64,
    pub actual_p95: f64,
    pub actual_p99: f64,
    pub actual_max: f64,
    pub passed: bool,
    pub regression_detected: bool,
}

impl PerformanceTestSuite {
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            tests: Vec::new(),
            created_at: Utc::now(),
        }
    }

    pub fn add_test(&mut self, test: PerformanceTestCase) {
        self.tests.push(test);
    }

    pub fn proxy_latency_test(target_ms: f64) -> PerformanceTestCase {
        Self::create_test("Proxy Latency", PerformanceMetric::ProxyLatency, target_ms, "ms")
    }

    pub fn concurrent_connections_test(target_count: f64) -> PerformanceTestCase {
        Self::create_test("Concurrent Connections", PerformanceMetric::ConcurrentConnections, target_count, "connections")
    }

    pub fn scanner_throughput_test(target_rps: f64) -> PerformanceTestCase {
        Self::create_test("Scanner Throughput", PerformanceMetric::ScannerThroughput, target_rps, "req/sec")
    }

    pub fn memory_usage_test(target_mb: f64) -> PerformanceTestCase {
        Self::create_test("Memory Usage", PerformanceMetric::MemoryUsage, target_mb, "MB")
    }

    pub fn css_rendering_test(target_ms: f64) -> PerformanceTestCase {
        Self::create_test("CSS Rendering", PerformanceMetric::CSSRendering, target_ms, "ms")
    }

    fn create_test(
        name: &str,
        metric: PerformanceMetric,
        threshold: f64,
        unit: &str,
    ) -> PerformanceTestCase {
        PerformanceTestCase {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            test_type: metric,
            target_threshold: threshold,
            actual_value: None,
            unit: unit.to_string(),
        }
    }
}

impl PerformanceResult {
    pub fn new(test_id: String, test_name: String, metric_type: String, threshold: f64) -> Self {
        Self {
            test_id,
            test_name,
            metric_type,
            start_time: Utc::now(),
            end_time: Utc::now(),
            measurements: Vec::new(),
            threshold,
            actual_avg: 0.0,
            actual_p95: 0.0,
            actual_p99: 0.0,
            actual_max: 0.0,
            passed: false,
            regression_detected: false,
        }
    }

    pub fn add_measurement(&mut self, value: f64) {
        self.measurements.push(value);
    }

    pub fn calculate_statistics(&mut self) {
        if self.measurements.is_empty() {
            return;
        }

        self.measurements.sort_by(|a, b| a.partial_cmp(b).unwrap());

        self.actual_avg = self.measurements.iter().sum::<f64>() / self.measurements.len() as f64;
        self.actual_max = self.measurements[self.measurements.len() - 1];

        let p95_index = (self.measurements.len() as f64 * 0.95) as usize;
        let p99_index = (self.measurements.len() as f64 * 0.99) as usize;

        self.actual_p95 = self.measurements.get(p95_index).copied().unwrap_or(self.actual_max);
        self.actual_p99 = self.measurements.get(p99_index).copied().unwrap_or(self.actual_max);

        self.passed = self.actual_avg <= self.threshold;
    }

    pub fn duration_seconds(&self) -> u64 {
        (self.end_time - self.start_time).num_seconds() as u64
    }

    pub fn variance(&self) -> f64 {
        if self.measurements.len() < 2 {
            return 0.0;
        }
        let mean = self.actual_avg;
        let variance: f64 = self.measurements
            .iter()
            .map(|m| (m - mean).powi(2))
            .sum::<f64>()
            / self.measurements.len() as f64;
        variance.sqrt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_suite_creation() {
        let mut suite = PerformanceTestSuite::new("API Performance".to_string());
        let test = PerformanceTestSuite::proxy_latency_test(50.0);
        suite.add_test(test);
        assert_eq!(suite.tests.len(), 1);
    }

    #[test]
    fn test_performance_test_creation() {
        let test = PerformanceTestSuite::concurrent_connections_test(1000.0);
        assert_eq!(test.test_type, PerformanceMetric::ConcurrentConnections);
        assert_eq!(test.target_threshold, 1000.0);
    }

    #[test]
    fn test_performance_result_statistics() {
        let mut result = PerformanceResult::new(
            "test_1".to_string(),
            "Latency".to_string(),
            "Proxy".to_string(),
            50.0,
        );
        result.add_measurement(30.0);
        result.add_measurement(45.0);
        result.add_measurement(50.0);
        result.add_measurement(55.0);
        result.calculate_statistics();

        assert!(result.actual_avg <= 50.0);
        assert!(result.passed);
    }
}
