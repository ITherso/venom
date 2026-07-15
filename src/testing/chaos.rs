use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosTest {
    pub id: String,
    pub name: String,
    pub description: String,
    pub scenario: ChaosScenario,
    pub target_service: String,
    pub duration_seconds: u32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChaosScenario {
    NetworkLatency { add_ms: u32 },
    NetworkPacketLoss { percentage: u32 },
    ServiceDowntime { duration_seconds: u32 },
    CPUSpike { duration_seconds: u32, usage_percent: u32 },
    MemoryExhaustion { target_mb: u32 },
    DatabaseFailure { recovery_delay_seconds: u32 },
    CascadingFailure { affected_services: Vec<String> },
    PartialResponseFailure { failure_rate: u32 },
    RequestTimeout { timeout_ms: u32 },
}

impl ChaosScenario {
    pub fn description(&self) -> &str {
        match self {
            Self::NetworkLatency { .. } => "Inject network latency",
            Self::NetworkPacketLoss { .. } => "Simulate packet loss",
            Self::ServiceDowntime { .. } => "Simulate service downtime",
            Self::CPUSpike { .. } => "Trigger CPU spike",
            Self::MemoryExhaustion { .. } => "Exhaust memory",
            Self::DatabaseFailure { .. } => "Simulate database failure",
            Self::CascadingFailure { .. } => "Trigger cascading failure",
            Self::PartialResponseFailure { .. } => "Fail percentage of requests",
            Self::RequestTimeout { .. } => "Timeout requests",
        }
    }
}

impl ChaosTest {
    pub fn new(name: String, scenario: ChaosScenario, target_service: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            description: scenario.description().to_string(),
            scenario,
            target_service,
            duration_seconds: 60,
            created_at: Utc::now(),
        }
    }

    pub fn with_duration(mut self, seconds: u32) -> Self {
        self.duration_seconds = seconds;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosResult {
    pub test_id: String,
    pub test_name: String,
    pub scenario: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_seconds: u32,
    pub status: ChaosStatus,
    pub metrics: ChaosMetrics,
    pub findings: Vec<ChaosDiscovery>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChaosStatus {
    Passed,
    Failed,
    Degraded,
    Catastrophic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosMetrics {
    pub requests_sent: u64,
    pub requests_failed: u64,
    pub requests_succeeded: u64,
    pub requests_timeout: u64,
    pub average_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub error_rate_percent: f32,
    pub service_recovery_time_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosDiscovery {
    pub finding_id: String,
    pub severity: DiscoverySeverity,
    pub title: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiscoverySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct ChaosTestRunner {
    pub tests: HashMap<String, ChaosTest>,
    pub results: Vec<ChaosResult>,
}

impl ChaosTestRunner {
    pub fn new() -> Self {
        Self {
            tests: HashMap::new(),
            results: Vec::new(),
        }
    }

    pub fn add_test(&mut self, test: ChaosTest) -> String {
        let test_id = test.id.clone();
        self.tests.insert(test_id.clone(), test);
        test_id
    }

    pub fn record_result(&mut self, result: ChaosResult) {
        self.results.push(result);
    }

    pub fn get_test(&self, test_id: &str) -> Option<&ChaosTest> {
        self.tests.get(test_id)
    }

    pub fn get_results_for_test(&self, test_id: &str) -> Vec<&ChaosResult> {
        self.results
            .iter()
            .filter(|r| r.test_id == test_id)
            .collect()
    }

    pub fn get_failed_results(&self) -> Vec<&ChaosResult> {
        self.results
            .iter()
            .filter(|r| r.status != ChaosStatus::Passed)
            .collect()
    }

    pub fn get_statistics(&self) -> ChaosStatistics {
        let total_tests = self.results.len();
        let passed = self.results.iter().filter(|r| r.status == ChaosStatus::Passed).count();
        let failed = self.results.iter().filter(|r| r.status == ChaosStatus::Failed).count();
        let degraded = self.results.iter().filter(|r| r.status == ChaosStatus::Degraded).count();
        let critical = self.results.iter().filter(|r| r.status == ChaosStatus::Catastrophic).count();

        let avg_error_rate = if total_tests > 0 {
            self.results.iter().map(|r| r.metrics.error_rate_percent).sum::<f32>() / total_tests as f32
        } else {
            0.0
        };

        let total_findings: usize = self.results.iter().map(|r| r.findings.len()).sum();

        ChaosStatistics {
            total_tests,
            passed,
            failed,
            degraded,
            critical,
            average_error_rate: avg_error_rate,
            total_findings,
        }
    }
}

impl Default for ChaosTestRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosStatistics {
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub degraded: usize,
    pub critical: usize,
    pub average_error_rate: f32,
    pub total_findings: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chaos_test_creation() {
        let test = ChaosTest::new(
            "Network Latency Test".to_string(),
            ChaosScenario::NetworkLatency { add_ms: 500 },
            "api-service".to_string(),
        );
        assert_eq!(test.name, "Network Latency Test");
    }

    #[test]
    fn test_chaos_runner() {
        let mut runner = ChaosTestRunner::new();
        let test = ChaosTest::new(
            "Test 1".to_string(),
            ChaosScenario::CPUSpike { duration_seconds: 30, usage_percent: 90 },
            "web-service".to_string(),
        );
        let test_id = test.id.clone();
        runner.add_test(test);

        assert!(runner.get_test(&test_id).is_some());
    }

    #[test]
    fn test_chaos_result_status() {
        let result = ChaosResult {
            test_id: "test_123".to_string(),
            test_name: "Test".to_string(),
            scenario: "Latency".to_string(),
            start_time: Utc::now(),
            end_time: Utc::now(),
            duration_seconds: 60,
            status: ChaosStatus::Passed,
            metrics: ChaosMetrics {
                requests_sent: 1000,
                requests_failed: 0,
                requests_succeeded: 1000,
                requests_timeout: 0,
                average_latency_ms: 50.0,
                p99_latency_ms: 150.0,
                error_rate_percent: 0.0,
                service_recovery_time_seconds: 0,
            },
            findings: Vec::new(),
        };

        assert_eq!(result.status, ChaosStatus::Passed);
        assert_eq!(result.metrics.error_rate_percent, 0.0);
    }
}
