pub mod chaos;
pub mod security_labs;
pub mod integration;
pub mod stress_testing;

pub use chaos::{ChaosTest, ChaosScenario, ChaosResult};
pub use security_labs::{SecurityLab, LabScenario, LabAssessment};
pub use integration::{IntegrationTest, TestCase};
pub use stress_testing::{StressTest, StressProfile};

#[derive(Debug, Clone)]
pub struct TestingConfig {
    pub chaos_testing_enabled: bool,
    pub security_labs_enabled: bool,
    pub integration_tests_enabled: bool,
    pub stress_testing_enabled: bool,
    pub test_timeout_seconds: u32,
    pub max_concurrent_tests: usize,
}

impl Default for TestingConfig {
    fn default() -> Self {
        Self {
            chaos_testing_enabled: true,
            security_labs_enabled: true,
            integration_tests_enabled: true,
            stress_testing_enabled: true,
            test_timeout_seconds: 300,
            max_concurrent_tests: 10,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestStatus {
    Passed,
    Failed,
    Skipped,
    Timeout,
}

#[derive(Debug, Clone)]
pub struct TestReport {
    pub test_name: String,
    pub status: TestStatus,
    pub duration_ms: u64,
    pub assertions: u32,
    pub failures: Vec<String>,
}
