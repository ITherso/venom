pub mod chaos;
pub mod security_labs;
pub mod integration;
pub mod stress_testing;
pub mod integration_tests;
pub mod e2e_tests;
pub mod performance_tests;
pub mod security_tests;
pub mod compatibility_tests;
pub mod ci_cd_tests;

pub use chaos::{ChaosTest, ChaosScenario, ChaosResult};
pub use security_labs::{SecurityLab, LabScenario, LabAssessment};
pub use integration::{IntegrationTest, TestCase};
pub use stress_testing::{StressTest, StressProfile};
pub use integration_tests::{IntegrationTestSuite, IntegrationTestCase, IntegrationCategory};
pub use e2e_tests::{E2ETestSuite, E2ETestCase, E2EWorkflow, BrowserType};
pub use performance_tests::{PerformanceTestSuite, PerformanceMetric};
pub use security_tests::{SecurityTestSuite, SecurityTestCase, SecurityTestType};
pub use compatibility_tests::{CompatibilityTestSuite, CompatibilityType, CompatibilityMatrix};
pub use ci_cd_tests::{CICDPipeline, WorkflowJob, PipelineExecution};

#[derive(Debug, Clone)]
pub struct TestingConfig {
    pub chaos_testing_enabled: bool,
    pub security_labs_enabled: bool,
    pub integration_tests_enabled: bool,
    pub stress_testing_enabled: bool,
    pub e2e_testing_enabled: bool,
    pub performance_testing_enabled: bool,
    pub security_testing_enabled: bool,
    pub compatibility_testing_enabled: bool,
    pub ci_cd_enabled: bool,
    pub test_timeout_seconds: u32,
    pub max_concurrent_tests: usize,
    pub min_code_coverage_percent: f32,
}

impl Default for TestingConfig {
    fn default() -> Self {
        Self {
            chaos_testing_enabled: true,
            security_labs_enabled: true,
            integration_tests_enabled: true,
            stress_testing_enabled: true,
            e2e_testing_enabled: true,
            performance_testing_enabled: true,
            security_testing_enabled: true,
            compatibility_testing_enabled: true,
            ci_cd_enabled: true,
            test_timeout_seconds: 300,
            max_concurrent_tests: 10,
            min_code_coverage_percent: 80.0,
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
