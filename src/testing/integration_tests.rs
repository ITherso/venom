use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationTestSuite {
    pub id: String,
    pub name: String,
    pub tests: Vec<IntegrationTestCase>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationTestCase {
    pub id: String,
    pub name: String,
    pub category: IntegrationCategory,
    pub setup: TestSetup,
    pub actions: Vec<TestAction>,
    pub assertions: Vec<TestAssertion>,
    pub expected_result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntegrationCategory {
    ProxyScanner,
    ScannerExploiter,
    APIDatabase,
    C2Agent,
    EndToEnd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSetup {
    pub initialize_proxy: bool,
    pub initialize_scanner: bool,
    pub initialize_database: bool,
    pub initialize_api: bool,
    pub setup_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestAction {
    pub sequence: u32,
    pub action_type: String,
    pub parameters: String,
    pub timeout_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestAssertion {
    pub assertion_id: String,
    pub condition: String,
    pub expected_value: String,
    pub actual_value: Option<String>,
    pub passed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationTestResult {
    pub test_id: String,
    pub test_name: String,
    pub category: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub status: TestStatus,
    pub assertions_passed: usize,
    pub assertions_failed: usize,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TestStatus {
    Passed,
    Failed,
    Skipped,
    Timeout,
}

impl IntegrationTestSuite {
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            tests: Vec::new(),
            created_at: Utc::now(),
        }
    }

    pub fn add_test(&mut self, test: IntegrationTestCase) {
        self.tests.push(test);
    }
}

impl IntegrationTestCase {
    pub fn new(name: String, category: IntegrationCategory) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            category,
            setup: TestSetup {
                initialize_proxy: false,
                initialize_scanner: false,
                initialize_database: false,
                initialize_api: false,
                setup_data: None,
            },
            actions: Vec::new(),
            assertions: Vec::new(),
            expected_result: String::new(),
        }
    }

    pub fn with_setup(mut self, setup: TestSetup) -> Self {
        self.setup = setup;
        self
    }

    pub fn add_action(&mut self, action: TestAction) {
        self.actions.push(action);
    }

    pub fn add_assertion(&mut self, assertion: TestAssertion) {
        self.assertions.push(assertion);
    }
}

impl IntegrationTestResult {
    pub fn new(test_id: String, test_name: String, category: String) -> Self {
        Self {
            test_id,
            test_name,
            category,
            start_time: Utc::now(),
            end_time: Utc::now(),
            status: TestStatus::Passed,
            assertions_passed: 0,
            assertions_failed: 0,
            error_message: None,
        }
    }

    pub fn success_rate(&self) -> f32 {
        let total = self.assertions_passed + self.assertions_failed;
        if total == 0 {
            return 0.0;
        }
        (self.assertions_passed as f32 / total as f32) * 100.0
    }

    pub fn duration_seconds(&self) -> u64 {
        (self.end_time - self.start_time).num_seconds() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration_suite_creation() {
        let suite = IntegrationTestSuite::new("Proxy-Scanner Integration".to_string());
        assert_eq!(suite.tests.len(), 0);
    }

    #[test]
    fn test_integration_test_case() {
        let case = IntegrationTestCase::new(
            "Proxy to Scanner".to_string(),
            IntegrationCategory::ProxyScanner,
        );
        assert_eq!(case.category, IntegrationCategory::ProxyScanner);
    }

    #[test]
    fn test_integration_result_metrics() {
        let mut result = IntegrationTestResult::new(
            "test_1".to_string(),
            "Test".to_string(),
            "ProxyScanner".to_string(),
        );
        result.assertions_passed = 8;
        result.assertions_failed = 2;
        assert_eq!(result.success_rate(), 80.0);
    }
}
