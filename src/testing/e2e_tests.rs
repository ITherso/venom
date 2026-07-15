use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2ETestSuite {
    pub id: String,
    pub name: String,
    pub tests: Vec<E2ETestCase>,
    pub browser: BrowserType,
    pub base_url: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BrowserType {
    Chrome,
    Firefox,
    Safari,
    Edge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2ETestCase {
    pub id: String,
    pub name: String,
    pub workflow: E2EWorkflow,
    pub steps: Vec<E2EStep>,
    pub preconditions: Vec<String>,
    pub expected_outcomes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum E2EWorkflow {
    DashboardNavigation,
    TeamCollaboration,
    ReportGeneration,
    SettingsManagement,
    UserAuthentication,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2EStep {
    pub sequence: u32,
    pub action: UserAction,
    pub target_element: String,
    pub input_data: Option<String>,
    pub expected_state: String,
    pub wait_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserAction {
    Click,
    Type,
    Submit,
    Navigate,
    Wait,
    Screenshot,
    Hover,
    Scroll,
    Select,
    DoubleClick,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2ETestResult {
    pub test_id: String,
    pub test_name: String,
    pub workflow: String,
    pub browser: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub status: E2EStatus,
    pub steps_executed: usize,
    pub steps_passed: usize,
    pub steps_failed: usize,
    pub screenshots: Vec<String>,
    pub console_logs: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum E2EStatus {
    Passed,
    Failed,
    Skipped,
}

impl E2ETestSuite {
    pub fn new(name: String, browser: BrowserType, base_url: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            tests: Vec::new(),
            browser,
            base_url,
            created_at: Utc::now(),
        }
    }

    pub fn add_test(&mut self, test: E2ETestCase) {
        self.tests.push(test);
    }

    pub fn test_count_by_workflow(&self, workflow: E2EWorkflow) -> usize {
        self.tests.iter().filter(|t| t.workflow == workflow).count()
    }
}

impl E2ETestCase {
    pub fn new(name: String, workflow: E2EWorkflow) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            workflow,
            steps: Vec::new(),
            preconditions: Vec::new(),
            expected_outcomes: Vec::new(),
        }
    }

    pub fn add_step(&mut self, step: E2EStep) {
        self.steps.push(step);
    }

    pub fn add_precondition(&mut self, condition: String) {
        self.preconditions.push(condition);
    }

    pub fn add_expected_outcome(&mut self, outcome: String) {
        self.expected_outcomes.push(outcome);
    }
}

impl E2ETestResult {
    pub fn new(test_id: String, test_name: String, workflow: String, browser: String) -> Self {
        Self {
            test_id,
            test_name,
            workflow,
            browser,
            start_time: Utc::now(),
            end_time: Utc::now(),
            status: E2EStatus::Passed,
            steps_executed: 0,
            steps_passed: 0,
            steps_failed: 0,
            screenshots: Vec::new(),
            console_logs: Vec::new(),
        }
    }

    pub fn pass_rate(&self) -> f32 {
        if self.steps_executed == 0 {
            return 0.0;
        }
        (self.steps_passed as f32 / self.steps_executed as f32) * 100.0
    }

    pub fn duration_seconds(&self) -> u64 {
        (self.end_time - self.start_time).num_seconds() as u64
    }

    pub fn add_screenshot(&mut self, screenshot_path: String) {
        self.screenshots.push(screenshot_path);
    }

    pub fn add_console_log(&mut self, log: String) {
        self.console_logs.push(log);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e2e_suite_creation() {
        let suite = E2ETestSuite::new(
            "Dashboard E2E".to_string(),
            BrowserType::Chrome,
            "http://localhost:3000".to_string(),
        );
        assert_eq!(suite.browser, BrowserType::Chrome);
    }

    #[test]
    fn test_e2e_test_case() {
        let case = E2ETestCase::new(
            "User Login".to_string(),
            E2EWorkflow::UserAuthentication,
        );
        assert_eq!(case.workflow, E2EWorkflow::UserAuthentication);
    }

    #[test]
    fn test_e2e_result_metrics() {
        let mut result = E2ETestResult::new(
            "test_1".to_string(),
            "Login Test".to_string(),
            "Authentication".to_string(),
            "Chrome".to_string(),
        );
        result.steps_executed = 5;
        result.steps_passed = 5;
        result.steps_failed = 0;
        assert_eq!(result.pass_rate(), 100.0);
    }
}
