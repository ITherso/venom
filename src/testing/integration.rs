use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationTest {
    pub id: String,
    pub name: String,
    pub description: String,
    pub test_cases: Vec<TestCase>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub id: String,
    pub name: String,
    pub setup: String,
    pub steps: Vec<TestStep>,
    pub teardown: String,
    pub expected_outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestStep {
    pub number: u32,
    pub action: String,
    pub expected_result: String,
}

impl IntegrationTest {
    pub fn new(name: String, description: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            description,
            test_cases: Vec::new(),
            created_at: Utc::now(),
        }
    }

    pub fn add_test_case(&mut self, test_case: TestCase) {
        self.test_cases.push(test_case);
    }
}

impl TestCase {
    pub fn new(name: String, expected_outcome: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            setup: String::new(),
            steps: Vec::new(),
            teardown: String::new(),
            expected_outcome,
        }
    }

    pub fn with_setup(mut self, setup: String) -> Self {
        self.setup = setup;
        self
    }

    pub fn add_step(&mut self, step: TestStep) {
        self.steps.push(step);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration_test_creation() {
        let test = IntegrationTest::new(
            "API Integration Test".to_string(),
            "Test API endpoints".to_string(),
        );
        assert_eq!(test.test_cases.len(), 0);
    }

    #[test]
    fn test_case_creation() {
        let case = TestCase::new(
            "Login Test".to_string(),
            "User successfully logged in".to_string(),
        );
        assert_eq!(case.name, "Login Test");
    }
}
