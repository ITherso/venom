use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTestSuite {
    pub id: String,
    pub name: String,
    pub tests: Vec<SecurityTestCase>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTestCase {
    pub id: String,
    pub name: String,
    pub test_type: SecurityTestType,
    pub payload: String,
    pub target_endpoint: String,
    pub expected_protection: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityTestType {
    SQLInjection,
    XSSPayload,
    CSRFToken,
    AuthenticationBypass,
    RBACPermission,
    SecretManagement,
    EncryptionValidation,
    InputValidation,
    OutputEncoding,
    HeaderInjection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTestResult {
    pub test_id: String,
    pub test_name: String,
    pub test_type: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub status: SecurityTestStatus,
    pub payload_blocked: bool,
    pub response_time_ms: u32,
    pub logs: Vec<String>,
    pub vulnerability_found: Option<VulnerabilityDetail>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityTestStatus {
    Passed,
    Failed,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityDetail {
    pub vulnerability_type: String,
    pub severity: String,
    pub cve: Option<String>,
    pub remediation: String,
}

impl SecurityTestSuite {
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            tests: Vec::new(),
            created_at: Utc::now(),
        }
    }

    pub fn add_test(&mut self, test: SecurityTestCase) {
        self.tests.push(test);
    }

    pub fn sqli_test(payload: String, endpoint: String) -> SecurityTestCase {
        Self::create_test(
            "SQL Injection Test",
            SecurityTestType::SQLInjection,
            payload,
            endpoint,
            "Input sanitization and parameterized queries".to_string(),
        )
    }

    pub fn xss_test(payload: String, endpoint: String) -> SecurityTestCase {
        Self::create_test(
            "XSS Payload Test",
            SecurityTestType::XSSPayload,
            payload,
            endpoint,
            "Output encoding and Content Security Policy".to_string(),
        )
    }

    pub fn csrf_test(endpoint: String) -> SecurityTestCase {
        Self::create_test(
            "CSRF Token Validation",
            SecurityTestType::CSRFToken,
            "test_csrf_payload".to_string(),
            endpoint,
            "CSRF token validation and SameSite cookies".to_string(),
        )
    }

    pub fn rbac_test(endpoint: String) -> SecurityTestCase {
        Self::create_test(
            "RBAC Permission Check",
            SecurityTestType::RBACPermission,
            "unauthorized_request".to_string(),
            endpoint,
            "Role-based access control enforcement".to_string(),
        )
    }

    fn create_test(
        name: &str,
        test_type: SecurityTestType,
        payload: String,
        endpoint: String,
        protection: String,
    ) -> SecurityTestCase {
        SecurityTestCase {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            test_type,
            payload,
            target_endpoint: endpoint,
            expected_protection: protection,
        }
    }
}

impl SecurityTestResult {
    pub fn new(test_id: String, test_name: String, test_type: String) -> Self {
        Self {
            test_id,
            test_name,
            test_type,
            start_time: Utc::now(),
            end_time: Utc::now(),
            status: SecurityTestStatus::Passed,
            payload_blocked: true,
            response_time_ms: 0,
            logs: Vec::new(),
            vulnerability_found: None,
        }
    }

    pub fn duration_seconds(&self) -> u64 {
        (self.end_time - self.start_time).num_seconds() as u64
    }

    pub fn add_log(&mut self, log: String) {
        self.logs.push(log);
    }

    pub fn set_vulnerability(&mut self, vuln: VulnerabilityDetail) {
        self.vulnerability_found = Some(vuln);
        self.status = SecurityTestStatus::Critical;
        self.payload_blocked = false;
    }

    pub fn is_secure(&self) -> bool {
        self.payload_blocked && self.status == SecurityTestStatus::Passed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_suite_creation() {
        let mut suite = SecurityTestSuite::new("OWASP Tests".to_string());
        let test = SecurityTestSuite::sqli_test(
            "' OR '1'='1".to_string(),
            "/api/users".to_string(),
        );
        suite.add_test(test);
        assert_eq!(suite.tests.len(), 1);
    }

    #[test]
    fn test_xss_test_creation() {
        let test = SecurityTestSuite::xss_test(
            "<script>alert('xss')</script>".to_string(),
            "/api/comment".to_string(),
        );
        assert_eq!(test.test_type, SecurityTestType::XSSPayload);
    }

    #[test]
    fn test_security_result_vulnerability() {
        let mut result = SecurityTestResult::new(
            "test_1".to_string(),
            "SQLi Test".to_string(),
            "SQLInjection".to_string(),
        );

        let vuln = VulnerabilityDetail {
            vulnerability_type: "SQL Injection".to_string(),
            severity: "Critical".to_string(),
            cve: Some("CVE-2024-1234".to_string()),
            remediation: "Use parameterized queries".to_string(),
        };

        result.set_vulnerability(vuln);
        assert!(!result.is_secure());
    }
}
