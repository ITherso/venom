use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityTestSuite {
    pub id: String,
    pub name: String,
    pub tests: Vec<CompatibilityTestCase>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityTestCase {
    pub id: String,
    pub name: String,
    pub compatibility_type: CompatibilityType,
    pub target_version: String,
    pub test_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CompatibilityType {
    BrowserChrome,
    BrowserFirefox,
    BrowserSafari,
    BrowserEdge,
    OSWindows,
    OSMacOS,
    OSLinux,
    RustVersion,
    DatabasePostgreSQL,
    DatabaseMySQL,
    DependencyVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityResult {
    pub test_id: String,
    pub test_name: String,
    pub compatibility_type: String,
    pub target_version: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub status: CompatibilityStatus,
    pub features_tested: usize,
    pub features_passed: usize,
    pub features_failed: usize,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CompatibilityStatus {
    Compatible,
    Partial,
    Incompatible,
    Untested,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityMatrix {
    pub results: Vec<CompatibilityResult>,
}

impl CompatibilityTestSuite {
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            tests: Vec::new(),
            created_at: Utc::now(),
        }
    }

    pub fn add_test(&mut self, test: CompatibilityTestCase) {
        self.tests.push(test);
    }

    pub fn browser_chrome_test(version: String) -> CompatibilityTestCase {
        Self::create_test(
            "Chrome Browser",
            CompatibilityType::BrowserChrome,
            version,
        )
    }

    pub fn browser_firefox_test(version: String) -> CompatibilityTestCase {
        Self::create_test(
            "Firefox Browser",
            CompatibilityType::BrowserFirefox,
            version,
        )
    }

    pub fn os_windows_test(version: String) -> CompatibilityTestCase {
        Self::create_test(
            "Windows OS",
            CompatibilityType::OSWindows,
            version,
        )
    }

    pub fn os_macos_test(version: String) -> CompatibilityTestCase {
        Self::create_test(
            "macOS OS",
            CompatibilityType::OSMacOS,
            version,
        )
    }

    pub fn os_linux_test(version: String) -> CompatibilityTestCase {
        Self::create_test(
            "Linux OS",
            CompatibilityType::OSLinux,
            version,
        )
    }

    pub fn rust_version_test(version: String) -> CompatibilityTestCase {
        Self::create_test(
            "Rust Version",
            CompatibilityType::RustVersion,
            version,
        )
    }

    pub fn database_postgresql_test(version: String) -> CompatibilityTestCase {
        Self::create_test(
            "PostgreSQL Database",
            CompatibilityType::DatabasePostgreSQL,
            version,
        )
    }

    fn create_test(
        name: &str,
        comp_type: CompatibilityType,
        version: String,
    ) -> CompatibilityTestCase {
        CompatibilityTestCase {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            compatibility_type: comp_type,
            target_version: version,
            test_data: String::new(),
        }
    }
}

impl CompatibilityResult {
    pub fn new(test_id: String, test_name: String, comp_type: String, version: String) -> Self {
        Self {
            test_id,
            test_name,
            compatibility_type: comp_type,
            target_version: version,
            start_time: Utc::now(),
            end_time: Utc::now(),
            status: CompatibilityStatus::Untested,
            features_tested: 0,
            features_passed: 0,
            features_failed: 0,
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn pass_rate(&self) -> f32 {
        if self.features_tested == 0 {
            return 0.0;
        }
        (self.features_passed as f32 / self.features_tested as f32) * 100.0
    }

    pub fn duration_seconds(&self) -> u64 {
        (self.end_time - self.start_time).num_seconds() as u64
    }

    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    pub fn add_error(&mut self, error: String) {
        self.errors.push(error);
    }

    pub fn finalize(&mut self) {
        let pass_rate = self.pass_rate();
        self.status = if pass_rate == 100.0 {
            CompatibilityStatus::Compatible
        } else if pass_rate > 75.0 {
            CompatibilityStatus::Partial
        } else {
            CompatibilityStatus::Incompatible
        };
    }
}

impl CompatibilityMatrix {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    pub fn add_result(&mut self, result: CompatibilityResult) {
        self.results.push(result);
    }

    pub fn get_compatible_count(&self) -> usize {
        self.results.iter().filter(|r| r.status == CompatibilityStatus::Compatible).count()
    }

    pub fn get_partial_count(&self) -> usize {
        self.results.iter().filter(|r| r.status == CompatibilityStatus::Partial).count()
    }

    pub fn get_incompatible_count(&self) -> usize {
        self.results.iter().filter(|r| r.status == CompatibilityStatus::Incompatible).count()
    }

    pub fn overall_compatibility(&self) -> f32 {
        if self.results.is_empty() {
            return 0.0;
        }
        let compatible = self.get_compatible_count() as f32;
        (compatible / self.results.len() as f32) * 100.0
    }
}

impl Default for CompatibilityMatrix {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compatibility_suite_creation() {
        let mut suite = CompatibilityTestSuite::new("Browser Compatibility".to_string());
        let test = CompatibilityTestSuite::browser_chrome_test("120.0".to_string());
        suite.add_test(test);
        assert_eq!(suite.tests.len(), 1);
    }

    #[test]
    fn test_compatibility_test_creation() {
        let test = CompatibilityTestSuite::os_linux_test("5.10".to_string());
        assert_eq!(test.compatibility_type, CompatibilityType::OSLinux);
    }

    #[test]
    fn test_compatibility_matrix() {
        let mut matrix = CompatibilityMatrix::new();
        let mut result = CompatibilityResult::new(
            "test_1".to_string(),
            "Chrome Test".to_string(),
            "Chrome".to_string(),
            "120.0".to_string(),
        );
        result.features_tested = 10;
        result.features_passed = 10;
        result.finalize();

        assert_eq!(result.status, CompatibilityStatus::Compatible);
        matrix.add_result(result);
        assert_eq!(matrix.get_compatible_count(), 1);
    }
}
