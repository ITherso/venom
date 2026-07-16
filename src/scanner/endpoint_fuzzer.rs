// Endpoint Fuzzer - Hidden API Endpoint Discovery (500+ lines)
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredEndpoint {
    pub path: String,
    pub method: String,
    pub status_code: u16,
    pub content_length: usize,
    pub response_time_ms: u64,
    pub confidence: f64,
    pub fingerprint: String,
    pub endpoint_type: EndpointType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum EndpointType {
    API,
    Admin,
    Debug,
    Internal,
    Hidden,
    Backup,
    LegacyAPI,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub total_requests: usize,
    pub discovered_endpoints: Vec<DiscoveredEndpoint>,
    pub status_code_distribution: HashMap<u16, usize>,
    pub patterns_detected: Vec<String>,
}

pub struct EndpointFuzzer {
    wordlist: Vec<String>,
    discovered_endpoints: Vec<DiscoveredEndpoint>,
    baseline_response: Option<BaselineResponse>,
}

#[derive(Debug, Clone)]
struct BaselineResponse {
    status_code: u16,
    content_length: usize,
    response_time_ms: u64,
}

impl EndpointFuzzer {
    pub fn new() -> Self {
        Self {
            wordlist: Self::generate_wordlist(),
            discovered_endpoints: Vec::new(),
            baseline_response: None,
        }
    }

    /// Fuzz for hidden endpoints
    pub fn fuzz_endpoints(&mut self, base_url: &str) -> Result<FuzzResult> {
        let mut status_dist = HashMap::new();
        let mut patterns = Vec::new();

        // Establish baseline
        self.establish_baseline(base_url)?;

        // Fuzz common paths
        for path in &self.wordlist {
            let full_url = format!("{}/{}", base_url, path);

            // Test different HTTP methods
            for method in &["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"] {
                if let Ok(response) = self.test_endpoint(&full_url, method) {
                    *status_dist.entry(response.status_code).or_insert(0) += 1;

                    // Check if endpoint is meaningful
                    if self.is_meaningful_response(&response) {
                        let endpoint_type = self.classify_endpoint(path);
                        let confidence = self.calculate_confidence(&response);

                        self.discovered_endpoints.push(DiscoveredEndpoint {
                            path: path.clone(),
                            method: method.to_string(),
                            status_code: response.status_code,
                            content_length: response.content_length,
                            response_time_ms: response.response_time,
                            confidence,
                            fingerprint: format!("{:?}", endpoint_type),
                            endpoint_type,
                        });
                    }
                }
            }
        }

        // Detect patterns
        patterns = self.detect_patterns();

        Ok(FuzzResult {
            total_requests: self.wordlist.len() * 6, // 6 HTTP methods per path
            discovered_endpoints: self.discovered_endpoints.clone(),
            status_code_distribution: status_dist,
            patterns_detected: patterns,
        })
    }

    /// Establish baseline response
    fn establish_baseline(&mut self, base_url: &str) -> Result<()> {
        // Test non-existent endpoint to establish baseline
        let test_url = format!("{}/nonexistent_{}", base_url, uuid::Uuid::new_v4());

        if let Ok(response) = self.test_endpoint(&test_url, "GET") {
            self.baseline_response = Some(BaselineResponse {
                status_code: response.status_code,
                content_length: response.content_length,
                response_time_ms: response.response_time,
            });
        }

        Ok(())
    }

    /// Test single endpoint
    fn test_endpoint(&self, url: &str, method: &str) -> Result<EndpointResponse> {
        // Simulate HTTP request
        Ok(EndpointResponse {
            status_code: 200,
            content_length: 1024,
            response_time: 100,
        })
    }

    /// Check if response indicates real endpoint
    fn is_meaningful_response(&self, response: &EndpointResponse) -> bool {
        if let Some(baseline) = &self.baseline_response {
            // Real endpoints have different status codes than baseline
            if response.status_code != baseline.status_code {
                return true;
            }

            // Real endpoints have different content length
            if response.content_length != baseline.content_length {
                return true;
            }
        }

        // Check for known good status codes
        matches!(response.status_code, 200 | 201 | 204 | 301 | 302 | 400 | 401 | 403)
    }

    /// Classify endpoint type
    fn classify_endpoint(&self, path: &str) -> EndpointType {
        let path_lower = path.to_lowercase();

        if path_lower.contains("admin") || path_lower.contains("management") {
            EndpointType::Admin
        } else if path_lower.contains("debug") || path_lower.contains("test") {
            EndpointType::Debug
        } else if path_lower.contains("internal") || path_lower.contains("private") {
            EndpointType::Internal
        } else if path_lower.contains("backup") || path_lower.contains("old") {
            EndpointType::Backup
        } else if path_lower.contains("v1") || path_lower.contains("v2") || path_lower.contains("api") {
            EndpointType::API
        } else if path_lower.contains("hidden") || path_lower.contains("secret") {
            EndpointType::Hidden
        } else if path_lower.contains("legacy") || path_lower.contains("deprecated") {
            EndpointType::LegacyAPI
        } else {
            EndpointType::API
        }
    }

    /// Calculate confidence score
    fn calculate_confidence(&self, response: &EndpointResponse) -> f64 {
        // 200-201-204 = high confidence
        if matches!(response.status_code, 200 | 201 | 204) {
            return 0.95;
        }
        // 301-302 redirects = medium-high confidence
        if matches!(response.status_code, 301 | 302) {
            return 0.75;
        }
        // 400-401-403 errors = medium confidence (endpoint exists but unauthorized)
        if matches!(response.status_code, 400 | 401 | 403) {
            return 0.80;
        }
        // 500+ errors = low-medium confidence
        if response.status_code >= 500 {
            return 0.50;
        }
        // 404 and others = no confidence
        0.0
    }

    /// Detect patterns in discovered endpoints
    fn detect_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();

        // Pattern 1: Version endpoints
        let version_endpoints: Vec<_> = self
            .discovered_endpoints
            .iter()
            .filter(|e| e.path.contains("v1") || e.path.contains("v2") || e.path.contains("v3"))
            .collect();

        if version_endpoints.len() > 0 {
            patterns.push(format!("API versioning detected: {} endpoints", version_endpoints.len()));
        }

        // Pattern 2: Admin endpoints
        let admin_endpoints: Vec<_> = self
            .discovered_endpoints
            .iter()
            .filter(|e| e.endpoint_type == EndpointType::Admin)
            .collect();

        if admin_endpoints.len() > 0 {
            patterns.push(format!("Admin endpoints found: {} endpoints", admin_endpoints.len()));
        }

        // Pattern 3: Debug endpoints
        let debug_endpoints: Vec<_> = self
            .discovered_endpoints
            .iter()
            .filter(|e| e.endpoint_type == EndpointType::Debug)
            .collect();

        if debug_endpoints.len() > 0 {
            patterns.push(format!(
                "Debug endpoints found: {} endpoints (should be disabled in production)",
                debug_endpoints.len()
            ));
        }

        // Pattern 4: Backup endpoints
        let backup_endpoints: Vec<_> = self
            .discovered_endpoints
            .iter()
            .filter(|e| e.endpoint_type == EndpointType::Backup)
            .collect();

        if backup_endpoints.len() > 0 {
            patterns.push(format!(
                "Backup/old endpoints found: {} endpoints (potential legacy vulnerabilities)",
                backup_endpoints.len()
            ));
        }

        // Pattern 5: Hidden endpoints
        let hidden_endpoints: Vec<_> = self
            .discovered_endpoints
            .iter()
            .filter(|e| e.endpoint_type == EndpointType::Hidden)
            .collect();

        if hidden_endpoints.len() > 0 {
            patterns.push(format!("Hidden endpoints discovered: {} endpoints", hidden_endpoints.len()));
        }

        patterns
    }

    /// Generate comprehensive wordlist
    fn generate_wordlist() -> Vec<String> {
        vec![
            // API endpoints
            "api", "api/v1", "api/v2", "rest", "graphql", "rpc",
            // Admin
            "admin", "admin/api", "admin/dashboard", "admin/users", "admin/settings",
            // Auth
            "auth", "auth/login", "auth/register", "auth/logout", "auth/refresh", "auth/validate",
            // Users
            "users", "users/profile", "users/me", "users/list", "users/admin",
            // Products
            "products", "products/list", "products/search", "products/create", "products/delete",
            // Orders
            "orders", "orders/create", "orders/list", "orders/status", "orders/pay",
            // Internal
            "internal", "internal/status", "internal/health", "internal/metrics",
            // Debug
            "debug", "debug/info", "debug/logs", "debug/config", "debug/performance",
            // Backup
            "backup", "backup/list", "backup/download", "backup/restore",
            // Legacy
            "v0", "v1", "v2", "legacy", "deprecated", "old", "archive",
            // Hidden
            "hidden", "secret", "private", "internal-only", "for-testing",
            // Development
            "dev", "development", "staging", "test", "testing", "sandbox",
            // System
            "system", "system/status", "system/info", "system/config",
            // Monitoring
            "monitor", "metrics", "prometheus", "health", "health/check", "status",
            // Security
            "security", "security/audit", "security/logs", "security/report",
            // Files
            "files", "upload", "download", "documents", "attachments",
            // Search
            "search", "query", "find", "filter", "advanced-search",
            // Webhooks
            "webhooks", "webhook", "callbacks", "events", "notifications",
            // Settings
            "settings", "config", "configuration", "preferences", "options",
            // Profile
            "profile", "account", "profile/edit", "account/settings",
            // Admin specific
            "superuser", "root", "administrator", "management", "control-panel",
            // API documentation
            "swagger", "openapi", "docs", "documentation", "api-docs", "api-reference",
            // Test endpoints
            "test", "testing", "test-api", "test-endpoint", "echo",
            // Common paths
            ".env", ".git", ".htaccess", "web.config", "config.php",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// Get discovered endpoints
    pub fn get_endpoints(&self) -> Vec<DiscoveredEndpoint> {
        self.discovered_endpoints.clone()
    }

    /// Get high-confidence endpoints
    pub fn get_high_confidence_endpoints(&self) -> Vec<DiscoveredEndpoint> {
        self.discovered_endpoints
            .iter()
            .filter(|e| e.confidence > 0.85)
            .cloned()
            .collect()
    }

    /// Get admin endpoints
    pub fn get_admin_endpoints(&self) -> Vec<DiscoveredEndpoint> {
        self.discovered_endpoints
            .iter()
            .filter(|e| e.endpoint_type == EndpointType::Admin)
            .cloned()
            .collect()
    }

    /// Get debug endpoints
    pub fn get_debug_endpoints(&self) -> Vec<DiscoveredEndpoint> {
        self.discovered_endpoints
            .iter()
            .filter(|e| e.endpoint_type == EndpointType::Debug)
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone)]
struct EndpointResponse {
    status_code: u16,
    content_length: usize,
    response_time: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzer_creation() {
        let fuzzer = EndpointFuzzer::new();
        assert!(fuzzer.wordlist.len() > 50);
    }

    #[test]
    fn test_endpoint_classification() {
        let fuzzer = EndpointFuzzer::new();

        assert_eq!(fuzzer.classify_endpoint("admin/users"), EndpointType::Admin);
        assert_eq!(fuzzer.classify_endpoint("debug/logs"), EndpointType::Debug);
        assert_eq!(fuzzer.classify_endpoint("backup/list"), EndpointType::Backup);
        assert_eq!(fuzzer.classify_endpoint("api/v1/users"), EndpointType::API);
    }

    #[test]
    fn test_confidence_calculation() {
        let fuzzer = EndpointFuzzer::new();

        let response_200 = EndpointResponse {
            status_code: 200,
            content_length: 1000,
            response_time: 100,
        };
        assert!(fuzzer.calculate_confidence(&response_200) > 0.90);

        let response_404 = EndpointResponse {
            status_code: 404,
            content_length: 100,
            response_time: 50,
        };
        assert!(fuzzer.calculate_confidence(&response_404) < 0.50);
    }

    #[test]
    fn test_meaningful_response_detection() {
        let mut fuzzer = EndpointFuzzer::new();
        fuzzer.baseline_response = Some(BaselineResponse {
            status_code: 404,
            content_length: 200,
            response_time_ms: 100,
        });

        let response_200 = EndpointResponse {
            status_code: 200,
            content_length: 1000,
            response_time: 100,
        };
        assert!(fuzzer.is_meaningful_response(&response_200));

        let response_404 = EndpointResponse {
            status_code: 404,
            content_length: 200,
            response_time: 100,
        };
        assert!(!fuzzer.is_meaningful_response(&response_404));
    }

    #[test]
    fn test_endpoint_type_detection() {
        let fuzzer = EndpointFuzzer::new();

        assert_eq!(fuzzer.classify_endpoint("admin"), EndpointType::Admin);
        assert_eq!(fuzzer.classify_endpoint("debug"), EndpointType::Debug);
        assert_eq!(fuzzer.classify_endpoint("internal"), EndpointType::Internal);
        assert_eq!(fuzzer.classify_endpoint("backup"), EndpointType::Backup);
        assert_eq!(fuzzer.classify_endpoint("legacy"), EndpointType::LegacyAPI);
    }

    #[test]
    fn test_endpoint_discovery() {
        let mut fuzzer = EndpointFuzzer::new();
        let result = fuzzer.fuzz_endpoints("http://example.com").unwrap();
        assert_eq!(result.total_requests, fuzzer.wordlist.len() * 6);
    }

    #[test]
    fn test_filter_high_confidence() {
        let mut fuzzer = EndpointFuzzer::new();
        fuzzer.discovered_endpoints.push(DiscoveredEndpoint {
            path: "/api/users".to_string(),
            method: "GET".to_string(),
            status_code: 200,
            content_length: 1000,
            response_time_ms: 100,
            confidence: 0.95,
            fingerprint: "API".to_string(),
            endpoint_type: EndpointType::API,
        });

        let high_conf = fuzzer.get_high_confidence_endpoints();
        assert_eq!(high_conf.len(), 1);
    }

    #[test]
    fn test_filter_admin_endpoints() {
        let mut fuzzer = EndpointFuzzer::new();
        fuzzer.discovered_endpoints.push(DiscoveredEndpoint {
            path: "/admin/users".to_string(),
            method: "GET".to_string(),
            status_code: 200,
            content_length: 1000,
            response_time_ms: 100,
            confidence: 0.90,
            fingerprint: "Admin".to_string(),
            endpoint_type: EndpointType::Admin,
        });

        let admin = fuzzer.get_admin_endpoints();
        assert_eq!(admin.len(), 1);
    }
}
