// Test Fixtures - Mock Objects & Test Data (300+ lines)
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockHttpRequest {
    pub method: String,
    pub url: String,
    pub path: String,
    pub query_params: HashMap<String, String>,
    pub body: String,
    pub headers: HashMap<String, String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockHttpResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub response_time_ms: u64,
    pub content_type: String,
}

pub struct TestDataGenerator;

impl TestDataGenerator {
    /// Generate mock SQL injection request
    pub fn generate_sqli_request() -> MockHttpRequest {
        let mut params = HashMap::new();
        params.insert("id".to_string(), "1' OR '1'='1".to_string());
        params.insert("search".to_string(), "admin' --".to_string());

        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "Mozilla/5.0".to_string());
        headers.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());

        MockHttpRequest {
            method: "GET".to_string(),
            url: "http://example.com/search".to_string(),
            path: "/search".to_string(),
            query_params: params,
            body: String::new(),
            headers,
            timestamp: 1234567890,
        }
    }

    /// Generate mock XSS request
    pub fn generate_xss_request() -> MockHttpRequest {
        let mut params = HashMap::new();
        params.insert("name".to_string(), "<script>alert('xss')</script>".to_string());
        params.insert("search".to_string(), "'\"><img src=x onerror=alert(1)>".to_string());

        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "Mozilla/5.0".to_string());
        headers.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());

        MockHttpRequest {
            method: "POST".to_string(),
            url: "http://example.com/profile".to_string(),
            path: "/profile".to_string(),
            query_params: params,
            body: "<script>alert('xss')</script>".to_string(),
            headers,
            timestamp: 1234567891,
        }
    }

    /// Generate mock IDOR request
    pub fn generate_idor_request() -> MockHttpRequest {
        let mut params = HashMap::new();
        params.insert("user_id".to_string(), "123".to_string());

        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "Mozilla/5.0".to_string());
        headers.insert("Cookie".to_string(), "session=abc123".to_string());

        MockHttpRequest {
            method: "GET".to_string(),
            url: "http://example.com/user/profile".to_string(),
            path: "/user/profile".to_string(),
            query_params: params,
            body: String::new(),
            headers,
            timestamp: 1234567892,
        }
    }

    /// Generate mock SSRF request
    pub fn generate_ssrf_request() -> MockHttpRequest {
        let mut params = HashMap::new();
        params.insert("url".to_string(), "http://127.0.0.1/".to_string());

        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "Mozilla/5.0".to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        MockHttpRequest {
            method: "POST".to_string(),
            url: "http://example.com/fetch".to_string(),
            path: "/fetch".to_string(),
            query_params: params,
            body: "{\"url\": \"http://169.254.169.254/\"}".to_string(),
            headers,
            timestamp: 1234567893,
        }
    }

    /// Generate normal benign request
    pub fn generate_benign_request() -> MockHttpRequest {
        let mut params = HashMap::new();
        params.insert("page".to_string(), "1".to_string());
        params.insert("sort".to_string(), "date".to_string());

        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "Mozilla/5.0".to_string());
        headers.insert("Accept".to_string(), "text/html".to_string());

        MockHttpRequest {
            method: "GET".to_string(),
            url: "http://example.com/posts".to_string(),
            path: "/posts".to_string(),
            query_params: params,
            body: String::new(),
            headers,
            timestamp: 1234567894,
        }
    }

    /// Generate bulk requests for scanning simulation
    pub fn generate_scan_requests(count: usize) -> Vec<MockHttpRequest> {
        let paths = vec![
            "/admin",
            "/api",
            "/login",
            "/register",
            "/search",
            "/products",
            "/users",
            "/config",
        ];

        let mut requests = Vec::new();
        for i in 0..count {
            let path = paths[i % paths.len()];
            let mut params = HashMap::new();
            params.insert("id".to_string(), i.to_string());

            let mut headers = HashMap::new();
            headers.insert("User-Agent".to_string(), "Scanner/1.0".to_string());

            requests.push(MockHttpRequest {
                method: "GET".to_string(),
                url: format!("http://example.com{}", path),
                path: path.to_string(),
                query_params: params,
                body: String::new(),
                headers,
                timestamp: 1234567894 + i as u64,
            });
        }

        requests
    }

    /// Generate mock vulnerable response
    pub fn generate_vulnerable_response() -> MockHttpResponse {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "text/html".to_string());

        MockHttpResponse {
            status_code: 200,
            headers,
            body: "MySQL error in query: SELECT * FROM users WHERE id = 1 OR 1=1".to_string(),
            response_time_ms: 150,
            content_type: "text/html".to_string(),
        }
    }

    /// Generate mock safe response
    pub fn generate_safe_response() -> MockHttpResponse {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
        headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());

        MockHttpResponse {
            status_code: 200,
            headers,
            body: r#"{"status": "ok", "data": []}"#.to_string(),
            response_time_ms: 50,
            content_type: "application/json".to_string(),
        }
    }

    /// Generate time-based detection response
    pub fn generate_time_based_response() -> MockHttpResponse {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "text/html".to_string());

        MockHttpResponse {
            status_code: 200,
            headers,
            body: "<html><body>User found</body></html>".to_string(),
            response_time_ms: 5000, // 5 second delay
            content_type: "text/html".to_string(),
        }
    }

    /// Generate mock CVSS vector
    pub fn generate_cvss_vector() -> String {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()
    }

    /// Generate test vulnerability data
    pub fn generate_vulnerability_data() -> Vec<(&'static str, f64, &'static str)> {
        vec![
            ("SQLi", 9.8, "Critical"),
            ("XSS", 7.1, "High"),
            ("IDOR", 8.2, "High"),
            ("SSRF", 8.6, "High"),
            ("Path Traversal", 7.5, "High"),
            ("Authentication Bypass", 9.1, "Critical"),
            ("Command Injection", 9.8, "Critical"),
            ("File Inclusion", 7.4, "High"),
        ]
    }

    /// Generate test indicators for threat intel
    pub fn generate_threat_indicators() -> Vec<(&'static str, &'static str)> {
        vec![
            ("192.168.1.100", "Malicious IP"),
            ("malware.com", "C2 Domain"),
            ("exploit.sh", "Exploit Script"),
            ("backdoor.exe", "Malware Binary"),
            ("attacker@evil.com", "Threat Actor"),
        ]
    }

    /// Generate behavioral test data
    pub fn generate_behavior_patterns() -> Vec<(&'static str, &'static str)> {
        vec![
            ("scanner", "Automated scanning"),
            ("brute_force", "Brute force attempt"),
            ("data_exfil", "Data exfiltration"),
            ("privilege_escalation", "Priv esc attempt"),
            ("persistence", "Persistence mechanism"),
        ]
    }
}

pub struct MockHttpServer;

impl MockHttpServer {
    /// Simulate vulnerable endpoint
    pub fn vulnerable_endpoint(_request: &MockHttpRequest) -> MockHttpResponse {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "text/html".to_string());

        MockHttpResponse {
            status_code: 200,
            headers,
            body: "SELECT * FROM users WHERE id = ".to_string() + &_request.query_params.get("id").unwrap_or(&"1".to_string()),
            response_time_ms: 100,
            content_type: "text/html".to_string(),
        }
    }

    /// Simulate secure endpoint
    pub fn secure_endpoint(_request: &MockHttpRequest) -> MockHttpResponse {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("X-XSS-Protection".to_string(), "1; mode=block".to_string());
        headers.insert("Content-Security-Policy".to_string(), "default-src 'self'".to_string());

        MockHttpResponse {
            status_code: 200,
            headers,
            body: r#"{"user": "protected"}"#.to_string(),
            response_time_ms: 50,
            content_type: "application/json".to_string(),
        }
    }

    /// Simulate endpoint with auth check
    pub fn auth_protected_endpoint(request: &MockHttpRequest) -> MockHttpResponse {
        if request.headers.get("Authorization").is_some() {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());

            MockHttpResponse {
                status_code: 200,
                headers,
                body: r#"{"data": "sensitive"}"#.to_string(),
                response_time_ms: 75,
                content_type: "application/json".to_string(),
            }
        } else {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());

            MockHttpResponse {
                status_code: 401,
                headers,
                body: r#"{"error": "Unauthorized"}"#.to_string(),
                response_time_ms: 25,
                content_type: "application/json".to_string(),
            }
        }
    }

    /// Simulate rate-limited endpoint
    pub fn rate_limited_endpoint(request_count: usize) -> MockHttpResponse {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        if request_count > 100 {
            MockHttpResponse {
                status_code: 429,
                headers,
                body: r#"{"error": "Too many requests"}"#.to_string(),
                response_time_ms: 10,
                content_type: "application/json".to_string(),
            }
        } else {
            MockHttpResponse {
                status_code: 200,
                headers,
                body: r#"{"status": "ok"}"#.to_string(),
                response_time_ms: 50,
                content_type: "application/json".to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqli_request_generation() {
        let req = TestDataGenerator::generate_sqli_request();
        assert_eq!(req.method, "GET");
        assert!(req.url.contains("search"));
    }

    #[test]
    fn test_xss_request_generation() {
        let req = TestDataGenerator::generate_xss_request();
        assert_eq!(req.method, "POST");
        assert!(req.body.contains("script"));
    }

    #[test]
    fn test_idor_request_generation() {
        let req = TestDataGenerator::generate_idor_request();
        assert_eq!(req.path, "/user/profile");
        assert!(req.query_params.contains_key("user_id"));
    }

    #[test]
    fn test_ssrf_request_generation() {
        let req = TestDataGenerator::generate_ssrf_request();
        assert!(req.body.contains("169.254"));
    }

    #[test]
    fn test_benign_request_generation() {
        let req = TestDataGenerator::generate_benign_request();
        assert_eq!(req.method, "GET");
        assert!(!req.body.contains("script"));
    }

    #[test]
    fn test_bulk_request_generation() {
        let requests = TestDataGenerator::generate_scan_requests(10);
        assert_eq!(requests.len(), 10);
    }

    #[test]
    fn test_vulnerable_response() {
        let resp = TestDataGenerator::generate_vulnerable_response();
        assert_eq!(resp.status_code, 200);
        assert!(resp.body.contains("error"));
    }

    #[test]
    fn test_safe_response() {
        let resp = TestDataGenerator::generate_safe_response();
        assert_eq!(resp.status_code, 200);
        assert!(resp.headers.contains_key("X-Frame-Options"));
    }

    #[test]
    fn test_cvss_vector_generation() {
        let vector = TestDataGenerator::generate_cvss_vector();
        assert!(vector.starts_with("CVSS:3.1"));
    }

    #[test]
    fn test_vulnerability_data() {
        let vulns = TestDataGenerator::generate_vulnerability_data();
        assert!(vulns.len() > 0);
        assert_eq!(vulns[0].0, "SQLi");
    }

    #[test]
    fn test_threat_indicators() {
        let indicators = TestDataGenerator::generate_threat_indicators();
        assert!(indicators.len() > 0);
    }

    #[test]
    fn test_behavior_patterns() {
        let patterns = TestDataGenerator::generate_behavior_patterns();
        assert!(patterns.len() > 0);
    }

    #[test]
    fn test_vulnerable_endpoint() {
        let req = TestDataGenerator::generate_sqli_request();
        let resp = MockHttpServer::vulnerable_endpoint(&req);
        assert_eq!(resp.status_code, 200);
    }

    #[test]
    fn test_secure_endpoint() {
        let req = TestDataGenerator::generate_benign_request();
        let resp = MockHttpServer::secure_endpoint(&req);
        assert_eq!(resp.status_code, 200);
        assert!(resp.headers.contains_key("Content-Security-Policy"));
    }

    #[test]
    fn test_auth_protected_endpoint_unauthorized() {
        let req = TestDataGenerator::generate_benign_request();
        let resp = MockHttpServer::auth_protected_endpoint(&req);
        assert_eq!(resp.status_code, 401);
    }

    #[test]
    fn test_auth_protected_endpoint_authorized() {
        let mut req = TestDataGenerator::generate_benign_request();
        req.headers.insert("Authorization".to_string(), "Bearer token".to_string());
        let resp = MockHttpServer::auth_protected_endpoint(&req);
        assert_eq!(resp.status_code, 200);
    }

    #[test]
    fn test_rate_limited_endpoint() {
        let resp = MockHttpServer::rate_limited_endpoint(150);
        assert_eq!(resp.status_code, 429);
    }
}
