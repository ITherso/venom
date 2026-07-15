use crate::Result;
use crate::proxy::http_parser::HttpRequest;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub id: String,
    pub vuln_type: String,
    pub severity: String,
    pub url: String,
    pub parameter: String,
    pub payload: String,
    pub evidence: String,
}

pub struct VulnerabilityDetector;

impl VulnerabilityDetector {
    pub fn detect_sqli(req: &HttpRequest) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Check URL parameters
        if req.path.contains("=") {
            let sqli_payloads = vec![
                "'",
                "' OR '1'='1",
                "1' AND '1'='1",
                "UNION SELECT NULL",
                "';DROP TABLE",
            ];

            for payload in sqli_payloads {
                if req.path.contains(payload) {
                    vulns.push(Vulnerability {
                        id: uuid::Uuid::new_v4().to_string(),
                        vuln_type: "SQL Injection".to_string(),
                        severity: "Critical".to_string(),
                        url: req.path.clone(),
                        parameter: "URL".to_string(),
                        payload: payload.to_string(),
                        evidence: format!("Found SQL payload in URL: {}", payload),
                    });
                }
            }
        }

        vulns
    }

    pub fn detect_xss(req: &HttpRequest) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        let xss_payloads = vec![
            "<script>",
            "onerror=",
            "onload=",
            "onclick=",
            "javascript:",
        ];

        for payload in xss_payloads {
            if req.path.to_lowercase().contains(payload) {
                vulns.push(Vulnerability {
                    id: uuid::Uuid::new_v4().to_string(),
                    vuln_type: "XSS".to_string(),
                    severity: "High".to_string(),
                    url: req.path.clone(),
                    parameter: "URL".to_string(),
                    payload: payload.to_string(),
                    evidence: format!("Found XSS payload: {}", payload),
                });
            }
        }

        vulns
    }

    pub fn detect_ssti(req: &HttpRequest) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        let ssti_payloads = vec!["{{", "${", "<%", "{%"];

        for payload in ssti_payloads {
            if req.path.contains(payload) {
                vulns.push(Vulnerability {
                    id: uuid::Uuid::new_v4().to_string(),
                    vuln_type: "SSTI".to_string(),
                    severity: "Critical".to_string(),
                    url: req.path.clone(),
                    parameter: "URL".to_string(),
                    payload: payload.to_string(),
                    evidence: format!("Found SSTI payload: {}", payload),
                });
            }
        }

        vulns
    }

    pub fn detect_xxe(req: &HttpRequest) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        if let Ok(body_str) = String::from_utf8(req.body.clone()) {
            if body_str.contains("<!DOCTYPE") && body_str.contains("ENTITY") {
                vulns.push(Vulnerability {
                    id: uuid::Uuid::new_v4().to_string(),
                    vuln_type: "XXE".to_string(),
                    severity: "Critical".to_string(),
                    url: req.path.clone(),
                    parameter: "Body".to_string(),
                    payload: "<!DOCTYPE ENTITY>".to_string(),
                    evidence: "Found XML with DOCTYPE ENTITY declaration".to_string(),
                });
            }
        }

        vulns
    }

    pub fn detect_idor(req: &HttpRequest) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        let idor_patterns = vec![
            "/user/",
            "/profile/",
            "/api/users/",
            "?id=",
            "?user_id=",
            "&id=",
        ];

        for pattern in idor_patterns {
            if req.path.contains(pattern) && req.path.contains(|c: char| c.is_numeric()) {
                vulns.push(Vulnerability {
                    id: uuid::Uuid::new_v4().to_string(),
                    vuln_type: "IDOR".to_string(),
                    severity: "High".to_string(),
                    url: req.path.clone(),
                    parameter: pattern.to_string(),
                    payload: "Numeric ID parameter".to_string(),
                    evidence: format!("Found IDOR pattern: {}", pattern),
                });
            }
        }

        vulns
    }

    pub fn detect_ssrf(req: &HttpRequest) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        let ssrf_patterns = vec![
            "url=",
            "fetch=",
            "resource=",
            "proxy=",
            "request=",
        ];

        for pattern in ssrf_patterns {
            if req.path.contains(pattern) {
                vulns.push(Vulnerability {
                    id: uuid::Uuid::new_v4().to_string(),
                    vuln_type: "SSRF".to_string(),
                    severity: "High".to_string(),
                    url: req.path.clone(),
                    parameter: pattern.to_string(),
                    payload: "External URL parameter".to_string(),
                    evidence: format!("Found SSRF parameter: {}", pattern),
                });
            }
        }

        vulns
    }

    pub fn scan_request(req: &HttpRequest) -> Vec<Vulnerability> {
        let mut all_vulns = Vec::new();

        all_vulns.extend(Self::detect_sqli(req));
        all_vulns.extend(Self::detect_xss(req));
        all_vulns.extend(Self::detect_ssti(req));
        all_vulns.extend(Self::detect_xxe(req));
        all_vulns.extend(Self::detect_idor(req));
        all_vulns.extend(Self::detect_ssrf(req));

        all_vulns
    }
}
