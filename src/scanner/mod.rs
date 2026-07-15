pub mod payloads;

use crate::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub vuln_type: String,
    pub severity: String,
    pub url: String,
    pub payload: String,
    pub response_code: u16,
}

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

    pub async fn scan(&self) -> Result<Vec<Vulnerability>> {
        let mut vulns = Vec::new();

        // SQLi test
        for payload in payloads::Payloads::sqli() {
            if let Ok(v) = self.test_sqli(payload).await {
                vulns.push(v);
            }
        }

        // XSS test
        for payload in payloads::Payloads::xss() {
            if let Ok(v) = self.test_xss(payload).await {
                vulns.push(v);
            }
        }

        // SSTI test
        for payload in payloads::Payloads::ssti() {
            if let Ok(v) = self.test_ssti(payload).await {
                vulns.push(v);
            }
        }

        // SSRF test
        for payload in payloads::Payloads::ssrf() {
            if let Ok(v) = self.test_ssrf(payload).await {
                vulns.push(v);
            }
        }

        Ok(vulns)
    }

    async fn test_sqli(&self, payload: &str) -> Result<Vulnerability> {
        let url = format!("{}?id={}", self.target, urlencoding::encode(payload));
        let resp = self.client.get(&url).send().await?;

        let code = resp.status().as_u16();
        if code != 200 {
            return Err(crate::Error::ScannerError("SQLi not detected".into()));
        }

        Ok(Vulnerability {
            vuln_type: "SQL Injection".to_string(),
            severity: "Critical".to_string(),
            url: self.target.clone(),
            payload: payload.to_string(),
            response_code: code,
        })
    }

    async fn test_xss(&self, payload: &str) -> Result<Vulnerability> {
        let url = format!("{}?q={}", self.target, urlencoding::encode(payload));
        let resp = self.client.get(&url).send().await?;
        let text = resp.text().await?;

        if !text.contains(payload) {
            return Err(crate::Error::ScannerError("XSS not detected".into()));
        }

        Ok(Vulnerability {
            vuln_type: "XSS".to_string(),
            severity: "High".to_string(),
            url: self.target.clone(),
            payload: payload.to_string(),
            response_code: 200,
        })
    }

    async fn test_ssti(&self, payload: &str) -> Result<Vulnerability> {
        let url = format!("{}?template={}", self.target, urlencoding::encode(payload));
        let resp = self.client.get(&url).send().await?;
        let text = resp.text().await?;

        if !text.contains("49") && !text.contains("7 * 7") {
            return Err(crate::Error::ScannerError("SSTI not detected".into()));
        }

        Ok(Vulnerability {
            vuln_type: "SSTI".to_string(),
            severity: "Critical".to_string(),
            url: self.target.clone(),
            payload: payload.to_string(),
            response_code: 200,
        })
    }

    async fn test_ssrf(&self, payload: &str) -> Result<Vulnerability> {
        let url = format!("{}?url={}", self.target, urlencoding::encode(payload));
        let resp = self.client.get(&url).send().await?;

        Ok(Vulnerability {
            vuln_type: "SSRF".to_string(),
            severity: "High".to_string(),
            url: self.target.clone(),
            payload: payload.to_string(),
            response_code: resp.status().as_u16(),
        })
    }
}
