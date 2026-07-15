pub mod payloads;
pub mod fuzzer;
pub mod response_analyzer;
pub mod macros;
pub mod conditional;

use crate::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Instant;

pub use fuzzer::Fuzzer;
pub use payloads::PayloadGenerator;
pub use response_analyzer::FuzzResponseAnalyzer;
pub use macros::{Macro, MacroExecutor, MacroStep};
pub use conditional::{ConditionalPayload, AdaptivePayloadEngine};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzConfig {
    pub target: String,
    pub parameter: String,
    pub payload_type: String,
    pub threads: usize,
    pub timeout_secs: u64,
    pub stop_on_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub payload: String,
    pub status_code: u16,
    pub response_size: usize,
    pub response_time_ms: u128,
    pub error: Option<String>,
    pub is_interesting: bool,
}

#[derive(Debug, Clone)]
pub struct FuzzStatistics {
    pub total_payloads: usize,
    pub successful: usize,
    pub failed: usize,
    pub interesting_findings: usize,
    pub total_time_ms: u128,
    pub avg_response_time_ms: u128,
}

pub struct Intruder {
    client: Client,
    config: FuzzConfig,
}

impl Intruder {
    pub fn new(config: FuzzConfig) -> Self {
        Self {
            client: Client::new(),
            config,
        }
    }

    /// Run fuzzing campaign with payload generator
    pub async fn fuzz_with_generator(
        &self,
        generator: &PayloadGenerator,
    ) -> Result<Vec<FuzzResult>> {
        let payloads = generator.generate();
        self.fuzz_payloads(&payloads).await
    }

    /// Fuzz with custom payloads
    pub async fn fuzz_payloads(&self, payloads: &[String]) -> Result<Vec<FuzzResult>> {
        let start = Instant::now();
        let mut results = Vec::new();
        let mut stats = FuzzStatistics {
            total_payloads: payloads.len(),
            successful: 0,
            failed: 0,
            interesting_findings: 0,
            total_time_ms: 0,
            avg_response_time_ms: 0,
        };

        for payload in payloads {
            let result = self.test_payload(payload).await;
            stats.successful += 1;

            if let Ok(fuzz_result) = &result {
                if fuzz_result.is_interesting {
                    stats.interesting_findings += 1;
                }
                results.push(fuzz_result.clone());
            } else {
                stats.failed += 1;
            }

            if self.config.stop_on_error && stats.failed > 0 {
                break;
            }
        }

        stats.total_time_ms = start.elapsed().as_millis();
        stats.avg_response_time_ms = if stats.successful > 0 {
            stats.total_time_ms / stats.successful as u128
        } else {
            0
        };

        println!("{}", self.format_statistics(&stats));

        Ok(results)
    }

    /// Test a single payload
    async fn test_payload(&self, payload: &str) -> Result<FuzzResult> {
        let start = Instant::now();

        let url = if self.config.target.contains('?') {
            format!(
                "{}&{}={}",
                self.config.target,
                self.config.parameter,
                urlencoding::encode(payload)
            )
        } else {
            format!(
                "{}?{}={}",
                self.config.target,
                self.config.parameter,
                urlencoding::encode(payload)
            )
        };

        match self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(self.config.timeout_secs))
            .send()
            .await
        {
            Ok(resp) => {
                let status_code = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let response_size = body.len();
                let response_time_ms = start.elapsed().as_millis();

                let is_interesting = FuzzResponseAnalyzer::is_interesting(status_code, &body);

                Ok(FuzzResult {
                    payload: payload.to_string(),
                    status_code,
                    response_size,
                    response_time_ms,
                    error: None,
                    is_interesting,
                })
            }
            Err(e) => Ok(FuzzResult {
                payload: payload.to_string(),
                status_code: 0,
                response_size: 0,
                response_time_ms: start.elapsed().as_millis(),
                error: Some(e.to_string()),
                is_interesting: false,
            }),
        }
    }

    /// Legacy simple fuzz method
    pub async fn fuzz(&self, payloads: Vec<&str>, param: &str) -> Result<Vec<(String, u16)>> {
        let mut results = Vec::new();

        for payload in payloads {
            let url = format!("{}?{}={}", self.config.target, param, urlencoding::encode(payload));
            if let Ok(resp) = self.client.get(&url).send().await {
                let code = resp.status().as_u16();
                results.push((payload.to_string(), code));
            }
        }

        Ok(results)
    }

    /// Format statistics for display
    fn format_statistics(&self, stats: &FuzzStatistics) -> String {
        format!(
            r#"
╔════════════════════════════════════════════════════════════════╗
║                   Fuzzing Statistics                            ║
╚════════════════════════════════════════════════════════════════╝

📊 CAMPAIGN RESULTS
├─ Total Payloads: {}
├─ Successful: {}
├─ Failed: {}
├─ Interesting Findings: {}
├─ Total Time: {}ms
└─ Average Response Time: {}ms

═══════════════════════════════════════════════════════════════════
"#,
            stats.total_payloads,
            stats.successful,
            stats.failed,
            stats.interesting_findings,
            stats.total_time_ms,
            stats.avg_response_time_ms
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intruder_creation() {
        let config = FuzzConfig {
            target: "http://example.com".to_string(),
            parameter: "id".to_string(),
            payload_type: "numbers".to_string(),
            threads: 4,
            timeout_secs: 30,
            stop_on_error: false,
        };

        let _intruder = Intruder::new(config);
    }

    #[test]
    fn test_fuzz_result_creation() {
        let result = FuzzResult {
            payload: "test_payload".to_string(),
            status_code: 200,
            response_size: 1024,
            response_time_ms: 150,
            error: None,
            is_interesting: true,
        };

        assert_eq!(result.payload, "test_payload");
        assert_eq!(result.status_code, 200);
    }
}
