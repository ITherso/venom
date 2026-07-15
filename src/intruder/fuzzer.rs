/// Core fuzzing orchestrator
pub struct Fuzzer {
    pub base_url: String,
    pub parameter: String,
    pub concurrent_requests: usize,
    pub timeout_secs: u64,
}

impl Fuzzer {
    pub fn new(base_url: String, parameter: String) -> Self {
        Self {
            base_url,
            parameter,
            concurrent_requests: 4,
            timeout_secs: 30,
        }
    }

    /// Set concurrency level
    pub fn with_concurrency(mut self, count: usize) -> Self {
        self.concurrent_requests = count;
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Build target URL for payload injection
    pub fn build_url(&self, payload: &str) -> String {
        if self.base_url.contains('?') {
            format!(
                "{}&{}={}",
                self.base_url,
                self.parameter,
                urlencoding::encode(payload)
            )
        } else {
            format!(
                "{}?{}={}",
                self.base_url,
                self.parameter,
                urlencoding::encode(payload)
            )
        }
    }

    /// Validate target URL
    pub fn validate_target(&self) -> Result<(), String> {
        if self.base_url.is_empty() {
            return Err("Target URL is empty".to_string());
        }

        if !self.base_url.starts_with("http://") && !self.base_url.starts_with("https://") {
            return Err("Target URL must start with http:// or https://".to_string());
        }

        if self.parameter.is_empty() {
            return Err("Parameter name is empty".to_string());
        }

        Ok(())
    }

    /// Get expected response baseline (for anomaly detection)
    pub async fn get_baseline(&self) -> Result<FuzzingBaseline, String> {
        let client = reqwest::Client::new();
        let url = self.build_url("baseline-value-12345");

        match tokio::time::timeout(
            std::time::Duration::from_secs(self.timeout_secs),
            client.get(&url).send(),
        )
        .await
        {
            Ok(Ok(resp)) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let size = body.len();

                Ok(FuzzingBaseline {
                    status_code: status,
                    response_size: size,
                    contains_error: body.to_lowercase().contains("error"),
                })
            }
            _ => Err("Failed to establish baseline".to_string()),
        }
    }

    /// Analyze response for interesting deviations
    pub fn analyze_response(
        &self,
        status_code: u16,
        body_size: usize,
        baseline: &FuzzingBaseline,
    ) -> ResponseAnomaly {
        let status_anomaly = status_code != baseline.status_code;
        let size_anomaly = (body_size as i32 - baseline.response_size as i32).abs() > 100;
        let error_disclosure = status_code >= 400 && status_code < 500;

        ResponseAnomaly {
            status_anomaly,
            size_anomaly,
            error_disclosure,
            is_interesting: status_anomaly || size_anomaly || error_disclosure,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FuzzingBaseline {
    pub status_code: u16,
    pub response_size: usize,
    pub contains_error: bool,
}

#[derive(Debug, Clone)]
pub struct ResponseAnomaly {
    pub status_anomaly: bool,
    pub size_anomaly: bool,
    pub error_disclosure: bool,
    pub is_interesting: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzer_creation() {
        let fuzzer = Fuzzer::new(
            "http://example.com/search".to_string(),
            "q".to_string(),
        );
        assert_eq!(fuzzer.base_url, "http://example.com/search");
        assert_eq!(fuzzer.parameter, "q");
    }

    #[test]
    fn test_fuzzer_url_building() {
        let fuzzer = Fuzzer::new(
            "http://example.com/search".to_string(),
            "q".to_string(),
        );
        let url = fuzzer.build_url("test payload");
        assert!(url.contains("q="));
        assert!(url.contains("test"));
    }

    #[test]
    fn test_fuzzer_url_with_existing_query() {
        let fuzzer = Fuzzer::new(
            "http://example.com/search?id=1".to_string(),
            "q".to_string(),
        );
        let url = fuzzer.build_url("test");
        assert!(url.contains("&q="));
    }

    #[test]
    fn test_target_validation() {
        let fuzzer = Fuzzer::new(
            "http://example.com".to_string(),
            "param".to_string(),
        );
        assert!(fuzzer.validate_target().is_ok());
    }

    #[test]
    fn test_target_validation_no_protocol() {
        let fuzzer = Fuzzer::new(
            "example.com".to_string(),
            "param".to_string(),
        );
        assert!(fuzzer.validate_target().is_err());
    }

    #[test]
    fn test_response_anomaly_detection() {
        let fuzzer = Fuzzer::new("http://example.com".to_string(), "q".to_string());
        let baseline = FuzzingBaseline {
            status_code: 200,
            response_size: 1000,
            contains_error: false,
        };

        let anomaly = fuzzer.analyze_response(500, 1000, &baseline);
        assert!(anomaly.status_anomaly);
        assert!(anomaly.is_interesting);
    }

    #[test]
    fn test_size_anomaly_detection() {
        let fuzzer = Fuzzer::new("http://example.com".to_string(), "q".to_string());
        let baseline = FuzzingBaseline {
            status_code: 200,
            response_size: 1000,
            contains_error: false,
        };

        let anomaly = fuzzer.analyze_response(200, 2000, &baseline);
        assert!(anomaly.size_anomaly);
        assert!(anomaly.is_interesting);
    }
}
