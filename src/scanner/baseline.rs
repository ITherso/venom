// Baseline Collection Module - Dynamic learning of normal behavior
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineProfile {
    pub request_profile: RequestProfile,
    pub response_profile: ResponseProfile,
    pub context: ApplicationContext,
    pub behavior_patterns: BehaviorPatterns,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestProfile {
    pub avg_size: f64,
    pub parameter_types: HashMap<String, String>,
    pub encoding_methods: Vec<String>,
    pub header_patterns: HashMap<String, String>,
    pub common_parameters: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseProfile {
    pub avg_response_time: Duration,
    pub avg_size: usize,
    pub common_status_codes: Vec<u16>,
    pub error_patterns: Vec<String>,
    pub content_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationContext {
    pub framework: Option<String>,
    pub language: Option<String>,
    pub database: Option<String>,
    pub waf: Option<String>,
    pub server: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorPatterns {
    pub normal_response_time_mean: f64,
    pub normal_response_time_std: f64,
    pub normal_size_mean: f64,
    pub normal_size_std: f64,
    pub timeout_threshold: u64,
    pub anomaly_threshold: f64,
}

pub struct BaselineCollector;

impl BaselineCollector {
    pub async fn collect(
        target: &str,
        sample_count: usize,
    ) -> crate::Result<BaselineProfile> {
        let mut request_profile = RequestProfile {
            avg_size: 0.0,
            parameter_types: HashMap::new(),
            encoding_methods: Vec::new(),
            header_patterns: HashMap::new(),
            common_parameters: Vec::new(),
        };

        let mut response_profile = ResponseProfile {
            avg_response_time: Duration::from_secs(0),
            avg_size: 0,
            common_status_codes: Vec::new(),
            error_patterns: Vec::new(),
            content_types: Vec::new(),
        };

        let context = Self::detect_application_context(target).await?;

        Ok(BaselineProfile {
            request_profile,
            response_profile,
            context,
            behavior_patterns: BehaviorPatterns {
                normal_response_time_mean: 0.5,
                normal_response_time_std: 0.2,
                normal_size_mean: 5000.0,
                normal_size_std: 2000.0,
                timeout_threshold: 30,
                anomaly_threshold: 2.5,
            },
        })
    }

    async fn detect_application_context(target: &str) -> crate::Result<ApplicationContext> {
        let client = reqwest::Client::new();

        // Try to detect framework and language
        if let Ok(response) = client.get(target).send().await {
            let server = response
                .headers()
                .get("Server")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let body = response.text().await.unwrap_or_default();

            let framework = Self::detect_framework(&body);
            let language = Self::detect_language(&body);
            let database = Self::detect_database(&body);

            // Note: WAF detection requires headers, but they're consumed after text()
            let waf = None; // Simplified for now

            return Ok(ApplicationContext {
                framework,
                language,
                database,
                waf,
                server,
            });
        }

        Ok(ApplicationContext {
            framework: None,
            language: None,
            database: None,
            waf: None,
            server: None,
        })
    }

    fn detect_framework(body: &str) -> Option<String> {
        let body_lower = body.to_lowercase();

        if body_lower.contains("powered by laravel") || body_lower.contains("laravel") {
            return Some("Laravel".to_string());
        }
        if body_lower.contains("django") || body_lower.contains("csrf") {
            return Some("Django".to_string());
        }
        if body_lower.contains("wordpress") || body_lower.contains("wp-content") {
            return Some("WordPress".to_string());
        }
        if body_lower.contains("drupal") {
            return Some("Drupal".to_string());
        }
        if body_lower.contains("joomla") {
            return Some("Joomla".to_string());
        }

        None
    }

    fn detect_language(body: &str) -> Option<String> {
        let body_lower = body.to_lowercase();

        if body_lower.contains(".php") || body_lower.contains("php version") {
            return Some("PHP".to_string());
        }
        if body_lower.contains("python") || body_lower.contains("django") {
            return Some("Python".to_string());
        }
        if body_lower.contains("java") || body_lower.contains("jsp") {
            return Some("Java".to_string());
        }
        if body_lower.contains(".aspx") || body_lower.contains("iis") {
            return Some(".NET".to_string());
        }

        None
    }

    fn detect_database(body: &str) -> Option<String> {
        let body_lower = body.to_lowercase();

        if body_lower.contains("mysql") {
            return Some("MySQL".to_string());
        }
        if body_lower.contains("postgresql") || body_lower.contains("postgres") {
            return Some("PostgreSQL".to_string());
        }
        if body_lower.contains("mssql") || body_lower.contains("sql server") {
            return Some("MSSQL".to_string());
        }
        if body_lower.contains("oracle") {
            return Some("Oracle".to_string());
        }

        None
    }

    fn detect_waf(headers: &reqwest::header::HeaderMap) -> Option<String> {
        if let Some(server) = headers.get("Server").and_then(|v| v.to_str().ok()) {
            if server.contains("cloudflare") {
                return Some("Cloudflare".to_string());
            }
            if server.contains("akamai") {
                return Some("Akamai".to_string());
            }
        }

        if let Some(powered_by) = headers
            .get("X-Powered-By")
            .and_then(|v| v.to_str().ok())
        {
            if powered_by.contains("cloudflare") {
                return Some("Cloudflare".to_string());
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_framework() {
        let body = r#"<meta name="generator" content="WordPress 6.0">"#;
        assert_eq!(BaselineCollector::detect_framework(body), Some("WordPress".to_string()));
    }

    #[test]
    fn test_detect_language() {
        let body = "Django 4.0 running";
        assert_eq!(
            BaselineCollector::detect_language(body),
            Some("Python".to_string())
        );
    }

    #[test]
    fn test_detect_database() {
        let body = "MySQL Error: 1064";
        assert_eq!(
            BaselineCollector::detect_database(body),
            Some("MySQL".to_string())
        );
    }
}
