// XSS Expert Module - Comprehensive Cross-Site Scripting detection
use crate::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use super::mutation::*;
use super::analyzer::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssVulnerability {
    pub url: String,
    pub parameter: String,
    pub xss_type: XssType,
    pub payload: String,
    pub context: String,
    pub severity: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum XssType {
    Reflected,
    Stored,
    Dom,
    Mutation,
}

pub struct XssExpert {
    client: Client,
}

impl XssExpert {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    /// Comprehensive XSS detection
    pub async fn detect_xss(
        &self,
        url: &str,
        parameters: &[(&str, &str)],
    ) -> Result<Vec<XssVulnerability>> {
        let mut vulnerabilities = Vec::new();

        for (param_name, param_value) in parameters {
            // Reflected XSS
            let reflected = self.test_reflected_xss(url, param_name, param_value).await?;
            vulnerabilities.extend(reflected);

            // DOM-based XSS (analyze response for JavaScript sinks)
            let dom = self.test_dom_xss(url, param_name, param_value).await?;
            vulnerabilities.extend(dom);

            // Mutation XSS
            let mutation = self.test_mutation_xss(url, param_name, param_value).await?;
            vulnerabilities.extend(mutation);
        }

        Ok(vulnerabilities)
    }

    /// Reflected XSS detection - payload appears directly in response
    async fn test_reflected_xss(
        &self,
        url: &str,
        param: &str,
        _original_value: &str,
    ) -> Result<Vec<XssVulnerability>> {
        let mut vulns = Vec::new();
        let payloads = MutationEngine::generate_xss_payloads();

        for payload in payloads {
            let test_url = self.build_url(url, param, &payload.encoded);

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(Duration::from_secs(10))
                .send()
                .await
            {
                if let Ok(body) = response.text().await {
                    // Check if payload is reflected
                    if body.contains(&payload.original)
                        || body.contains(&payload.encoded)
                        || self.is_payload_reflected(&body, &payload.original)
                    {
                        let context = self.detect_context(&body, &payload.original);
                        vulns.push(XssVulnerability {
                            url: test_url,
                            parameter: param.to_string(),
                            xss_type: XssType::Reflected,
                            payload: payload.original,
                            context,
                            severity: "High".to_string(),
                            confidence: 0.95,
                            evidence: vec!["Payload reflected in response".to_string()],
                        });
                        break;
                    }
                }
            }
        }

        Ok(vulns)
    }

    /// DOM-based XSS detection - vulnerability in JavaScript processing
    async fn test_dom_xss(
        &self,
        url: &str,
        param: &str,
        _original_value: &str,
    ) -> Result<Vec<XssVulnerability>> {
        let mut vulns = Vec::new();

        if let Ok(response) = self
            .client
            .get(url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
            if let Ok(body) = response.text().await {
                // Detect common DOM sinks
                let sinks = vec![
                    "eval(",
                    "innerHTML",
                    "outerHTML",
                    "document.write",
                    "appendChild",
                    "insertBefore",
                    "location.href =",
                    "location =",
                    "window.open",
                ];

                for sink in sinks {
                    if body.contains(sink) {
                        // Check if the parameter appears near the sink
                        if self.is_parameter_used_in_sink(&body, param, sink) {
                            vulns.push(XssVulnerability {
                                url: url.to_string(),
                                parameter: param.to_string(),
                                xss_type: XssType::Dom,
                                payload: format!("Dangerous sink: {}", sink),
                                context: "JavaScript".to_string(),
                                severity: "High".to_string(),
                                confidence: 0.80,
                                evidence: vec![format!("Parameter used in '{}' sink", sink)],
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok(vulns)
    }

    /// Mutation XSS detection - HTML parsing quirks
    async fn test_mutation_xss(
        &self,
        url: &str,
        param: &str,
        _original_value: &str,
    ) -> Result<Vec<XssVulnerability>> {
        let mut vulns = Vec::new();

        let mutation_payloads = vec![
            "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>",
            "<svg><style><img title=\"</style><img src=x onerror=alert(1)\">",
            "<table><td background=\"javascript:alert(1)\">",
        ];

        for payload in mutation_payloads {
            let test_url = self.build_url(url, param, &urlencoding::encode(payload).to_string());

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(Duration::from_secs(10))
                .send()
                .await
            {
                if let Ok(body) = response.text().await {
                    if body.contains("img") || body.contains("onerror") {
                        vulns.push(XssVulnerability {
                            url: test_url,
                            parameter: param.to_string(),
                            xss_type: XssType::Mutation,
                            payload: payload.to_string(),
                            context: "HTML Parser Quirk".to_string(),
                            severity: "Medium".to_string(),
                            confidence: 0.70,
                            evidence: vec!["Potential mutation XSS via HTML parsing".to_string()],
                        });
                    }
                }
            }
        }

        Ok(vulns)
    }

    /// Detect XSS context (HTML, JavaScript, CSS, URL, etc.)
    fn detect_context(&self, body: &str, payload: &str) -> String {
        if body.contains(&format!("\"{}\"", payload)) {
            "HTML Attribute".to_string()
        } else if body.contains(&format!("'{}'", payload)) {
            "HTML Attribute (Single Quote)".to_string()
        } else if body.contains(&format!(">{}<", payload)) {
            "HTML Text Content".to_string()
        } else if body.contains(&format!("script>{}", payload)) {
            "JavaScript Context".to_string()
        } else if body.contains(&format!("style>{}", payload)) {
            "CSS Context".to_string()
        } else {
            "Unknown Context".to_string()
        }
    }

    /// Check if payload is reflected (accounting for HTML encoding)
    fn is_payload_reflected(&self, response: &str, payload: &str) -> bool {
        // Check direct reflection
        if response.contains(payload) {
            return true;
        }

        // Check for HTML-encoded version
        let html_encoded = payload
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;");

        response.contains(&html_encoded)
            || response.contains(
                &urlencoding::encode(payload).to_string(),
            )
    }

    /// Check if parameter is used in a dangerous sink
    fn is_parameter_used_in_sink(&self, body: &str, param: &str, sink: &str) -> bool {
        if let Some(sink_pos) = body.find(sink) {
            let context_start = if sink_pos > 100 { sink_pos - 100 } else { 0 };
            let context_end = if sink_pos + sink.len() + 100 < body.len() {
                sink_pos + sink.len() + 100
            } else {
                body.len()
            };

            body[context_start..context_end].contains(param)
        } else {
            false
        }
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
    fn test_context_detection_html_attribute() {
        let xss = XssExpert::new();
        let response = r#"<input value="<script>alert(1)</script>">"#;
        let context = xss.detect_context(response, "<script>alert(1)</script>");
        assert_eq!(context, "HTML Attribute");
    }

    #[test]
    fn test_context_detection_text_content() {
        let xss = XssExpert::new();
        let response = r#"><img src=x><"#;
        let context = xss.detect_context(response, "<img src=x>");
        assert_eq!(context, "HTML Text Content");
    }

    #[test]
    fn test_payload_reflection_check() {
        let xss = XssExpert::new();
        let response = "Welcome <script>alert(1)</script> to site";
        assert!(xss.is_payload_reflected(response, "<script>alert(1)</script>"));
    }

    #[test]
    fn test_html_encoded_reflection() {
        let xss = XssExpert::new();
        let response = "&lt;script&gt;alert(1)&lt;/script&gt;";
        assert!(xss.is_payload_reflected(response, "<script>alert(1)</script>"));
    }

    #[test]
    fn test_sink_detection() {
        let xss = XssExpert::new();
        let code = "var x = document.getElementById('id'); x.innerHTML = id;";
        assert!(xss.is_parameter_used_in_sink(code, "id", "innerHTML"));
    }

    #[test]
    fn test_sink_not_detected_when_no_param() {
        let xss = XssExpert::new();
        let code = "var x = document.getElementById('data'); x.innerHTML = data;";
        assert!(!xss.is_parameter_used_in_sink(code, "id", "innerHTML"));
    }
}
