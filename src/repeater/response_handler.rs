use super::RepeaterResponse;
use regex::Regex;

/// Analyzer for response content and patterns
pub struct ResponseAnalyzer;

#[derive(Debug, Clone)]
pub struct ResponseMetrics {
    pub contains_html: bool,
    pub contains_json: bool,
    pub contains_xml: bool,
    pub line_count: usize,
    pub word_count: usize,
    pub unique_words: usize,
    pub has_cookies: bool,
    pub has_redirects: bool,
    pub compression_detected: bool,
    pub encoding: String,
}

impl ResponseAnalyzer {
    /// Analyze response content
    pub fn analyze(resp: &RepeaterResponse) -> ResponseMetrics {
        let body = &resp.body;

        let contains_html = body.contains("<html>") || body.contains("<HTML>");
        let contains_json = body.trim_start().starts_with('{') || body.trim_start().starts_with('[');
        let contains_xml = body.contains("<?xml") || body.contains("<root>");

        let lines: Vec<&str> = body.lines().collect();
        let line_count = lines.len();

        let words: Vec<&str> = body.split_whitespace().collect();
        let word_count = words.len();

        let mut unique_words = std::collections::HashSet::new();
        for word in &words {
            unique_words.insert(word.to_lowercase());
        }

        let has_cookies = resp
            .headers
            .iter()
            .any(|(k, _)| k.to_lowercase() == "set-cookie");

        let has_redirects = matches!(resp.status_code, 301 | 302 | 303 | 307 | 308);

        let compression_detected = resp
            .headers
            .iter()
            .any(|(k, v)| k.to_lowercase() == "content-encoding" && !v.is_empty());

        let encoding = resp
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "content-type")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "text/html".to_string());

        ResponseMetrics {
            contains_html,
            contains_json,
            contains_xml,
            line_count,
            word_count,
            unique_words: unique_words.len(),
            has_cookies,
            has_redirects,
            compression_detected,
            encoding,
        }
    }

    /// Extract values using regex
    pub fn extract_regex(resp: &RepeaterResponse, pattern: &str) -> Vec<String> {
        if let Ok(re) = Regex::new(pattern) {
            re.captures_iter(&resp.body)
                .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
                .collect()
        } else {
            vec![]
        }
    }

    /// Check for common vulnerability patterns
    pub fn check_vulnerabilities(resp: &RepeaterResponse) -> Vec<String> {
        let mut findings = vec![];

        // SQL Error patterns
        if resp.body.contains("SQL syntax")
            || resp.body.contains("mysql_fetch_array")
            || resp.body.contains("OracleException")
        {
            findings.push("Potential SQL Error Disclosure".to_string());
        }

        // XSS indicators
        if resp.body.contains("<script>") || resp.body.contains("javascript:") {
            findings.push("Potential XSS Vulnerability".to_string());
        }

        // XXE indicators
        if resp.body.contains("<!DOCTYPE") && resp.body.contains("ENTITY") {
            findings.push("Potential XXE Vulnerability".to_string());
        }

        // Information disclosure
        if resp.body.contains("version") && resp.body.to_lowercase().contains("apache") {
            findings.push("Server Version Disclosure".to_string());
        }

        findings
    }

    /// Extract cookies from response
    pub fn extract_cookies(resp: &RepeaterResponse) -> Vec<(String, String)> {
        resp.headers
            .iter()
            .filter(|(k, _)| k.to_lowercase() == "set-cookie")
            .filter_map(|(_, v)| {
                if let Some((name, value)) = v.split_once('=') {
                    Some((name.to_string(), value.split(';').next().unwrap_or("").to_string()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Extract redirect location
    pub fn extract_redirect(resp: &RepeaterResponse) -> Option<String> {
        resp.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "location")
            .map(|(_, v)| v.clone())
    }

    /// Check response time for timing attacks
    pub fn analyze_timing(resp: &RepeaterResponse) -> TimingAnalysis {
        TimingAnalysis {
            response_time_ms: resp.time_ms,
            is_slow: resp.time_ms > 5000,
            is_very_fast: resp.time_ms < 100,
        }
    }

    /// Format response summary
    pub fn summary(resp: &RepeaterResponse) -> String {
        let metrics = Self::analyze(resp);
        let timing = Self::analyze_timing(resp);
        let vulns = Self::check_vulnerabilities(resp);

        format!(
            r#"
╔════════════════════════════════════════════════════════════════╗
║                   Response Analysis                             ║
╚════════════════════════════════════════════════════════════════╝

📊 HTTP STATUS
├─ Status Code: {}
├─ Size: {} bytes
└─ Time: {}ms

📝 CONTENT ANALYSIS
├─ HTML: {}
├─ JSON: {}
├─ XML: {}
├─ Lines: {}
├─ Words: {}
└─ Unique Words: {}

🔒 SECURITY HEADERS
├─ Set-Cookie: {}
├─ Redirects: {}
├─ Compression: {}
└─ Encoding: {}

⚠️  POTENTIAL ISSUES
{}

═══════════════════════════════════════════════════════════════════
"#,
            resp.status_code,
            resp.size_bytes,
            resp.time_ms,
            if metrics.contains_html { "✓" } else { "✗" },
            if metrics.contains_json { "✓" } else { "✗" },
            if metrics.contains_xml { "✓" } else { "✗" },
            metrics.line_count,
            metrics.word_count,
            metrics.unique_words,
            if metrics.has_cookies { "✓" } else { "✗" },
            if metrics.has_redirects { "✓" } else { "✗" },
            if metrics.compression_detected { "✓" } else { "✗" },
            metrics.encoding,
            if vulns.is_empty() {
                "└─ None detected".to_string()
            } else {
                vulns
                    .iter()
                    .enumerate()
                    .map(|(i, v)| format!("{} {}", if i == vulns.len() - 1 { "└─" } else { "├─" }, v))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        )
    }
}

#[derive(Debug)]
pub struct TimingAnalysis {
    pub response_time_ms: u128,
    pub is_slow: bool,
    pub is_very_fast: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_analysis() {
        let resp = RepeaterResponse {
            status_code: 200,
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: r#"{"key":"value"}"#.to_string(),
            size_bytes: 16,
            time_ms: 150,
            error: None,
        };

        let metrics = ResponseAnalyzer::analyze(&resp);
        assert!(metrics.contains_json);
        assert!(!metrics.contains_html);
    }

    #[test]
    fn test_extract_cookies() {
        let resp = RepeaterResponse {
            status_code: 200,
            headers: vec![("Set-Cookie".to_string(), "session=abc123; Path=/".to_string())],
            body: String::new(),
            size_bytes: 0,
            time_ms: 100,
            error: None,
        };

        let cookies = ResponseAnalyzer::extract_cookies(&resp);
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].0, "session");
    }
}
