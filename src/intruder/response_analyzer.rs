use regex::Regex;

/// Analyzer for fuzzing responses
pub struct FuzzResponseAnalyzer;

#[derive(Debug, Clone)]
pub struct ResponseSignature {
    pub contains_sql_error: bool,
    pub contains_xss_pattern: bool,
    pub contains_command_injection_indicator: bool,
    pub contains_path_traversal_indicator: bool,
    pub contains_xxe_pattern: bool,
    pub status_code: u16,
    pub body_size: usize,
    pub reflection_detected: bool,
}

impl FuzzResponseAnalyzer {
    /// Check if response is interesting (contains potential vulnerabilities)
    pub fn is_interesting(status_code: u16, body: &str) -> bool {
        // Status codes that indicate interesting findings
        if matches!(status_code, 500 | 502 | 503 | 504) {
            return true;
        }

        // 4xx status codes with error messages
        if status_code >= 400 && status_code < 500 && body.contains("error") {
            return true;
        }

        // SQL error patterns
        if Self::contains_sql_error(body) {
            return true;
        }

        // XSS reflection
        if Self::contains_xss_reflection(body) {
            return true;
        }

        // Command execution indicators
        if Self::contains_command_output(body) {
            return true;
        }

        false
    }

    /// Analyze response for vulnerability indicators
    pub fn analyze(status_code: u16, body: &str) -> ResponseSignature {
        ResponseSignature {
            contains_sql_error: Self::contains_sql_error(body),
            contains_xss_pattern: Self::contains_xss_pattern(body),
            contains_command_injection_indicator: Self::contains_command_output(body),
            contains_path_traversal_indicator: Self::contains_path_traversal_indicator(body),
            contains_xxe_pattern: Self::contains_xxe_pattern(body),
            status_code,
            body_size: body.len(),
            reflection_detected: Self::contains_xss_reflection(body),
        }
    }

    /// Detect SQL injection error messages
    fn contains_sql_error(body: &str) -> bool {
        let patterns = [
            "SQL syntax",
            "mysql_fetch",
            "mysql_num_rows",
            "OracleException",
            "SQLException",
            "PostgreSQL",
            "SQL Server",
            "Unexpected end of command",
            "Syntax error",
            "SQLSTATE",
            "Warning: mysql",
            "Notice: Undefined",
            "Fatal error",
        ];

        patterns.iter().any(|p| body.contains(p))
    }

    /// Detect XSS patterns in response
    fn contains_xss_pattern(body: &str) -> bool {
        body.contains("<script>")
            || body.contains("javascript:")
            || body.contains("onerror=")
            || body.contains("onload=")
            || body.contains("onclick=")
    }

    /// Detect XSS reflection (payload echoed in response)
    fn contains_xss_reflection(body: &str) -> bool {
        body.contains("<img") && body.contains("onerror") || body.contains("src=x")
    }

    /// Detect command execution output
    fn contains_command_output(body: &str) -> bool {
        let patterns = [
            "root:x:",
            "bin/bash",
            "Linux",
            "uid=",
            "total",
            "drwxr",
            "lrwx",
            "etc/passwd",
            "/bin/",
            "No such file",
            "command not found",
        ];

        patterns.iter().any(|p| body.contains(p))
    }

    /// Detect path traversal indicators
    fn contains_path_traversal_indicator(body: &str) -> bool {
        body.contains("root:") || body.contains("SYSTEM32") || body.contains("Program Files")
    }

    /// Detect XXE patterns
    fn contains_xxe_pattern(body: &str) -> bool {
        body.contains("<!DOCTYPE") && body.contains("ENTITY")
            || body.contains("<!ELEMENT")
            || body.contains("file:///")
    }

    /// Extract potential evidence from response
    pub fn extract_evidence(body: &str, pattern: &str) -> Vec<String> {
        if let Ok(re) = Regex::new(pattern) {
            re.captures_iter(body)
                .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
                .collect()
        } else {
            vec![]
        }
    }

    /// Rate response interestingness (0.0 - 1.0)
    pub fn calculate_interestingness(signature: &ResponseSignature) -> f32 {
        let mut score: f32 = 0.0;

        if signature.contains_sql_error {
            score += 0.4;
        }
        if signature.contains_xss_pattern {
            score += 0.3;
        }
        if signature.contains_command_injection_indicator {
            score += 0.5;
        }
        if signature.contains_path_traversal_indicator {
            score += 0.4;
        }
        if signature.contains_xxe_pattern {
            score += 0.4;
        }
        if signature.reflection_detected {
            score += 0.3;
        }
        if matches!(signature.status_code, 500 | 502 | 503 | 504) {
            score += 0.2;
        }

        score.min(1.0)
    }

    /// Generate detailed response report
    pub fn generate_report(signature: &ResponseSignature) -> String {
        let interestingness = Self::calculate_interestingness(signature);

        format!(
            r#"
╔════════════════════════════════════════════════════════════════╗
║                   Fuzzing Response Analysis                    ║
╚════════════════════════════════════════════════════════════════╝

📊 RESPONSE CHARACTERISTICS
├─ Status Code: {}
├─ Body Size: {} bytes
└─ Interestingness Score: {:.2}%

🔍 VULNERABILITY INDICATORS
├─ SQL Error: {}
├─ XSS Pattern: {}
├─ Command Injection: {}
├─ Path Traversal: {}
├─ XXE Pattern: {}
└─ Reflection Detected: {}

═══════════════════════════════════════════════════════════════════
"#,
            signature.status_code,
            signature.body_size,
            interestingness * 100.0,
            if signature.contains_sql_error { "✓ YES" } else { "✗ NO" },
            if signature.contains_xss_pattern { "✓ YES" } else { "✗ NO" },
            if signature.contains_command_injection_indicator {
                "✓ YES"
            } else {
                "✗ NO"
            },
            if signature.contains_path_traversal_indicator {
                "✓ YES"
            } else {
                "✗ NO"
            },
            if signature.contains_xxe_pattern { "✓ YES" } else { "✗ NO" },
            if signature.reflection_detected { "✓ YES" } else { "✗ NO" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_error_detection() {
        let body = "SELECT * FROM users: SQL syntax error";
        assert!(FuzzResponseAnalyzer::contains_sql_error(body));
    }

    #[test]
    fn test_xss_pattern_detection() {
        let body = "<img src=x onerror=alert('XSS')>";
        assert!(FuzzResponseAnalyzer::contains_xss_pattern(body));
    }

    #[test]
    fn test_command_output_detection() {
        let body = "root:x:0:0:/root:/bin/bash";
        assert!(FuzzResponseAnalyzer::contains_command_output(body));
    }

    #[test]
    fn test_interesting_detection() {
        let body = "root:x:0:0";
        assert!(FuzzResponseAnalyzer::is_interesting(200, body));
    }

    #[test]
    fn test_response_signature_analysis() {
        let body = "SQL syntax error in line 1";
        let sig = FuzzResponseAnalyzer::analyze(500, body);
        assert!(sig.contains_sql_error);
        assert_eq!(sig.status_code, 500);
    }

    #[test]
    fn test_interestingness_scoring() {
        let sig = ResponseSignature {
            contains_sql_error: true,
            contains_xss_pattern: false,
            contains_command_injection_indicator: false,
            contains_path_traversal_indicator: false,
            contains_xxe_pattern: false,
            status_code: 200,
            body_size: 100,
            reflection_detected: false,
        };

        let score = FuzzResponseAnalyzer::calculate_interestingness(&sig);
        assert!(score > 0.0);
    }
}
