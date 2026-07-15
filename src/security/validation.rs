use serde::{Deserialize, Serialize};
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationRule {
    Required,
    MinLength(usize),
    MaxLength(usize),
    Pattern(String),
    Email,
    URL,
    IPv4,
    IPv6,
    NoSQLInjection,
    NoXSS,
    AlphanumericOnly,
    NumericOnly,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SanitizationRule {
    TrimWhitespace,
    RemoveSpecialChars,
    HTMLEncode,
    URLEncode,
    Base64Encode,
    RemoveNulls,
    NormalizePath,
    RemoveScriptTags,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn add_error(&mut self, error: String) {
        self.valid = false;
        self.errors.push(error);
    }

    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }
}

pub struct InputValidator {
    rules: HashMap<String, Vec<ValidationRule>>,
    sanitization_rules: HashMap<String, Vec<SanitizationRule>>,
    common_patterns: HashMap<String, String>,
}

impl InputValidator {
    pub fn new() -> Self {
        let mut common_patterns = HashMap::new();
        common_patterns.insert(
            "email".to_string(),
            r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$".to_string(),
        );
        common_patterns.insert(
            "url".to_string(),
            r"^https?://[^\s/$.?#].[^\s]*$".to_string(),
        );
        common_patterns.insert(
            "ipv4".to_string(),
            r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
                .to_string(),
        );
        common_patterns.insert(
            "alphanumeric".to_string(),
            r"^[a-zA-Z0-9]+$".to_string(),
        );
        common_patterns.insert(
            "numeric".to_string(),
            r"^\d+$".to_string(),
        );

        Self {
            rules: HashMap::new(),
            sanitization_rules: HashMap::new(),
            common_patterns,
        }
    }

    pub fn add_rule(&mut self, field: String, rule: ValidationRule) {
        self.rules.entry(field).or_insert_with(Vec::new).push(rule);
    }

    pub fn add_sanitization(&mut self, field: String, rule: SanitizationRule) {
        self.sanitization_rules.entry(field).or_insert_with(Vec::new).push(rule);
    }

    pub fn validate(&self, field: &str, value: &str) -> ValidationResult {
        let mut result = ValidationResult::new();

        if let Some(rules) = self.rules.get(field) {
            for rule in rules {
                match rule {
                    ValidationRule::Required => {
                        if value.is_empty() {
                            result.add_error(format!("{} is required", field));
                        }
                    }
                    ValidationRule::MinLength(min) => {
                        if value.len() < *min {
                            result.add_error(format!("{} must be at least {} characters", field, min));
                        }
                    }
                    ValidationRule::MaxLength(max) => {
                        if value.len() > *max {
                            result.add_error(format!("{} must not exceed {} characters", field, max));
                        }
                    }
                    ValidationRule::Pattern(pattern) => {
                        if let Ok(regex) = Regex::new(pattern) {
                            if !regex.is_match(value) {
                                result.add_error(format!("{} does not match required pattern", field));
                            }
                        }
                    }
                    ValidationRule::Email => {
                        if let Some(pattern) = self.common_patterns.get("email") {
                            if let Ok(regex) = Regex::new(pattern) {
                                if !regex.is_match(value) {
                                    result.add_error(format!("{} is not a valid email", field));
                                }
                            }
                        }
                    }
                    ValidationRule::URL => {
                        if let Some(pattern) = self.common_patterns.get("url") {
                            if let Ok(regex) = Regex::new(pattern) {
                                if !regex.is_match(value) {
                                    result.add_error(format!("{} is not a valid URL", field));
                                }
                            }
                        }
                    }
                    ValidationRule::IPv4 => {
                        if let Some(pattern) = self.common_patterns.get("ipv4") {
                            if let Ok(regex) = Regex::new(pattern) {
                                if !regex.is_match(value) {
                                    result.add_error(format!("{} is not a valid IPv4 address", field));
                                }
                            }
                        }
                    }
                    ValidationRule::NoSQLInjection => {
                        if self.contains_sql_injection(value) {
                            result.add_error(format!("{} contains potential SQL injection", field));
                        }
                    }
                    ValidationRule::NoXSS => {
                        if self.contains_xss(value) {
                            result.add_error(format!("{} contains potential XSS payload", field));
                        }
                    }
                    ValidationRule::AlphanumericOnly => {
                        if let Some(pattern) = self.common_patterns.get("alphanumeric") {
                            if let Ok(regex) = Regex::new(pattern) {
                                if !regex.is_match(value) {
                                    result.add_error(format!("{} must contain only alphanumeric characters", field));
                                }
                            }
                        }
                    }
                    ValidationRule::NumericOnly => {
                        if let Some(pattern) = self.common_patterns.get("numeric") {
                            if let Ok(regex) = Regex::new(pattern) {
                                if !regex.is_match(value) {
                                    result.add_error(format!("{} must contain only numeric characters", field));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        result
    }

    pub fn sanitize(&self, field: &str, value: &str) -> String {
        let mut sanitized = value.to_string();

        if let Some(rules) = self.sanitization_rules.get(field) {
            for rule in rules {
                sanitized = match rule {
                    SanitizationRule::TrimWhitespace => sanitized.trim().to_string(),
                    SanitizationRule::RemoveSpecialChars => {
                        sanitized.chars().filter(|c| c.is_alphanumeric() || *c == '_').collect()
                    }
                    SanitizationRule::HTMLEncode => {
                        sanitized
                            .replace("&", "&amp;")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;")
                            .replace("\"", "&quot;")
                            .replace("'", "&#39;")
                    }
                    SanitizationRule::RemoveNulls => {
                        sanitized.replace("\0", "")
                    }
                    SanitizationRule::RemoveScriptTags => {
                        sanitized.replace("<script", "<scr1pt")
                            .replace("</script>", "</scr1pt>")
                    }
                    _ => sanitized,
                };
            }
        }

        sanitized
    }

    fn contains_sql_injection(&self, value: &str) -> bool {
        let sql_keywords = vec!["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "OR", "AND"];
        let upper_value = value.to_uppercase();

        sql_keywords.iter().any(|keyword| {
            upper_value.contains(&format!(" {} ", keyword))
                || upper_value.contains(&format!("({}", keyword))
                || upper_value.contains(&format!("{}(", keyword))
        })
    }

    fn contains_xss(&self, value: &str) -> bool {
        let xss_patterns = vec![
            "<script", "</script>", "onerror=", "onclick=", "onload=",
            "javascript:", "alert(", "document.", "window.",
        ];

        let lower_value = value.to_lowercase();
        xss_patterns.iter().any(|pattern| lower_value.contains(pattern))
    }
}

impl Default for InputValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_validation() {
        let validator = InputValidator::new();
        let validator_copy = InputValidator::new();
        let mut validator_mut = validator_copy;
        validator_mut.add_rule("email".to_string(), ValidationRule::Email);

        let result = validator_mut.validate("email", "test@example.com");
        assert!(result.valid);
    }

    #[test]
    fn test_sql_injection_detection() {
        let validator = InputValidator::new();
        assert!(validator.contains_sql_injection("id=1 OR 1=1"));
        assert!(validator.contains_sql_injection("id=1 UNION SELECT username FROM users"));
        assert!(!validator.contains_sql_injection("normal text"));
    }

    #[test]
    fn test_xss_detection() {
        let validator = InputValidator::new();
        assert!(validator.contains_xss("<script>alert('xss')</script>"));
        assert!(!validator.contains_xss("normal text"));
    }

    #[test]
    fn test_html_sanitization() {
        let validator = InputValidator::new();
        let mut validator_mut = validator;
        validator_mut.add_sanitization("content".to_string(), SanitizationRule::HTMLEncode);

        let sanitized = validator_mut.sanitize("content", "<script>alert('xss')</script>");
        assert!(!sanitized.contains("<"));
    }
}
