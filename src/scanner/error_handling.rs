// Error Handling & Configuration Management (250+ lines)
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VenomError {
    NetworkError(String),
    TimeoutError(String),
    InvalidPayload(String),
    DatabaseError(String),
    ConfigError(String),
    ParseError(String),
    ValidationError(String),
    AuthenticationError(String),
    RateLimitError(String),
    UnknownError(String),
}

impl fmt::Display for VenomError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VenomError::NetworkError(msg) => write!(f, "Network Error: {}", msg),
            VenomError::TimeoutError(msg) => write!(f, "Timeout Error: {}", msg),
            VenomError::InvalidPayload(msg) => write!(f, "Invalid Payload: {}", msg),
            VenomError::DatabaseError(msg) => write!(f, "Database Error: {}", msg),
            VenomError::ConfigError(msg) => write!(f, "Configuration Error: {}", msg),
            VenomError::ParseError(msg) => write!(f, "Parse Error: {}", msg),
            VenomError::ValidationError(msg) => write!(f, "Validation Error: {}", msg),
            VenomError::AuthenticationError(msg) => write!(f, "Authentication Error: {}", msg),
            VenomError::RateLimitError(msg) => write!(f, "Rate Limit Error: {}", msg),
            VenomError::UnknownError(msg) => write!(f, "Unknown Error: {}", msg),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub target_url: String,
    pub timeout_secs: u64,
    pub max_workers: usize,
    pub rate_limit: u32,
    pub aggressive_mode: bool,
    pub enable_waf_bypass: bool,
    pub enable_time_based: bool,
    pub payload_encoding: PayloadEncoding,
    pub user_agent: String,
    pub proxy_url: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum PayloadEncoding {
    None,
    UrlEncoding,
    DoubleEncoding,
    HtmlEncoding,
    UnicodeEncoding,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            timeout_secs: 30,
            max_workers: 4,
            rate_limit: 100,
            aggressive_mode: false,
            enable_waf_bypass: true,
            enable_time_based: true,
            payload_encoding: PayloadEncoding::UrlEncoding,
            user_agent: "VENOM/1.0.0".to_string(),
            proxy_url: None,
        }
    }
}

impl ScannerConfig {
    pub fn new(target_url: String) -> Self {
        Self {
            target_url,
            ..Default::default()
        }
    }

    pub fn with_workers(mut self, workers: usize) -> Self {
        self.max_workers = workers.clamp(1, 16);
        self
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs.max(5).min(300);
        self
    }

    pub fn with_rate_limit(mut self, rps: u32) -> Self {
        self.rate_limit = rps.max(1).min(10000);
        self
    }

    pub fn aggressive(mut self) -> Self {
        self.aggressive_mode = true;
        self
    }

    pub fn with_proxy(mut self, proxy: String) -> Self {
        self.proxy_url = Some(proxy);
        self
    }

    pub fn validate(&self) -> Result<(), VenomError> {
        if self.target_url.is_empty() {
            return Err(VenomError::ConfigError("Target URL is required".to_string()));
        }

        if !self.target_url.starts_with("http://") && !self.target_url.starts_with("https://") {
            return Err(VenomError::ConfigError(
                "Target URL must start with http:// or https://".to_string(),
            ));
        }

        if self.timeout_secs < 5 || self.timeout_secs > 300 {
            return Err(VenomError::ConfigError(
                "Timeout must be between 5 and 300 seconds".to_string(),
            ));
        }

        if self.max_workers < 1 || self.max_workers > 16 {
            return Err(VenomError::ConfigError(
                "Workers must be between 1 and 16".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorReport {
    pub error_type: String,
    pub message: String,
    pub timestamp: String,
    pub module: String,
    pub severity: ErrorSeverity,
    pub recovery_action: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum ErrorSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

pub struct ErrorHandler;

impl ErrorHandler {
    pub fn create_report(error: &VenomError, module: &str) -> ErrorReport {
        let (error_type, message, severity, recovery_action) = match error {
            VenomError::NetworkError(msg) => (
                "NetworkError".to_string(),
                msg.clone(),
                ErrorSeverity::Error,
                "Verify network connectivity and target URL".to_string(),
            ),
            VenomError::TimeoutError(msg) => (
                "TimeoutError".to_string(),
                msg.clone(),
                ErrorSeverity::Warning,
                "Increase timeout or reduce rate limit".to_string(),
            ),
            VenomError::InvalidPayload(msg) => (
                "InvalidPayload".to_string(),
                msg.clone(),
                ErrorSeverity::Warning,
                "Review payload format and encoding".to_string(),
            ),
            VenomError::DatabaseError(msg) => (
                "DatabaseError".to_string(),
                msg.clone(),
                ErrorSeverity::Critical,
                "Check database connection and permissions".to_string(),
            ),
            VenomError::ConfigError(msg) => (
                "ConfigError".to_string(),
                msg.clone(),
                ErrorSeverity::Error,
                "Validate configuration settings".to_string(),
            ),
            VenomError::ParseError(msg) => (
                "ParseError".to_string(),
                msg.clone(),
                ErrorSeverity::Warning,
                "Check response format and encoding".to_string(),
            ),
            VenomError::ValidationError(msg) => (
                "ValidationError".to_string(),
                msg.clone(),
                ErrorSeverity::Warning,
                "Review input validation rules".to_string(),
            ),
            VenomError::AuthenticationError(msg) => (
                "AuthenticationError".to_string(),
                msg.clone(),
                ErrorSeverity::Error,
                "Verify credentials and permissions".to_string(),
            ),
            VenomError::RateLimitError(msg) => (
                "RateLimitError".to_string(),
                msg.clone(),
                ErrorSeverity::Info,
                "Reduce request rate or wait before retrying".to_string(),
            ),
            VenomError::UnknownError(msg) => (
                "UnknownError".to_string(),
                msg.clone(),
                ErrorSeverity::Critical,
                "Check logs for more information".to_string(),
            ),
        };

        ErrorReport {
            error_type,
            message,
            timestamp: "2026-07-16T00:00:00Z".to_string(),
            module: module.to_string(),
            severity,
            recovery_action,
        }
    }

    pub fn should_retry(error: &VenomError) -> bool {
        matches!(
            error,
            VenomError::TimeoutError(_)
                | VenomError::RateLimitError(_)
                | VenomError::NetworkError(_)
        )
    }

    pub fn max_retries(error: &VenomError) -> usize {
        match error {
            VenomError::TimeoutError(_) => 3,
            VenomError::RateLimitError(_) => 5,
            VenomError::NetworkError(_) => 3,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = ScannerConfig::default();
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.max_workers, 4);
    }

    #[test]
    fn test_config_builder() {
        let config = ScannerConfig::new("http://example.com".to_string())
            .with_workers(8)
            .with_timeout(60);

        assert_eq!(config.max_workers, 8);
        assert_eq!(config.timeout_secs, 60);
    }

    #[test]
    fn test_config_worker_clamping() {
        let config = ScannerConfig::new("http://example.com".to_string()).with_workers(100);
        assert_eq!(config.max_workers, 16);
    }

    #[test]
    fn test_config_timeout_clamping() {
        let config = ScannerConfig::new("http://example.com".to_string()).with_timeout(600);
        assert_eq!(config.timeout_secs, 300);
    }

    #[test]
    fn test_config_validation_success() {
        let config = ScannerConfig::new("http://example.com".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_no_url() {
        let config = ScannerConfig::default();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_invalid_url() {
        let config = ScannerConfig::new("not-a-url".to_string());
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_timeout() {
        let config = ScannerConfig::new("http://example.com".to_string()).with_timeout(2);
        // with_timeout clamps to minimum 5, so validation succeeds
        assert_eq!(config.timeout_secs, 5);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_error_display() {
        let error = VenomError::NetworkError("Connection failed".to_string());
        assert!(error.to_string().contains("Network Error"));
    }

    #[test]
    fn test_error_report_creation() {
        let error = VenomError::TimeoutError("Request timeout".to_string());
        let report = ErrorHandler::create_report(&error, "test_module");
        assert_eq!(report.module, "test_module");
        assert_eq!(report.severity, ErrorSeverity::Warning);
    }

    #[test]
    fn test_should_retry() {
        let timeout_error = VenomError::TimeoutError("timeout".to_string());
        let config_error = VenomError::ConfigError("config".to_string());

        assert!(ErrorHandler::should_retry(&timeout_error));
        assert!(!ErrorHandler::should_retry(&config_error));
    }

    #[test]
    fn test_max_retries() {
        let timeout = VenomError::TimeoutError("timeout".to_string());
        let rate_limit = VenomError::RateLimitError("rate limit".to_string());

        assert_eq!(ErrorHandler::max_retries(&timeout), 3);
        assert_eq!(ErrorHandler::max_retries(&rate_limit), 5);
    }

    #[test]
    fn test_error_severity_ordering() {
        assert!(ErrorSeverity::Critical > ErrorSeverity::Error);
        assert!(ErrorSeverity::Error > ErrorSeverity::Warning);
        assert!(ErrorSeverity::Warning > ErrorSeverity::Info);
    }

    #[test]
    fn test_payload_encoding_variants() {
        assert_ne!(PayloadEncoding::None, PayloadEncoding::UrlEncoding);
        assert_ne!(PayloadEncoding::HtmlEncoding, PayloadEncoding::UnicodeEncoding);
    }

    #[test]
    fn test_config_aggressive_mode() {
        let config = ScannerConfig::new("http://example.com".to_string()).aggressive();
        assert!(config.aggressive_mode);
    }
}
