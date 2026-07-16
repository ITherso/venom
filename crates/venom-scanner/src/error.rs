use std::fmt;

#[derive(Debug)]
pub enum ScannerError {
    NetworkError(String),
    UrlParseError(String),
    PayloadGenerationError(String),
    PhaseTimeout,
    InvalidTarget,
    IoError(std::io::Error),
}

impl fmt::Display for ScannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScannerError::NetworkError(e) => write!(f, "Network error: {}", e),
            ScannerError::UrlParseError(e) => write!(f, "URL parse error: {}", e),
            ScannerError::PayloadGenerationError(e) => write!(f, "Payload generation error: {}", e),
            ScannerError::PhaseTimeout => write!(f, "Phase execution timeout"),
            ScannerError::InvalidTarget => write!(f, "Invalid target URL"),
            ScannerError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for ScannerError {}

impl From<reqwest::Error> for ScannerError {
    fn from(err: reqwest::Error) -> Self {
        ScannerError::NetworkError(err.to_string())
    }
}

impl From<url::ParseError> for ScannerError {
    fn from(err: url::ParseError) -> Self {
        ScannerError::UrlParseError(err.to_string())
    }
}

impl From<std::io::Error> for ScannerError {
    fn from(err: std::io::Error) -> Self {
        ScannerError::IoError(err)
    }
}

pub type Result<T> = std::result::Result<T, ScannerError>;
