use std::fmt;

/// VENOM error types
#[derive(Debug)]
pub enum Error {
    ProxyError(String),
    ScannerError(String),
    ApiError(String),
    IoError(std::io::Error),
    JsonError(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ProxyError(e) => write!(f, "Proxy error: {}", e),
            Error::ScannerError(e) => write!(f, "Scanner error: {}", e),
            Error::ApiError(e) => write!(f, "API error: {}", e),
            Error::IoError(e) => write!(f, "IO error: {}", e),
            Error::JsonError(e) => write!(f, "JSON error: {}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::JsonError(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
