use std::fmt;

#[derive(Debug)]
pub enum Error {
    ProxyError(String),
    ScannerError(String),
    DatabaseError(String),
    NetworkError(String),
    IoError(std::io::Error),
    JsonError(serde_json::Error),
    ReqwestError(reqwest::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ProxyError(e) => write!(f, "Proxy error: {}", e),
            Error::ScannerError(e) => write!(f, "Scanner error: {}", e),
            Error::DatabaseError(e) => write!(f, "Database error: {}", e),
            Error::NetworkError(e) => write!(f, "Network error: {}", e),
            Error::IoError(e) => write!(f, "IO error: {}", e),
            Error::JsonError(e) => write!(f, "JSON error: {}", e),
            Error::ReqwestError(e) => write!(f, "HTTP error: {}", e),
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

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::ReqwestError(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
