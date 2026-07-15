pub mod payloads;
pub mod detector;
pub mod exploiter;

use crate::Result;
use crate::proxy::http_parser::HttpRequest;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub use detector::{Vulnerability, VulnerabilityDetector};
pub use exploiter::{Exploit, ExploitFinder};

#[derive(Debug, Clone)]
pub struct Scanner {
    client: Client,
    target: String,
    aggressive: bool,
}

impl Scanner {
    pub fn new(target: String, aggressive: bool) -> Self {
        Self {
            client: Client::new(),
            target,
            aggressive,
        }
    }

    pub fn scan_request(&self, req: &HttpRequest) -> Vec<Vulnerability> {
        VulnerabilityDetector::scan_request(req)
    }

    pub async fn scan(&self) -> Result<Vec<Vulnerability>> {
        // Passive scanning from captured requests
        // (will be integrated with proxy history in PHASE 3.2)
        Ok(Vec::new())
    }
}
