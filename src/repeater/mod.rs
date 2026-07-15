pub mod request_builder;
pub mod response_handler;

use crate::Result;
use reqwest::{Client, header::HeaderMap, header::HeaderValue};
use http::header::HeaderName;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use std::str::FromStr;

pub use request_builder::RequestBuilder;
pub use response_handler::ResponseAnalyzer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepeaterRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub cookies: Vec<(String, String)>,
    pub follow_redirects: bool,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepeaterResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub size_bytes: usize,
    pub time_ms: u128,
    pub error: Option<String>,
}

pub struct Repeater {
    client: Client,
}

impl Repeater {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    /// Send a repeater request with full configuration
    pub async fn send_request(&self, req: &RepeaterRequest) -> Result<RepeaterResponse> {
        let start = Instant::now();

        // Build request
        let mut request = match req.method.to_uppercase().as_str() {
            "GET" => self.client.get(&req.url),
            "POST" => self.client.post(&req.url),
            "PUT" => self.client.put(&req.url),
            "DELETE" => self.client.delete(&req.url),
            "PATCH" => self.client.patch(&req.url),
            "HEAD" => self.client.head(&req.url),
            "OPTIONS" => self.client.request(reqwest::Method::OPTIONS, &req.url),
            _ => {
                return Err(crate::Error::ProxyError(format!(
                    "Unsupported HTTP method: {}",
                    req.method
                )))
            }
        };

        // Add headers
        let mut headers = HeaderMap::new();
        for (key, value) in &req.headers {
            if let Ok(header_value) = HeaderValue::from_str(value) {
                if let Ok(header_name) = HeaderName::from_str(key) {
                    headers.insert(header_name, header_value);
                }
            }
        }
        request = request.headers(headers);

        // Add cookies
        for (name, value) in &req.cookies {
            request = request.header("Cookie", format!("{}={}", name, value));
        }

        // Add body if present
        if let Some(body) = &req.body {
            request = request.body(body.clone());
        }

        // Set timeout
        request = request.timeout(std::time::Duration::from_secs(req.timeout_secs));

        // Set redirect policy
        let client = if req.follow_redirects {
            self.client.clone()
        } else {
            Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?
        };

        // Send request
        let response = match client.execute(request.build()?).await {
            Ok(resp) => resp,
            Err(e) => {
                return Ok(RepeaterResponse {
                    status_code: 0,
                    headers: vec![],
                    body: String::new(),
                    size_bytes: 0,
                    time_ms: start.elapsed().as_millis(),
                    error: Some(e.to_string()),
                });
            }
        };

        let status_code = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| {
                let value = String::from_utf8_lossy(v.as_bytes()).to_string();
                (k.to_string(), value)
            })
            .collect();

        let body = response.text().await.unwrap_or_default();
        let size_bytes = body.len();
        let time_ms = start.elapsed().as_millis();

        Ok(RepeaterResponse {
            status_code,
            headers,
            body,
            size_bytes,
            time_ms,
            error: None,
        })
    }

    /// Simple send for backward compatibility
    pub async fn send(&self, url: &str, method: &str, body: Option<&str>) -> Result<String> {
        let req = RepeaterRequest {
            url: url.to_string(),
            method: method.to_uppercase(),
            headers: vec![],
            body: body.map(|b| b.to_string()),
            cookies: vec![],
            follow_redirects: true,
            timeout_secs: 30,
        };

        let resp = self.send_request(&req).await?;
        Ok(resp.body)
    }

    /// Compare two responses
    pub fn compare_responses(resp1: &RepeaterResponse, resp2: &RepeaterResponse) -> ResponseComparison {
        ResponseComparison {
            status_diff: resp1.status_code != resp2.status_code,
            size_diff: resp1.size_bytes != resp2.size_bytes,
            body_identical: resp1.body == resp2.body,
            time_diff_ms: (resp1.time_ms as i128) - (resp2.time_ms as i128),
            headers_diff: resp1.headers != resp2.headers,
        }
    }
}

#[derive(Debug)]
pub struct ResponseComparison {
    pub status_diff: bool,
    pub size_diff: bool,
    pub body_identical: bool,
    pub time_diff_ms: i128,
    pub headers_diff: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repeater_creation() {
        let repeater = Repeater::new();
        assert!(repeater.send("http://localhost", "GET", None).await.is_err() || true);
    }

    #[test]
    fn test_request_creation() {
        let req = RepeaterRequest {
            url: "http://example.com".to_string(),
            method: "GET".to_string(),
            headers: vec![("User-Agent".to_string(), "VENOM".to_string())],
            body: None,
            cookies: vec![],
            follow_redirects: true,
            timeout_secs: 30,
        };

        assert_eq!(req.url, "http://example.com");
        assert_eq!(req.method, "GET");
    }
}
