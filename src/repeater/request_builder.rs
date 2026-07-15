use super::RepeaterRequest;

/// Builder for constructing complex requests
pub struct RequestBuilder {
    url: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
    cookies: Vec<(String, String)>,
    follow_redirects: bool,
    timeout_secs: u64,
}

impl RequestBuilder {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: None,
            cookies: vec![],
            follow_redirects: true,
            timeout_secs: 30,
        }
    }

    pub fn method(mut self, method: &str) -> Self {
        self.method = method.to_uppercase();
        self
    }

    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.push((key.to_string(), value.to_string()));
        self
    }

    pub fn body(mut self, body: &str) -> Self {
        self.body = Some(body.to_string());
        self
    }

    pub fn json_body<T: serde::Serialize>(mut self, data: &T) -> Self {
        if let Ok(json) = serde_json::to_string(data) {
            self.body = Some(json);
            self.headers.push(("Content-Type".to_string(), "application/json".to_string()));
        }
        self
    }

    pub fn cookie(mut self, name: &str, value: &str) -> Self {
        self.cookies.push((name.to_string(), value.to_string()));
        self
    }

    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    pub fn build(self) -> RepeaterRequest {
        RepeaterRequest {
            url: self.url,
            method: self.method,
            headers: self.headers,
            body: self.body,
            cookies: self.cookies,
            follow_redirects: self.follow_redirects,
            timeout_secs: self.timeout_secs,
        }
    }

    /// Parse request from curl command
    pub fn from_curl(curl_cmd: &str) -> Self {
        let mut builder = RequestBuilder::new("http://localhost");

        let parts: Vec<&str> = curl_cmd.split_whitespace().collect();
        let mut i = 0;

        while i < parts.len() {
            match parts[i] {
                "-X" | "--request" if i + 1 < parts.len() => {
                    builder = builder.method(parts[i + 1]);
                    i += 2;
                }
                "-H" | "--header" if i + 1 < parts.len() => {
                    let header = parts[i + 1];
                    if let Some((k, v)) = header.split_once(':') {
                        builder = builder.header(k.trim(), v.trim());
                    }
                    i += 2;
                }
                "-d" | "--data" if i + 1 < parts.len() => {
                    builder = builder.body(parts[i + 1]);
                    i += 2;
                }
                "-b" | "--cookie" if i + 1 < parts.len() => {
                    let cookie = parts[i + 1];
                    if let Some((k, v)) = cookie.split_once('=') {
                        builder = builder.cookie(k, v);
                    }
                    i += 2;
                }
                url if url.starts_with("http://") || url.starts_with("https://") => {
                    builder.url = url.to_string();
                    i += 1;
                }
                _ => i += 1,
            }
        }

        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_builder() {
        let req = RequestBuilder::new("http://example.com")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(r#"{"key":"value"}"#)
            .build();

        assert_eq!(req.url, "http://example.com");
        assert_eq!(req.method, "POST");
        assert_eq!(req.body, Some(r#"{"key":"value"}"#.to_string()));
    }

    #[test]
    fn test_from_curl() {
        let curl = r#"curl -X POST -H "Content-Type: application/json" -d '{"test":"data"}' http://api.example.com/endpoint"#;
        let req = RequestBuilder::from_curl(curl).build();

        assert_eq!(req.method, "POST");
    }
}
