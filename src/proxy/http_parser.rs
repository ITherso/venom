use crate::Result;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

pub struct HttpParser;

impl HttpParser {
    pub fn parse_request(data: &[u8]) -> Result<(HttpRequest, usize)> {
        let text = String::from_utf8_lossy(data);
        let lines: Vec<&str> = text.split("\r\n").collect();

        if lines.is_empty() {
            return Err(crate::Error::ProxyError("Empty request".into()));
        }

        // Parse request line: GET /path HTTP/1.1
        let request_line_parts: Vec<&str> = lines[0].split_whitespace().collect();
        if request_line_parts.len() < 3 {
            return Err(crate::Error::ProxyError("Invalid request line".into()));
        }

        let method = request_line_parts[0].to_string();
        let path = request_line_parts[1].to_string();
        let version = request_line_parts[2].to_string();

        // Parse headers
        let mut headers = HashMap::new();
        let mut body_start = 0;

        for (i, line) in lines.iter().enumerate().skip(1) {
            if line.is_empty() {
                body_start = i;
                break;
            }

            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_lowercase(), value.trim().to_string());
            }
        }

        // Parse body
        let body = if body_start > 0 {
            lines[body_start + 1..].join("\r\n").into_bytes()
        } else {
            Vec::new()
        };

        Ok((
            HttpRequest {
                method,
                path,
                version,
                headers,
                body,
            },
            data.len(),
        ))
    }

    pub fn parse_response(data: &[u8]) -> Result<(HttpResponse, usize)> {
        let text = String::from_utf8_lossy(data);
        let lines: Vec<&str> = text.split("\r\n").collect();

        if lines.is_empty() {
            return Err(crate::Error::ProxyError("Empty response".into()));
        }

        // Parse status line: HTTP/1.1 200 OK
        let status_line_parts: Vec<&str> = lines[0].split_whitespace().collect();
        if status_line_parts.len() < 2 {
            return Err(crate::Error::ProxyError("Invalid status line".into()));
        }

        let version = status_line_parts[0].to_string();
        let status_code: u16 = status_line_parts[1]
            .parse()
            .map_err(|_| crate::Error::ProxyError("Invalid status code".into()))?;
        let reason = status_line_parts[2..].join(" ");

        // Parse headers
        let mut headers = HashMap::new();
        let mut body_start = 0;

        for (i, line) in lines.iter().enumerate().skip(1) {
            if line.is_empty() {
                body_start = i;
                break;
            }

            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_lowercase(), value.trim().to_string());
            }
        }

        // Parse body
        let body = if body_start > 0 {
            lines[body_start + 1..].join("\r\n").into_bytes()
        } else {
            Vec::new()
        };

        Ok((
            HttpResponse {
                version,
                status_code,
                reason,
                headers,
                body,
            },
            data.len(),
        ))
    }

    pub fn serialize_request(req: &HttpRequest) -> Vec<u8> {
        let mut result = format!("{} {} {}\r\n", req.method, req.path, req.version);

        for (key, value) in &req.headers {
            result.push_str(&format!("{}: {}\r\n", key, value));
        }

        result.push_str("\r\n");
        let mut bytes = result.into_bytes();
        bytes.extend_from_slice(&req.body);
        bytes
    }

    pub fn serialize_response(res: &HttpResponse) -> Vec<u8> {
        let mut result = format!("{} {} {}\r\n", res.version, res.status_code, res.reason);

        for (key, value) in &res.headers {
            result.push_str(&format!("{}: {}\r\n", key, value));
        }

        result.push_str("\r\n");
        let mut bytes = result.into_bytes();
        bytes.extend_from_slice(&res.body);
        bytes
    }
}
