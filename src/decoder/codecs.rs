use base64::{engine::general_purpose, Engine as _};
use serde_json::json;

/// Base64 encoding/decoding
pub struct Base64Codec;

impl Base64Codec {
    pub fn encode(input: &str) -> Result<String, String> {
        Ok(general_purpose::STANDARD.encode(input.as_bytes()))
    }

    pub fn decode(input: &str) -> Result<String, String> {
        match general_purpose::STANDARD.decode(input) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => Ok(s),
                Err(_) => Err("Invalid UTF-8 in decoded output".to_string()),
            },
            Err(e) => Err(format!("Base64 decode error: {}", e)),
        }
    }
}

/// Hexadecimal encoding/decoding
pub struct HexCodec;

impl HexCodec {
    pub fn encode(input: &str) -> Result<String, String> {
        Ok(input.as_bytes().iter().map(|b| format!("{:02x}", b)).collect())
    }

    pub fn decode(input: &str) -> Result<String, String> {
        if input.len() % 2 != 0 {
            return Err("Invalid hex string length".to_string());
        }

        let bytes = (0..input.len())
            .step_by(2)
            .filter_map(|i| {
                u8::from_str_radix(&input[i..i + 2], 16)
                    .ok()
            })
            .collect::<Vec<u8>>();

        String::from_utf8(bytes).map_err(|e| format!("UTF-8 error: {}", e))
    }
}

/// URL encoding/decoding
pub struct UrlCodec;

impl UrlCodec {
    pub fn encode(input: &str) -> Result<String, String> {
        Ok(urlencoding::encode(input).to_string())
    }

    pub fn decode(input: &str) -> Result<String, String> {
        urlencoding::decode(input)
            .map(|s| s.to_string())
            .map_err(|e| format!("URL decode error: {}", e))
    }
}

/// HTML entity encoding/decoding
pub struct HtmlCodec;

impl HtmlCodec {
    pub fn encode(input: &str) -> Result<String, String> {
        Ok(html_escape::encode_text(input).to_string())
    }

    pub fn decode(input: &str) -> Result<String, String> {
        Ok(html_escape::decode_html_entities(input).to_string())
    }
}

/// JWT decoding (header.payload.signature)
pub struct JwtCodec;

impl JwtCodec {
    pub fn decode(input: &str) -> Result<String, String> {
        let parts: Vec<&str> = input.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid JWT format (expected 3 parts)".to_string());
        }

        let mut result = String::new();

        // Decode header
        match general_purpose::STANDARD_NO_PAD.decode(parts[0]) {
            Ok(bytes) => {
                if let Ok(s) = String::from_utf8(bytes) {
                    result.push_str("HEADER:\n");
                    result.push_str(&s);
                    result.push('\n');
                }
            }
            Err(_) => return Err("Failed to decode JWT header".to_string()),
        }

        // Decode payload
        match general_purpose::STANDARD_NO_PAD.decode(parts[1]) {
            Ok(bytes) => {
                if let Ok(s) = String::from_utf8(bytes) {
                    result.push_str("PAYLOAD:\n");
                    result.push_str(&s);
                    result.push('\n');
                }
            }
            Err(_) => return Err("Failed to decode JWT payload".to_string()),
        }

        result.push_str("SIGNATURE:\n");
        result.push_str(parts[2]);

        Ok(result)
    }
}

/// UTF-8 byte representation
pub struct Utf8Codec;

impl Utf8Codec {
    pub fn encode(input: &str) -> Result<String, String> {
        let bytes: Vec<String> = input
            .as_bytes()
            .iter()
            .map(|b| format!("\\x{:02x}", b))
            .collect();
        Ok(bytes.join(""))
    }

    pub fn decode(input: &str) -> Result<String, String> {
        let mut bytes = Vec::new();
        let parts: Vec<&str> = input.split("\\x").collect();

        for part in parts.iter().skip(1) {
            if let Ok(byte) = u8::from_str_radix(part, 16) {
                bytes.push(byte);
            } else {
                return Err("Invalid UTF-8 escape sequence".to_string());
            }
        }

        String::from_utf8(bytes).map_err(|e| format!("UTF-8 error: {}", e))
    }
}

/// ROT13 encoding/decoding
pub struct Rot13Codec;

impl Rot13Codec {
    pub fn encode(input: &str) -> String {
        input
            .chars()
            .map(|c| match c {
                'a'..='z' => ((c as u32 - 'a' as u32 + 13) % 26 + 'a' as u32) as u8 as char,
                'A'..='Z' => ((c as u32 - 'A' as u32 + 13) % 26 + 'A' as u32) as u8 as char,
                _ => c,
            })
            .collect()
    }

    pub fn decode(input: &str) -> String {
        Self::encode(input)
    }
}

/// ASCII code representation
pub struct AsciiCodec;

impl AsciiCodec {
    pub fn encode(input: &str) -> Result<String, String> {
        let codes: Vec<String> = input
            .chars()
            .map(|c| (c as u32).to_string())
            .collect();
        Ok(codes.join(","))
    }

    pub fn decode(input: &str) -> Result<String, String> {
        let codes: Vec<&str> = input.split(',').collect();
        let mut result = String::new();

        for code_str in codes {
            match code_str.trim().parse::<u32>() {
                Ok(code) => {
                    if let Some(c) = char::from_u32(code) {
                        result.push(c);
                    } else {
                        return Err(format!("Invalid character code: {}", code));
                    }
                }
                Err(_) => return Err(format!("Invalid ASCII code: {}", code_str)),
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_codec() {
        let encoded = Base64Codec::encode("test").unwrap();
        let decoded = Base64Codec::decode(&encoded).unwrap();
        assert_eq!(decoded, "test");
    }

    #[test]
    fn test_hex_codec() {
        let encoded = HexCodec::encode("ABC").unwrap();
        let decoded = HexCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, "ABC");
    }

    #[test]
    fn test_url_codec() {
        let encoded = UrlCodec::encode("hello world").unwrap();
        let decoded = UrlCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, "hello world");
    }

    #[test]
    fn test_html_codec() {
        let encoded = HtmlCodec::encode("<script>").unwrap();
        assert!(encoded.contains("&lt;"));
    }

    #[test]
    fn test_rot13_codec() {
        let encoded = Rot13Codec::encode("hello");
        let decoded = Rot13Codec::decode(&encoded);
        assert_eq!(decoded, "hello");
    }

    #[test]
    fn test_ascii_codec() {
        let encoded = AsciiCodec::encode("AB").unwrap();
        let decoded = AsciiCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, "AB");
    }
}
