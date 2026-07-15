pub mod codecs;

use crate::Result;
use serde::{Deserialize, Serialize};

pub use codecs::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodeResult {
    pub input: String,
    pub output: String,
    pub encoding_type: String,
    pub success: bool,
    pub error: Option<String>,
}

pub struct Decoder;

impl Decoder {
    /// Decode input using specified encoding type
    pub fn decode(input: &str, encoding_type: &str) -> DecodeResult {
        let (output, success, error) = match encoding_type.to_lowercase().as_str() {
            "base64" => {
                match Base64Codec::decode(input) {
                    Ok(decoded) => (decoded, true, None),
                    Err(e) => (String::new(), false, Some(e.to_string())),
                }
            }
            "hex" => {
                match HexCodec::decode(input) {
                    Ok(decoded) => (decoded, true, None),
                    Err(e) => (String::new(), false, Some(e.to_string())),
                }
            }
            "url" => {
                match UrlCodec::decode(input) {
                    Ok(decoded) => (decoded, true, None),
                    Err(e) => (String::new(), false, Some(e.to_string())),
                }
            }
            "html" => {
                match HtmlCodec::decode(input) {
                    Ok(decoded) => (decoded, true, None),
                    Err(e) => (String::new(), false, Some(e.to_string())),
                }
            }
            "jwt" => {
                match JwtCodec::decode(input) {
                    Ok(decoded) => (decoded, true, None),
                    Err(e) => (String::new(), false, Some(e.to_string())),
                }
            }
            "utf8" => {
                match Utf8Codec::decode(input) {
                    Ok(decoded) => (decoded, true, None),
                    Err(e) => (String::new(), false, Some(e.to_string())),
                }
            }
            "rot13" => {
                (Rot13Codec::decode(input), true, None)
            }
            "ascii" => {
                match AsciiCodec::decode(input) {
                    Ok(decoded) => (decoded, true, None),
                    Err(e) => (String::new(), false, Some(e.to_string())),
                }
            }
            _ => (
                String::new(),
                false,
                Some(format!("Unknown encoding type: {}", encoding_type)),
            ),
        };

        DecodeResult {
            input: input.to_string(),
            output,
            encoding_type: encoding_type.to_string(),
            success,
            error,
        }
    }

    /// Encode input using specified encoding type
    pub fn encode(input: &str, encoding_type: &str) -> DecodeResult {
        let (output, success, error) = match encoding_type.to_lowercase().as_str() {
            "base64" => {
                match Base64Codec::encode(input) {
                    Ok(encoded) => (encoded, true, None),
                    Err(e) => (String::new(), false, Some(e.to_string())),
                }
            }
            "hex" => {
                match HexCodec::encode(input) {
                    Ok(encoded) => (encoded, true, None),
                    Err(e) => (String::new(), false, Some(e.to_string())),
                }
            }
            "url" => {
                match UrlCodec::encode(input) {
                    Ok(encoded) => (encoded, true, None),
                    Err(e) => (String::new(), false, Some(e.to_string())),
                }
            }
            "html" => {
                match HtmlCodec::encode(input) {
                    Ok(encoded) => (encoded, true, None),
                    Err(e) => (String::new(), false, Some(e.to_string())),
                }
            }
            "utf8" => {
                match Utf8Codec::encode(input) {
                    Ok(encoded) => (encoded, true, None),
                    Err(e) => (String::new(), false, Some(e.to_string())),
                }
            }
            "rot13" => {
                (Rot13Codec::encode(input), true, None)
            }
            "ascii" => {
                match AsciiCodec::encode(input) {
                    Ok(encoded) => (encoded, true, None),
                    Err(e) => (String::new(), false, Some(e.to_string())),
                }
            }
            _ => (
                String::new(),
                false,
                Some(format!("Unknown encoding type: {}", encoding_type)),
            ),
        };

        DecodeResult {
            input: input.to_string(),
            output,
            encoding_type: encoding_type.to_string(),
            success,
            error,
        }
    }

    /// Auto-detect encoding type
    pub fn auto_detect(input: &str) -> Option<String> {
        if let Ok(_) = Base64Codec::decode(input) {
            return Some("base64".to_string());
        }

        if let Ok(_) = HexCodec::decode(input) {
            return Some("hex".to_string());
        }

        if input.contains("%") {
            return Some("url".to_string());
        }

        if input.contains("&") && input.contains(";") {
            return Some("html".to_string());
        }

        if input.split('.').count() == 3 {
            if let Ok(_) = JwtCodec::decode(input) {
                return Some("jwt".to_string());
            }
        }

        None
    }

    /// List all supported encodings
    pub fn supported_encodings() -> Vec<&'static str> {
        vec![
            "base64", "hex", "url", "html", "jwt", "utf8", "rot13", "ascii",
        ]
    }

    /// Legacy compatibility methods
    pub fn url_encode(input: &str) -> String {
        urlencoding::encode(input).to_string()
    }

    pub fn url_decode(input: &str) -> Result<String> {
        urlencoding::decode(input)
            .map(|s| s.to_string())
            .map_err(|_| crate::Error::ScannerError("Decode error".into()))
    }

    pub fn base64_encode(input: &[u8]) -> String {
        use base64::{engine::general_purpose, Engine as _};
        general_purpose::STANDARD.encode(input)
    }

    pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
        use base64::{engine::general_purpose, Engine as _};
        general_purpose::STANDARD
            .decode(input)
            .map_err(|_| crate::Error::ScannerError("Base64 decode error".into()))
    }

    pub fn hex_encode(input: &[u8]) -> String {
        input.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn hex_decode(input: &str) -> Result<Vec<u8>> {
        if input.len() % 2 != 0 {
            return Err(crate::Error::ScannerError("Invalid hex string length".into()));
        }

        (0..input.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&input[i..i + 2], 16)
                    .map_err(|_| crate::Error::ScannerError("Hex decode error".into()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode_decode() {
        let result = Decoder::encode("hello world", "base64");
        assert!(result.success);

        let decoded = Decoder::decode(&result.output, "base64");
        assert!(decoded.success);
        assert_eq!(decoded.output, "hello world");
    }

    #[test]
    fn test_hex_encode_decode() {
        let result = Decoder::encode("test", "hex");
        assert!(result.success);

        let decoded = Decoder::decode(&result.output, "hex");
        assert!(decoded.success);
        assert_eq!(decoded.output, "test");
    }

    #[test]
    fn test_url_encode_decode() {
        let result = Decoder::encode("hello world", "url");
        assert!(result.success);

        let decoded = Decoder::decode(&result.output, "url");
        assert!(decoded.success);
        assert_eq!(decoded.output, "hello world");
    }

    #[test]
    fn test_rot13() {
        let encoded = Rot13Codec::encode("hello");
        let decoded = Rot13Codec::decode(&encoded);
        assert_eq!(decoded, "hello");
    }

    #[test]
    fn test_supported_encodings() {
        let encodings = Decoder::supported_encodings();
        assert!(encodings.contains(&"base64"));
        assert!(encodings.contains(&"hex"));
        assert!(encodings.contains(&"url"));
    }
}
