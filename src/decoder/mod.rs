use crate::Result;

pub struct Decoder;

impl Decoder {
    pub fn url_encode(input: &str) -> String {
        urlencoding::encode(input).to_string()
    }

    pub fn url_decode(input: &str) -> Result<String> {
        urlencoding::decode(input)
            .map(|s| s.to_string())
            .map_err(|_| crate::Error::ScannerError("Decode error".into()))
    }

    pub fn base64_encode(input: &[u8]) -> String {
        base64::encode(input)
    }

    pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
        base64::decode(input)
            .map_err(|_| crate::Error::ScannerError("Base64 decode error".into()))
    }

    pub fn hex_encode(input: &[u8]) -> String {
        hex::encode(input)
    }

    pub fn hex_decode(input: &str) -> Result<Vec<u8>> {
        hex::decode(input)
            .map_err(|_| crate::Error::ScannerError("Hex decode error".into()))
    }
}
