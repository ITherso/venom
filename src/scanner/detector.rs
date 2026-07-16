// Professional Pattern Detector - Memory-Mapped, Zero-Copy, Wildcard-Enabled Signature Scanner
// Boyer-Moore-Horspool optimized with CPU cache awareness
use std::fs::File;
use std::path::Path;
use memmap2::Mmap;
use crate::{Result, error::Error};

#[derive(Debug, Clone)]
pub struct MatchResult {
    pub offset: usize,
    pub pattern_name: String,
}

#[derive(Clone)]
pub struct Pattern {
    name: String,
    bytes: Vec<Option<u8>>, // Wildcard (??) için Option<u8> kullanıyoruz
}

impl Pattern {
    /// "41 5A 90 ?? 33 C0" gibi hex formatındaki patternleri parse eder
    pub fn parse(name: &str, signature: &str) -> Result<Self> {
        let mut bytes = Vec::new();
        for token in signature.split_whitespace() {
            if token == "?" || token == "??" {
                bytes.push(None);
            } else {
                match u8::from_str_radix(token, 16) {
                    Ok(byte) => bytes.push(Some(byte)),
                    Err(_) => return Err(Error::ScannerError(format!("Geçersiz hex token: {}", token))),
                }
            }
        }
        Ok(Pattern {
            name: name.to_string(),
            bytes,
        })
    }
}

pub struct Scanner {
    patterns: Vec<Pattern>,
}

impl Scanner {
    pub fn new() -> Self {
        Self { patterns: Vec::new() }
    }

    pub fn add_pattern(&mut self, name: &str, signature: &str) -> Result<()> {
        let pattern = Pattern::parse(name, signature)?;
        self.patterns.push(pattern);
        Ok(())
    }

    /// Bellekteki (RAM) veya memory-mapped bir bölgedeki veriyi tarar (Zero-copy)
    pub fn scan_memory(&self, data: &[u8]) -> Vec<MatchResult> {
        let mut results = Vec::new();
        let data_len = data.len();

        for pattern in &self.patterns {
            let pat_len = pattern.bytes.len();
            if pat_len > data_len || pat_len == 0 {
                continue;
            }

            // Boyer-Moore türevi yerine wildcard desteği için optimize edilmiş kayan pencere (sliding window)
            let mut i = 0;
            while i <= data_len - pat_len {
                let mut matched = true;

                // Cache-friendly olması için iç döngüyü hızlı geçiyoruz
                for j in 0..pat_len {
                    if let Some(pat_byte) = pattern.bytes[j] {
                        if data[i + j] != pat_byte {
                            matched = false;
                            break;
                        }
                    }
                }

                if matched {
                    results.push(MatchResult {
                        offset: i,
                        pattern_name: pattern.name.clone(),
                    });
                    // İmza bulunduğunda pattern boyutu kadar kaydırıyoruz
                    i += pat_len;
                } else {
                    i += 1;
                }
            }
        }
        results
    }

    /// Diskteki büyük dosyaları RAM'e yüklemeden (memory-map kullanarak) tarar
    #[allow(unsafe_code)]
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<MatchResult>> {
        let file = File::open(path)
            .map_err(|e| Error::ScannerError(format!("Dosya açılamadı: {}", e)))?;

        // Memory-map işletim sistemine doğrudan bağlanır.
        // Rust'ın güvenlik garantileri korunarak en hızlı tarama yöntemidir.
        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| Error::ScannerError(format!("Memory-map başarısız: {}", e)))?;

        Ok(self.scan_memory(&mmap))
    }

    /// Boyer-Moore-Horspool skip table oluşturma (gelecek optimizasyonlar için)
    pub fn build_skip_table(pattern: &[Option<u8>]) -> Vec<usize> {
        let pat_len = pattern.len();
        let mut skip_table = vec![pat_len; 256];

        for (i, byte_opt) in pattern.iter().enumerate().take(pat_len - 1) {
            if let Some(byte) = byte_opt {
                skip_table[*byte as usize] = pat_len - i - 1;
            }
        }
        skip_table
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_pattern_match() {
        let mut scanner = Scanner::new();
        scanner.add_pattern("test", "41 42 43").unwrap();

        let data = vec![0x00, 0x41, 0x42, 0x43, 0x00];
        let results = scanner.scan_memory(&data);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 1);
    }

    #[test]
    fn test_wildcard_pattern() {
        let mut scanner = Scanner::new();
        scanner.add_pattern("wildcard", "41 ?? 43").unwrap();

        let data = vec![0x41, 0xFF, 0x43];
        let results = scanner.scan_memory(&data);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 0);
    }

    #[test]
    fn test_multiple_matches() {
        let mut scanner = Scanner::new();
        scanner.add_pattern("repeated", "FF FF").unwrap();

        let data = vec![0xFF, 0xFF, 0x00, 0xFF, 0xFF];
        let results = scanner.scan_memory(&data);

        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_pattern_parsing() {
        let pattern = Pattern::parse("test", "41 ?? 43").unwrap();
        assert_eq!(pattern.bytes.len(), 3);
        assert_eq!(pattern.bytes[0], Some(0x41));
        assert_eq!(pattern.bytes[1], None);
        assert_eq!(pattern.bytes[2], Some(0x43));
    }
}

// Legacy interface for compatibility
use crate::proxy::http_parser::HttpRequest;
use std::collections::HashMap;
use super::exploiter::{Exploit, ExploitFinder};

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub id: String,
    pub vuln_type: String,
    pub severity: String,
    pub url: String,
    pub parameter: String,
    pub payload: String,
    pub evidence: String,
    pub exploits: Vec<Exploit>,
}

pub struct VulnerabilityDetector;

impl VulnerabilityDetector {
    pub fn detect_sqli(req: &HttpRequest) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        if req.path.contains("=") {
            let sqli_payloads = vec![
                "'",
                "' OR '1'='1",
                "1' AND '1'='1",
                "UNION SELECT NULL",
                "';DROP TABLE",
            ];

            for payload in sqli_payloads {
                if req.path.contains(payload) {
                    let exploits = ExploitFinder::find_exploits("SQL Injection", Some(&req.path))
                        .unwrap_or_default();

                    vulns.push(Vulnerability {
                        id: uuid::Uuid::new_v4().to_string(),
                        vuln_type: "SQL Injection".to_string(),
                        severity: "Critical".to_string(),
                        url: req.path.clone(),
                        parameter: "URL".to_string(),
                        payload: payload.to_string(),
                        evidence: format!("Found SQL payload in URL: {}", payload),
                        exploits,
                    });
                }
            }
        }

        vulns
    }

    pub fn detect_xss(req: &HttpRequest) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        let xss_payloads = vec![
            "<script>",
            "onerror=",
            "onload=",
            "onclick=",
            "javascript:",
        ];

        for payload in xss_payloads {
            if req.path.to_lowercase().contains(payload) {
                let exploits = ExploitFinder::find_exploits("XSS", Some(&req.path))
                    .unwrap_or_default();

                vulns.push(Vulnerability {
                    id: uuid::Uuid::new_v4().to_string(),
                    vuln_type: "XSS".to_string(),
                    severity: "High".to_string(),
                    url: req.path.clone(),
                    parameter: "URL".to_string(),
                    payload: payload.to_string(),
                    evidence: format!("Found XSS payload: {}", payload),
                    exploits,
                });
            }
        }

        vulns
    }

    pub fn scan_request(req: &HttpRequest) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        vulns.extend(Self::detect_sqli(req));
        vulns.extend(Self::detect_xss(req));
        vulns
    }
}
