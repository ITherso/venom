use crate::{ScanFinding, ScanPhase, context::ScanContext, error::ScannerError};
use async_trait::async_trait;

pub struct ReconPhase;

#[async_trait]
impl ScanPhase for ReconPhase {
    fn phase_number(&self) -> u8 {
        1
    }

    fn name(&self) -> &'static str {
        "Reconnaissance & Port Scanning"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        ctx.log("Phase 1: Passive reconnaissance initiated...".to_string());
        let mut findings = Vec::new();

        // Passive recon: HEAD request to check server headers
        let target_str = ctx.target.to_string();
        match ctx.client.head(&target_str).send().await {
            Ok(response) => {
                ctx.log(format!("Target responded with status: {}", response.status()));

                // Check for Server header leakage
                if let Some(server) = response.headers().get("server") {
                    if let Ok(server_str) = server.to_str() {
                        ctx.log(format!("Server header: {}", server_str));

                        // Common vulnerable server versions
                        if server_str.contains("Apache/2.4.49") || server_str.contains("Apache/2.4.50") {
                            findings.push(ScanFinding {
                                phase: self.phase_number(),
                                module_name: self.name().to_string(),
                                severity: "HIGH".to_string(),
                                description: "Vulnerable Apache version detected (CVE-2021-41773 - Path Traversal)".to_string(),
                                evidence: format!("Server header: {}", server_str),
                            });
                        }
                    }
                }

                // Check for X-Powered-By header
                if let Some(powered_by) = response.headers().get("x-powered-by") {
                    if let Ok(tech) = powered_by.to_str() {
                        ctx.log(format!("X-Powered-By: {}", tech));
                        findings.push(ScanFinding {
                            phase: self.phase_number(),
                            module_name: self.name().to_string(),
                            severity: "LOW".to_string(),
                            description: "Technology fingerprint detected".to_string(),
                            evidence: format!("X-Powered-By: {}", tech),
                        });
                    }
                }
            }
            Err(e) => {
                ctx.log(format!("Failed to reach target: {}", e));
                return Err(ScannerError::from(e));
            }
        }

        ctx.log("Phase 1: Reconnaissance completed.".to_string());
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase_number() {
        let recon = ReconPhase;
        assert_eq!(recon.phase_number(), 1);
    }

    #[test]
    fn test_phase_name() {
        let recon = ReconPhase;
        assert_eq!(recon.name(), "Reconnaissance & Port Scanning");
    }
}
