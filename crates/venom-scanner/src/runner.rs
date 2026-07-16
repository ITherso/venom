use crate::{ScanFinding, ScanPhase, context::ScanContext};
use std::sync::Arc;

pub struct ScanRunner {
    phases: Vec<Box<dyn ScanPhase>>,
}

impl ScanRunner {
    pub fn new() -> Self {
        Self { phases: Vec::new() }
    }

    pub fn register_phase(&mut self, phase: Box<dyn ScanPhase>) {
        self.phases.push(phase);
        // Sort by phase number to ensure proper execution order
        self.phases.sort_by_key(|p| p.phase_number());
    }

    pub async fn run_pipeline(&self, ctx: ScanContext) -> Vec<ScanFinding> {
        let mut all_findings = Vec::new();
        let ctx_arc = Arc::new(ctx);

        for phase in &self.phases {
            ctx_arc.log(format!(
                "[*] Executing Phase {} - {}",
                phase.phase_number(),
                phase.name()
            ));

            match phase.execute(&ctx_arc).await {
                Ok(findings) => {
                    ctx_arc.log(format!(
                        "[+] Phase {} completed successfully. Findings: {}",
                        phase.phase_number(),
                        findings.len()
                    ));
                    all_findings.extend(findings);
                }
                Err(e) => {
                    ctx_arc.log(format!(
                        "[-] Phase {} failed: {:?}",
                        phase.phase_number(),
                        e
                    ));
                }
            }
        }

        all_findings
    }
}

impl Default for ScanRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runner_creation() {
        let runner = ScanRunner::new();
        assert_eq!(runner.phases.len(), 0);
    }

    #[test]
    fn test_runner_phase_sorting() {
        use crate::phases::{ReconPhase, CrawlPhase, SqliScanner};

        let mut runner = ScanRunner::new();
        runner.register_phase(Box::new(SqliScanner));
        runner.register_phase(Box::new(ReconPhase));
        runner.register_phase(Box::new(CrawlPhase));

        assert_eq!(runner.phases[0].phase_number(), 1);
        assert_eq!(runner.phases[1].phase_number(), 2);
        assert_eq!(runner.phases[2].phase_number(), 5);
    }
}
