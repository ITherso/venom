//! Scan pipeline orchestration with phase execution and finding aggregation
//!
//! The ScanRunner coordinates sequential execution of all 9 scanning phases,
//! manages error handling, and aggregates findings with timing metrics.

use crate::{ScanFinding, ScanPhase, context::ScanContext, LogEntry, LogLevel};
use std::sync::Arc;
use std::time::Instant;

/// Orchestrates multi-phase scanning pipeline
///
/// - Maintains phase registry in execution order
/// - Tracks timing for performance metrics
/// - Aggregates findings from all phases
/// - Handles phase-level errors gracefully
pub struct ScanRunner {
    phases: Vec<Box<dyn ScanPhase>>,
}

impl ScanRunner {
    /// Creates a new empty runner
    pub fn new() -> Self {
        Self { phases: Vec::new() }
    }

    /// Registers a phase for execution
    ///
    /// Automatically maintains phases in order by phase_number()
    pub fn register_phase(&mut self, phase: Box<dyn ScanPhase>) {
        self.phases.push(phase);
        // Sort by phase number to ensure proper execution order
        self.phases.sort_by_key(|p| p.phase_number());
    }

    /// Executes all registered phases sequentially
    ///
    /// # Process
    /// 1. For each phase (in order):
    ///    - Log phase start with structured logging
    ///    - Execute phase with timeout
    ///    - Log completion with timing metrics
    ///    - Aggregate findings
    /// 2. Return combined findings from all phases
    ///
    /// # Error Handling
    /// Phase errors are logged but don't halt pipeline. Returns partial results.
    pub async fn run_pipeline(&self, ctx: ScanContext) -> Vec<ScanFinding> {
        let mut all_findings = Vec::new();
        let ctx_arc = Arc::new(ctx);

        for phase in &self.phases {
            let phase_num = phase.phase_number();
            let phase_name = phase.name();
            let start = Instant::now();

            // Log structured phase start
            let start_entry = LogEntry::new(
                LogLevel::Info,
                format!("Starting Phase {}: {}", phase_num, phase_name),
            )
            .with_phase(phase_num);
            ctx_arc.logger.log(start_entry);
            ctx_arc.log(format!("[*] Phase {}: {}", phase_num, phase_name));

            // Execute phase with implicit timeout from HTTP client config
            match phase.execute(&ctx_arc).await {
                Ok(findings) => {
                    let elapsed = start.elapsed().as_millis() as u64;
                    let finding_count = findings.len();

                    // Log structured completion
                    let complete_entry = LogEntry::new(
                        LogLevel::Info,
                        format!("Phase {} completed: {} findings", phase_num, finding_count),
                    )
                    .with_phase(phase_num)
                    .with_duration(elapsed);
                    ctx_arc.logger.log(complete_entry);
                    ctx_arc.log(format!(
                        "[+] Phase {} complete: {} findings in {}ms",
                        phase_num, finding_count, elapsed
                    ));

                    all_findings.extend(findings);
                }
                Err(e) => {
                    let elapsed = start.elapsed().as_millis() as u64;

                    // Log error with context
                    let error_entry = LogEntry::new(
                        LogLevel::Error,
                        format!("Phase {} failed: {}", phase_num, e),
                    )
                    .with_phase(phase_num)
                    .with_duration(elapsed);
                    ctx_arc.logger.log(error_entry);
                    ctx_arc.log(format!("[-] Phase {} error: {:?}", phase_num, e));
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
