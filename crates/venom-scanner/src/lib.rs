// VENOM Scanner - Professional multi-phase vulnerability scanner
pub mod context;
pub mod error;
pub mod phases;
pub mod runner;

pub use context::ScanContext;
pub use error::{ScannerError, Result};
pub use runner::ScanRunner;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub phase: u8,
    pub module_name: String,
    pub severity: String, // "CRITICAL", "HIGH", "MEDIUM", "LOW"
    pub description: String,
    pub evidence: String,
}

#[async_trait]
pub trait ScanPhase: Send + Sync {
    /// Phase number (1-10)
    fn phase_number(&self) -> u8;

    /// Phase name
    fn name(&self) -> &'static str;

    /// Execute phase logic
    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>>;
}
