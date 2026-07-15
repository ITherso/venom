pub mod gdpr;
pub mod hipaa;
pub mod soc2;
pub mod reporting;

pub use gdpr::{GDPRCompliance, DataProcessing, ConsentRecord};
pub use hipaa::{HIPAACompliance, PHIRecord, AccessLog};
pub use soc2::{SOC2Compliance, SecurityPolicy, ControlAssessment};
pub use reporting::{ComplianceReport, ReportFormat, AuditFinding};

#[derive(Debug, Clone)]
pub struct ComplianceConfig {
    pub gdpr_enabled: bool,
    pub hipaa_enabled: bool,
    pub soc2_enabled: bool,
    pub pci_dss_enabled: bool,
    pub audit_retention_days: u32,
    pub encryption_required: bool,
    pub data_minimization: bool,
    pub consent_tracking: bool,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            gdpr_enabled: true,
            hipaa_enabled: false,
            soc2_enabled: true,
            pci_dss_enabled: false,
            audit_retention_days: 2555, // 7 years
            encryption_required: true,
            data_minimization: true,
            consent_tracking: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceStatus {
    Compliant,
    PartiallyCompliant,
    NonCompliant,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ComplianceFramework {
    pub framework_name: String,
    pub status: ComplianceStatus,
    pub findings: Vec<String>,
    pub last_assessment: Option<chrono::DateTime<chrono::Utc>>,
}
