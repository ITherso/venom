pub mod audit_logging;
pub mod rbac;
pub mod data_retention;
pub mod backup_restore;
pub mod disaster_recovery;
pub mod sla_monitoring;

pub use audit_logging::{AuditLogger, AuditEvent, AuditLevel};
pub use rbac::{RBACManager, Role, Permission, Subject};
pub use data_retention::{RetentionPolicy, RetentionManager};
pub use backup_restore::{BackupManager, BackupJob, RestoreJob};
pub use disaster_recovery::{DisasterRecoveryManager, RecoveryPoint};
pub use sla_monitoring::{SLAMonitor, SLAMetric, SLALevel};

#[derive(Debug, Clone)]
pub struct EnterpriseConfig {
    pub audit_enabled: bool,
    pub rbac_enabled: bool,
    pub backup_enabled: bool,
    pub disaster_recovery_enabled: bool,
    pub sla_monitoring_enabled: bool,
}

impl Default for EnterpriseConfig {
    fn default() -> Self {
        Self {
            audit_enabled: true,
            rbac_enabled: true,
            backup_enabled: true,
            disaster_recovery_enabled: true,
            sla_monitoring_enabled: true,
        }
    }
}
