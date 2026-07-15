use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandContext {
    pub command: String,
    pub subcommand: Option<String>,
    pub args: Vec<String>,
    pub flags: HashMap<String, String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl CommandContext {
    pub fn new(command: String) -> Self {
        Self {
            command,
            subcommand: None,
            args: Vec::new(),
            flags: HashMap::new(),
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn with_subcommand(mut self, subcommand: String) -> Self {
        self.subcommand = Some(subcommand);
        self
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    pub fn with_flag(mut self, key: String, value: String) -> Self {
        self.flags.insert(key, value);
        self
    }

    pub fn get_flag(&self, key: &str) -> Option<&String> {
        self.flags.get(key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Command {
    // Scan commands
    ScanStart,
    ScanStatus,
    ScanStop,
    ScanList,
    ScanResults,

    // Backup commands
    BackupCreate,
    BackupRestore,
    BackupList,
    BackupSchedule,
    BackupStatus,

    // Deployment commands
    DeployStatus,
    DeployRollback,
    DeployHealth,
    DeployScale,

    // Monitoring commands
    SLAStatus,
    SLAReport,
    MetricsGet,
    AuditLog,

    // RBAC commands
    RoleCreate,
    RoleList,
    RoleDelete,
    UserCreate,
    UserList,
    UserDelete,
    PermissionGrant,
    PermissionRevoke,

    // Disaster Recovery commands
    DRPlanCreate,
    DRDrillStart,
    DRDrillStatus,
    DRFailover,
    DRHistory,

    // System commands
    Status,
    Config,
    Help,
    Version,
    Health,
    Reset,
}

impl Command {
    pub fn from_string(s: &str) -> Option<Self> {
        match s {
            "scan:start" => Some(Command::ScanStart),
            "scan:status" => Some(Command::ScanStatus),
            "scan:stop" => Some(Command::ScanStop),
            "scan:list" => Some(Command::ScanList),
            "scan:results" => Some(Command::ScanResults),
            "backup:create" => Some(Command::BackupCreate),
            "backup:restore" => Some(Command::BackupRestore),
            "backup:list" => Some(Command::BackupList),
            "backup:schedule" => Some(Command::BackupSchedule),
            "backup:status" => Some(Command::BackupStatus),
            "deploy:status" => Some(Command::DeployStatus),
            "deploy:rollback" => Some(Command::DeployRollback),
            "deploy:health" => Some(Command::DeployHealth),
            "deploy:scale" => Some(Command::DeployScale),
            "sla:status" => Some(Command::SLAStatus),
            "sla:report" => Some(Command::SLAReport),
            "metrics:get" => Some(Command::MetricsGet),
            "audit:log" => Some(Command::AuditLog),
            "role:create" => Some(Command::RoleCreate),
            "role:list" => Some(Command::RoleList),
            "role:delete" => Some(Command::RoleDelete),
            "user:create" => Some(Command::UserCreate),
            "user:list" => Some(Command::UserList),
            "user:delete" => Some(Command::UserDelete),
            "permission:grant" => Some(Command::PermissionGrant),
            "permission:revoke" => Some(Command::PermissionRevoke),
            "dr:plan:create" => Some(Command::DRPlanCreate),
            "dr:drill:start" => Some(Command::DRDrillStart),
            "dr:drill:status" => Some(Command::DRDrillStatus),
            "dr:failover" => Some(Command::DRFailover),
            "dr:history" => Some(Command::DRHistory),
            "status" => Some(Command::Status),
            "config" => Some(Command::Config),
            "help" => Some(Command::Help),
            "version" => Some(Command::Version),
            "health" => Some(Command::Health),
            "reset" => Some(Command::Reset),
            _ => None,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            Command::ScanStart => "Start a new security scan",
            Command::ScanStatus => "Get scan status",
            Command::ScanStop => "Stop running scan",
            Command::ScanList => "List all scans",
            Command::ScanResults => "Get scan results",
            Command::BackupCreate => "Create a new backup",
            Command::BackupRestore => "Restore from backup",
            Command::BackupList => "List all backups",
            Command::BackupSchedule => "Configure backup schedule",
            Command::BackupStatus => "Check backup status",
            Command::DeployStatus => "Get deployment status",
            Command::DeployRollback => "Rollback deployment",
            Command::DeployHealth => "Check deployment health",
            Command::DeployScale => "Scale deployment",
            Command::SLAStatus => "Get SLA status",
            Command::SLAReport => "Generate SLA report",
            Command::MetricsGet => "Get system metrics",
            Command::AuditLog => "View audit logs",
            Command::RoleCreate => "Create new role",
            Command::RoleList => "List all roles",
            Command::RoleDelete => "Delete role",
            Command::UserCreate => "Create new user",
            Command::UserList => "List all users",
            Command::UserDelete => "Delete user",
            Command::PermissionGrant => "Grant permission",
            Command::PermissionRevoke => "Revoke permission",
            Command::DRPlanCreate => "Create disaster recovery plan",
            Command::DRDrillStart => "Start DR drill",
            Command::DRDrillStatus => "Get DR drill status",
            Command::DRFailover => "Execute failover",
            Command::DRHistory => "View failover history",
            Command::Status => "Show system status",
            Command::Config => "Show configuration",
            Command::Help => "Show help",
            Command::Version => "Show version",
            Command::Health => "Check system health",
            Command::Reset => "Reset system",
        }
    }

    pub fn category(&self) -> &str {
        match self {
            Command::ScanStart | Command::ScanStatus | Command::ScanStop | Command::ScanList | Command::ScanResults => "Scanning",
            Command::BackupCreate | Command::BackupRestore | Command::BackupList | Command::BackupSchedule | Command::BackupStatus => "Backup",
            Command::DeployStatus | Command::DeployRollback | Command::DeployHealth | Command::DeployScale => "Deployment",
            Command::SLAStatus | Command::SLAReport | Command::MetricsGet | Command::AuditLog => "Monitoring",
            Command::RoleCreate | Command::RoleList | Command::RoleDelete | Command::UserCreate | Command::UserList | Command::UserDelete | Command::PermissionGrant | Command::PermissionRevoke => "Access Control",
            Command::DRPlanCreate | Command::DRDrillStart | Command::DRDrillStatus | Command::DRFailover | Command::DRHistory => "Disaster Recovery",
            Command::Status | Command::Config | Command::Help | Command::Version | Command::Health | Command::Reset => "System",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_context_creation() {
        let ctx = CommandContext::new("scan:start".to_string());
        assert_eq!(ctx.command, "scan:start");
    }

    #[test]
    fn test_command_from_string() {
        let cmd = Command::from_string("scan:start");
        assert_eq!(cmd, Some(Command::ScanStart));
    }

    #[test]
    fn test_command_description() {
        let cmd = Command::ScanStart;
        assert!(!cmd.description().is_empty());
    }

    #[test]
    fn test_command_category() {
        let cmd = Command::BackupCreate;
        assert_eq!(cmd.category(), "Backup");
    }
}
