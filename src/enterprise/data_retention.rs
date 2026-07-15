use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DataType {
    AuditLogs,
    ScanResults,
    Vulnerabilities,
    ReportData,
    UserData,
    SessionData,
    BackupMetadata,
    PerformanceMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub id: String,
    pub name: String,
    pub data_type: DataType,
    pub retention_days: i64,
    pub description: String,
    pub is_active: bool,
    pub auto_delete: bool,
    pub archive_after_days: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl RetentionPolicy {
    pub fn new(
        name: String,
        data_type: DataType,
        retention_days: i64,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            data_type,
            retention_days,
            description: String::new(),
            is_active: true,
            auto_delete: true,
            archive_after_days: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn with_description(mut self, desc: String) -> Self {
        self.description = desc;
        self
    }

    pub fn with_archive(mut self, archive_days: i64) -> Self {
        self.archive_after_days = Some(archive_days);
        self
    }

    pub fn disable_auto_delete(mut self) -> Self {
        self.auto_delete = false;
        self
    }

    pub fn should_delete(&self, created_at: DateTime<Utc>) -> bool {
        if !self.is_active || !self.auto_delete {
            return false;
        }

        let age_days = (Utc::now() - created_at).num_days();
        age_days > self.retention_days
    }

    pub fn should_archive(&self, created_at: DateTime<Utc>) -> bool {
        if let Some(archive_days) = self.archive_after_days {
            let age_days = (Utc::now() - created_at).num_days();
            age_days > archive_days
        } else {
            false
        }
    }

    pub fn get_expiry_date(&self, created_at: DateTime<Utc>) -> DateTime<Utc> {
        created_at + Duration::days(self.retention_days)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionManager {
    policies: HashMap<String, RetentionPolicy>,
    audit_trail: Vec<RetentionAuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionAuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub policy_id: String,
    pub action: String,
    pub records_affected: u32,
    pub reason: String,
}

impl RetentionManager {
    pub fn new() -> Self {
        let mut manager = Self {
            policies: HashMap::new(),
            audit_trail: Vec::new(),
        };

        manager.create_default_policies();
        manager
    }

    fn create_default_policies(&mut self) {
        // Audit logs: 1 year
        let audit_policy = RetentionPolicy::new(
            "Audit Logs".to_string(),
            DataType::AuditLogs,
            365,
        )
        .with_description("Keep audit logs for 1 year with 90-day archive".to_string())
        .with_archive(90);
        self.policies.insert(audit_policy.id.clone(), audit_policy);

        // Scan results: 6 months
        let scan_policy = RetentionPolicy::new(
            "Scan Results".to_string(),
            DataType::ScanResults,
            180,
        )
        .with_description("Keep scan results for 6 months".to_string());
        self.policies.insert(scan_policy.id.clone(), scan_policy);

        // Vulnerabilities: 2 years
        let vuln_policy = RetentionPolicy::new(
            "Vulnerabilities".to_string(),
            DataType::Vulnerabilities,
            730,
        )
        .with_description("Keep vulnerability data for 2 years".to_string());
        self.policies.insert(vuln_policy.id.clone(), vuln_policy);

        // Session data: 30 days
        let session_policy = RetentionPolicy::new(
            "Session Data".to_string(),
            DataType::SessionData,
            30,
        )
        .with_description("Keep session data for 30 days".to_string());
        self.policies.insert(session_policy.id.clone(), session_policy);

        // Performance metrics: 90 days
        let metrics_policy = RetentionPolicy::new(
            "Performance Metrics".to_string(),
            DataType::PerformanceMetrics,
            90,
        )
        .with_description("Keep performance metrics for 90 days".to_string());
        self.policies.insert(metrics_policy.id.clone(), metrics_policy);
    }

    pub fn add_policy(&mut self, policy: RetentionPolicy) -> String {
        let policy_id = policy.id.clone();
        self.policies.insert(policy_id.clone(), policy);
        policy_id
    }

    pub fn get_policy(&self, policy_id: &str) -> Option<&RetentionPolicy> {
        self.policies.get(policy_id)
    }

    pub fn get_policy_mut(&mut self, policy_id: &str) -> Option<&mut RetentionPolicy> {
        self.policies.get_mut(policy_id)
    }

    pub fn get_policy_by_data_type(&self, data_type: &DataType) -> Option<&RetentionPolicy> {
        self.policies
            .values()
            .find(|p| p.data_type == *data_type)
    }

    pub fn update_policy(&mut self, policy_id: &str, retention_days: i64) -> bool {
        if let Some(policy) = self.get_policy_mut(policy_id) {
            policy.retention_days = retention_days;
            policy.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    pub fn delete_policy(&mut self, policy_id: &str) -> bool {
        self.policies.remove(policy_id).is_some()
    }

    pub fn list_policies(&self) -> Vec<&RetentionPolicy> {
        self.policies.values().collect()
    }

    pub fn activate_policy(&mut self, policy_id: &str) -> bool {
        if let Some(policy) = self.get_policy_mut(policy_id) {
            policy.is_active = true;
            policy.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    pub fn deactivate_policy(&mut self, policy_id: &str) -> bool {
        if let Some(policy) = self.get_policy_mut(policy_id) {
            policy.is_active = false;
            policy.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    pub fn log_retention_action(&mut self, policy_id: String, action: String, records_affected: u32, reason: String) {
        let entry = RetentionAuditEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            policy_id,
            action,
            records_affected,
            reason,
        };
        self.audit_trail.push(entry);
    }

    pub fn get_audit_trail(&self) -> &[RetentionAuditEntry] {
        &self.audit_trail
    }

    pub fn get_statistics(&self) -> RetentionStatistics {
        let active_policies = self.policies.values().filter(|p| p.is_active).count();
        let policies_with_archive = self.policies.values().filter(|p| p.archive_after_days.is_some()).count();

        let total_retention_years: f32 = self.policies
            .values()
            .map(|p| p.retention_days as f32 / 365.0)
            .sum();

        RetentionStatistics {
            total_policies: self.policies.len(),
            active_policies,
            policies_with_archive,
            total_audit_entries: self.audit_trail.len(),
            average_retention_years: if self.policies.is_empty() { 0.0 } else { total_retention_years / self.policies.len() as f32 },
        }
    }
}

impl Default for RetentionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionStatistics {
    pub total_policies: usize,
    pub active_policies: usize,
    pub policies_with_archive: usize,
    pub total_audit_entries: usize,
    pub average_retention_years: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retention_policy_creation() {
        let policy = RetentionPolicy::new(
            "Test".to_string(),
            DataType::AuditLogs,
            365,
        );
        assert_eq!(policy.retention_days, 365);
        assert!(policy.is_active);
    }

    #[test]
    fn test_should_delete() {
        let policy = RetentionPolicy::new(
            "Test".to_string(),
            DataType::AuditLogs,
            1,
        );

        let old_date = Utc::now() - Duration::days(2);
        assert!(policy.should_delete(old_date));

        let recent_date = Utc::now() - Duration::hours(12);
        assert!(!policy.should_delete(recent_date));
    }

    #[test]
    fn test_retention_manager_creation() {
        let manager = RetentionManager::new();
        assert!(!manager.list_policies().is_empty());
    }

    #[test]
    fn test_get_policy_by_data_type() {
        let manager = RetentionManager::new();
        let policy = manager.get_policy_by_data_type(&DataType::AuditLogs);
        assert!(policy.is_some());
    }

    #[test]
    fn test_log_retention_action() {
        let mut manager = RetentionManager::new();
        let policy = manager.list_policies()[0];
        manager.log_retention_action(
            policy.id.clone(),
            "delete".to_string(),
            100,
            "Automated cleanup".to_string(),
        );
        assert_eq!(manager.get_audit_trail().len(), 1);
    }
}
