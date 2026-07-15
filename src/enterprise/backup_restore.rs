use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BackupType {
    Full,
    Incremental,
    Differential,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupJob {
    pub id: String,
    pub name: String,
    pub backup_type: BackupType,
    pub status: JobStatus,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub data_size_bytes: u64,
    pub compressed_size_bytes: u64,
    pub location: String,
    pub compression_ratio: f32,
    pub checksum: String,
    pub retention_days: u32,
}

impl BackupJob {
    pub fn new(
        name: String,
        backup_type: BackupType,
        location: String,
        retention_days: u32,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            backup_type,
            status: JobStatus::Pending,
            start_time: Utc::now(),
            end_time: None,
            data_size_bytes: 0,
            compressed_size_bytes: 0,
            location,
            compression_ratio: 0.0,
            checksum: String::new(),
            retention_days,
        }
    }

    pub fn mark_running(&mut self) {
        self.status = JobStatus::Running;
    }

    pub fn mark_completed(&mut self, data_size: u64, compressed_size: u64, checksum: String) {
        self.status = JobStatus::Completed;
        self.end_time = Some(Utc::now());
        self.data_size_bytes = data_size;
        self.compressed_size_bytes = compressed_size;
        self.checksum = checksum;
        self.compression_ratio = if data_size > 0 {
            (data_size as f32 - compressed_size as f32) / data_size as f32
        } else {
            0.0
        };
    }

    pub fn mark_failed(&mut self) {
        self.status = JobStatus::Failed;
        self.end_time = Some(Utc::now());
    }

    pub fn get_duration(&self) -> Duration {
        let end = self.end_time.unwrap_or_else(Utc::now);
        end - self.start_time
    }

    pub fn is_expired(&self, retention_days: u32) -> bool {
        let expiry_date = self.start_time + Duration::days(retention_days as i64);
        Utc::now() > expiry_date
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreJob {
    pub id: String,
    pub backup_id: String,
    pub status: JobStatus,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub target_location: String,
    pub recovery_point_id: String,
    pub records_restored: u32,
    pub verification_status: VerificationStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerificationStatus {
    NotVerified,
    Verified,
    FailedVerification,
}

impl RestoreJob {
    pub fn new(backup_id: String, target_location: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            backup_id,
            status: JobStatus::Pending,
            start_time: Utc::now(),
            end_time: None,
            target_location,
            recovery_point_id: Uuid::new_v4().to_string(),
            records_restored: 0,
            verification_status: VerificationStatus::NotVerified,
        }
    }

    pub fn mark_running(&mut self) {
        self.status = JobStatus::Running;
    }

    pub fn mark_completed(&mut self, records_restored: u32) {
        self.status = JobStatus::Completed;
        self.end_time = Some(Utc::now());
        self.records_restored = records_restored;
    }

    pub fn mark_failed(&mut self) {
        self.status = JobStatus::Failed;
        self.end_time = Some(Utc::now());
    }

    pub fn set_verified(&mut self) {
        self.verification_status = VerificationStatus::Verified;
    }

    pub fn set_verification_failed(&mut self) {
        self.verification_status = VerificationStatus::FailedVerification;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManager {
    backups: HashMap<String, BackupJob>,
    restores: HashMap<String, RestoreJob>,
    backup_schedule: Vec<BackupSchedule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSchedule {
    pub id: String,
    pub name: String,
    pub backup_type: BackupType,
    pub frequency: String,
    pub retention_days: u32,
    pub location_template: String,
    pub is_active: bool,
    pub last_backup: Option<DateTime<Utc>>,
}

impl BackupManager {
    pub fn new() -> Self {
        Self {
            backups: HashMap::new(),
            restores: HashMap::new(),
            backup_schedule: Vec::new(),
        }
    }

    pub fn create_backup(
        &mut self,
        name: String,
        backup_type: BackupType,
        location: String,
        retention_days: u32,
    ) -> String {
        let backup = BackupJob::new(name, backup_type, location, retention_days);
        let backup_id = backup.id.clone();
        self.backups.insert(backup_id.clone(), backup);
        backup_id
    }

    pub fn get_backup(&self, backup_id: &str) -> Option<&BackupJob> {
        self.backups.get(backup_id)
    }

    pub fn get_backup_mut(&mut self, backup_id: &str) -> Option<&mut BackupJob> {
        self.backups.get_mut(backup_id)
    }

    pub fn list_backups(&self) -> Vec<&BackupJob> {
        self.backups.values().collect()
    }

    pub fn get_backups_by_status(&self, status: JobStatus) -> Vec<&BackupJob> {
        self.backups
            .values()
            .filter(|b| b.status == status)
            .collect()
    }

    pub fn create_restore_job(&mut self, backup_id: String, target_location: String) -> String {
        let restore = RestoreJob::new(backup_id, target_location);
        let restore_id = restore.id.clone();
        self.restores.insert(restore_id.clone(), restore);
        restore_id
    }

    pub fn get_restore_job(&self, restore_id: &str) -> Option<&RestoreJob> {
        self.restores.get(restore_id)
    }

    pub fn get_restore_job_mut(&mut self, restore_id: &str) -> Option<&mut RestoreJob> {
        self.restores.get_mut(restore_id)
    }

    pub fn list_restore_jobs(&self) -> Vec<&RestoreJob> {
        self.restores.values().collect()
    }

    pub fn add_schedule(&mut self, schedule: BackupSchedule) -> String {
        let schedule_id = schedule.id.clone();
        self.backup_schedule.push(schedule);
        schedule_id
    }

    pub fn list_schedules(&self) -> Vec<&BackupSchedule> {
        self.backup_schedule.iter().collect()
    }

    pub fn get_active_schedules(&self) -> Vec<&BackupSchedule> {
        self.backup_schedule
            .iter()
            .filter(|s| s.is_active)
            .collect()
    }

    pub fn cleanup_expired_backups(&mut self) -> u32 {
        let expired_ids: Vec<String> = self.backups
            .iter()
            .filter(|(_, b)| b.is_expired(b.retention_days))
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired_ids.len() as u32;
        for id in expired_ids {
            self.backups.remove(&id);
        }
        count
    }

    pub fn get_statistics(&self) -> BackupStatistics {
        let total_backups = self.backups.len();
        let successful_backups = self.backups.values().filter(|b| b.status == JobStatus::Completed).count();
        let failed_backups = self.backups.values().filter(|b| b.status == JobStatus::Failed).count();
        let total_data_size: u64 = self.backups.values().map(|b| b.data_size_bytes).sum();
        let total_compressed_size: u64 = self.backups.values().map(|b| b.compressed_size_bytes).sum();

        let avg_compression = if !self.backups.is_empty() {
            self.backups.values().map(|b| b.compression_ratio).sum::<f32>() / self.backups.len() as f32
        } else {
            0.0
        };

        BackupStatistics {
            total_backups,
            successful_backups,
            failed_backups,
            total_data_size,
            total_compressed_size,
            average_compression_ratio: avg_compression,
            total_restore_jobs: self.restores.len(),
        }
    }
}

impl Default for BackupManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupStatistics {
    pub total_backups: usize,
    pub successful_backups: usize,
    pub failed_backups: usize,
    pub total_data_size: u64,
    pub total_compressed_size: u64,
    pub average_compression_ratio: f32,
    pub total_restore_jobs: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_job_creation() {
        let backup = BackupJob::new(
            "Test".to_string(),
            BackupType::Full,
            "/backup/test".to_string(),
            30,
        );
        assert_eq!(backup.status, JobStatus::Pending);
    }

    #[test]
    fn test_backup_mark_completed() {
        let mut backup = BackupJob::new(
            "Test".to_string(),
            BackupType::Full,
            "/backup/test".to_string(),
            30,
        );
        backup.mark_completed(1000, 500, "abc123".to_string());
        assert_eq!(backup.status, JobStatus::Completed);
        assert_eq!(backup.compression_ratio, 0.5);
    }

    #[test]
    fn test_restore_job_creation() {
        let restore = RestoreJob::new(
            "backup123".to_string(),
            "/restore/target".to_string(),
        );
        assert_eq!(restore.status, JobStatus::Pending);
    }

    #[test]
    fn test_backup_manager_create_backup() {
        let mut manager = BackupManager::new();
        let backup_id = manager.create_backup(
            "Test".to_string(),
            BackupType::Full,
            "/backup/test".to_string(),
            30,
        );
        assert!(manager.get_backup(&backup_id).is_some());
    }

    #[test]
    fn test_cleanup_expired_backups() {
        let mut manager = BackupManager::new();
        let mut backup = BackupJob::new(
            "Test".to_string(),
            BackupType::Full,
            "/backup/test".to_string(),
            0,
        );
        backup.start_time = Utc::now() - Duration::days(1);
        let backup_id = backup.id.clone();
        manager.backups.insert(backup_id, backup);

        let count = manager.cleanup_expired_backups();
        assert_eq!(count, 1);
    }
}
