use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Datelike, Timelike};
use std::collections::HashMap;
use crate::zeroday_db::{ZeroDayManager, Exploit};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateJob {
    pub id: String,
    pub feed_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub exploits_added: usize,
    pub exploits_updated: usize,
    pub errors: Vec<String>,
    pub status: UpdateStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UpdateStatus {
    Pending,
    Running,
    Completed,
    Failed,
    PartiallyFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroDayUpdater {
    pub jobs: HashMap<String, UpdateJob>,
    pub last_full_update: Option<DateTime<Utc>>,
    pub update_interval_hours: u64,
    pub auto_update_enabled: bool,
}

impl ZeroDayUpdater {
    pub fn new() -> Self {
        Self {
            jobs: HashMap::new(),
            last_full_update: None,
            update_interval_hours: 24,
            auto_update_enabled: true,
        }
    }

    pub fn enable_auto_update(&mut self) {
        self.auto_update_enabled = true;
    }

    pub fn disable_auto_update(&mut self) {
        self.auto_update_enabled = false;
    }

    pub fn set_update_interval(&mut self, hours: u64) {
        self.update_interval_hours = hours.max(1);
    }

    pub fn create_update_job(&mut self, feed_id: String) -> UpdateJob {
        let job = UpdateJob {
            id: uuid::Uuid::new_v4().to_string(),
            feed_id,
            started_at: Utc::now(),
            completed_at: None,
            exploits_added: 0,
            exploits_updated: 0,
            errors: Vec::new(),
            status: UpdateStatus::Running,
        };

        self.jobs.insert(job.id.clone(), job.clone());
        job
    }

    pub fn get_job(&self, job_id: &str) -> Option<&UpdateJob> {
        self.jobs.get(job_id)
    }

    pub fn get_job_mut(&mut self, job_id: &str) -> Option<&mut UpdateJob> {
        self.jobs.get_mut(job_id)
    }

    pub fn complete_job(&mut self, job_id: &str, added: usize, updated: usize) {
        if let Some(job) = self.get_job_mut(job_id) {
            job.completed_at = Some(Utc::now());
            job.exploits_added = added;
            job.exploits_updated = updated;
            job.status = UpdateStatus::Completed;
            self.last_full_update = Some(Utc::now());
        }
    }

    pub fn fail_job(&mut self, job_id: &str, error: String) {
        if let Some(job) = self.get_job_mut(job_id) {
            job.completed_at = Some(Utc::now());
            job.errors.push(error);
            job.status = UpdateStatus::Failed;
        }
    }

    pub fn add_job_error(&mut self, job_id: &str, error: String) {
        if let Some(job) = self.get_job_mut(job_id) {
            job.errors.push(error);
            if job.status == UpdateStatus::Completed {
                job.status = UpdateStatus::PartiallyFailed;
            }
        }
    }

    pub fn should_update(&self) -> bool {
        if !self.auto_update_enabled {
            return false;
        }

        if let Some(last_update) = self.last_full_update {
            let duration = Utc::now() - last_update;
            duration.num_hours() >= self.update_interval_hours as i64
        } else {
            true
        }
    }

    pub fn get_job_history(&self) -> Vec<&UpdateJob> {
        let mut jobs: Vec<_> = self.jobs.values().collect();
        jobs.sort_by_key(|j| std::cmp::Reverse(j.started_at));
        jobs
    }

    pub fn get_successful_jobs(&self) -> Vec<&UpdateJob> {
        self.jobs
            .values()
            .filter(|j| j.status == UpdateStatus::Completed)
            .collect()
    }

    pub fn get_failed_jobs(&self) -> Vec<&UpdateJob> {
        self.jobs
            .values()
            .filter(|j| matches!(j.status, UpdateStatus::Failed | UpdateStatus::PartiallyFailed))
            .collect()
    }

    pub fn clear_old_jobs(&mut self, days: i64) {
        let cutoff = Utc::now() - chrono::Duration::days(days);
        self.jobs.retain(|_, job| {
            job.completed_at.is_none() || job.completed_at.unwrap() > cutoff
        });
    }

    pub fn get_update_statistics(&self) -> UpdateStatistics {
        let jobs = self.get_job_history();
        let total = jobs.len();
        let successful = jobs.iter().filter(|j| j.status == UpdateStatus::Completed).count();
        let failed = jobs
            .iter()
            .filter(|j| matches!(j.status, UpdateStatus::Failed | UpdateStatus::PartiallyFailed))
            .count();

        let total_added: usize = jobs.iter().map(|j| j.exploits_added).sum();
        let total_updated: usize = jobs.iter().map(|j| j.exploits_updated).sum();

        UpdateStatistics {
            total_jobs: total,
            successful_jobs: successful,
            failed_jobs: failed,
            total_exploits_added: total_added,
            total_exploits_updated: total_updated,
            success_rate: if total > 0 {
                (successful as f32 / total as f32) * 100.0
            } else {
                0.0
            },
            last_update: self.last_full_update,
        }
    }
}

impl Default for ZeroDayUpdater {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateStatistics {
    pub total_jobs: usize,
    pub successful_jobs: usize,
    pub failed_jobs: usize,
    pub total_exploits_added: usize,
    pub total_exploits_updated: usize,
    pub success_rate: f32,
    pub last_update: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSchedule {
    pub enabled: bool,
    pub frequency: UpdateFrequency,
    pub hour_of_day: u8,
    pub day_of_week: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateFrequency {
    Hourly,
    Daily,
    Weekly,
    Monthly,
}

impl UpdateSchedule {
    pub fn daily_at(hour: u8) -> Self {
        Self {
            enabled: true,
            frequency: UpdateFrequency::Daily,
            hour_of_day: hour,
            day_of_week: None,
        }
    }

    pub fn weekly_on(day: u8, hour: u8) -> Self {
        Self {
            enabled: true,
            frequency: UpdateFrequency::Weekly,
            hour_of_day: hour,
            day_of_week: Some(day),
        }
    }

    pub fn should_run_now(&self) -> bool {
        if !self.enabled {
            return false;
        }

        let now = Utc::now();
        match self.frequency {
            UpdateFrequency::Hourly => true,
            UpdateFrequency::Daily => now.hour() == self.hour_of_day as u32,
            UpdateFrequency::Weekly => {
                now.hour() == self.hour_of_day as u32
                    && self.day_of_week.map_or(true, |d| now.weekday().num_days_from_sunday() as u8 == d)
            }
            UpdateFrequency::Monthly => {
                now.hour() == self.hour_of_day as u32 && now.day() == 1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_updater_creation() {
        let updater = ZeroDayUpdater::new();
        assert!(updater.auto_update_enabled);
    }

    #[test]
    fn test_create_update_job() {
        let mut updater = ZeroDayUpdater::new();
        let job = updater.create_update_job("feed1".to_string());

        assert_eq!(job.status, UpdateStatus::Running);
        assert!(updater.get_job(&job.id).is_some());
    }

    #[test]
    fn test_complete_job() {
        let mut updater = ZeroDayUpdater::new();
        let job = updater.create_update_job("feed1".to_string());
        let job_id = job.id.clone();

        updater.complete_job(&job_id, 10, 5);
        let completed = updater.get_job(&job_id).unwrap();

        assert_eq!(completed.status, UpdateStatus::Completed);
        assert_eq!(completed.exploits_added, 10);
    }

    #[test]
    fn test_update_schedule() {
        let schedule = UpdateSchedule::daily_at(2);
        assert!(schedule.enabled);
    }

    #[test]
    fn test_should_update() {
        let updater = ZeroDayUpdater::new();
        assert!(updater.should_update());
    }
}
