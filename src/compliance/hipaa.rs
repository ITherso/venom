use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PHIRecord {
    pub id: String,
    pub patient_id: String,
    pub data_type: String,
    pub encrypted: bool,
    pub created_at: DateTime<Utc>,
    pub last_accessed: Option<DateTime<Utc>>,
    pub access_logs: Vec<AccessLog>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLog {
    pub id: String,
    pub user_id: String,
    pub access_time: DateTime<Utc>,
    pub action: String,
    pub purpose: String,
}

#[derive(Debug, Clone)]
pub struct HIPAACompliance {
    pub phi_records: HashMap<String, PHIRecord>,
    pub breach_reports: Vec<BreachReport>,
    pub training_completed: bool,
    pub baa_signed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachReport {
    pub id: String,
    pub date_discovered: DateTime<Utc>,
    pub affected_individuals: u32,
    pub description: String,
    pub mitigation_steps: Vec<String>,
    pub reported: bool,
}

impl HIPAACompliance {
    pub fn new() -> Self {
        Self {
            phi_records: HashMap::new(),
            breach_reports: Vec::new(),
            training_completed: false,
            baa_signed: false,
        }
    }

    pub fn add_phi_record(&mut self, record: PHIRecord) {
        self.phi_records.insert(record.id.clone(), record);
    }

    pub fn log_access(&mut self, phi_id: &str, user_id: String, action: String, purpose: String) {
        if let Some(record) = self.phi_records.get_mut(phi_id) {
            record.access_logs.push(AccessLog {
                id: uuid::Uuid::new_v4().to_string(),
                user_id,
                access_time: Utc::now(),
                action,
                purpose,
            });
            record.last_accessed = Some(Utc::now());
        }
    }

    pub fn get_statistics(&self) -> HIPAAStatistics {
        let encrypted_records = self.phi_records.values().filter(|r| r.encrypted).count();
        let total_accesses: usize = self.phi_records.values()
            .map(|r| r.access_logs.len())
            .sum();

        HIPAAStatistics {
            total_phi_records: self.phi_records.len(),
            encrypted_records,
            total_access_logs: total_accesses,
            training_completed: self.training_completed,
            baa_signed: self.baa_signed,
            breaches_reported: self.breach_reports.iter().filter(|b| b.reported).count(),
        }
    }
}

impl Default for HIPAACompliance {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HIPAAStatistics {
    pub total_phi_records: usize,
    pub encrypted_records: usize,
    pub total_access_logs: usize,
    pub training_completed: bool,
    pub baa_signed: bool,
    pub breaches_reported: usize,
}
