use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProcessing {
    pub id: String,
    pub purpose: String,
    pub data_categories: Vec<String>,
    pub legal_basis: LegalBasis,
    pub recipients: Vec<String>,
    pub retention_days: u32,
    pub requires_consent: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LegalBasis {
    Consent,
    Contract,
    LegalObligation,
    VitalInterests,
    PublicTask,
    LegitimateInterests,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub id: String,
    pub user_id: String,
    pub processing_id: String,
    pub given_at: DateTime<Utc>,
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub active: bool,
    pub version: u32,
}

#[derive(Debug, Clone)]
pub struct GDPRCompliance {
    pub processing_activities: HashMap<String, DataProcessing>,
    pub consent_records: Vec<ConsentRecord>,
    pub dpia_completed: bool,
    pub dpia_date: Option<DateTime<Utc>>,
}

impl GDPRCompliance {
    pub fn new() -> Self {
        Self {
            processing_activities: HashMap::new(),
            consent_records: Vec::new(),
            dpia_completed: false,
            dpia_date: None,
        }
    }

    pub fn add_processing(&mut self, processing: DataProcessing) {
        self.processing_activities.insert(processing.id.clone(), processing);
    }

    pub fn record_consent(&mut self, consent: ConsentRecord) {
        self.consent_records.push(consent);
    }

    pub fn get_active_consents(&self, user_id: &str) -> Vec<&ConsentRecord> {
        self.consent_records
            .iter()
            .filter(|c| c.user_id == user_id && c.active)
            .collect()
    }

    pub fn get_statistics(&self) -> GDPRStatistics {
        GDPRStatistics {
            total_processing_activities: self.processing_activities.len(),
            total_consents: self.consent_records.len(),
            active_consents: self.consent_records.iter().filter(|c| c.active).count(),
            dpia_completed: self.dpia_completed,
        }
    }
}

impl Default for GDPRCompliance {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GDPRStatistics {
    pub total_processing_activities: usize,
    pub total_consents: usize,
    pub active_consents: usize,
    pub dpia_completed: bool,
}
