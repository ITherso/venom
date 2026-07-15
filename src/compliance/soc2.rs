use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustServiceCriteria {
    Security,
    Availability,
    ProcessIntegrity,
    Confidentiality,
    Privacy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub criteria: Vec<TrustServiceCriteria>,
    pub last_reviewed: DateTime<Utc>,
    pub effective_date: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlAssessment {
    pub id: String,
    pub control_id: String,
    pub control_name: String,
    pub assessment_date: DateTime<Utc>,
    pub status: ControlStatus,
    pub evidence: Vec<String>,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlStatus {
    Operating,
    PartiallyImplemented,
    NotImplemented,
    Remediated,
}

#[derive(Debug, Clone)]
pub struct SOC2Compliance {
    pub type_level: SOC2Type,
    pub policies: HashMap<String, SecurityPolicy>,
    pub assessments: Vec<ControlAssessment>,
    pub last_audit: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SOC2Type {
    TypeI,
    TypeII,
}

impl SOC2Compliance {
    pub fn new(type_level: SOC2Type) -> Self {
        Self {
            type_level,
            policies: HashMap::new(),
            assessments: Vec::new(),
            last_audit: None,
        }
    }

    pub fn add_policy(&mut self, policy: SecurityPolicy) {
        self.policies.insert(policy.id.clone(), policy);
    }

    pub fn add_assessment(&mut self, assessment: ControlAssessment) {
        self.assessments.push(assessment);
    }

    pub fn get_operating_controls(&self) -> usize {
        self.assessments.iter().filter(|a| a.status == ControlStatus::Operating).count()
    }

    pub fn get_statistics(&self) -> SOC2Statistics {
        let total_controls = self.assessments.len();
        let operating = self.get_operating_controls();
        let partial = self.assessments.iter().filter(|a| a.status == ControlStatus::PartiallyImplemented).count();
        let not_impl = self.assessments.iter().filter(|a| a.status == ControlStatus::NotImplemented).count();

        SOC2Statistics {
            soc2_type: self.type_level,
            total_controls,
            operating_controls: operating,
            partially_implemented: partial,
            not_implemented: not_impl,
            total_policies: self.policies.len(),
        }
    }
}

impl Default for SOC2Compliance {
    fn default() -> Self {
        Self::new(SOC2Type::TypeII)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SOC2Statistics {
    pub soc2_type: SOC2Type,
    pub total_controls: usize,
    pub operating_controls: usize,
    pub partially_implemented: usize,
    pub not_implemented: usize,
    pub total_policies: usize,
}
