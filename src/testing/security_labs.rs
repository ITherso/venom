use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityLab {
    pub id: String,
    pub name: String,
    pub description: String,
    pub difficulty: DifficultyLevel,
    pub category: LabCategory,
    pub scenarios: Vec<LabScenario>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum DifficultyLevel {
    Beginner,
    Intermediate,
    Advanced,
    Expert,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum LabCategory {
    WebApplication,
    API,
    Infrastructure,
    Authentication,
    DataProtection,
    NetworkSecurity,
    CloudSecurity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabScenario {
    pub id: String,
    pub name: String,
    pub description: String,
    pub objective: String,
    pub target_url: String,
    pub hints: Vec<String>,
    pub expected_findings: Vec<ExpectedFinding>,
    pub time_limit_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedFinding {
    pub vulnerability_type: String,
    pub severity: String,
    pub parameter: String,
    pub evidence: String,
}

impl SecurityLab {
    pub fn new(
        name: String,
        description: String,
        difficulty: DifficultyLevel,
        category: LabCategory,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            description,
            difficulty,
            category,
            scenarios: Vec::new(),
            created_at: Utc::now(),
        }
    }

    pub fn add_scenario(&mut self, scenario: LabScenario) {
        self.scenarios.push(scenario);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabAssessment {
    pub assessment_id: String,
    pub lab_id: String,
    pub scenario_id: String,
    pub participant: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub findings_discovered: Vec<DiscoveredFinding>,
    pub score: f32,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredFinding {
    pub finding_id: String,
    pub vulnerability_type: String,
    pub severity: String,
    pub parameter: String,
    pub evidence: String,
    pub time_to_discover_seconds: u32,
}

impl LabAssessment {
    pub fn new(lab_id: String, scenario_id: String, participant: String) -> Self {
        Self {
            assessment_id: Uuid::new_v4().to_string(),
            lab_id,
            scenario_id,
            participant,
            start_time: Utc::now(),
            end_time: None,
            findings_discovered: Vec::new(),
            score: 0.0,
            passed: false,
        }
    }

    pub fn add_finding(&mut self, finding: DiscoveredFinding) {
        self.findings_discovered.push(finding);
    }

    pub fn complete(&mut self, expected_findings_count: usize) {
        self.end_time = Some(Utc::now());

        let discovered_count = self.findings_discovered.len();
        self.score = (discovered_count as f32 / expected_findings_count as f32) * 100.0;
        self.passed = discovered_count >= expected_findings_count;
    }

    pub fn get_duration_minutes(&self) -> u32 {
        if let Some(end_time) = self.end_time {
            ((end_time - self.start_time).num_minutes() as u32).max(1)
        } else {
            0
        }
    }
}

#[derive(Debug, Clone)]
pub struct LabManager {
    pub labs: HashMap<String, SecurityLab>,
    pub assessments: Vec<LabAssessment>,
}

impl LabManager {
    pub fn new() -> Self {
        Self {
            labs: HashMap::new(),
            assessments: Vec::new(),
        }
    }

    pub fn create_lab(
        &mut self,
        name: String,
        description: String,
        difficulty: DifficultyLevel,
        category: LabCategory,
    ) -> String {
        let lab = SecurityLab::new(name, description, difficulty, category);
        let lab_id = lab.id.clone();
        self.labs.insert(lab_id.clone(), lab);
        lab_id
    }

    pub fn get_lab(&self, lab_id: &str) -> Option<&SecurityLab> {
        self.labs.get(lab_id)
    }

    pub fn get_lab_mut(&mut self, lab_id: &str) -> Option<&mut SecurityLab> {
        self.labs.get_mut(lab_id)
    }

    pub fn get_labs_by_difficulty(&self, difficulty: DifficultyLevel) -> Vec<&SecurityLab> {
        self.labs
            .values()
            .filter(|lab| lab.difficulty == difficulty)
            .collect()
    }

    pub fn get_labs_by_category(&self, category: &LabCategory) -> Vec<&SecurityLab> {
        self.labs
            .values()
            .filter(|lab| &lab.category == category)
            .collect()
    }

    pub fn create_assessment(
        &mut self,
        lab_id: String,
        scenario_id: String,
        participant: String,
    ) -> String {
        let assessment = LabAssessment::new(lab_id, scenario_id, participant);
        let assessment_id = assessment.assessment_id.clone();
        self.assessments.push(assessment);
        assessment_id
    }

    pub fn get_assessment(&self, assessment_id: &str) -> Option<&LabAssessment> {
        self.assessments.iter().find(|a| a.assessment_id == assessment_id)
    }

    pub fn get_assessment_mut(&mut self, assessment_id: &str) -> Option<&mut LabAssessment> {
        self.assessments.iter_mut().find(|a| a.assessment_id == assessment_id)
    }

    pub fn get_participant_assessments(&self, participant: &str) -> Vec<&LabAssessment> {
        self.assessments
            .iter()
            .filter(|a| a.participant == participant)
            .collect()
    }

    pub fn get_lab_assessments(&self, lab_id: &str) -> Vec<&LabAssessment> {
        self.assessments
            .iter()
            .filter(|a| a.lab_id == lab_id)
            .collect()
    }

    pub fn get_statistics(&self) -> LabStatistics {
        let total_labs = self.labs.len();
        let total_assessments = self.assessments.len();
        let passed_assessments = self.assessments.iter().filter(|a| a.passed).count();
        let avg_score = if total_assessments > 0 {
            self.assessments.iter().map(|a| a.score).sum::<f32>() / total_assessments as f32
        } else {
            0.0
        };

        LabStatistics {
            total_labs,
            total_assessments,
            passed_assessments,
            failed_assessments: total_assessments - passed_assessments,
            average_score: avg_score,
            pass_rate: if total_assessments > 0 {
                (passed_assessments as f32 / total_assessments as f32) * 100.0
            } else {
                0.0
            },
        }
    }
}

impl Default for LabManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabStatistics {
    pub total_labs: usize,
    pub total_assessments: usize,
    pub passed_assessments: usize,
    pub failed_assessments: usize,
    pub average_score: f32,
    pub pass_rate: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_lab_creation() {
        let lab = SecurityLab::new(
            "SQL Injection Lab".to_string(),
            "Learn SQL injection techniques".to_string(),
            DifficultyLevel::Beginner,
            LabCategory::WebApplication,
        );
        assert_eq!(lab.name, "SQL Injection Lab");
    }

    #[test]
    fn test_lab_assessment() {
        let mut assessment = LabAssessment::new(
            "lab_123".to_string(),
            "scenario_456".to_string(),
            "user_789".to_string(),
        );

        assessment.add_finding(DiscoveredFinding {
            finding_id: "finding_1".to_string(),
            vulnerability_type: "SQL Injection".to_string(),
            severity: "High".to_string(),
            parameter: "id".to_string(),
            evidence: "' OR '1'='1".to_string(),
            time_to_discover_seconds: 300,
        });

        assessment.complete(1);
        assert!(assessment.passed);
    }

    #[test]
    fn test_lab_manager() {
        let mut manager = LabManager::new();
        let lab_id = manager.create_lab(
            "XSS Lab".to_string(),
            "Learn XSS attacks".to_string(),
            DifficultyLevel::Intermediate,
            LabCategory::WebApplication,
        );

        assert!(manager.get_lab(&lab_id).is_some());
    }
}
