use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecoveryStrategy {
    RPO,
    RTO,
    Combined,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DrillStatus {
    Planned,
    InProgress,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPoint {
    pub id: String,
    pub name: String,
    pub timestamp: DateTime<Utc>,
    pub data_state: String,
    pub metadata: HashMap<String, String>,
    pub is_verified: bool,
    pub associated_backup_id: String,
    pub size_bytes: u64,
}

impl RecoveryPoint {
    pub fn new(
        name: String,
        data_state: String,
        associated_backup_id: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            timestamp: Utc::now(),
            data_state,
            metadata: HashMap::new(),
            is_verified: false,
            associated_backup_id,
            size_bytes: 0,
        }
    }

    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    pub fn mark_verified(&mut self) {
        self.is_verified = true;
    }

    pub fn set_size(&mut self, size: u64) {
        self.size_bytes = size;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRPlan {
    pub id: String,
    pub name: String,
    pub strategy: RecoveryStrategy,
    pub rto_minutes: u32,
    pub rpo_minutes: u32,
    pub backup_frequency_minutes: u32,
    pub test_frequency_days: u32,
    pub critical_systems: Vec<String>,
    pub recovery_teams: HashMap<String, String>,
    pub last_tested: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl DRPlan {
    pub fn new(
        name: String,
        strategy: RecoveryStrategy,
        rto_minutes: u32,
        rpo_minutes: u32,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            strategy,
            rto_minutes,
            rpo_minutes,
            backup_frequency_minutes: rpo_minutes / 2,
            test_frequency_days: 30,
            critical_systems: Vec::new(),
            recovery_teams: HashMap::new(),
            last_tested: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn add_critical_system(&mut self, system: String) {
        self.critical_systems.push(system);
    }

    pub fn add_team_lead(&mut self, team: String, lead: String) {
        self.recovery_teams.insert(team, lead);
    }

    pub fn mark_tested(&mut self) {
        self.last_tested = Some(Utc::now());
    }

    pub fn needs_testing(&self) -> bool {
        if let Some(last) = self.last_tested {
            let days_since = (Utc::now() - last).num_days();
            days_since > self.test_frequency_days as i64
        } else {
            true
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRDrill {
    pub id: String,
    pub plan_id: String,
    pub status: DrillStatus,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub actual_rto_minutes: Option<u32>,
    pub actual_rpo_minutes: Option<u32>,
    pub systems_recovered: Vec<String>,
    pub issues_found: Vec<String>,
    pub passed: bool,
}

impl DRDrill {
    pub fn new(plan_id: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            plan_id,
            status: DrillStatus::Planned,
            start_time: Utc::now(),
            end_time: None,
            actual_rto_minutes: None,
            actual_rpo_minutes: None,
            systems_recovered: Vec::new(),
            issues_found: Vec::new(),
            passed: false,
        }
    }

    pub fn start(&mut self) {
        self.status = DrillStatus::InProgress;
        self.start_time = Utc::now();
    }

    pub fn complete(&mut self, actual_rto: u32) {
        self.status = DrillStatus::Completed;
        self.end_time = Some(Utc::now());
        self.actual_rto_minutes = Some(actual_rto);
    }

    pub fn fail(&mut self) {
        self.status = DrillStatus::Failed;
        self.end_time = Some(Utc::now());
    }

    pub fn add_recovered_system(&mut self, system: String) {
        self.systems_recovered.push(system);
    }

    pub fn add_issue(&mut self, issue: String) {
        self.issues_found.push(issue);
    }

    pub fn mark_passed(&mut self) {
        self.passed = true;
    }

    pub fn get_duration_minutes(&self) -> Option<u32> {
        self.end_time.map(|end| {
            ((end - self.start_time).num_seconds() / 60) as u32
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisasterRecoveryManager {
    plans: HashMap<String, DRPlan>,
    recovery_points: HashMap<String, RecoveryPoint>,
    drills: Vec<DRDrill>,
    failover_events: Vec<FailoverEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub trigger_reason: String,
    pub recovery_point_used: String,
    pub success: bool,
    pub systems_affected: Vec<String>,
    pub notes: String,
}

impl DisasterRecoveryManager {
    pub fn new() -> Self {
        Self {
            plans: HashMap::new(),
            recovery_points: HashMap::new(),
            drills: Vec::new(),
            failover_events: Vec::new(),
        }
    }

    pub fn create_plan(
        &mut self,
        name: String,
        strategy: RecoveryStrategy,
        rto_minutes: u32,
        rpo_minutes: u32,
    ) -> String {
        let plan = DRPlan::new(name, strategy, rto_minutes, rpo_minutes);
        let plan_id = plan.id.clone();
        self.plans.insert(plan_id.clone(), plan);
        plan_id
    }

    pub fn get_plan(&self, plan_id: &str) -> Option<&DRPlan> {
        self.plans.get(plan_id)
    }

    pub fn get_plan_mut(&mut self, plan_id: &str) -> Option<&mut DRPlan> {
        self.plans.get_mut(plan_id)
    }

    pub fn list_plans(&self) -> Vec<&DRPlan> {
        self.plans.values().collect()
    }

    pub fn add_recovery_point(&mut self, recovery_point: RecoveryPoint) -> String {
        let rp_id = recovery_point.id.clone();
        self.recovery_points.insert(rp_id.clone(), recovery_point);
        rp_id
    }

    pub fn get_recovery_point(&self, rp_id: &str) -> Option<&RecoveryPoint> {
        self.recovery_points.get(rp_id)
    }

    pub fn list_recovery_points(&self) -> Vec<&RecoveryPoint> {
        let mut points: Vec<_> = self.recovery_points.values().collect();
        points.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        points
    }

    pub fn create_drill(&mut self, plan_id: String) -> String {
        let drill = DRDrill::new(plan_id);
        let drill_id = drill.id.clone();
        self.drills.push(drill);
        drill_id
    }

    pub fn get_drill(&mut self, drill_id: &str) -> Option<&mut DRDrill> {
        self.drills.iter_mut().find(|d| d.id == drill_id)
    }

    pub fn list_drills(&self) -> Vec<&DRDrill> {
        self.drills.iter().collect()
    }

    pub fn log_failover(
        &mut self,
        trigger_reason: String,
        recovery_point_id: String,
        success: bool,
        systems_affected: Vec<String>,
    ) -> String {
        let event = FailoverEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            trigger_reason,
            recovery_point_used: recovery_point_id,
            success,
            systems_affected,
            notes: String::new(),
        };
        let event_id = event.id.clone();
        self.failover_events.push(event);
        event_id
    }

    pub fn get_failover_history(&self) -> Vec<&FailoverEvent> {
        let mut events = self.failover_events.iter().collect::<Vec<_>>();
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        events
    }

    pub fn get_plans_needing_testing(&self) -> Vec<&DRPlan> {
        self.plans
            .values()
            .filter(|p| p.needs_testing())
            .collect()
    }

    pub fn get_statistics(&self) -> DRStatistics {
        let passed_drills = self.drills.iter().filter(|d| d.passed).count();
        let failed_drills = self.drills.iter().filter(|d| d.status == DrillStatus::Failed).count();
        let avg_rto = if !self.drills.is_empty() {
            self.drills
                .iter()
                .filter_map(|d| d.actual_rto_minutes)
                .sum::<u32>() as f32 / self.drills.len() as f32
        } else {
            0.0
        };

        DRStatistics {
            total_plans: self.plans.len(),
            total_recovery_points: self.recovery_points.len(),
            total_drills: self.drills.len(),
            passed_drills,
            failed_drills,
            average_actual_rto_minutes: avg_rto,
            total_failovers: self.failover_events.len(),
        }
    }
}

impl Default for DisasterRecoveryManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRStatistics {
    pub total_plans: usize,
    pub total_recovery_points: usize,
    pub total_drills: usize,
    pub passed_drills: usize,
    pub failed_drills: usize,
    pub average_actual_rto_minutes: f32,
    pub total_failovers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_point_creation() {
        let rp = RecoveryPoint::new(
            "RP1".to_string(),
            "snapshot".to_string(),
            "backup123".to_string(),
        );
        assert_eq!(rp.name, "RP1");
        assert!(!rp.is_verified);
    }

    #[test]
    fn test_dr_plan_creation() {
        let plan = DRPlan::new(
            "Plan1".to_string(),
            RecoveryStrategy::RPO,
            60,
            30,
        );
        assert_eq!(plan.rto_minutes, 60);
        assert!(plan.needs_testing());
    }

    #[test]
    fn test_dr_drill_creation() {
        let drill = DRDrill::new("plan123".to_string());
        assert_eq!(drill.status, DrillStatus::Planned);
    }

    #[test]
    fn test_manager_create_plan() {
        let mut manager = DisasterRecoveryManager::new();
        let plan_id = manager.create_plan(
            "Plan1".to_string(),
            RecoveryStrategy::Combined,
            60,
            30,
        );
        assert!(manager.get_plan(&plan_id).is_some());
    }

    #[test]
    fn test_log_failover() {
        let mut manager = DisasterRecoveryManager::new();
        let failover_id = manager.log_failover(
            "Hardware failure".to_string(),
            "rp123".to_string(),
            true,
            vec!["API".to_string(), "DB".to_string()],
        );
        assert_eq!(manager.get_failover_history().len(), 1);
    }
}
