use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: SecurityEventType,
    pub threat_level: ThreatLevel,
    pub actor: String,
    pub target: String,
    pub action: String,
    pub result: EventResult,
    pub details: HashMap<String, String>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityEventType {
    AuthenticationFailure,
    AuthorizationFailure,
    EncryptionFailure,
    InputValidationFailure,
    SQLInjectionAttempt,
    XSSAttempt,
    BruteForceAttempt,
    UnauthorizedAccess,
    DataAccess,
    SecretAccess,
    ConfigurationChange,
    PrivilegeEscalation,
    MalwareDetected,
    AnomalyDetected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventResult {
    Blocked,
    Allowed,
    AlertedOnly,
    Quarantined,
}

impl SecurityEvent {
    pub fn new(
        event_type: SecurityEventType,
        threat_level: ThreatLevel,
        actor: String,
        target: String,
        action: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            threat_level,
            actor,
            target,
            action,
            result: EventResult::AlertedOnly,
            details: HashMap::new(),
            source_ip: None,
            user_agent: None,
        }
    }

    pub fn with_result(mut self, result: EventResult) -> Self {
        self.result = result;
        self
    }

    pub fn with_source_ip(mut self, ip: String) -> Self {
        self.source_ip = Some(ip);
        self
    }

    pub fn with_detail(mut self, key: String, value: String) -> Self {
        self.details.insert(key, value);
        self
    }

    pub fn is_critical(&self) -> bool {
        self.threat_level == ThreatLevel::Critical
    }
}

#[derive(Debug, Clone)]
pub struct SecurityAudit {
    pub id: String,
    pub name: String,
    pub events: Vec<SecurityEvent>,
    pub blocked_count: u32,
    pub allowed_count: u32,
    pub critical_events: u32,
    pub created_at: DateTime<Utc>,
}

impl SecurityAudit {
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            events: Vec::new(),
            blocked_count: 0,
            allowed_count: 0,
            critical_events: 0,
            created_at: Utc::now(),
        }
    }

    pub fn record_event(&mut self, event: SecurityEvent) {
        if event.is_critical() {
            self.critical_events += 1;
        }

        match event.result {
            EventResult::Blocked | EventResult::Quarantined => self.blocked_count += 1,
            EventResult::Allowed => self.allowed_count += 1,
            _ => {}
        }

        self.events.push(event);
    }

    pub fn get_critical_events(&self) -> Vec<&SecurityEvent> {
        self.events
            .iter()
            .filter(|e| e.threat_level == ThreatLevel::Critical)
            .collect()
    }

    pub fn get_events_by_type(&self, event_type: SecurityEventType) -> Vec<&SecurityEvent> {
        self.events
            .iter()
            .filter(|e| e.event_type == event_type)
            .collect()
    }

    pub fn get_events_by_actor(&self, actor: &str) -> Vec<&SecurityEvent> {
        self.events
            .iter()
            .filter(|e| e.actor == actor)
            .collect()
    }

    pub fn get_events_since(&self, since: DateTime<Utc>) -> Vec<&SecurityEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp > since)
            .collect()
    }

    pub fn get_statistics(&self) -> SecurityAuditStatistics {
        let total_events = self.events.len();
        let by_threat_level = self.get_threat_distribution();
        let by_event_type = self.get_event_type_distribution();

        SecurityAuditStatistics {
            total_events,
            blocked_events: self.blocked_count,
            allowed_events: self.allowed_count,
            critical_events: self.critical_events,
            threat_level_distribution: by_threat_level,
            event_type_distribution: by_event_type,
        }
    }

    fn get_threat_distribution(&self) -> HashMap<String, usize> {
        let mut distribution = HashMap::new();
        for event in &self.events {
            let level = match event.threat_level {
                ThreatLevel::Low => "Low",
                ThreatLevel::Medium => "Medium",
                ThreatLevel::High => "High",
                ThreatLevel::Critical => "Critical",
            };
            *distribution.entry(level.to_string()).or_insert(0) += 1;
        }
        distribution
    }

    fn get_event_type_distribution(&self) -> HashMap<String, usize> {
        let mut distribution = HashMap::new();
        for event in &self.events {
            let event_type = format!("{:?}", event.event_type);
            *distribution.entry(event_type).or_insert(0) += 1;
        }
        distribution
    }
}

impl Default for SecurityAudit {
    fn default() -> Self {
        Self::new("Default Audit".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditStatistics {
    pub total_events: usize,
    pub blocked_events: u32,
    pub allowed_events: u32,
    pub critical_events: u32,
    pub threat_level_distribution: HashMap<String, usize>,
    pub event_type_distribution: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_event_creation() {
        let event = SecurityEvent::new(
            SecurityEventType::AuthenticationFailure,
            ThreatLevel::Medium,
            "user1".to_string(),
            "api".to_string(),
            "failed_login".to_string(),
        );
        assert_eq!(event.threat_level, ThreatLevel::Medium);
    }

    #[test]
    fn test_security_event_is_critical() {
        let event = SecurityEvent::new(
            SecurityEventType::PrivilegeEscalation,
            ThreatLevel::Critical,
            "attacker".to_string(),
            "system".to_string(),
            "escalation_attempt".to_string(),
        );
        assert!(event.is_critical());
    }

    #[test]
    fn test_security_audit_creation() {
        let audit = SecurityAudit::new("test_audit".to_string());
        assert_eq!(audit.events.len(), 0);
    }

    #[test]
    fn test_record_event() {
        let mut audit = SecurityAudit::new("test_audit".to_string());
        let event = SecurityEvent::new(
            SecurityEventType::SQLInjectionAttempt,
            ThreatLevel::High,
            "attacker".to_string(),
            "database".to_string(),
            "injection_attempt".to_string(),
        ).with_result(EventResult::Blocked);

        audit.record_event(event);
        assert_eq!(audit.blocked_count, 1);
    }

    #[test]
    fn test_get_critical_events() {
        let mut audit = SecurityAudit::new("test_audit".to_string());
        let event = SecurityEvent::new(
            SecurityEventType::MalwareDetected,
            ThreatLevel::Critical,
            "system".to_string(),
            "file".to_string(),
            "malware_detected".to_string(),
        );
        audit.record_event(event);

        let critical = audit.get_critical_events();
        assert_eq!(critical.len(), 1);
    }
}
