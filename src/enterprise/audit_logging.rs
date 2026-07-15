use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditLevel {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuditCategory {
    Authentication,
    Authorization,
    DataAccess,
    Configuration,
    Backup,
    Restore,
    UserManagement,
    RoleManagement,
    SystemEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub level: AuditLevel,
    pub category: AuditCategory,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub status: String,
    pub details: HashMap<String, String>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
}

impl AuditEvent {
    pub fn new(
        level: AuditLevel,
        category: AuditCategory,
        actor: String,
        action: String,
        resource: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            level,
            category,
            actor,
            action,
            resource,
            status: "success".to_string(),
            details: HashMap::new(),
            source_ip: None,
            user_agent: None,
        }
    }

    pub fn with_status(mut self, status: String) -> Self {
        self.status = status;
        self
    }

    pub fn with_detail(mut self, key: String, value: String) -> Self {
        self.details.insert(key, value);
        self
    }

    pub fn with_source_ip(mut self, ip: String) -> Self {
        self.source_ip = Some(ip);
        self
    }

    pub fn with_user_agent(mut self, agent: String) -> Self {
        self.user_agent = Some(agent);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogger {
    events: Vec<AuditEvent>,
    retention_days: u32,
    max_events: usize,
    categories_enabled: HashMap<AuditCategory, bool>,
    level_filter: AuditLevel,
}

impl AuditLogger {
    pub fn new(retention_days: u32, max_events: usize) -> Self {
        let mut categories_enabled = HashMap::new();
        categories_enabled.insert(AuditCategory::Authentication, true);
        categories_enabled.insert(AuditCategory::Authorization, true);
        categories_enabled.insert(AuditCategory::DataAccess, true);
        categories_enabled.insert(AuditCategory::Configuration, true);
        categories_enabled.insert(AuditCategory::Backup, true);
        categories_enabled.insert(AuditCategory::Restore, true);
        categories_enabled.insert(AuditCategory::UserManagement, true);
        categories_enabled.insert(AuditCategory::RoleManagement, true);
        categories_enabled.insert(AuditCategory::SystemEvent, true);

        Self {
            events: Vec::new(),
            retention_days,
            max_events,
            categories_enabled,
            level_filter: AuditLevel::Info,
        }
    }

    pub fn log(&mut self, event: AuditEvent) {
        if self.should_log(&event) {
            self.events.push(event);
            if self.events.len() > self.max_events {
                self.events.remove(0);
            }
        }
    }

    fn should_log(&self, event: &AuditEvent) -> bool {
        let category_enabled = self
            .categories_enabled
            .get(&event.category)
            .copied()
            .unwrap_or(false);

        category_enabled && event.level >= self.level_filter
    }

    pub fn set_category_enabled(&mut self, category: AuditCategory, enabled: bool) {
        self.categories_enabled.insert(category, enabled);
    }

    pub fn set_level_filter(&mut self, level: AuditLevel) {
        self.level_filter = level;
    }

    pub fn get_events(&self) -> &[AuditEvent] {
        &self.events
    }

    pub fn get_events_by_category(&self, category: &AuditCategory) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| &e.category == category)
            .collect()
    }

    pub fn get_events_by_actor(&self, actor: &str) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| e.actor == actor)
            .collect()
    }

    pub fn get_events_by_level(&self, level: AuditLevel) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| e.level >= level)
            .collect()
    }

    pub fn get_events_by_resource(&self, resource: &str) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| e.resource == resource)
            .collect()
    }

    pub fn search(&self, query: &str) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                e.action.to_lowercase().contains(&query.to_lowercase())
                    || e.actor.to_lowercase().contains(&query.to_lowercase())
                    || e.resource.to_lowercase().contains(&query.to_lowercase())
            })
            .collect()
    }

    pub fn cleanup_expired(&mut self) {
        let cutoff = Utc::now() - chrono::Duration::days(self.retention_days as i64);
        self.events.retain(|e| e.timestamp > cutoff);
    }

    pub fn get_statistics(&self) -> AuditStatistics {
        let total_events = self.events.len();
        let critical_events = self.events.iter().filter(|e| e.level == AuditLevel::Critical).count();
        let error_events = self.events.iter().filter(|e| e.level == AuditLevel::Error).count();
        let warning_events = self.events.iter().filter(|e| e.level == AuditLevel::Warning).count();

        let mut actors = std::collections::HashSet::new();
        for event in &self.events {
            actors.insert(event.actor.clone());
        }

        AuditStatistics {
            total_events,
            critical_events,
            error_events,
            warning_events,
            unique_actors: actors.len(),
        }
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new(90, 10000)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStatistics {
    pub total_events: usize,
    pub critical_events: usize,
    pub error_events: usize,
    pub warning_events: usize,
    pub unique_actors: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            AuditLevel::Info,
            AuditCategory::Authentication,
            "user1".to_string(),
            "login".to_string(),
            "api".to_string(),
        );
        assert_eq!(event.actor, "user1");
        assert_eq!(event.status, "success");
    }

    #[test]
    fn test_audit_logger_creation() {
        let logger = AuditLogger::new(90, 10000);
        assert_eq!(logger.get_events().len(), 0);
    }

    #[test]
    fn test_log_event() {
        let mut logger = AuditLogger::new(90, 10000);
        let event = AuditEvent::new(
            AuditLevel::Info,
            AuditCategory::Authentication,
            "user1".to_string(),
            "login".to_string(),
            "api".to_string(),
        );
        logger.log(event);
        assert_eq!(logger.get_events().len(), 1);
    }

    #[test]
    fn test_search_events() {
        let mut logger = AuditLogger::new(90, 10000);
        let event = AuditEvent::new(
            AuditLevel::Info,
            AuditCategory::Authentication,
            "user1".to_string(),
            "login".to_string(),
            "api".to_string(),
        );
        logger.log(event);
        let results = logger.search("login");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_get_statistics() {
        let mut logger = AuditLogger::new(90, 10000);
        let event = AuditEvent::new(
            AuditLevel::Critical,
            AuditCategory::Authentication,
            "user1".to_string(),
            "login".to_string(),
            "api".to_string(),
        );
        logger.log(event);
        let stats = logger.get_statistics();
        assert_eq!(stats.total_events, 1);
        assert_eq!(stats.critical_events, 1);
    }
}
