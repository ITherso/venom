use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub status: HealthStatus,
    pub timestamp: DateTime<Utc>,
    pub version: String,
    pub components: HashMap<String, ComponentStatus>,
    pub dependencies: HashMap<String, DependencyStatus>,
    pub uptime_seconds: u64,
    pub checks_passed: usize,
    pub checks_failed: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub name: String,
    pub status: HealthStatus,
    pub message: String,
    pub last_check: DateTime<Utc>,
    pub response_time_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyStatus {
    pub name: String,
    pub service_type: String,
    pub status: HealthStatus,
    pub host: String,
    pub port: u16,
    pub latency_ms: u32,
    pub last_check: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct HealthChecker {
    pub components: HashMap<String, ComponentStatus>,
    pub dependencies: HashMap<String, DependencyStatus>,
    pub start_time: DateTime<Utc>,
}

impl HealthChecker {
    pub fn new() -> Self {
        Self {
            components: HashMap::new(),
            dependencies: HashMap::new(),
            start_time: Utc::now(),
        }
    }

    pub fn add_component(&mut self, component: ComponentStatus) {
        self.components.insert(component.name.clone(), component);
    }

    pub fn add_dependency(&mut self, dependency: DependencyStatus) {
        self.dependencies.insert(dependency.name.clone(), dependency);
    }

    pub fn check_health(&self) -> HealthReport {
        let all_healthy = self.components.values().all(|c| c.status == HealthStatus::Healthy)
            && self.dependencies.values().all(|d| d.status == HealthStatus::Healthy);

        let any_degraded = self.components.values().any(|c| c.status == HealthStatus::Degraded)
            || self.dependencies.values().any(|d| d.status == HealthStatus::Degraded);

        let status = if all_healthy {
            HealthStatus::Healthy
        } else if any_degraded {
            HealthStatus::Degraded
        } else {
            HealthStatus::Unhealthy
        };

        let checks_passed = self.components.values().filter(|c| c.status == HealthStatus::Healthy).count()
            + self.dependencies.values().filter(|d| d.status == HealthStatus::Healthy).count();

        let checks_failed = self.components.len() + self.dependencies.len() - checks_passed;

        HealthReport {
            status,
            timestamp: Utc::now(),
            version: "1.0.0".to_string(),
            components: self.components.clone(),
            dependencies: self.dependencies.clone(),
            uptime_seconds: (Utc::now() - self.start_time).num_seconds() as u64,
            checks_passed,
            checks_failed,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.components.values().all(|c| c.status != HealthStatus::Unhealthy)
            && self.dependencies.values().all(|d| d.status != HealthStatus::Unhealthy)
    }

    pub fn is_alive(&self) -> bool {
        true
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_checker_creation() {
        let checker = HealthChecker::new();
        assert_eq!(checker.components.len(), 0);
    }

    #[test]
    fn test_add_component() {
        let mut checker = HealthChecker::new();
        let component = ComponentStatus {
            name: "database".to_string(),
            status: HealthStatus::Healthy,
            message: "Connected".to_string(),
            last_check: Utc::now(),
            response_time_ms: 10,
        };
        checker.add_component(component);
        assert_eq!(checker.components.len(), 1);
    }

    #[test]
    fn test_health_report() {
        let mut checker = HealthChecker::new();
        let component = ComponentStatus {
            name: "api".to_string(),
            status: HealthStatus::Healthy,
            message: "Running".to_string(),
            last_check: Utc::now(),
            response_time_ms: 5,
        };
        checker.add_component(component);

        let report = checker.check_health();
        assert_eq!(report.status, HealthStatus::Healthy);
        assert!(report.checks_passed > 0);
    }
}
