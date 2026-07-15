use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub os_type: String,
    pub os_version: Option<String>,
    pub arch: String,
    pub ip_address: Option<String>,
    pub process_id: Option<u32>,
    pub parent_process_id: Option<u32>,
    pub username: Option<String>,
    pub status: AgentStatus,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub is_privileged: bool,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgentStatus {
    Active,
    Idle,
    Lost,
    Dead,
}

impl Agent {
    pub fn new(hostname: String, os_type: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: format!("Agent-{}", &Uuid::new_v4().to_string()[0..8]),
            hostname,
            os_type,
            os_version: None,
            arch: "x64".to_string(),
            ip_address: None,
            process_id: None,
            parent_process_id: None,
            username: None,
            status: AgentStatus::Active,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            is_privileged: false,
            capabilities: Vec::new(),
        }
    }

    pub fn with_ip(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }

    pub fn with_pid(mut self, pid: u32) -> Self {
        self.process_id = Some(pid);
        self
    }

    pub fn with_user(mut self, username: String) -> Self {
        self.username = Some(username);
        self
    }

    pub fn with_privileges(mut self, privileged: bool) -> Self {
        self.is_privileged = privileged;
        self
    }

    pub fn add_capability(&mut self, capability: String) {
        if !self.capabilities.contains(&capability) {
            self.capabilities.push(capability);
        }
    }

    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|c| c == capability)
    }

    pub fn mark_active(&mut self) {
        self.status = AgentStatus::Active;
        self.last_seen = Utc::now();
    }

    pub fn mark_idle(&mut self) {
        self.status = AgentStatus::Idle;
    }

    pub fn mark_lost(&mut self) {
        self.status = AgentStatus::Lost;
    }

    pub fn is_alive(&self) -> bool {
        matches!(self.status, AgentStatus::Active | AgentStatus::Idle)
    }

    pub fn uptime_seconds(&self) -> u64 {
        (Utc::now() - self.first_seen).num_seconds().max(0) as u64
    }

    pub fn idle_seconds(&self) -> u64 {
        (Utc::now() - self.last_seen).num_seconds().max(0) as u64
    }

    pub fn is_idle(&self) -> bool {
        self.idle_seconds() > 300 // 5 minutes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub agent_id: String,
    pub hostname: String,
    pub ip_address: Option<String>,
    pub os_info: String,
    pub username: Option<String>,
    pub is_privileged: bool,
    pub capabilities: Vec<String>,
}

impl From<&Agent> for AgentInfo {
    fn from(agent: &Agent) -> Self {
        Self {
            agent_id: agent.id.clone(),
            hostname: agent.hostname.clone(),
            ip_address: agent.ip_address.clone(),
            os_info: format!("{} {}", agent.os_type, agent.os_version.as_deref().unwrap_or("")),
            username: agent.username.clone(),
            is_privileged: agent.is_privileged,
            capabilities: agent.capabilities.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealth {
    pub agent_id: String,
    pub status: AgentStatus,
    pub uptime_seconds: u64,
    pub idle_seconds: u64,
    pub last_checkin: DateTime<Utc>,
}

impl AgentHealth {
    pub fn from_agent(agent: &Agent) -> Self {
        Self {
            agent_id: agent.id.clone(),
            status: agent.status.clone(),
            uptime_seconds: agent.uptime_seconds(),
            idle_seconds: agent.idle_seconds(),
            last_checkin: agent.last_seen,
        }
    }

    pub fn is_healthy(&self) -> bool {
        matches!(self.status, AgentStatus::Active) && self.idle_seconds < 300
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_creation() {
        let agent = Agent::new("localhost".to_string(), "Linux".to_string());
        assert_eq!(agent.hostname, "localhost");
        assert!(matches!(agent.status, AgentStatus::Active));
    }

    #[test]
    fn test_agent_builder() {
        let agent = Agent::new("target.com".to_string(), "Windows".to_string())
            .with_ip("192.168.1.100".to_string())
            .with_user("admin".to_string())
            .with_privileges(true);

        assert_eq!(agent.ip_address, Some("192.168.1.100".to_string()));
        assert!(agent.is_privileged);
    }

    #[test]
    fn test_agent_capabilities() {
        let mut agent = Agent::new("localhost".to_string(), "Linux".to_string());

        agent.add_capability("cmd_exec".to_string());
        agent.add_capability("file_transfer".to_string());

        assert!(agent.has_capability("cmd_exec"));
        assert_eq!(agent.capabilities.len(), 2);
    }

    #[test]
    fn test_agent_status_transitions() {
        let mut agent = Agent::new("localhost".to_string(), "Linux".to_string());

        assert!(agent.is_alive());

        agent.mark_idle();
        assert_eq!(agent.status, AgentStatus::Idle);
        assert!(agent.is_alive());

        agent.mark_lost();
        assert!(!agent.is_alive());
    }

    #[test]
    fn test_agent_info_conversion() {
        let agent = Agent::new("test.com".to_string(), "Linux".to_string())
            .with_user("testuser".to_string());

        let info = AgentInfo::from(&agent);
        assert_eq!(info.hostname, "test.com");
        assert_eq!(info.username, Some("testuser".to_string()));
    }

    #[test]
    fn test_agent_health() {
        let agent = Agent::new("localhost".to_string(), "Linux".to_string());
        let health = AgentHealth::from_agent(&agent);

        assert_eq!(health.agent_id, agent.id);
    }
}
