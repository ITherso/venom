pub mod console;
pub mod commands;
pub mod agents;

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

pub use console::{C2Console, ConsoleSession};
pub use commands::{Command, CommandType, CommandResult};
pub use agents::{Agent, AgentStatus};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Server {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub created_at: DateTime<Utc>,
    pub agents: HashMap<String, Agent>,
    pub is_active: bool,
}

impl C2Server {
    pub fn new(name: String, host: String, port: u16) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            host,
            port,
            created_at: Utc::now(),
            agents: HashMap::new(),
            is_active: true,
        }
    }

    pub fn register_agent(&mut self, agent: Agent) -> bool {
        if !self.agents.contains_key(&agent.id) {
            self.agents.insert(agent.id.clone(), agent);
            true
        } else {
            false
        }
    }

    pub fn get_agent(&self, agent_id: &str) -> Option<&Agent> {
        self.agents.get(agent_id)
    }

    pub fn get_agent_mut(&mut self, agent_id: &str) -> Option<&mut Agent> {
        self.agents.get_mut(agent_id)
    }

    pub fn unregister_agent(&mut self, agent_id: &str) -> Option<Agent> {
        self.agents.remove(agent_id)
    }

    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }

    pub fn active_agents(&self) -> Vec<&Agent> {
        self.agents
            .values()
            .filter(|a| matches!(a.status, AgentStatus::Active))
            .collect()
    }

    pub fn idle_agents(&self) -> Vec<&Agent> {
        self.agents
            .values()
            .filter(|a| matches!(a.status, AgentStatus::Idle))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Task {
    pub id: String,
    pub agent_id: String,
    pub command: Command,
    pub created_at: DateTime<Utc>,
    pub executed_at: Option<DateTime<Utc>>,
    pub result: Option<CommandResult>,
    pub status: TaskStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl C2Task {
    pub fn new(agent_id: String, command: Command) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            agent_id,
            command,
            created_at: Utc::now(),
            executed_at: None,
            result: None,
            status: TaskStatus::Pending,
        }
    }

    pub fn mark_running(&mut self) {
        self.status = TaskStatus::Running;
        self.executed_at = Some(Utc::now());
    }

    pub fn mark_completed(&mut self, result: CommandResult) {
        self.status = TaskStatus::Completed;
        self.result = Some(result);
    }

    pub fn mark_failed(&mut self, error: String) {
        self.status = TaskStatus::Failed;
        self.result = Some(CommandResult {
            output: String::new(),
            error: Some(error),
            exit_code: 1,
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskQueue {
    tasks: HashMap<String, C2Task>,
}

impl TaskQueue {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
        }
    }

    pub fn add_task(&mut self, task: C2Task) {
        self.tasks.insert(task.id.clone(), task);
    }

    pub fn get_task(&self, task_id: &str) -> Option<&C2Task> {
        self.tasks.get(task_id)
    }

    pub fn get_task_mut(&mut self, task_id: &str) -> Option<&mut C2Task> {
        self.tasks.get_mut(task_id)
    }

    pub fn get_pending_for_agent(&self, agent_id: &str) -> Vec<&C2Task> {
        self.tasks
            .values()
            .filter(|t| t.agent_id == agent_id && matches!(t.status, TaskStatus::Pending))
            .collect()
    }

    pub fn list_tasks(&self) -> Vec<&C2Task> {
        self.tasks.values().collect()
    }

    pub fn cancel_task(&mut self, task_id: &str) -> bool {
        if let Some(task) = self.tasks.get_mut(task_id) {
            if matches!(task.status, TaskStatus::Pending | TaskStatus::Running) {
                task.status = TaskStatus::Cancelled;
                return true;
            }
        }
        false
    }
}

impl Default for TaskQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c2_server_creation() {
        let server = C2Server::new("C2 Server".to_string(), "127.0.0.1".to_string(), 8888);
        assert_eq!(server.name, "C2 Server");
        assert!(server.is_active);
    }

    #[test]
    fn test_agent_registration() {
        let mut server = C2Server::new("C2".to_string(), "127.0.0.1".to_string(), 8888);
        let agent = Agent::new("test-target".to_string(), "windows".to_string());

        assert!(server.register_agent(agent));
        assert_eq!(server.agent_count(), 1);
    }

    #[test]
    fn test_task_creation() {
        let cmd = Command::new(CommandType::Exec, "whoami".to_string());
        let task = C2Task::new("agent1".to_string(), cmd);

        assert_eq!(task.status, TaskStatus::Pending);
    }

    #[test]
    fn test_task_queue() {
        let mut queue = TaskQueue::new();
        let cmd = Command::new(CommandType::Exec, "ls".to_string());
        let task = C2Task::new("agent1".to_string(), cmd);

        queue.add_task(task);
        assert_eq!(queue.list_tasks().len(), 1);
    }
}
