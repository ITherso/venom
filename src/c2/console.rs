use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Console {
    pub id: String,
    pub session_id: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub sessions: HashMap<String, ConsoleSession>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleSession {
    pub id: String,
    pub agent_id: String,
    pub started_at: DateTime<Utc>,
    pub last_command_at: Option<DateTime<Utc>>,
    pub command_count: u32,
    pub is_interactive: bool,
}

impl C2Console {
    pub fn new(user_id: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            session_id: Uuid::new_v4().to_string(),
            user_id,
            created_at: Utc::now(),
            last_activity: Utc::now(),
            sessions: HashMap::new(),
        }
    }

    pub fn create_session(&mut self, agent_id: String, interactive: bool) -> ConsoleSession {
        let session = ConsoleSession {
            id: Uuid::new_v4().to_string(),
            agent_id,
            started_at: Utc::now(),
            last_command_at: None,
            command_count: 0,
            is_interactive: interactive,
        };

        self.sessions.insert(session.id.clone(), session.clone());
        self.last_activity = Utc::now();

        session
    }

    pub fn get_session(&self, session_id: &str) -> Option<&ConsoleSession> {
        self.sessions.get(session_id)
    }

    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut ConsoleSession> {
        self.sessions.get_mut(session_id)
    }

    pub fn close_session(&mut self, session_id: &str) -> Option<ConsoleSession> {
        self.last_activity = Utc::now();
        self.sessions.remove(session_id)
    }

    pub fn record_command(&mut self, session_id: &str) {
        if let Some(session) = self.get_session_mut(session_id) {
            session.command_count += 1;
            session.last_command_at = Some(Utc::now());
        }
        self.last_activity = Utc::now();
    }

    pub fn list_sessions(&self) -> Vec<&ConsoleSession> {
        self.sessions.values().collect()
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }
}

impl ConsoleSession {
    pub fn duration_seconds(&self) -> u64 {
        (Utc::now() - self.started_at).num_seconds().max(0) as u64
    }

    pub fn idle_seconds(&self) -> u64 {
        if let Some(last_cmd) = self.last_command_at {
            (Utc::now() - last_cmd).num_seconds().max(0) as u64
        } else {
            self.duration_seconds()
        }
    }

    pub fn is_idle(&self) -> bool {
        self.idle_seconds() > 300 // 5 minutes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleMessage {
    pub id: String,
    pub session_id: String,
    pub content: String,
    pub message_type: MessageType,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Command,
    Output,
    Error,
    Status,
    System,
}

impl ConsoleMessage {
    pub fn new(session_id: String, content: String, message_type: MessageType) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            session_id,
            content,
            message_type,
            timestamp: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleHistory {
    pub session_id: String,
    pub messages: Vec<ConsoleMessage>,
    pub created_at: DateTime<Utc>,
}

impl ConsoleHistory {
    pub fn new(session_id: String) -> Self {
        Self {
            session_id,
            messages: Vec::new(),
            created_at: Utc::now(),
        }
    }

    pub fn add_message(&mut self, message: ConsoleMessage) {
        self.messages.push(message);
    }

    pub fn get_messages(&self, count: usize) -> Vec<&ConsoleMessage> {
        self.messages.iter().rev().take(count).collect()
    }

    pub fn last_n_messages(&self, n: usize) -> Vec<&ConsoleMessage> {
        self.messages.iter().rev().take(n).rev().collect()
    }

    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    pub fn search_messages(&self, query: &str) -> Vec<&ConsoleMessage> {
        self.messages
            .iter()
            .filter(|m| m.content.to_lowercase().contains(&query.to_lowercase()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_console_creation() {
        let console = C2Console::new("user1".to_string());
        assert_eq!(console.user_id, "user1");
        assert_eq!(console.active_session_count(), 0);
    }

    #[test]
    fn test_session_creation() {
        let mut console = C2Console::new("user1".to_string());
        let session = console.create_session("agent1".to_string(), true);

        assert_eq!(session.agent_id, "agent1");
        assert!(session.is_interactive);
    }

    #[test]
    fn test_command_recording() {
        let mut console = C2Console::new("user1".to_string());
        let session = console.create_session("agent1".to_string(), true);

        console.record_command(&session.id);
        let updated = console.get_session(&session.id).unwrap();
        assert_eq!(updated.command_count, 1);
    }

    #[test]
    fn test_console_history() {
        let mut history = ConsoleHistory::new("session1".to_string());
        let msg = ConsoleMessage::new("session1".to_string(), "test".to_string(), MessageType::Command);

        history.add_message(msg);
        assert_eq!(history.message_count(), 1);
    }

    #[test]
    fn test_message_search() {
        let mut history = ConsoleHistory::new("session1".to_string());

        history.add_message(ConsoleMessage::new(
            "session1".to_string(),
            "whoami".to_string(),
            MessageType::Command,
        ));

        history.add_message(ConsoleMessage::new(
            "session1".to_string(),
            "root".to_string(),
            MessageType::Output,
        ));

        let results = history.search_messages("root");
        assert_eq!(results.len(), 1);
    }
}
