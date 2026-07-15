use crate::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketMessage {
    pub message_type: String, // "task_update", "scan_result", "exploit_success", "error"
    pub data: serde_json::Value,
    pub timestamp: String,
}

pub struct WebSocketBroadcaster {
    tx: broadcast::Sender<WebSocketMessage>,
}

impl WebSocketBroadcaster {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Subscribe to WebSocket messages
    pub fn subscribe(&self) -> broadcast::Receiver<WebSocketMessage> {
        self.tx.subscribe()
    }

    /// Broadcast task update
    pub fn broadcast_task_update(
        &self,
        task_id: &str,
        status: &str,
        progress: f32,
    ) -> Result<()> {
        let msg = WebSocketMessage {
            message_type: "task_update".to_string(),
            data: serde_json::json!({
                "task_id": task_id,
                "status": status,
                "progress": progress,
            }),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let _ = self.tx.send(msg);
        Ok(())
    }

    /// Broadcast scan result
    pub fn broadcast_scan_result(
        &self,
        scan_id: &str,
        vulnerability_type: &str,
        severity: &str,
    ) -> Result<()> {
        let msg = WebSocketMessage {
            message_type: "scan_result".to_string(),
            data: serde_json::json!({
                "scan_id": scan_id,
                "vulnerability_type": vulnerability_type,
                "severity": severity,
            }),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let _ = self.tx.send(msg);
        Ok(())
    }

    /// Broadcast exploit success
    pub fn broadcast_exploit_success(&self, exploit_id: &str, target: &str) -> Result<()> {
        let msg = WebSocketMessage {
            message_type: "exploit_success".to_string(),
            data: serde_json::json!({
                "exploit_id": exploit_id,
                "target": target,
            }),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let _ = self.tx.send(msg);
        Ok(())
    }

    /// Broadcast error
    pub fn broadcast_error(&self, error_type: &str, message: &str) -> Result<()> {
        let msg = WebSocketMessage {
            message_type: "error".to_string(),
            data: serde_json::json!({
                "error_type": error_type,
                "message": message,
            }),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let _ = self.tx.send(msg);
        Ok(())
    }

    /// Broadcast C2 callback
    pub fn broadcast_c2_callback(&self, agent_id: &str, output: &str) -> Result<()> {
        let msg = WebSocketMessage {
            message_type: "c2_callback".to_string(),
            data: serde_json::json!({
                "agent_id": agent_id,
                "output": output,
            }),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let _ = self.tx.send(msg);
        Ok(())
    }

    /// Get number of subscribers
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Clone for WebSocketBroadcaster {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_websocket_broadcast() {
        let broadcaster = WebSocketBroadcaster::new(100);
        let mut rx = broadcaster.subscribe();

        broadcaster
            .broadcast_task_update("task1", "running", 0.5)
            .unwrap();

        let msg = rx.recv().await.unwrap();
        assert_eq!(msg.message_type, "task_update");
    }
}
