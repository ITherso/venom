use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub secret: Option<String>,
    pub events: Vec<String>,
    pub active: bool,
    pub retry_enabled: bool,
    pub retry_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub id: String,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub data: serde_json::Value,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub id: String,
    pub webhook_id: String,
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub status: DeliveryStatus,
    pub response_status: Option<u16>,
    pub response_body: Option<String>,
    pub attempts: u32,
    pub next_retry: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeliveryStatus {
    Pending,
    Success,
    Failed,
    Retrying,
}

#[derive(Debug, Clone)]
pub struct WebhookManager {
    pub webhooks: HashMap<String, WebhookConfig>,
    pub events: Vec<WebhookEvent>,
    pub deliveries: Vec<WebhookDelivery>,
}

impl WebhookConfig {
    pub fn new(url: String) -> Self {
        Self {
            url,
            secret: None,
            events: vec!["*".to_string()],
            active: true,
            retry_enabled: true,
            retry_count: 3,
        }
    }

    pub fn with_secret(mut self, secret: String) -> Self {
        self.secret = Some(secret);
        self
    }

    pub fn with_events(mut self, events: Vec<String>) -> Self {
        self.events = events;
        self
    }

    pub fn should_handle_event(&self, event_type: &str) -> bool {
        self.active && (
            self.events.contains(&"*".to_string()) ||
            self.events.contains(&event_type.to_string())
        )
    }
}

impl WebhookEvent {
    pub fn new(event_type: String, data: serde_json::Value) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            event_type,
            timestamp: Utc::now(),
            data,
            signature: None,
        }
    }

    pub fn sign(&mut self, secret: &str) {
        use sha2::{Sha256, Digest};
        use hex;

        let payload = serde_json::to_string(&self.data).unwrap_or_default();
        let combined = format!("{}.{}", self.timestamp.timestamp(), payload);

        let mut hasher = Sha256::new();
        hasher.update(format!("{}:{}", combined, secret).as_bytes());
        let result = hasher.finalize();

        self.signature = Some(format!("sha256={}", hex::encode(result)));
    }
}

impl WebhookManager {
    pub fn new() -> Self {
        Self {
            webhooks: HashMap::new(),
            events: Vec::new(),
            deliveries: Vec::new(),
        }
    }

    pub fn register_webhook(&mut self, url: String) -> String {
        let id = Uuid::new_v4().to_string();
        let config = WebhookConfig::new(url);
        self.webhooks.insert(id.clone(), config);
        id
    }

    pub fn unregister_webhook(&mut self, id: &str) {
        self.webhooks.remove(id);
    }

    pub fn record_event(&mut self, event_type: String, data: serde_json::Value) {
        let mut event = WebhookEvent::new(event_type.clone(), data);

        // Sign event for each webhook
        for webhook in self.webhooks.values() {
            if webhook.should_handle_event(&event_type) {
                if let Some(secret) = &webhook.secret {
                    event.sign(secret);
                }
            }
        }

        self.events.push(event);
    }

    pub fn record_delivery(
        &mut self,
        webhook_id: String,
        event_id: String,
        status: DeliveryStatus,
    ) {
        let delivery = WebhookDelivery {
            id: Uuid::new_v4().to_string(),
            webhook_id,
            event_id,
            timestamp: Utc::now(),
            status,
            response_status: None,
            response_body: None,
            attempts: 1,
            next_retry: None,
        };

        self.deliveries.push(delivery);
    }

    pub fn get_delivery_status(&self, webhook_id: &str) -> Vec<&WebhookDelivery> {
        self.deliveries
            .iter()
            .filter(|d| d.webhook_id == webhook_id)
            .collect()
    }

    pub fn get_failed_deliveries(&self) -> Vec<&WebhookDelivery> {
        self.deliveries
            .iter()
            .filter(|d| d.status == DeliveryStatus::Failed)
            .collect()
    }

    pub fn retry_failed_deliveries(&mut self) {
        for delivery in self.deliveries.iter_mut() {
            if delivery.status == DeliveryStatus::Failed && delivery.attempts < 3 {
                delivery.status = DeliveryStatus::Retrying;
                delivery.attempts += 1;
            }
        }
    }
}

impl Default for WebhookManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_creation() {
        let webhook = WebhookConfig::new("https://example.com/webhook".to_string());
        assert_eq!(webhook.url, "https://example.com/webhook");
        assert!(webhook.active);
    }

    #[test]
    fn test_webhook_event_handling() {
        let webhook = WebhookConfig::new("https://example.com/webhook".to_string());
        assert!(webhook.should_handle_event("scan.complete"));
    }

    #[test]
    fn test_webhook_manager() {
        let mut manager = WebhookManager::new();
        let id = manager.register_webhook("https://example.com/webhook".to_string());
        assert!(manager.webhooks.contains_key(&id));
    }
}
