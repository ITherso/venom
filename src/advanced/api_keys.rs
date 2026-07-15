use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use std::collections::HashMap;
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    pub key_hash: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub usage_count: u32,
    pub rate_limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyManager {
    keys: HashMap<String, ApiKey>,
}

impl ApiKey {
    pub fn new(name: String, scopes: Vec<String>) -> (Self, String) {
        let raw_key = format!("venom_{}", Uuid::new_v4().to_string().replace("-", ""));
        let key_prefix = raw_key[0..12].to_string();

        let mut hasher = Sha256::new();
        hasher.update(&raw_key);
        let key_hash = format!("{:x}", hasher.finalize());

        let key = Self {
            id: Uuid::new_v4().to_string(),
            name,
            key_hash,
            key_prefix,
            scopes,
            created_at: Utc::now(),
            last_used_at: None,
            expires_at: None,
            is_active: true,
            usage_count: 0,
            rate_limit: None,
        };

        (key, raw_key)
    }

    pub fn with_expiry(mut self, days: i64) -> Self {
        self.expires_at = Some(Utc::now() + Duration::days(days));
        self
    }

    pub fn with_rate_limit(mut self, limit: u32) -> Self {
        self.rate_limit = Some(limit);
        self
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            Utc::now() > expires
        } else {
            false
        }
    }

    pub fn is_valid(&self) -> bool {
        self.is_active && !self.is_expired()
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(&scope.to_string())
    }

    pub fn record_usage(&mut self) {
        self.usage_count += 1;
        self.last_used_at = Some(Utc::now());
    }
}

impl ApiKeyManager {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    pub fn create_key(&mut self, name: String, scopes: Vec<String>) -> (String, String) {
        let (key, raw_key) = ApiKey::new(name, scopes);
        let key_id = key.id.clone();
        self.keys.insert(key_id.clone(), key);
        (key_id, raw_key)
    }

    pub fn get_key(&self, key_id: &str) -> Option<&ApiKey> {
        self.keys.get(key_id)
    }

    pub fn get_key_mut(&mut self, key_id: &str) -> Option<&mut ApiKey> {
        self.keys.get_mut(key_id)
    }

    pub fn verify_key(&self, raw_key: &str) -> Option<&ApiKey> {
        let mut hasher = Sha256::new();
        hasher.update(raw_key);
        let key_hash = format!("{:x}", hasher.finalize());

        self.keys
            .values()
            .find(|k| k.key_hash == key_hash && k.is_valid())
    }

    pub fn verify_key_and_scope(&self, raw_key: &str, scope: &str) -> bool {
        if let Some(key) = self.verify_key(raw_key) {
            key.has_scope(scope)
        } else {
            false
        }
    }

    pub fn revoke_key(&mut self, key_id: &str) -> bool {
        if let Some(key) = self.keys.get_mut(key_id) {
            key.is_active = false;
            true
        } else {
            false
        }
    }

    pub fn delete_key(&mut self, key_id: &str) -> Option<ApiKey> {
        self.keys.remove(key_id)
    }

    pub fn list_keys(&self) -> Vec<&ApiKey> {
        self.keys.values().collect()
    }

    pub fn list_active_keys(&self) -> Vec<&ApiKey> {
        self.keys
            .values()
            .filter(|k| k.is_active && !k.is_expired())
            .collect()
    }

    pub fn get_by_name(&self, name: &str) -> Option<&ApiKey> {
        self.keys.values().find(|k| k.name == name)
    }

    pub fn rotate_key(&mut self, key_id: &str) -> Option<(String, String)> {
        if let Some(old_key) = self.keys.remove(key_id) {
            let (new_key, raw_key) = ApiKey::new(old_key.name, old_key.scopes);
            let new_key_id = new_key.id.clone();
            self.keys.insert(new_key_id.clone(), new_key);
            Some((new_key_id, raw_key))
        } else {
            None
        }
    }

    pub fn cleanup_expired(&mut self) {
        self.keys.retain(|_, k| !k.is_expired());
    }

    pub fn get_statistics(&self) -> ApiKeyStatistics {
        let total = self.keys.len();
        let active = self.keys.values().filter(|k| k.is_valid()).count();
        let expired = self.keys.values().filter(|k| k.is_expired()).count();
        let total_usage: u32 = self.keys.values().map(|k| k.usage_count).sum();

        ApiKeyStatistics {
            total_keys: total,
            active_keys: active,
            expired_keys: expired,
            revoked_keys: total - active - expired,
            total_usage,
            average_usage_per_key: if total > 0 { total_usage as f32 / total as f32 } else { 0.0 },
        }
    }
}

impl Default for ApiKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyStatistics {
    pub total_keys: usize,
    pub active_keys: usize,
    pub expired_keys: usize,
    pub revoked_keys: usize,
    pub total_usage: u32,
    pub average_usage_per_key: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_creation() {
        let (key, raw_key) = ApiKey::new("test".to_string(), vec!["read".to_string()]);
        assert!(key.is_valid());
        assert!(!raw_key.is_empty());
    }

    #[test]
    fn test_key_manager_create_and_verify() {
        let mut manager = ApiKeyManager::new();
        let (key_id, raw_key) = manager.create_key("test".to_string(), vec!["read".to_string()]);

        let verified = manager.verify_key(&raw_key);
        assert!(verified.is_some());
    }

    #[test]
    fn test_key_expiry() {
        let key = ApiKey::new("test".to_string(), vec!["read".to_string()]).0;
        assert!(!key.is_expired());

        let expired_key = ApiKey::new("test".to_string(), vec!["read".to_string()])
            .0
            .with_expiry(-1);
        assert!(expired_key.is_expired());
    }

    #[test]
    fn test_key_revocation() {
        let mut manager = ApiKeyManager::new();
        let (key_id, _) = manager.create_key("test".to_string(), vec!["read".to_string()]);

        assert!(manager.revoke_key(&key_id));
        let key = manager.get_key(&key_id).unwrap();
        assert!(!key.is_active);
    }

    #[test]
    fn test_scope_verification() {
        let mut manager = ApiKeyManager::new();
        let (_, raw_key) = manager.create_key("test".to_string(), vec!["read".to_string(), "write".to_string()]);

        assert!(manager.verify_key_and_scope(&raw_key, "read"));
        assert!(!manager.verify_key_and_scope(&raw_key, "admin"));
    }
}
