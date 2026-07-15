use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: String,
    pub name: String,
    pub secret_type: SecretType,
    pub value_hash: String,
    pub created_at: DateTime<Utc>,
    pub last_rotated: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SecretType {
    APIKey,
    DatabasePassword,
    TLSCertificate,
    PrivateKey,
    JWTSecret,
    OAuthToken,
    SessionSecret,
    EncryptionKey,
}

impl SecretType {
    pub fn rotation_days(&self) -> u32 {
        match self {
            SecretType::APIKey => 90,
            SecretType::DatabasePassword => 90,
            SecretType::TLSCertificate => 365,
            SecretType::PrivateKey => 365,
            SecretType::JWTSecret => 90,
            SecretType::OAuthToken => 180,
            SecretType::SessionSecret => 30,
            SecretType::EncryptionKey => 180,
        }
    }
}

impl Secret {
    pub fn new(name: String, secret_type: SecretType, value_hash: String) -> Self {
        let rotation_days = secret_type.rotation_days();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            secret_type,
            value_hash,
            created_at: Utc::now(),
            last_rotated: Utc::now(),
            expires_at: Some(Utc::now() + Duration::days(rotation_days as i64)),
            is_active: true,
            metadata: HashMap::new(),
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            Utc::now() > expires
        } else {
            false
        }
    }

    pub fn needs_rotation(&self) -> bool {
        let rotation_days = self.secret_type.rotation_days();
        let age = (Utc::now() - self.last_rotated).num_days();
        age >= rotation_days as i64
    }

    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRotation {
    pub id: String,
    pub secret_id: String,
    pub secret_name: String,
    pub rotation_time: DateTime<Utc>,
    pub rotated_by: String,
    pub reason: String,
    pub success: bool,
    pub error_message: Option<String>,
}

impl SecretRotation {
    pub fn new(secret_id: String, secret_name: String, rotated_by: String, reason: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            secret_id,
            secret_name,
            rotation_time: Utc::now(),
            rotated_by,
            reason,
            success: true,
            error_message: None,
        }
    }

    pub fn mark_failed(mut self, error: String) -> Self {
        self.success = false;
        self.error_message = Some(error);
        self
    }
}

#[derive(Debug, Clone)]
pub struct SecretManager {
    secrets: HashMap<String, Secret>,
    rotation_history: Vec<SecretRotation>,
    max_age_days: u32,
}

impl SecretManager {
    pub fn new(max_age_days: u32) -> Self {
        Self {
            secrets: HashMap::new(),
            rotation_history: Vec::new(),
            max_age_days,
        }
    }

    pub fn store_secret(&mut self, secret: Secret) -> String {
        let secret_id = secret.id.clone();
        self.secrets.insert(secret_id.clone(), secret);
        secret_id
    }

    pub fn get_secret(&self, secret_id: &str) -> Option<&Secret> {
        self.secrets.get(secret_id)
    }

    pub fn get_secret_by_name(&self, name: &str) -> Option<&Secret> {
        self.secrets.values().find(|s| s.name == name)
    }

    pub fn rotate_secret(&mut self, secret_id: &str, new_value_hash: String, rotated_by: String) -> bool {
        if let Some(secret) = self.secrets.get_mut(secret_id) {
            let secret_name = secret.name.clone();
            let secret_type = secret.secret_type;

            secret.value_hash = new_value_hash;
            secret.last_rotated = Utc::now();
            secret.expires_at = Some(Utc::now() + Duration::days(secret_type.rotation_days() as i64));

            let rotation = SecretRotation::new(
                secret_id.to_string(),
                secret_name,
                rotated_by,
                "Scheduled rotation".to_string(),
            );
            self.rotation_history.push(rotation);

            true
        } else {
            false
        }
    }

    pub fn get_secrets_needing_rotation(&self) -> Vec<&Secret> {
        self.secrets
            .values()
            .filter(|s| s.is_active && s.needs_rotation())
            .collect()
    }

    pub fn get_expired_secrets(&self) -> Vec<&Secret> {
        self.secrets
            .values()
            .filter(|s| s.is_expired())
            .collect()
    }

    pub fn deactivate_secret(&mut self, secret_id: &str) -> bool {
        if let Some(secret) = self.secrets.get_mut(secret_id) {
            secret.is_active = false;
            true
        } else {
            false
        }
    }

    pub fn get_rotation_history(&self, secret_id: &str) -> Vec<&SecretRotation> {
        self.rotation_history
            .iter()
            .filter(|r| r.secret_id == secret_id)
            .collect()
    }

    pub fn cleanup_expired(&mut self) {
        self.secrets.retain(|_, s| !s.is_expired());
    }

    pub fn get_statistics(&self) -> SecretStatistics {
        let total_secrets = self.secrets.len();
        let active_secrets = self.secrets.values().filter(|s| s.is_active).count();
        let expired_secrets = self.secrets.values().filter(|s| s.is_expired()).count();
        let needing_rotation = self.get_secrets_needing_rotation().len();

        let secret_types = self.secrets.values()
            .map(|s| s.secret_type)
            .collect::<std::collections::HashSet<_>>()
            .len();

        SecretStatistics {
            total_secrets,
            active_secrets,
            expired_secrets,
            needing_rotation,
            secret_types,
            total_rotations: self.rotation_history.len(),
            successful_rotations: self.rotation_history.iter().filter(|r| r.success).count(),
        }
    }
}

impl Default for SecretManager {
    fn default() -> Self {
        Self::new(365)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretStatistics {
    pub total_secrets: usize,
    pub active_secrets: usize,
    pub expired_secrets: usize,
    pub needing_rotation: usize,
    pub secret_types: usize,
    pub total_rotations: usize,
    pub successful_rotations: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_creation() {
        let secret = Secret::new(
            "api_key".to_string(),
            SecretType::APIKey,
            "hash123".to_string(),
        );
        assert!(secret.is_active);
    }

    #[test]
    fn test_secret_needs_rotation() {
        let mut secret = Secret::new(
            "db_password".to_string(),
            SecretType::DatabasePassword,
            "hash123".to_string(),
        );
        secret.last_rotated = Utc::now() - Duration::days(91);
        assert!(secret.needs_rotation());
    }

    #[test]
    fn test_secret_manager() {
        let mut manager = SecretManager::new(365);
        let secret = Secret::new(
            "api_key".to_string(),
            SecretType::APIKey,
            "hash123".to_string(),
        );
        let id = secret.id.clone();
        manager.store_secret(secret);

        assert!(manager.get_secret(&id).is_some());
    }

    #[test]
    fn test_secret_rotation() {
        let mut manager = SecretManager::new(365);
        let secret = Secret::new(
            "api_key".to_string(),
            SecretType::APIKey,
            "hash123".to_string(),
        );
        let id = secret.id.clone();
        manager.store_secret(secret);

        assert!(manager.rotate_secret(&id, "new_hash".to_string(), "admin".to_string()));
        assert_eq!(manager.rotation_history.len(), 1);
    }

    #[test]
    fn test_get_statistics() {
        let mut manager = SecretManager::new(365);
        let secret = Secret::new(
            "api_key".to_string(),
            SecretType::APIKey,
            "hash123".to_string(),
        );
        manager.store_secret(secret);

        let stats = manager.get_statistics();
        assert_eq!(stats.total_secrets, 1);
    }
}
