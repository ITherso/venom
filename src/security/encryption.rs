use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    AES256GCM,
    ChaCha20Poly1305,
    AES128CBC,
}

impl EncryptionAlgorithm {
    pub fn key_size(&self) -> usize {
        match self {
            EncryptionAlgorithm::AES256GCM => 32,
            EncryptionAlgorithm::ChaCha20Poly1305 => 32,
            EncryptionAlgorithm::AES128CBC => 16,
        }
    }

    pub fn iv_size(&self) -> usize {
        match self {
            EncryptionAlgorithm::AES256GCM => 12,
            EncryptionAlgorithm::ChaCha20Poly1305 => 12,
            EncryptionAlgorithm::AES128CBC => 16,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            EncryptionAlgorithm::AES256GCM => "AES-256-GCM",
            EncryptionAlgorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            EncryptionAlgorithm::AES128CBC => "AES-128-CBC",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub id: String,
    pub algorithm: String,
    pub ciphertext: String,
    pub iv: String,
    pub tag: Option<String>,
    pub encrypted_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl EncryptedData {
    pub fn new(algorithm: EncryptionAlgorithm, ciphertext: String, iv: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            algorithm: algorithm.name().to_string(),
            ciphertext,
            iv,
            tag: None,
            encrypted_at: Utc::now(),
            created_at: Utc::now(),
        }
    }

    pub fn with_tag(mut self, tag: String) -> Self {
        self.tag = Some(tag);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cipher {
    pub id: String,
    pub algorithm: EncryptionAlgorithm,
    pub key_hash: String,
    pub key_derivation: KeyDerivation,
    pub rotation_count: u32,
    pub last_rotated: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyDerivation {
    PBKDF2,
    Argon2,
    HKDF,
    None,
}

impl Cipher {
    pub fn new(algorithm: EncryptionAlgorithm, key_hash: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            algorithm,
            key_hash,
            key_derivation: KeyDerivation::Argon2,
            rotation_count: 0,
            last_rotated: Utc::now(),
            is_active: true,
        }
    }

    pub fn with_key_derivation(mut self, derivation: KeyDerivation) -> Self {
        self.key_derivation = derivation;
        self
    }

    pub fn rotate(&mut self) {
        self.rotation_count += 1;
        self.last_rotated = Utc::now();
    }

    pub fn needs_rotation(&self, days_threshold: u32) -> bool {
        let age_days = (Utc::now() - self.last_rotated).num_days();
        age_days > days_threshold as i64
    }
}

#[derive(Debug, Clone)]
pub struct CipherManager {
    ciphers: HashMap<String, Cipher>,
    encrypted_data: HashMap<String, EncryptedData>,
    active_cipher_id: Option<String>,
}

impl CipherManager {
    pub fn new() -> Self {
        Self {
            ciphers: HashMap::new(),
            encrypted_data: HashMap::new(),
            active_cipher_id: None,
        }
    }

    pub fn register_cipher(&mut self, cipher: Cipher) -> String {
        let cipher_id = cipher.id.clone();
        self.ciphers.insert(cipher_id.clone(), cipher);
        if self.active_cipher_id.is_none() {
            self.active_cipher_id = Some(cipher_id.clone());
        }
        cipher_id
    }

    pub fn get_cipher(&self, cipher_id: &str) -> Option<&Cipher> {
        self.ciphers.get(cipher_id)
    }

    pub fn get_active_cipher(&self) -> Option<&Cipher> {
        self.active_cipher_id.as_ref()
            .and_then(|id| self.ciphers.get(id))
    }

    pub fn set_active_cipher(&mut self, cipher_id: String) -> bool {
        if self.ciphers.contains_key(&cipher_id) {
            self.active_cipher_id = Some(cipher_id);
            true
        } else {
            false
        }
    }

    pub fn store_encrypted(&mut self, data: EncryptedData) -> String {
        let data_id = data.id.clone();
        self.encrypted_data.insert(data_id.clone(), data);
        data_id
    }

    pub fn get_encrypted(&self, data_id: &str) -> Option<&EncryptedData> {
        self.encrypted_data.get(data_id)
    }

    pub fn rotate_cipher(&mut self, cipher_id: &str) -> bool {
        if let Some(cipher) = self.ciphers.get_mut(cipher_id) {
            cipher.rotate();
            true
        } else {
            false
        }
    }

    pub fn get_ciphers_needing_rotation(&self, days_threshold: u32) -> Vec<&Cipher> {
        self.ciphers
            .values()
            .filter(|c| c.needs_rotation(days_threshold))
            .collect()
    }

    pub fn deactivate_cipher(&mut self, cipher_id: &str) -> bool {
        if let Some(cipher) = self.ciphers.get_mut(cipher_id) {
            cipher.is_active = false;
            if self.active_cipher_id.as_ref().map(|id| id == cipher_id).unwrap_or(false) {
                self.active_cipher_id = None;
            }
            true
        } else {
            false
        }
    }

    pub fn get_statistics(&self) -> EncryptionStatistics {
        let total_ciphers = self.ciphers.len();
        let active_ciphers = self.ciphers.values().filter(|c| c.is_active).count();
        let ciphers_needing_rotation = self.ciphers
            .values()
            .filter(|c| c.needs_rotation(90))
            .count();

        EncryptionStatistics {
            total_ciphers,
            active_ciphers,
            ciphers_needing_rotation,
            total_encrypted_items: self.encrypted_data.len(),
            algorithms_in_use: self.ciphers.values()
                .map(|c| c.algorithm.name().to_string())
                .collect::<std::collections::HashSet<_>>()
                .len(),
        }
    }
}

impl Default for CipherManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionStatistics {
    pub total_ciphers: usize,
    pub active_ciphers: usize,
    pub ciphers_needing_rotation: usize,
    pub total_encrypted_items: usize,
    pub algorithms_in_use: usize,
}

pub fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    general_purpose::STANDARD.encode(result)
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    hash_password(password) == hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_algorithm_properties() {
        let algo = EncryptionAlgorithm::AES256GCM;
        assert_eq!(algo.key_size(), 32);
        assert_eq!(algo.iv_size(), 12);
    }

    #[test]
    fn test_encrypted_data_creation() {
        let encrypted = EncryptedData::new(
            EncryptionAlgorithm::AES256GCM,
            "ciphertext".to_string(),
            "iv".to_string(),
        );
        assert_eq!(encrypted.algorithm, "AES-256-GCM");
    }

    #[test]
    fn test_cipher_creation() {
        let cipher = Cipher::new(EncryptionAlgorithm::ChaCha20Poly1305, "hash".to_string());
        assert!(cipher.is_active);
    }

    #[test]
    fn test_cipher_rotation() {
        let mut cipher = Cipher::new(EncryptionAlgorithm::AES256GCM, "hash".to_string());
        cipher.rotate();
        assert_eq!(cipher.rotation_count, 1);
    }

    #[test]
    fn test_cipher_manager() {
        let mut manager = CipherManager::new();
        let cipher = Cipher::new(EncryptionAlgorithm::AES256GCM, "hash".to_string());
        let id = cipher.id.clone();
        manager.register_cipher(cipher);

        assert!(manager.get_cipher(&id).is_some());
    }

    #[test]
    fn test_password_hashing() {
        let password = "secure_password";
        let hash = hash_password(password);
        assert!(verify_password(password, &hash));
        assert!(!verify_password("wrong_password", &hash));
    }
}
