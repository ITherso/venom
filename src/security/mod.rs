pub mod encryption;
pub mod secrets;
pub mod validation;
pub mod audit;
pub mod threat_detection;

pub use encryption::{Cipher, EncryptionAlgorithm, EncryptedData};
pub use secrets::{SecretManager, Secret, SecretRotation};
pub use validation::{InputValidator, ValidationRule, SanitizationRule};
pub use audit::{SecurityAudit, SecurityEvent, ThreatLevel};
pub use threat_detection::{ThreatDetector, ThreatIndicator, DetectionResult};

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub encryption_enabled: bool,
    pub tls_enabled: bool,
    pub min_tls_version: String,
    pub secret_rotation_days: u32,
    pub audit_enabled: bool,
    pub threat_detection_enabled: bool,
    pub max_login_attempts: u32,
    pub lockout_duration_minutes: u32,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            encryption_enabled: true,
            tls_enabled: true,
            min_tls_version: "1.3".to_string(),
            secret_rotation_days: 90,
            audit_enabled: true,
            threat_detection_enabled: true,
            max_login_attempts: 5,
            lockout_duration_minutes: 15,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityStatus {
    pub overall_status: SecurityStatusLevel,
    pub encryption_status: bool,
    pub threat_detection_status: bool,
    pub audit_status: bool,
    pub secrets_rotation_status: bool,
    pub vulnerabilities_found: u32,
    pub last_security_scan: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityStatusLevel {
    Secure,
    Warning,
    Critical,
}
