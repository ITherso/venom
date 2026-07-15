use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOProvider {
    pub id: String,
    pub name: String,
    pub provider_type: ProviderType,
    pub config: OAuthConfig,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProviderType {
    OAuth2,
    OpenIDConnect,
    SAML2,
    LDAP,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub authorize_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOSession {
    pub id: String,
    pub user_id: String,
    pub provider: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOUser {
    pub id: String,
    pub email: String,
    pub name: String,
    pub picture: Option<String>,
    pub provider: String,
    pub provider_user_id: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOManager {
    providers: HashMap<String, SSOProvider>,
    sessions: HashMap<String, SSOSession>,
}

impl SSOProvider {
    pub fn new(
        name: String,
        provider_type: ProviderType,
        config: OAuthConfig,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            provider_type,
            config,
            is_enabled: true,
            created_at: Utc::now(),
        }
    }

    pub fn github() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: "GitHub".to_string(),
            provider_type: ProviderType::OAuth2,
            config: OAuthConfig {
                client_id: String::new(),
                client_secret: String::new(),
                authorize_url: "https://github.com/login/oauth/authorize".to_string(),
                token_url: "https://github.com/login/oauth/access_token".to_string(),
                userinfo_url: "https://api.github.com/user".to_string(),
                redirect_uri: "http://localhost:3000/auth/github/callback".to_string(),
                scopes: vec!["user:email".to_string()],
            },
            is_enabled: false,
            created_at: Utc::now(),
        }
    }

    pub fn google() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: "Google".to_string(),
            provider_type: ProviderType::OpenIDConnect,
            config: OAuthConfig {
                client_id: String::new(),
                client_secret: String::new(),
                authorize_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
                token_url: "https://www.googleapis.com/oauth2/v4/token".to_string(),
                userinfo_url: "https://www.googleapis.com/oauth2/v1/userinfo".to_string(),
                redirect_uri: "http://localhost:3000/auth/google/callback".to_string(),
                scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
            },
            is_enabled: false,
            created_at: Utc::now(),
        }
    }

    pub fn microsoft() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: "Microsoft".to_string(),
            provider_type: ProviderType::OpenIDConnect,
            config: OAuthConfig {
                client_id: String::new(),
                client_secret: String::new(),
                authorize_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string(),
                token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string(),
                userinfo_url: "https://graph.microsoft.com/v1.0/me".to_string(),
                redirect_uri: "http://localhost:3000/auth/microsoft/callback".to_string(),
                scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
            },
            is_enabled: false,
            created_at: Utc::now(),
        }
    }

    pub fn configure(&mut self, client_id: String, client_secret: String) {
        self.config.client_id = client_id;
        self.config.client_secret = client_secret;
        self.is_enabled = true;
    }
}

impl SSOSession {
    pub fn new(
        user_id: String,
        provider: String,
        access_token: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            provider,
            access_token,
            refresh_token: None,
            expires_at: Utc::now() + chrono::Duration::hours(24),
            created_at: Utc::now(),
            last_used_at: Utc::now(),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn update_activity(&mut self) {
        self.last_used_at = Utc::now();
    }
}

impl SSOManager {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            sessions: HashMap::new(),
        }
    }

    pub fn add_provider(&mut self, provider: SSOProvider) {
        self.providers.insert(provider.name.clone(), provider);
    }

    pub fn get_provider(&self, name: &str) -> Option<&SSOProvider> {
        self.providers.get(name)
    }

    pub fn get_provider_mut(&mut self, name: &str) -> Option<&mut SSOProvider> {
        self.providers.get_mut(name)
    }

    pub fn list_providers(&self) -> Vec<&SSOProvider> {
        self.providers.values().collect()
    }

    pub fn list_enabled_providers(&self) -> Vec<&SSOProvider> {
        self.providers
            .values()
            .filter(|p| p.is_enabled)
            .collect()
    }

    pub fn create_session(
        &mut self,
        user_id: String,
        provider: String,
        access_token: String,
    ) -> String {
        let session = SSOSession::new(user_id, provider, access_token);
        let session_id = session.id.clone();
        self.sessions.insert(session_id.clone(), session);
        session_id
    }

    pub fn get_session(&self, session_id: &str) -> Option<&SSOSession> {
        self.sessions.get(session_id)
    }

    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut SSOSession> {
        self.sessions.get_mut(session_id)
    }

    pub fn validate_session(&self, session_id: &str) -> bool {
        if let Some(session) = self.get_session(session_id) {
            !session.is_expired()
        } else {
            false
        }
    }

    pub fn revoke_session(&mut self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    pub fn cleanup_expired_sessions(&mut self) {
        self.sessions.retain(|_, s| !s.is_expired());
    }

    pub fn enable_provider(&mut self, name: &str) -> bool {
        if let Some(provider) = self.get_provider_mut(name) {
            provider.is_enabled = true;
            true
        } else {
            false
        }
    }

    pub fn disable_provider(&mut self, name: &str) -> bool {
        if let Some(provider) = self.get_provider_mut(name) {
            provider.is_enabled = false;
            true
        } else {
            false
        }
    }
}

impl Default for SSOManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_config_github() {
        let provider = SSOProvider::github();
        assert_eq!(provider.name, "GitHub");
        assert_eq!(provider.provider_type, ProviderType::OAuth2);
    }

    #[test]
    fn test_sso_session_creation() {
        let session = SSOSession::new(
            "user1".to_string(),
            "github".to_string(),
            "token123".to_string(),
        );
        assert!(!session.is_expired());
    }

    #[test]
    fn test_sso_manager_provider_management() {
        let mut manager = SSOManager::new();
        let provider = SSOProvider::google();
        manager.add_provider(provider);

        assert!(manager.get_provider("Google").is_some());
    }

    #[test]
    fn test_sso_session_management() {
        let mut manager = SSOManager::new();
        let session_id = manager.create_session(
            "user1".to_string(),
            "github".to_string(),
            "token123".to_string(),
        );

        assert!(manager.validate_session(&session_id));
    }
}
