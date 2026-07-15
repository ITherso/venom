pub mod macro_library;
pub mod payload_templates;
pub mod api_keys;
pub mod sso;

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

pub use macro_library::{MacroLibrary, MacroTemplate};
pub use payload_templates::{PayloadTemplateLibrary, PayloadTemplate};
pub use api_keys::{ApiKeyManager, ApiKey};
pub use sso::{SSOProvider, OAuthConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedConfig {
    pub macro_library: MacroLibrary,
    pub payload_templates: PayloadTemplateLibrary,
    pub api_key_manager: ApiKeyManager,
    pub sso_providers: Vec<SSOProvider>,
}

impl AdvancedConfig {
    pub fn new() -> Self {
        Self {
            macro_library: MacroLibrary::new(),
            payload_templates: PayloadTemplateLibrary::new(),
            api_key_manager: ApiKeyManager::new(),
            sso_providers: Vec::new(),
        }
    }

    pub fn add_sso_provider(&mut self, provider: SSOProvider) {
        self.sso_providers.push(provider);
    }

    pub fn get_sso_provider(&self, name: &str) -> Option<&SSOProvider> {
        self.sso_providers.iter().find(|p| p.name == name)
    }
}

impl Default for AdvancedConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advanced_config_creation() {
        let config = AdvancedConfig::new();
        assert!(config.sso_providers.is_empty());
    }
}
