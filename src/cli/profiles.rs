use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CLIProfile {
    pub name: String,
    pub description: String,
    pub settings: HashMap<String, String>,
    pub aliases: HashMap<String, String>,
    pub defaults: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileManager {
    pub profiles: HashMap<String, CLIProfile>,
    pub active_profile: String,
}

impl CLIProfile {
    pub fn new(name: String, description: String) -> Self {
        Self {
            name,
            description,
            settings: HashMap::new(),
            aliases: HashMap::new(),
            defaults: HashMap::new(),
            created_at: Utc::now(),
            active: false,
        }
    }

    pub fn set_setting(&mut self, key: String, value: String) {
        self.settings.insert(key, value);
    }

    pub fn add_alias(&mut self, alias: String, command: String) {
        self.aliases.insert(alias, command);
    }

    pub fn set_default(&mut self, key: String, value: String) {
        self.defaults.insert(key, value);
    }

    pub fn export(&self) -> String {
        serde_yaml::to_string(self).unwrap_or_default()
    }

    pub fn import(yaml: &str) -> Result<Self, String> {
        serde_yaml::from_str(yaml)
            .map_err(|e| format!("Failed to parse profile: {}", e))
    }
}

impl ProfileManager {
    pub fn new() -> Self {
        let mut manager = Self {
            profiles: HashMap::new(),
            active_profile: "default".to_string(),
        };

        // Create default profile
        let default = CLIProfile::new(
            "default".to_string(),
            "Default configuration profile".to_string(),
        );
        manager.profiles.insert("default".to_string(), default);

        manager
    }

    pub fn create_profile(&mut self, name: String, description: String) -> String {
        let profile = CLIProfile::new(name.clone(), description);
        self.profiles.insert(name.clone(), profile);
        name
    }

    pub fn activate_profile(&mut self, name: &str) -> Result<(), String> {
        if self.profiles.contains_key(name) {
            self.active_profile = name.to_string();
            Ok(())
        } else {
            Err(format!("Profile '{}' not found", name))
        }
    }

    pub fn get_active_profile(&self) -> Option<&CLIProfile> {
        self.profiles.get(&self.active_profile)
    }

    pub fn get_active_profile_mut(&mut self) -> Option<&mut CLIProfile> {
        let profile_name = self.active_profile.clone();
        self.profiles.get_mut(&profile_name)
    }

    pub fn delete_profile(&mut self, name: &str) -> Result<(), String> {
        if name == "default" {
            return Err("Cannot delete default profile".to_string());
        }

        if self.active_profile == name {
            self.active_profile = "default".to_string();
        }

        self.profiles.remove(name);
        Ok(())
    }

    pub fn list_profiles(&self) -> Vec<(&str, &CLIProfile)> {
        self.profiles
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect()
    }

    pub fn export_profile(&self, name: &str) -> Result<String, String> {
        self.profiles
            .get(name)
            .map(|p| p.export())
            .ok_or_else(|| format!("Profile '{}' not found", name))
    }

    pub fn import_profile(&mut self, yaml: &str) -> Result<String, String> {
        let profile = CLIProfile::import(yaml)?;
        let name = profile.name.clone();
        self.profiles.insert(name.clone(), profile);
        Ok(name)
    }
}

impl Default for ProfileManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_profile() {
        let mut manager = ProfileManager::new();
        let id = manager.create_profile("test".to_string(), "Test profile".to_string());
        assert_eq!(id, "test");
        assert!(manager.profiles.contains_key("test"));
    }

    #[test]
    fn test_activate_profile() {
        let mut manager = ProfileManager::new();
        manager.create_profile("test".to_string(), "Test".to_string());
        assert!(manager.activate_profile("test").is_ok());
        assert_eq!(manager.active_profile, "test");
    }

    #[test]
    fn test_profile_settings() {
        let mut profile = CLIProfile::new("test".to_string(), "Test".to_string());
        profile.set_setting("color".to_string(), "true".to_string());
        assert_eq!(profile.settings.get("color"), Some(&"true".to_string()));
    }
}
