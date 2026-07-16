//! Plugin System for Extensibility
//!
//! Allows custom scanners and detectors to be registered and executed.

use crate::ScanFinding;

/// Plugin trait for custom scanners
pub trait ScannerPlugin: Send + Sync {
    /// Plugin name
    fn name(&self) -> &'static str;

    /// Plugin version
    fn version(&self) -> &'static str;

    /// Execute custom scan logic
    fn execute(&self, target: &str) -> Result<Vec<ScanFinding>, String>;

    /// Plugin description
    fn description(&self) -> &'static str {
        "Custom scanner plugin"
    }
}

/// Plugin metadata
#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub enabled: bool,
}

/// Plugin registry for managing installed plugins
pub struct PluginRegistry {
    plugins: Vec<Box<dyn ScannerPlugin>>,
}

impl PluginRegistry {
    /// Creates a new plugin registry
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Registers a plugin
    pub fn register(&mut self, plugin: Box<dyn ScannerPlugin>) {
        self.plugins.push(plugin);
    }

    /// Gets number of registered plugins
    pub fn count(&self) -> usize {
        self.plugins.len()
    }

    /// Executes all plugins against a target
    pub fn execute_all(&self, target: &str) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        for plugin in &self.plugins {
            match plugin.execute(target) {
                Ok(results) => findings.extend(results),
                Err(e) => eprintln!("Plugin {} error: {}", plugin.name(), e),
            }
        }

        findings
    }

    /// Lists all registered plugins
    pub fn list_plugins(&self) -> Vec<PluginInfo> {
        self.plugins
            .iter()
            .map(|p| PluginInfo {
                name: p.name().to_string(),
                version: p.version().to_string(),
                description: p.description().to_string(),
                author: "Unknown".to_string(),
                enabled: true,
            })
            .collect()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Example custom plugin for demonstration
pub struct ExamplePlugin;

impl ScannerPlugin for ExamplePlugin {
    fn name(&self) -> &'static str {
        "Example Plugin"
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }

    fn execute(&self, _target: &str) -> Result<Vec<ScanFinding>, String> {
        // Custom scan logic would go here
        Ok(vec![])
    }

    fn description(&self) -> &'static str {
        "Example plugin demonstrating the plugin system"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_plugin() {
        let plugin = ExamplePlugin;
        assert_eq!(plugin.name(), "Example Plugin");
        assert_eq!(plugin.version(), "1.0.0");
    }

    #[test]
    fn test_plugin_registry_creation() {
        let registry = PluginRegistry::new();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_plugin_registration() {
        let mut registry = PluginRegistry::new();
        registry.register(Box::new(ExamplePlugin));
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn test_list_plugins() {
        let mut registry = PluginRegistry::new();
        registry.register(Box::new(ExamplePlugin));

        let plugins = registry.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "Example Plugin");
    }

    #[test]
    fn test_plugin_execution() {
        let mut registry = PluginRegistry::new();
        registry.register(Box::new(ExamplePlugin));

        let findings = registry.execute_all("http://example.com");
        assert!(findings.is_empty()); // Example plugin returns empty
    }

    #[test]
    fn test_plugin_info() {
        let info = PluginInfo {
            name: "Test Plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Test".to_string(),
            author: "Test Author".to_string(),
            enabled: true,
        };

        assert_eq!(info.name, "Test Plugin");
        assert_eq!(info.version, "1.0.0");
        assert!(info.enabled);
    }
}
