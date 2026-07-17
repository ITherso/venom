//! Lua Script Engine - NSE-style Scripting Support
//!
//! Execute Lua scripts for custom scanning logic, similar to Nmap's NSE.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Lua script metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaScript {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub script_path: String,
    pub categories: Vec<String>,
    pub enabled: bool,
    pub timeout_ms: u64,
}

impl LuaScript {
    pub fn new(id: impl Into<String>, name: impl Into<String>, script_path: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version: "1.0.0".to_string(),
            description: String::new(),
            author: "Unknown".to_string(),
            script_path: script_path.into(),
            categories: vec![],
            enabled: true,
            timeout_ms: 5000,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    pub fn with_categories(mut self, cats: Vec<String>) -> Self {
        self.categories = cats;
        self
    }

    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }
}

/// Lua script execution context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaContext {
    pub target: String,
    pub payload: String,
    pub parameters: HashMap<String, String>,
    pub timeout_ms: u64,
}

impl LuaContext {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            payload: String::new(),
            parameters: HashMap::new(),
            timeout_ms: 5000,
        }
    }

    pub fn with_payload(mut self, payload: impl Into<String>) -> Self {
        self.payload = payload.into();
        self
    }

    pub fn with_parameter(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.parameters.insert(key.into(), value.into());
        self
    }
}

/// Lua script execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaExecutionResult {
    pub script_id: String,
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
    pub execution_time_ms: u64,
    pub return_value: Option<String>,
}

/// Lua script status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LuaScriptStatus {
    #[serde(rename = "loaded")]
    Loaded,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "timeout")]
    Timeout,
}

impl LuaScriptStatus {
    pub fn as_str(&self) -> &str {
        match self {
            LuaScriptStatus::Loaded => "loaded",
            LuaScriptStatus::Running => "running",
            LuaScriptStatus::Completed => "completed",
            LuaScriptStatus::Failed => "failed",
            LuaScriptStatus::Timeout => "timeout",
        }
    }
}

/// Lua Script Registry
pub struct LuaScriptRegistry {
    scripts: Arc<dashmap::DashMap<String, LuaScript>>,
    execution_history: Arc<dashmap::DashMap<String, Vec<LuaExecutionResult>>>,
    enabled_count: Arc<std::sync::atomic::AtomicU32>,
}

impl LuaScriptRegistry {
    /// Creates new Lua script registry
    pub fn new() -> Self {
        Self {
            scripts: Arc::new(dashmap::DashMap::new()),
            execution_history: Arc::new(dashmap::DashMap::new()),
            enabled_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    /// Registers a Lua script
    pub fn register(&self, script: LuaScript) {
        if script.enabled {
            self.enabled_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.scripts.insert(script.id.clone(), script);
    }

    /// Gets script by ID
    pub fn get(&self, script_id: &str) -> Option<LuaScript> {
        self.scripts.get(script_id).map(|s| s.clone())
    }

    /// Lists all scripts
    pub fn list_all(&self) -> Vec<LuaScript> {
        self.scripts
            .iter()
            .map(|ref_multi| ref_multi.value().clone())
            .collect()
    }

    /// Lists enabled scripts
    pub fn list_enabled(&self) -> Vec<LuaScript> {
        self.scripts
            .iter()
            .filter(|ref_multi| ref_multi.value().enabled)
            .map(|ref_multi| ref_multi.value().clone())
            .collect()
    }

    /// Lists scripts by category
    pub fn list_by_category(&self, category: &str) -> Vec<LuaScript> {
        self.scripts
            .iter()
            .filter(|ref_multi| ref_multi.value().categories.contains(&category.to_string()))
            .map(|ref_multi| ref_multi.value().clone())
            .collect()
    }

    /// Records execution result
    pub fn record_execution(&self, result: LuaExecutionResult) {
        self.execution_history
            .entry(result.script_id.clone())
            .or_insert_with(Vec::new)
            .push(result);
    }

    /// Gets execution history for script
    pub fn get_history(&self, script_id: &str) -> Vec<LuaExecutionResult> {
        self.execution_history
            .get(script_id)
            .map(|h| h.clone())
            .unwrap_or_default()
    }

    /// Gets script count
    pub fn count(&self) -> usize {
        self.scripts.len()
    }

    /// Gets enabled script count
    pub fn enabled_count(&self) -> u32 {
        self.enabled_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Enables/disables script
    pub fn set_enabled(&self, script_id: &str, enabled: bool) -> Result<(), String> {
        if let Some(mut script) = self.scripts.get_mut(script_id) {
            let was_enabled = script.enabled;
            script.enabled = enabled;

            if enabled && !was_enabled {
                self.enabled_count
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            } else if !enabled && was_enabled {
                self.enabled_count
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(())
        } else {
            Err(format!("Script {} not found", script_id))
        }
    }

    /// Unregisters script
    pub fn unregister(&self, script_id: &str) -> Result<(), String> {
        if let Some((_, script)) = self.scripts.remove(script_id) {
            if script.enabled {
                self.enabled_count
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
            self.execution_history.remove(script_id);
            Ok(())
        } else {
            Err(format!("Script {} not found", script_id))
        }
    }
}

impl Default for LuaScriptRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lua_script_creation() {
        let script = LuaScript::new("test_1", "Test Script", "scripts/test.lua");
        assert_eq!(script.id, "test_1");
        assert_eq!(script.name, "Test Script");
        assert!(script.enabled);
    }

    #[test]
    fn test_lua_script_with_metadata() {
        let script = LuaScript::new("xss_1", "XSS Scanner", "scripts/xss.lua")
            .with_description("Detects XSS vulnerabilities")
            .with_author("VENOM Team")
            .with_categories(vec!["xss".to_string(), "web".to_string()])
            .with_timeout(3000);

        assert_eq!(script.description, "Detects XSS vulnerabilities");
        assert_eq!(script.author, "VENOM Team");
        assert_eq!(script.categories.len(), 2);
        assert_eq!(script.timeout_ms, 3000);
    }

    #[test]
    fn test_lua_context_creation() {
        let ctx = LuaContext::new("http://target.com")
            .with_payload("<script>alert('xss')</script>")
            .with_parameter("timeout", "5000");

        assert_eq!(ctx.target, "http://target.com");
        assert_eq!(ctx.payload, "<script>alert('xss')</script>");
        assert_eq!(ctx.parameters.get("timeout"), Some(&"5000".to_string()));
    }

    #[test]
    fn test_lua_execution_result() {
        let result = LuaExecutionResult {
            script_id: "test_1".to_string(),
            success: true,
            output: "Vulnerability found".to_string(),
            error: None,
            execution_time_ms: 234,
            return_value: Some("HIGH".to_string()),
        };

        assert!(result.success);
        assert_eq!(result.return_value, Some("HIGH".to_string()));
    }

    #[test]
    fn test_lua_script_status() {
        assert_eq!(LuaScriptStatus::Loaded.as_str(), "loaded");
        assert_eq!(LuaScriptStatus::Failed.as_str(), "failed");
    }

    #[test]
    fn test_script_registry_creation() {
        let registry = LuaScriptRegistry::new();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_script_registration() {
        let registry = LuaScriptRegistry::new();
        let script = LuaScript::new("test_1", "Test", "test.lua");

        registry.register(script);
        assert_eq!(registry.count(), 1);
        assert_eq!(registry.enabled_count(), 1);
    }

    #[test]
    fn test_script_retrieval() {
        let registry = LuaScriptRegistry::new();
        let script = LuaScript::new("test_2", "Test 2", "test2.lua");

        registry.register(script);
        let retrieved = registry.get("test_2");

        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test 2");
    }

    #[test]
    fn test_list_by_category() {
        let registry = LuaScriptRegistry::new();

        for i in 0..3 {
            let script = LuaScript::new(format!("xss_{}", i), "XSS", "xss.lua")
                .with_categories(vec!["xss".to_string()]);
            registry.register(script);
        }

        let xss_scripts = registry.list_by_category("xss");
        assert_eq!(xss_scripts.len(), 3);
    }

    #[test]
    fn test_script_enable_disable() {
        let registry = LuaScriptRegistry::new();
        let script = LuaScript::new("test_3", "Test 3", "test3.lua");

        registry.register(script);
        assert_eq!(registry.enabled_count(), 1);

        registry.set_enabled("test_3", false).unwrap();
        assert_eq!(registry.enabled_count(), 0);

        registry.set_enabled("test_3", true).unwrap();
        assert_eq!(registry.enabled_count(), 1);
    }

    #[test]
    fn test_script_unregister() {
        let registry = LuaScriptRegistry::new();
        let script = LuaScript::new("test_4", "Test 4", "test4.lua");

        registry.register(script);
        assert_eq!(registry.count(), 1);

        registry.unregister("test_4").unwrap();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_execution_history() {
        let registry = LuaScriptRegistry::new();
        let script = LuaScript::new("test_5", "Test 5", "test5.lua");

        registry.register(script);

        for i in 0..3 {
            let result = LuaExecutionResult {
                script_id: "test_5".to_string(),
                success: true,
                output: format!("Run {}", i),
                error: None,
                execution_time_ms: 100 + i as u64,
                return_value: None,
            };
            registry.record_execution(result);
        }

        let history = registry.get_history("test_5");
        assert_eq!(history.len(), 3);
    }

    #[test]
    fn test_list_all_scripts() {
        let registry = LuaScriptRegistry::new();

        for i in 0..5 {
            let script = LuaScript::new(format!("script_{}", i), format!("Script {}", i), "script.lua");
            registry.register(script);
        }

        let all = registry.list_all();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn test_list_enabled_scripts() {
        let registry = LuaScriptRegistry::new();

        for i in 0..3 {
            let script = LuaScript::new(format!("script_{}", i), format!("Script {}", i), "script.lua");
            registry.register(script);
        }

        registry.set_enabled("script_1", false).unwrap();

        let enabled = registry.list_enabled();
        assert_eq!(enabled.len(), 2);
    }
}
