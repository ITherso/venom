//! Lua script registry
//!
//! Manages script metadata and tracking.

use super::types::{LuaScript, LuaExecutionResult, ScriptCategory};
use super::history::BoundedExecutionHistory;
use std::sync::Arc;

pub struct LuaScriptRegistry {
    scripts: Arc<dashmap::DashMap<String, LuaScript>>,
    execution_history: Arc<dashmap::DashMap<String, BoundedExecutionHistory>>,
    enabled_count: Arc<std::sync::atomic::AtomicU32>,
    max_history_size: usize,
}

impl LuaScriptRegistry {
    pub fn new() -> Self {
        Self {
            scripts: Arc::new(dashmap::DashMap::new()),
            execution_history: Arc::new(dashmap::DashMap::new()),
            enabled_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            max_history_size: 100,
        }
    }

    pub fn with_history_size(max_history_size: usize) -> Self {
        Self {
            scripts: Arc::new(dashmap::DashMap::new()),
            execution_history: Arc::new(dashmap::DashMap::new()),
            enabled_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            max_history_size,
        }
    }

    pub fn register(&self, script: LuaScript) {
        if script.enabled {
            self.enabled_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.scripts.insert(script.id.to_string(), script);
    }

    pub fn get(&self, script_id: &str) -> Option<LuaScript> {
        self.scripts.get(script_id).map(|s| s.clone())
    }

    pub fn list_all(&self) -> Vec<LuaScript> {
        self.scripts
            .iter()
            .map(|ref_multi| ref_multi.value().clone())
            .collect()
    }

    pub fn list_enabled(&self) -> Vec<LuaScript> {
        self.scripts
            .iter()
            .filter(|ref_multi| ref_multi.value().enabled)
            .map(|ref_multi| ref_multi.value().clone())
            .collect()
    }

    pub fn list_by_category(&self, category: &str) -> Vec<LuaScript> {
        self.scripts
            .iter()
            .filter(|ref_multi| {
                ref_multi.value().categories.iter()
                    .any(|c| c.as_str() == category)
            })
            .map(|ref_multi| ref_multi.value().clone())
            .collect()
    }

    pub fn record_execution(&self, result: LuaExecutionResult) {
        let script_id = result.script_id.clone();
        if let Some(mut history) = self.execution_history.get_mut(&script_id) {
            history.push(result);
        } else {
            let mut history = BoundedExecutionHistory::new(self.max_history_size);
            history.push(result);
            self.execution_history.insert(script_id, history);
        }
    }

    pub fn get_history(&self, script_id: &str) -> Vec<LuaExecutionResult> {
        self.execution_history
            .get(script_id)
            .map(|h| h.all())
            .unwrap_or_default()
    }

    pub fn count(&self) -> usize {
        self.scripts.len()
    }

    pub fn enabled_count(&self) -> u32 {
        self.enabled_count.load(std::sync::atomic::Ordering::SeqCst)
    }

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
    fn test_registry_creation() {
        let registry = LuaScriptRegistry::new();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_register_and_get() {
        let registry = LuaScriptRegistry::new();
        let script = LuaScript {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            version: "1.0".to_string(),
            description: String::new(),
            author: "Test".to_string(),
            script_path: "test.lua".into(),
            categories: vec![],
            enabled: true,
            timeout_ms: 5000,
            status: super::super::types::LuaScriptStatus::Loaded,
        };

        registry.register(script.clone());
        let retrieved = registry.get(&script.id.to_string());
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_enabled_tracking() {
        let registry = LuaScriptRegistry::new();
        let script = LuaScript {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            version: "1.0".to_string(),
            description: String::new(),
            author: "Test".to_string(),
            script_path: "test.lua".into(),
            categories: vec![],
            enabled: true,
            timeout_ms: 5000,
            status: super::super::types::LuaScriptStatus::Loaded,
        };

        registry.register(script.clone());
        assert_eq!(registry.enabled_count(), 1);

        registry.set_enabled(&script.id.to_string(), false).unwrap();
        assert_eq!(registry.enabled_count(), 0);
    }
}
