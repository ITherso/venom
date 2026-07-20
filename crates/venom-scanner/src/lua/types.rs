//! Lua engine type definitions (data structures only)
//!
//! Core types for script metadata, context, and execution results.
//! No execution logic - just data structures.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

/// Script categories (type-safe, no typos, autocomplete)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScriptCategory {
    #[serde(rename = "web")]
    Web,
    #[serde(rename = "dns")]
    DNS,
    #[serde(rename = "smb")]
    SMB,
    #[serde(rename = "ssh")]
    SSH,
    #[serde(rename = "database")]
    Database,
}

impl ScriptCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScriptCategory::Web => "web",
            ScriptCategory::DNS => "dns",
            ScriptCategory::SMB => "smb",
            ScriptCategory::SSH => "ssh",
            ScriptCategory::Database => "database",
        }
    }

    pub fn all() -> &'static [ScriptCategory] {
        &[
            ScriptCategory::Web,
            ScriptCategory::DNS,
            ScriptCategory::SMB,
            ScriptCategory::SSH,
            ScriptCategory::Database,
        ]
    }
}

impl std::str::FromStr for ScriptCategory {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "web" => Ok(ScriptCategory::Web),
            "dns" => Ok(ScriptCategory::DNS),
            "smb" => Ok(ScriptCategory::SMB),
            "ssh" => Ok(ScriptCategory::SSH),
            "database" => Ok(ScriptCategory::Database),
            _ => Err(format!("Unknown category: {}", s)),
        }
    }
}

impl std::fmt::Display for ScriptCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Script execution status (runtime tracking)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

impl std::fmt::Display for LuaScriptStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Lua script metadata (immutable after creation)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct LuaScriptMetadata {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub script_path: PathBuf,
    pub categories: Vec<ScriptCategory>,
    pub timeout_ms: u64,
}

/// Lua script (core structure)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaScript {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub script_path: PathBuf,
    pub categories: Vec<ScriptCategory>,
    pub enabled: bool,
    pub timeout_ms: u64,
    pub status: LuaScriptStatus,
}

impl LuaScript {
    /// Create new Lua script with path validation (P0 security)
    pub fn new_safe(
        name: impl Into<String>,
        script_path: impl AsRef<std::path::Path>,
        script_root: &std::path::Path,
    ) -> Result<Self, String> {
        let path_buf = PathBuf::from(script_path.as_ref());

        let canonical_script = path_buf.canonicalize()
            .map_err(|e| format!("Failed to canonicalize script path: {}", e))?;
        let canonical_root = script_root.canonicalize()
            .map_err(|e| format!("Failed to canonicalize root path: {}", e))?;

        if !canonical_script.starts_with(&canonical_root) {
            return Err(format!(
                "Path traversal detected: {} is outside root {}",
                canonical_script.display(),
                canonical_root.display()
            ));
        }

        Ok(Self {
            id: Uuid::new_v4(),
            name: name.into(),
            version: "1.0.0".to_string(),
            description: String::new(),
            author: "Unknown".to_string(),
            script_path: canonical_script,
            categories: vec![],
            enabled: true,
            timeout_ms: 5000,
            status: LuaScriptStatus::Loaded,
        })
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
    pub timestamp_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_category_conversion() {
        assert_eq!(ScriptCategory::Web.as_str(), "web");
        assert_eq!("dns".parse::<ScriptCategory>().unwrap(), ScriptCategory::DNS);
    }

    #[test]
    fn test_lua_context_builder() {
        let ctx = LuaContext::new("http://example.com")
            .with_payload("test_payload")
            .with_parameter("key", "value");

        assert_eq!(ctx.target, "http://example.com");
        assert_eq!(ctx.payload, "test_payload");
        assert_eq!(ctx.parameters.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_execution_result() {
        let result = LuaExecutionResult {
            script_id: "test".to_string(),
            success: true,
            output: "output".to_string(),
            error: None,
            execution_time_ms: 100,
            return_value: Some("result".to_string()),
            timestamp_ms: 1234567890,
        };

        assert!(result.success);
        assert_eq!(result.execution_time_ms, 100);
    }

    #[test]
    fn test_script_status_display() {
        assert_eq!(LuaScriptStatus::Loaded.as_str(), "loaded");
        assert_eq!(LuaScriptStatus::Running.as_str(), "running");
        assert_eq!(LuaScriptStatus::Timeout.as_str(), "timeout");
    }
}
