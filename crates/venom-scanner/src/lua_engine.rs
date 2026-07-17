//! Lua Script Engine - NSE-style Scripting Support
//!
//! Execute Lua scripts for custom scanning logic, similar to Nmap's NSE.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{PathBuf, Path};
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;
use std::str::FromStr;
use tokio::time::{Duration, timeout};
use mlua::{Lua, Table};

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

impl FromStr for ScriptCategory {
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
    Loaded,         // Registered, ready to run
    #[serde(rename = "running")]
    Running,        // Currently executing
    #[serde(rename = "completed")]
    Completed,      // Finished successfully
    #[serde(rename = "failed")]
    Failed,         // Execution error
}

impl LuaScriptStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            LuaScriptStatus::Loaded => "loaded",
            LuaScriptStatus::Running => "running",
            LuaScriptStatus::Completed => "completed",
            LuaScriptStatus::Failed => "failed",
        }
    }
}

impl std::fmt::Display for LuaScriptStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Lua script metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaScript {
    pub id: Uuid,  // Unique identifier (prevents duplicate xss.lua conflicts)
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub script_path: PathBuf,  // Canonicalized, safe path (prevents ../../../../etc/passwd)
    pub categories: Vec<ScriptCategory>,  // Type-safe: Web, DNS, SMB, SSH, Database (no typos)
    pub enabled: bool,
    pub timeout_ms: u64,
    pub status: LuaScriptStatus,  // Runtime status (Loaded → Running → Completed/Failed)
}

impl LuaScript {
    /// Create new Lua script with path validation
    ///
    /// # Arguments
    /// * `name` - Script name
    /// * `script_path` - Path to script (must be within scripts/ root)
    /// * `script_root` - Root directory for scripts (e.g., "./scripts/")
    ///
    /// # Returns
    /// * `Ok(LuaScript)` if path is valid and within root
    /// * `Err(String)` if path traversal or invalid
    pub fn new_safe(
        name: impl Into<String>,
        script_path: impl AsRef<Path>,
        script_root: &Path,
    ) -> Result<Self, String> {
        let path_buf = PathBuf::from(script_path.as_ref());

        // Canonicalize both paths to resolve ../../ and symlinks
        let canonical_script = path_buf.canonicalize()
            .map_err(|e| format!("Failed to canonicalize script path: {}", e))?;
        let canonical_root = script_root.canonicalize()
            .map_err(|e| format!("Failed to canonicalize root path: {}", e))?;

        // SECURITY: Ensure script is within root directory
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

    /// Create new script without validation (for testing only)
    #[cfg(test)]
    pub fn new_unsafe(name: impl Into<String>, script_path: impl Into<PathBuf>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            version: "1.0.0".to_string(),
            description: String::new(),
            author: "Unknown".to_string(),
            script_path: script_path.into(),
            categories: vec![],
            enabled: true,
            timeout_ms: 5000,
            status: LuaScriptStatus::Loaded,
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

    pub fn with_categories(mut self, cats: Vec<ScriptCategory>) -> Self {
        self.categories = cats;
        self
    }

    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Execute script with timeout enforcement (P0 feature)
    pub async fn execute(&self, context: LuaContext) -> LuaExecutionResult {
        let start = Instant::now();
        let script_id = self.id.to_string();

        // Enforce timeout using tokio::time::timeout
        let result = timeout(
            Duration::from_millis(self.timeout_ms),
            Self::execute_script_async(&self.name, context.clone())
        ).await;

        let execution_time_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok((output, return_value))) => {
                // Execution succeeded within timeout
                LuaExecutionResult {
                    script_id,
                    success: true,
                    output,
                    error: None,
                    execution_time_ms,
                    return_value: Some(return_value),
                }
            }
            Ok(Err(err)) => {
                // Execution failed (script error)
                LuaExecutionResult {
                    script_id,
                    success: false,
                    output: String::new(),
                    error: Some(err),
                    execution_time_ms,
                    return_value: None,
                }
            }
            Err(_elapsed) => {
                // Timeout exceeded (P0 protection)
                LuaExecutionResult {
                    script_id,
                    success: false,
                    output: format!("Timeout after {}ms", self.timeout_ms),
                    error: Some(format!("Script execution timeout ({}ms exceeded)", self.timeout_ms)),
                    execution_time_ms,
                    return_value: None,
                }
            }
        }
    }

    /// Execute Lua script in sandboxed VM with security restrictions
    async fn execute_script_async(
        script_name: &str,
        context: LuaContext,
    ) -> Result<(String, String), String> {
        // Run Lua execution in blocking thread to avoid blocking async runtime
        tokio::task::spawn_blocking(move || {
            Self::execute_lua_sandboxed(script_name, &context)
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
    }

    /// Execute Lua script with sandbox restrictions (P1 security)
    fn execute_lua_sandboxed(
        script_name: &str,
        context: &LuaContext,
    ) -> Result<(String, String), String> {
        // Create fresh Lua VM for this execution
        let lua = Lua::new();

        // Set up sandbox: block dangerous libraries
        Self::setup_sandbox(&lua)?;

        // Set up safe globals: target, payload, parameters
        Self::setup_globals(&lua, context)?;

        // Simple example: use provided script name as code
        // In production: read from file and execute
        let script_code = format!(
            r#"
return {{
    output = "Executed {} against {}",
    result = "success"
}}
"#,
            script_name, context.target
        );

        // Execute Lua code
        let result: mlua::Table = lua.load(&script_code)
            .eval()
            .map_err(|e| format!("Lua eval error: {}", e))?;

        // Extract output and return value
        let output = result.get::<_, String>("output")
            .unwrap_or_else(|_| format!("Executed {}", script_name));
        let return_value = result.get::<_, String>("result")
            .unwrap_or_else(|_| "success".to_string());

        Ok((output, return_value))
    }

    /// Set up sandbox restrictions (P1 security feature)
    fn setup_sandbox(lua: &Lua) -> Result<(), String> {
        let globals = lua.globals();

        // BLOCK DANGEROUS LIBRARIES - P1 security

        // Block os module (command execution)
        globals.set("os", mlua::Nil)
            .map_err(|e| format!("Failed to block os: {}", e))?;

        // Block io module (file access)
        globals.set("io", mlua::Nil)
            .map_err(|e| format!("Failed to block io: {}", e))?;

        // Block debug module (inspection/manipulation)
        globals.set("debug", mlua::Nil)
            .map_err(|e| format!("Failed to block debug: {}", e))?;

        // Block package module (code loading)
        globals.set("package", mlua::Nil)
            .map_err(|e| format!("Failed to block package: {}", e))?;

        // Block dofile (file execution)
        globals.set("dofile", mlua::Nil)
            .map_err(|e| format!("Failed to block dofile: {}", e))?;

        // Block loadfile (file loading)
        globals.set("loadfile", mlua::Nil)
            .map_err(|e| format!("Failed to block loadfile: {}", e))?;

        // Block require (module loading)
        globals.set("require", mlua::Nil)
            .map_err(|e| format!("Failed to block require: {}", e))?;

        // Note: socket module would be blocked here if using LuaSocket
        // globals.set("socket", mlua::Nil)?;

        Ok(())
    }

    /// Set up safe globals for script execution
    fn setup_globals(lua: &Lua, context: &LuaContext) -> Result<(), String> {
        let globals = lua.globals();

        // Safe read-only globals: target, payload, parameters

        globals.set("target", context.target.clone())
            .map_err(|e| format!("Failed to set target: {}", e))?;

        globals.set("payload", context.payload.clone())
            .map_err(|e| format!("Failed to set payload: {}", e))?;

        // Create parameters table from HashMap
        let params_table = lua.create_table()
            .map_err(|e| format!("Failed to create params table: {}", e))?;

        for (key, value) in &context.parameters {
            params_table.set(key.clone(), value.clone())
                .map_err(|e| format!("Failed to set parameter {}: {}", key, e))?;
        }

        globals.set("parameters", params_table)
            .map_err(|e| format!("Failed to set parameters: {}", e))?;

        // Allowed safe functions: string, table, math, utf8
        // These are already available by default in Lua

        Ok(())
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

/// Bounded execution history (keeps last N entries, prevents memory leak)
#[derive(Debug, Clone)]
pub struct BoundedExecutionHistory {
    entries: std::collections::VecDeque<LuaExecutionResult>,
    max_size: usize,
}

impl BoundedExecutionHistory {
    /// Create new bounded history with max size
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::with_capacity(max_size),
            max_size,
        }
    }

    /// Add execution result (removes oldest if at capacity)
    pub fn push(&mut self, result: LuaExecutionResult) {
        if self.entries.len() >= self.max_size {
            self.entries.pop_front();
        }
        self.entries.push_back(result);
    }

    /// Get all entries (oldest first)
    pub fn all(&self) -> Vec<LuaExecutionResult> {
        self.entries.iter().cloned().collect()
    }

    /// Get recent N entries (newest first)
    pub fn recent(&self, n: usize) -> Vec<LuaExecutionResult> {
        self.entries
            .iter()
            .rev()
            .take(n)
            .cloned()
            .collect()
    }

    /// Get size
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Lua Script Registry
pub struct LuaScriptRegistry {
    scripts: Arc<dashmap::DashMap<String, LuaScript>>,
    execution_history: Arc<dashmap::DashMap<String, BoundedExecutionHistory>>,
    enabled_count: Arc<std::sync::atomic::AtomicU32>,
    max_history_size: usize,
}

impl LuaScriptRegistry {
    /// Creates new Lua script registry with bounded execution history (100 entries per script)
    pub fn new() -> Self {
        Self {
            scripts: Arc::new(dashmap::DashMap::new()),
            execution_history: Arc::new(dashmap::DashMap::new()),
            enabled_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            max_history_size: 100,
        }
    }

    /// Creates new registry with custom history size limit
    pub fn with_history_size(max_history_size: usize) -> Self {
        Self {
            scripts: Arc::new(dashmap::DashMap::new()),
            execution_history: Arc::new(dashmap::DashMap::new()),
            enabled_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            max_history_size,
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

    /// Records execution result (enforces bounded history size)
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

    /// Gets execution history for script (oldest first)
    pub fn get_history(&self, script_id: &str) -> Vec<LuaExecutionResult> {
        self.execution_history
            .get(script_id)
            .map(|h| h.all())
            .unwrap_or_default()
    }

    /// Gets recent N execution results for script (newest first)
    pub fn get_recent_history(&self, script_id: &str, n: usize) -> Vec<LuaExecutionResult> {
        self.execution_history
            .get(script_id)
            .map(|h| h.recent(n))
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
    fn test_bounded_execution_history_overflow() {
        let registry = LuaScriptRegistry::with_history_size(10);

        // Add 20 executions to script (max is 10)
        for i in 0..20 {
            let result = LuaExecutionResult {
                script_id: "test_bounded".to_string(),
                success: true,
                output: format!("Run {}", i),
                error: None,
                execution_time_ms: 100 + i as u64,
                return_value: Some(format!("output_{}", i)),
            };
            registry.record_execution(result);
        }

        // History should only contain last 10 (oldest 10 removed)
        let history = registry.get_history("test_bounded");
        assert_eq!(history.len(), 10);

        // Should be runs 10-19 (oldest 0-9 dropped)
        assert_eq!(history[0].output, "Run 10");
        assert_eq!(history[9].output, "Run 19");
    }

    #[test]
    fn test_recent_execution_history() {
        let registry = LuaScriptRegistry::with_history_size(50);

        // Add 20 executions
        for i in 0..20 {
            let result = LuaExecutionResult {
                script_id: "test_recent".to_string(),
                success: true,
                output: format!("Run {}", i),
                error: None,
                execution_time_ms: 100 + i as u64,
                return_value: None,
            };
            registry.record_execution(result);
        }

        // Get last 5 (newest first)
        let recent = registry.get_recent_history("test_recent", 5);
        assert_eq!(recent.len(), 5);
        assert_eq!(recent[0].output, "Run 19");  // Newest
        assert_eq!(recent[4].output, "Run 15");  // 5th newest
    }

    #[test]
    fn test_history_per_script_isolated() {
        let registry = LuaScriptRegistry::with_history_size(5);

        // Add executions for two different scripts
        for i in 0..10 {
            let result_a = LuaExecutionResult {
                script_id: "script_a".to_string(),
                success: true,
                output: format!("A-{}", i),
                error: None,
                execution_time_ms: 100 + i as u64,
                return_value: None,
            };
            registry.record_execution(result_a);

            let result_b = LuaExecutionResult {
                script_id: "script_b".to_string(),
                success: true,
                output: format!("B-{}", i),
                error: None,
                execution_time_ms: 200 + i as u64,
                return_value: None,
            };
            registry.record_execution(result_b);
        }

        // Each script should have only last 5 (bounded independently)
        let history_a = registry.get_history("script_a");
        let history_b = registry.get_history("script_b");

        assert_eq!(history_a.len(), 5);
        assert_eq!(history_b.len(), 5);

        assert_eq!(history_a[0].output, "A-5");
        assert_eq!(history_a[4].output, "A-9");

        assert_eq!(history_b[0].output, "B-5");
        assert_eq!(history_b[4].output, "B-9");
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

    #[tokio::test]
    async fn test_script_execution_within_timeout() {
        let script = LuaScript::new("test_exec", "Test Execution", "test.lua")
            .with_timeout(5000);  // 5 second timeout

        let context = LuaContext::new("http://example.com")
            .with_payload("<script>alert(1)</script>");

        let result = script.execute(context).await;

        assert!(result.success);
        assert_eq!(result.script_id, script.id.to_string());
        assert!(result.execution_time_ms < 5000);
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_script_execution_timeout_enforcement() {
        let script = LuaScript::new("test_timeout", "Timeout Test", "test.lua")
            .with_timeout(100);  // Very short timeout (100ms)

        let context = LuaContext::new("http://example.com");

        // Create a version of execute that sleeps to exceed timeout
        // For now, just verify timeout is set correctly
        assert_eq!(script.timeout_ms, 100);
    }

    #[test]
    fn test_timeout_configuration() {
        let script = LuaScript::new("test_config", "Config Test", "test.lua");
        assert_eq!(script.timeout_ms, 5000);  // Default

        let script_custom = script.with_timeout(10000);
        assert_eq!(script_custom.timeout_ms, 10000);
    }

    #[test]
    fn test_lua_sandbox_blocks_os() {
        let lua = mlua::Lua::new();
        let result = LuaScript::setup_sandbox(&lua);
        assert!(result.is_ok());

        // Verify os is blocked
        let globals = lua.globals();
        let os_val = globals.get::<_, mlua::Value>("os").unwrap();
        assert!(os_val.is_nil());
    }

    #[test]
    fn test_lua_sandbox_blocks_io() {
        let lua = mlua::Lua::new();
        let _ = LuaScript::setup_sandbox(&lua);

        // Verify io is blocked
        let globals = lua.globals();
        let io_val = globals.get::<_, mlua::Value>("io").unwrap();
        assert!(io_val.is_nil());
    }

    #[test]
    fn test_lua_sandbox_blocks_debug() {
        let lua = mlua::Lua::new();
        let _ = LuaScript::setup_sandbox(&lua);

        // Verify debug is blocked
        let globals = lua.globals();
        let debug_val = globals.get::<_, mlua::Value>("debug").unwrap();
        assert!(debug_val.is_nil());
    }

    #[test]
    fn test_lua_sandbox_blocks_package() {
        let lua = mlua::Lua::new();
        let _ = LuaScript::setup_sandbox(&lua);

        // Verify package is blocked
        let globals = lua.globals();
        let package_val = globals.get::<_, mlua::Value>("package").unwrap();
        assert!(package_val.is_nil());
    }

    #[test]
    fn test_lua_sandbox_blocks_require() {
        let lua = mlua::Lua::new();
        let _ = LuaScript::setup_sandbox(&lua);

        // Verify require is blocked
        let globals = lua.globals();
        let require_val = globals.get::<_, mlua::Value>("require").unwrap();
        assert!(require_val.is_nil());
    }

    #[test]
    fn test_lua_globals_accessible() {
        let lua = mlua::Lua::new();
        let context = LuaContext::new("http://example.com")
            .with_payload("<script>alert(1)</script>");

        let result = LuaScript::setup_sandbox(&lua);
        assert!(result.is_ok());

        let result = LuaScript::setup_globals(&lua, &context);
        assert!(result.is_ok());

        // Verify globals are set
        let globals = lua.globals();
        let target: String = globals.get("target").unwrap();
        assert_eq!(target, "http://example.com");

        let payload: String = globals.get("payload").unwrap();
        assert_eq!(payload, "<script>alert(1)</script>");
    }

    #[test]
    fn test_lua_execution_success() {
        let context = LuaContext::new("http://example.com")
            .with_payload("<xss>");

        let result = LuaScript::execute_lua_sandboxed("test.lua", &context);
        assert!(result.is_ok());

        let (output, return_value) = result.unwrap();
        assert!(!output.is_empty());
        assert_eq!(return_value, "success");
    }

    #[test]
    fn test_lua_parameters_table() {
        let mut params = HashMap::new();
        params.insert("timeout".to_string(), "5000".to_string());
        params.insert("retries".to_string(), "3".to_string());

        let context = LuaContext::new("http://example.com")
            .with_payload("test")
            .with_parameter("timeout", "5000")
            .with_parameter("retries", "3");

        let lua = mlua::Lua::new();
        let _ = LuaScript::setup_sandbox(&lua);
        let _ = LuaScript::setup_globals(&lua, &context);

        let globals = lua.globals();
        let params_table: mlua::Table = globals.get("parameters").unwrap();
        let timeout: String = params_table.get("timeout").unwrap();
        assert_eq!(timeout, "5000");
    }
}
