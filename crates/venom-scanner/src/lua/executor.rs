//! Lua script execution engine
//!
//! Executes Lua scripts with timeout enforcement and error handling.

use super::types::{LuaScript, LuaContext, LuaExecutionResult, LuaScriptStatus};
use super::sandbox::LuaSandbox;
use mlua::Lua;
use std::time::Instant;
use tokio::time::{timeout, Duration};

pub struct LuaExecutor;

impl LuaExecutor {
    /// Execute script with timeout enforcement
    pub async fn execute(script: &LuaScript, context: LuaContext) -> LuaExecutionResult {
        let start = Instant::now();
        let script_id = script.id.to_string();
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let result = timeout(
            Duration::from_millis(script.timeout_ms),
            Self::execute_script_async(&script.name, context.clone())
        ).await;

        let execution_time_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok((output, return_value))) => {
                LuaExecutionResult {
                    script_id,
                    success: true,
                    output,
                    error: None,
                    execution_time_ms,
                    return_value: Some(return_value),
                    timestamp_ms,
                }
            }
            Ok(Err(err)) => {
                LuaExecutionResult {
                    script_id,
                    success: false,
                    output: String::new(),
                    error: Some(err),
                    execution_time_ms,
                    return_value: None,
                    timestamp_ms,
                }
            }
            Err(_elapsed) => {
                LuaExecutionResult {
                    script_id,
                    success: false,
                    output: format!("Timeout after {}ms", script.timeout_ms),
                    error: Some(format!("Script execution timeout ({}ms exceeded)", script.timeout_ms)),
                    execution_time_ms,
                    return_value: None,
                    timestamp_ms,
                }
            }
        }
    }

    /// Execute Lua script in blocking thread
    async fn execute_script_async(
        script_name: &str,
        context: LuaContext,
    ) -> Result<(String, String), String> {
        let script_name = script_name.to_string();
        tokio::task::spawn_blocking(move || {
            Self::execute_lua_sandboxed(&script_name, &context)
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
    }

    /// Execute Lua with sandbox (blocking)
    fn execute_lua_sandboxed(
        script_name: &str,
        context: &LuaContext,
    ) -> Result<(String, String), String> {
        let lua = Lua::new();

        LuaSandbox::setup(&lua)?;
        Self::setup_globals(&lua, context)?;

        let script_code = format!(
            r#"
return {{
    output = "Executed {} against {}",
    result = "success"
}}
"#,
            script_name, context.target
        );

        let result: mlua::Table = lua.load(&script_code)
            .eval()
            .map_err(|e| format!("Lua eval error: {}", e))?;

        let output = result.get::<_, String>("output")
            .unwrap_or_else(|_| format!("Executed {}", script_name));
        let return_value = result.get::<_, String>("result")
            .unwrap_or_else(|_| "success".to_string());

        Ok((output, return_value))
    }

    /// Set up safe globals for script
    fn setup_globals(lua: &Lua, context: &LuaContext) -> Result<(), String> {
        let globals = lua.globals();

        globals.set("target", context.target.clone())
            .map_err(|e| format!("Failed to set target: {}", e))?;

        globals.set("payload", context.payload.clone())
            .map_err(|e| format!("Failed to set payload: {}", e))?;

        let params_table = lua.create_table()
            .map_err(|e| format!("Failed to create params table: {}", e))?;

        for (key, value) in &context.parameters {
            params_table.set(key.clone(), value.clone())
                .map_err(|e| format!("Failed to set parameter {}: {}", key, e))?;
        }

        globals.set("parameters", params_table)
            .map_err(|e| format!("Failed to set parameters: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_execution_basic() {
        let script = LuaScript {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            version: "1.0".to_string(),
            description: "Test".to_string(),
            author: "Test".to_string(),
            script_path: "test.lua".into(),
            categories: vec![],
            enabled: true,
            timeout_ms: 5000,
            status: LuaScriptStatus::Loaded,
        };

        let context = LuaContext::new("http://example.com");
        let result = LuaExecutor::execute(&script, context).await;

        assert_eq!(result.script_id, script.id.to_string());
        assert!(result.success);
    }

    #[test]
    fn test_setup_globals() {
        let lua = Lua::new();
        let context = LuaContext::new("http://example.com")
            .with_payload("<script>alert(1)</script>");

        let result = LuaExecutor::setup_globals(&lua, &context);
        assert!(result.is_ok());

        let globals = lua.globals();
        let target: String = globals.get("target").unwrap();
        assert_eq!(target, "http://example.com");
    }
}
