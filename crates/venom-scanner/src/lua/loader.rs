//! Lua script loader
//!
//! Loads scripts from file and string with path validation.

use super::types::{LuaScript, ScriptCategory};
use std::path::{Path, PathBuf};

pub struct LuaScriptLoader;

impl LuaScriptLoader {
    /// Load script from file with path validation (P0 security)
    pub fn load_from_file(
        name: impl Into<String>,
        script_path: impl AsRef<Path>,
        script_root: &Path,
    ) -> Result<LuaScript, String> {
        LuaScript::new_safe(name, script_path, script_root)
    }

    /// Load script from string (no validation)
    pub fn load_from_string(name: impl Into<String>) -> LuaScript {
        LuaScript {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            version: "1.0.0".to_string(),
            description: String::new(),
            author: "Unknown".to_string(),
            script_path: PathBuf::from("inline"),
            categories: vec![],
            enabled: true,
            timeout_ms: 5000,
            status: super::types::LuaScriptStatus::Loaded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_load_from_string() {
        let script = LuaScriptLoader::load_from_string("test_script");
        assert_eq!(script.name, "test_script");
        assert!(script.enabled);
    }

    #[test]
    fn test_load_from_file_invalid_path() {
        let root = PathBuf::from(".");
        let result = LuaScriptLoader::load_from_file("test", "../etc/passwd", &root);
        assert!(result.is_err());
    }
}
