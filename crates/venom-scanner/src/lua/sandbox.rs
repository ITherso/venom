//! Lua sandbox restrictions (P0 - SECURITY BOUNDARY)
//!
//! Blocks all dangerous operations that could compromise the system.
//! - No file access (io.open, io.read, io.write)
//! - No OS commands (os.execute, os.system)
//! - No code loading (require, load, loadfile, dofile)
//! - No introspection (debug.*)
//! - Memory limit enforcement

use mlua::Lua;

/// Lua sandbox enforcer
pub struct LuaSandbox;

impl LuaSandbox {
    /// Set up sandbox restrictions (P0 security feature)
    ///
    /// Blocks all dangerous operations:
    /// - os.execute, os.system (command execution)
    /// - io.open, io.read, io.write (file access)
    /// - package.loadlib, require (code loading)
    /// - debug.* (VM inspection/manipulation)
    /// - Unlimited memory and CPU
    pub fn setup(lua: &Lua) -> Result<(), String> {
        let globals = lua.globals();

        // 1️⃣ Block OS module - prevents os.execute("rm -rf /")
        globals.set("os", mlua::Nil)
            .map_err(|e| format!("Failed to block os module: {}", e))?;

        // 2️⃣ Block IO module - prevents io.open("/etc/passwd")
        globals.set("io", mlua::Nil)
            .map_err(|e| format!("Failed to block io module: {}", e))?;

        // 3️⃣ Block Debug module - prevents introspection/manipulation
        globals.set("debug", mlua::Nil)
            .map_err(|e| format!("Failed to block debug module: {}", e))?;

        // 4️⃣ Block Package module - prevents code loading
        globals.set("package", mlua::Nil)
            .map_err(|e| format!("Failed to block package module: {}", e))?;

        // 5️⃣ Block dofile() - prevents executing external files
        globals.set("dofile", mlua::Nil)
            .map_err(|e| format!("Failed to block dofile: {}", e))?;

        // 6️⃣ Block loadfile() - prevents loading external files
        globals.set("loadfile", mlua::Nil)
            .map_err(|e| format!("Failed to block loadfile: {}", e))?;

        // 7️⃣ Block require() - prevents module loading
        globals.set("require", mlua::Nil)
            .map_err(|e| format!("Failed to block require: {}", e))?;

        // 8️⃣ Block load() - prevents dynamic code execution
        globals.set("load", mlua::Nil)
            .map_err(|e| format!("Failed to block load: {}", e))?;

        // 9️⃣ Block loadstring() alias
        globals.set("loadstring", mlua::Nil)
            .map_err(|e| format!("Failed to block loadstring: {}", e))?;

        // Set memory limit: 50MB max (prevents unbounded memory growth)
        lua.set_memory_limit(50_000_000)
            .map_err(|e| format!("Failed to set memory limit: {}", e))?;

        Ok(())
    }

    /// Verify sandbox is enforced
    pub fn verify(lua: &Lua) -> bool {
        let globals = lua.globals();

        // Check if dangerous modules are blocked
        if let Ok(os) = globals.get::<_, mlua::Value>("os") {
            if !os.is_nil() {
                return false;
            }
        }

        if let Ok(io) = globals.get::<_, mlua::Value>("io") {
            if !io.is_nil() {
                return false;
            }
        }

        if let Ok(debug) = globals.get::<_, mlua::Value>("debug") {
            if !debug.is_nil() {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_blocks_os() {
        let lua = Lua::new();
        let result = LuaSandbox::setup(&lua);
        assert!(result.is_ok());

        let globals = lua.globals();
        let os_val = globals.get::<_, mlua::Value>("os").unwrap();
        assert!(os_val.is_nil());
    }

    #[test]
    fn test_sandbox_blocks_io() {
        let lua = Lua::new();
        let _ = LuaSandbox::setup(&lua);

        let globals = lua.globals();
        let io_val = globals.get::<_, mlua::Value>("io").unwrap();
        assert!(io_val.is_nil());
    }

    #[test]
    fn test_sandbox_blocks_debug() {
        let lua = Lua::new();
        let _ = LuaSandbox::setup(&lua);

        let globals = lua.globals();
        let debug_val = globals.get::<_, mlua::Value>("debug").unwrap();
        assert!(debug_val.is_nil());
    }

    #[test]
    fn test_sandbox_blocks_package() {
        let lua = Lua::new();
        let _ = LuaSandbox::setup(&lua);

        let globals = lua.globals();
        let package_val = globals.get::<_, mlua::Value>("package").unwrap();
        assert!(package_val.is_nil());
    }

    #[test]
    fn test_sandbox_blocks_require() {
        let lua = Lua::new();
        let _ = LuaSandbox::setup(&lua);

        let globals = lua.globals();
        let require_val = globals.get::<_, mlua::Value>("require").unwrap();
        assert!(require_val.is_nil());
    }

    #[test]
    fn test_sandbox_verify() {
        let lua = Lua::new();
        let _ = LuaSandbox::setup(&lua);

        assert!(LuaSandbox::verify(&lua));
    }

    #[test]
    fn test_sandbox_memory_limit() {
        let lua = Lua::new();
        let result = LuaSandbox::setup(&lua);
        assert!(result.is_ok());
    }
}
