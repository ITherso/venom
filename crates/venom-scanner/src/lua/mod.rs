//! Lua script engine module (refactored Sprint 1)
//!
//! Organized into focused modules:
//! - types: data structures
//! - sandbox: security boundary
//! - executor: execution engine
//! - loader: script loading
//! - registry: script management
//! - cache: bytecode caching
//! - history: execution tracking

pub mod types;
pub mod sandbox;
pub mod executor;
pub mod loader;
pub mod registry;
pub mod cache;
pub mod history;

pub use types::{ScriptCategory, LuaScriptStatus, LuaScript, LuaContext, LuaExecutionResult};
pub use sandbox::LuaSandbox;
pub use executor::LuaExecutor;
pub use loader::LuaScriptLoader;
pub use registry::LuaScriptRegistry;
pub use cache::LuaScriptCache;
pub use history::BoundedExecutionHistory;
