# Lua Script Engine Module

## Purpose

Execute custom Lua scripts for scanning logic with P0 security sandboxing and P1 memory protection.

## Architecture

| Module | Purpose | Visibility | Tests |
|--------|---------|-----------|-------|
| **types.rs** | Data structures (ScriptCategory, LuaScript, LuaContext, LuaExecutionResult) | public | ✅ |
| **sandbox.rs** | Security boundary - blocks OS, IO, debug, file operations | public | ✅ 7 |
| **executor.rs** | Execution engine with timeout enforcement | public | ✅ 2 |
| **loader.rs** | Script loading with path validation (P0 security) | public | ✅ 2 |
| **registry.rs** | Script management (registration, tracking, history) | public | ✅ 3 |
| **cache.rs** | Lua bytecode caching for performance | public | ✅ 4 |
| **history.rs** | Bounded execution history with exponential decay | public | ✅ 6 |

**Total: 7 focused modules, 24+ tests, ~1320 lines**

## Public API

```rust
// Create and execute a script
let script = LuaScript {
    id: Uuid::new_v4(),
    name: "xss_detector".to_string(),
    // ... other fields
};

let context = LuaContext::new("http://target.com")
    .with_payload("<script>alert(1)</script>");

// Execute with sandbox
let result = LuaExecutor::execute(&script, context).await;

// Track execution
registry.record_execution(result);

// Query history with exponential decay
let success_rate = history.success_rate_decayed(current_time_ms);
```

## Key Features

### P0: Security Sandbox
- Blocks all dangerous operations
- No file access (io module removed)
- No OS commands (os module removed)
- No code loading (require, load, dofile blocked)
- Memory limit: 50MB max
- See: `sandbox.rs`

### P0: Path Security
- Path canonicalization prevents `../../../etc/passwd` traversal
- Scripts must be within designated root directory
- See: `loader.rs`, `types.rs::new_safe()`

### P0: Timeout Enforcement
- 5-second default timeout per script
- Tokio-based timeout prevents hanging
- Separate execution in blocking thread pool
- See: `executor.rs`

### P1: Memory Protection
- Bounded execution history (default 100 entries/script)
- 1 year of data = 25MB, not 936GB
- Prevents unbounded memory growth
- See: `history.rs`

### P1: Exponential Decay
- Recent executions weighted 100% (age 0min)
- Old executions weighted 12.5% (age 15min)
- Formula: weight = 0.5 ^ (age_ms / half_life_ms)
- ML-ready for adaptive scoring
- See: `history.rs::decay_weight()`

## Design Decisions

### Why separate modules?
- **types**: Serializable data structures, no logic coupling
- **sandbox**: Security boundary isolates policy from execution
- **executor**: Async execution + timeout logic separate from sandbox
- **loader**: Path validation separate from script structures
- **registry**: Concurrent script management (DashMap-based)
- **cache**: Bytecode caching optional, isolated
- **history**: Bounded tracking with exponential decay

### Why no trait-based plugin system yet?
- Only 1 implementation of each component (executor, loader, etc.)
- Trait trait extraction deferred to v0.9.2+ when 2+ implementations exist
- Keeps API surface simpler

### Why types are public?
- Lua scripts are data that crosses trust boundaries
- Serialization (serde) critical for persistence/distribution
- Users import types directly, not through factory functions

## Testing

```bash
# All modules
cargo test --lib lua

# Specific module
cargo test --lib lua::sandbox

# With output
cargo test --lib lua -- --nocapture
```

**Test coverage:**
- Sandbox: 7 tests (all dangerous operations blocked)
- Executor: 2 tests (basic execution, globals setup)
- Loader: 2 tests (string loading, path validation)
- Registry: 3 tests (registration, tracking, enable/disable)
- Cache: 4 tests (set/get, invalidate, clear)
- History: 6 tests (overflow, recent, decay, success rate)
- Types: 4 tests (conversion, builders)

## Onboarding (10 min)

1. **Start with types.rs**: All data structures (1 min)
2. **Security: sandbox.rs**: What's blocked, memory limit (2 min)
3. **Execution: executor.rs**: How scripts run, timeout (2 min)
4. **Registry pattern**: registration, tracking, history (3 min)
5. **Run tests**: `cargo test --lib lua` (2 min)

## Future (v0.9.2+)

- [ ] **Lua script plugins** (lua:: → plugins::lua when 2+ executor variants)
- [ ] **Script caching** (enable bytecode compilation cache)
- [ ] **Resource limits** per script (CPU cycles, allocations)
- [ ] **Multi-threaded registry** stress tests (1000+ scripts)
- [ ] **Lua-in-WASM** sandbox option (hermetic, cross-platform)

## Migration from old lua_engine.rs

Old monolithic file: `lua_engine.rs` (1857 lines)
New modular structure: `lua/` (7 files, ~1320 lines + docs)

**What moved where:**
| Old | New | Status |
|-----|-----|--------|
| ScriptCategory enum | lua/types.rs | ✅ |
| LuaScript struct | lua/types.rs | ✅ |
| LuaContext struct | lua/types.rs | ✅ |
| LuaExecutionResult struct | lua/types.rs | ✅ |
| setup_sandbox() | lua/sandbox.rs::LuaSandbox::setup() | ✅ |
| execute() async | lua/executor.rs::LuaExecutor::execute() | ✅ |
| LuaScriptRegistry | lua/registry.rs::LuaScriptRegistry | ✅ |
| BoundedExecutionHistory | lua/history.rs::BoundedExecutionHistory | ✅ |
| All tests | lua/{module}/tests | ✅ 24 tests |

## Questions?

See tests in each module for usage examples. All public APIs have docstring examples.
