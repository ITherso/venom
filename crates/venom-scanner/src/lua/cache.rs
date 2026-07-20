//! Lua script compilation cache
//!
//! Caches compiled Lua bytecode to improve performance.

use std::sync::Arc;

pub struct LuaScriptCache {
    cache: Arc<dashmap::DashMap<String, Vec<u8>>>,
}

impl LuaScriptCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(dashmap::DashMap::new()),
        }
    }

    pub fn get(&self, script_id: &str) -> Option<Vec<u8>> {
        self.cache.get(script_id).map(|v| v.clone())
    }

    pub fn set(&self, script_id: String, bytecode: Vec<u8>) {
        self.cache.insert(script_id, bytecode);
    }

    pub fn invalidate(&self, script_id: &str) {
        self.cache.remove(script_id);
    }

    pub fn clear(&self) {
        self.cache.clear();
    }

    pub fn size(&self) -> usize {
        self.cache.len()
    }
}

impl Default for LuaScriptCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_set_get() {
        let cache = LuaScriptCache::new();
        let bytecode = vec![1, 2, 3, 4, 5];

        cache.set("test".to_string(), bytecode.clone());
        assert_eq!(cache.get("test"), Some(bytecode));
    }

    #[test]
    fn test_cache_invalidate() {
        let cache = LuaScriptCache::new();
        cache.set("test".to_string(), vec![1, 2, 3]);

        cache.invalidate("test");
        assert!(cache.get("test").is_none());
    }

    #[test]
    fn test_cache_size() {
        let cache = LuaScriptCache::new();
        cache.set("t1".to_string(), vec![1, 2, 3]);
        cache.set("t2".to_string(), vec![4, 5, 6]);

        assert_eq!(cache.size(), 2);
    }

    #[test]
    fn test_cache_clear() {
        let cache = LuaScriptCache::new();
        cache.set("t1".to_string(), vec![1]);
        cache.set("t2".to_string(), vec![2]);

        cache.clear();
        assert_eq!(cache.size(), 0);
    }
}
