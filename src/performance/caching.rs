use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CacheStrategy {
    LRU,
    LFU,
    FIFO,
    Random,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry<T: Clone> {
    pub key: String,
    pub value: T,
    pub created_at: DateTime<Utc>,
    pub accessed_at: DateTime<Utc>,
    pub access_count: u64,
    pub ttl: Option<Duration>,
}

impl<T: Clone> CacheEntry<T> {
    pub fn new(key: String, value: T, ttl: Option<Duration>) -> Self {
        let now = Utc::now();
        Self {
            key,
            value,
            created_at: now,
            accessed_at: now,
            access_count: 0,
            ttl,
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(ttl) = self.ttl {
            Utc::now() > self.accessed_at + ttl
        } else {
            false
        }
    }

    pub fn record_access(&mut self) {
        self.accessed_at = Utc::now();
        self.access_count += 1;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetrics {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub total_requests: u64,
    pub entries_count: usize,
    pub max_entries: usize,
    pub memory_usage_bytes: usize,
    pub max_memory_bytes: usize,
}

impl CacheMetrics {
    pub fn new(max_entries: usize, max_memory_bytes: usize) -> Self {
        Self {
            hits: 0,
            misses: 0,
            evictions: 0,
            total_requests: 0,
            entries_count: 0,
            max_entries,
            memory_usage_bytes: 0,
            max_memory_bytes,
        }
    }

    pub fn hit_ratio(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.hits as f64 / self.total_requests as f64
    }

    pub fn miss_ratio(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.misses as f64 / self.total_requests as f64
    }

    pub fn memory_utilization(&self) -> f64 {
        if self.max_memory_bytes == 0 {
            return 0.0;
        }
        (self.memory_usage_bytes as f64 / self.max_memory_bytes as f64) * 100.0
    }
}

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub strategy: CacheStrategy,
    pub max_entries: usize,
    pub max_memory_bytes: usize,
    pub default_ttl: Option<Duration>,
    pub eviction_policy: EvictionPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionPolicy {
    Aggressive,
    Normal,
    Conservative,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            strategy: CacheStrategy::LRU,
            max_entries: 10000,
            max_memory_bytes: 100 * 1024 * 1024, // 100MB
            default_ttl: Some(Duration::hours(1)),
            eviction_policy: EvictionPolicy::Normal,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Cache<T: Clone> {
    pub config: CacheConfig,
    entries: HashMap<String, CacheEntry<T>>,
    pub metrics: CacheMetrics,
}

impl<T: Clone + serde::Serialize> Cache<T> {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            metrics: CacheMetrics::new(config.max_entries, config.max_memory_bytes),
            config,
            entries: HashMap::new(),
        }
    }

    pub fn get(&mut self, key: &str) -> Option<T> {
        self.metrics.total_requests += 1;

        if let Some(entry) = self.entries.get_mut(key) {
            if entry.is_expired() {
                self.entries.remove(key);
                self.metrics.misses += 1;
                return None;
            }

            entry.record_access();
            self.metrics.hits += 1;
            return Some(entry.value.clone());
        }

        self.metrics.misses += 1;
        None
    }

    pub fn put(&mut self, key: String, value: T, ttl: Option<Duration>) {
        let entry = CacheEntry::new(key.clone(), value, ttl.or(self.config.default_ttl));

        // Check if we need to evict
        if self.entries.len() >= self.config.max_entries {
            self.evict();
        }

        self.entries.insert(key, entry);
        self.metrics.entries_count = self.entries.len();
    }

    pub fn remove(&mut self, key: &str) -> Option<T> {
        self.entries.remove(key).map(|e| {
            self.metrics.entries_count = self.entries.len();
            e.value
        })
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.metrics.entries_count = 0;
    }

    pub fn cleanup_expired(&mut self) {
        let expired_keys: Vec<_> = self.entries
            .iter()
            .filter(|(_, e)| e.is_expired())
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired_keys {
            self.entries.remove(&key);
            self.metrics.evictions += 1;
        }

        self.metrics.entries_count = self.entries.len();
    }

    fn evict(&mut self) {
        match self.config.strategy {
            CacheStrategy::LRU => self.evict_lru(),
            CacheStrategy::LFU => self.evict_lfu(),
            CacheStrategy::FIFO => self.evict_fifo(),
            CacheStrategy::Random => self.evict_random(),
        }
    }

    fn evict_lru(&mut self) {
        if let Some((key, _)) = self.entries.iter().min_by_key(|(_, e)| e.accessed_at) {
            let key = key.clone();
            self.entries.remove(&key);
            self.metrics.evictions += 1;
        }
    }

    fn evict_lfu(&mut self) {
        if let Some((key, _)) = self.entries.iter().min_by_key(|(_, e)| e.access_count) {
            let key = key.clone();
            self.entries.remove(&key);
            self.metrics.evictions += 1;
        }
    }

    fn evict_fifo(&mut self) {
        if let Some((key, _)) = self.entries.iter().min_by_key(|(_, e)| e.created_at) {
            let key = key.clone();
            self.entries.remove(&key);
            self.metrics.evictions += 1;
        }
    }

    fn evict_random(&mut self) {
        if let Some(key) = self.entries.keys().next().cloned() {
            self.entries.remove(&key);
            self.metrics.evictions += 1;
        }
    }

    pub fn size(&self) -> usize {
        self.entries.len()
    }

    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.config.max_entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_put_get() {
        let config = CacheConfig::default();
        let mut cache: Cache<String> = Cache::new(config);

        cache.put("key1".to_string(), "value1".to_string(), None);
        assert_eq!(cache.get("key1"), Some("value1".to_string()));
    }

    #[test]
    fn test_cache_miss() {
        let config = CacheConfig::default();
        let mut cache: Cache<String> = Cache::new(config);
        assert_eq!(cache.get("nonexistent"), None);
        assert_eq!(cache.metrics.misses, 1);
    }

    #[test]
    fn test_cache_hit_ratio() {
        let config = CacheConfig::default();
        let mut cache: Cache<String> = Cache::new(config);

        cache.put("key1".to_string(), "value1".to_string(), None);
        cache.get("key1");
        cache.get("key1");
        cache.get("nonexistent");

        assert!(cache.metrics.hit_ratio() > 0.0);
    }

    #[test]
    fn test_cache_eviction() {
        let mut config = CacheConfig::default();
        config.max_entries = 2;
        let mut cache: Cache<String> = Cache::new(config);

        cache.put("key1".to_string(), "value1".to_string(), None);
        cache.put("key2".to_string(), "value2".to_string(), None);
        cache.put("key3".to_string(), "value3".to_string(), None);

        assert!(cache.metrics.evictions > 0);
    }

    #[test]
    fn test_cache_cleanup_expired() {
        let mut config = CacheConfig::default();
        config.default_ttl = Some(Duration::seconds(1));
        let mut cache: Cache<String> = Cache::new(config);

        cache.put("key1".to_string(), "value1".to_string(), Some(Duration::seconds(1)));
        std::thread::sleep(std::time::Duration::from_secs(2));
        cache.cleanup_expired();

        assert_eq!(cache.size(), 0);
    }
}
