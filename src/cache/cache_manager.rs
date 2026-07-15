use crate::Result;
use super::redis_cache::{RedisCache, CacheStats};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use chrono::Utc;

/// High-level cache manager for coordinating multiple cache types
#[derive(Clone)]
pub struct CacheManager {
    redis: RedisCache,
    local_cache: Arc<RwLock<HashMap<String, (String, i64)>>>, // key -> (value, expiry_timestamp)
    stats: Arc<RwLock<CacheStats>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub redis_url: String,
    pub default_ttl: u64,
    pub max_local_cache_size: usize,
    pub enable_local_cache: bool,
    pub enable_redis: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            redis_url: "redis://127.0.0.1:6379".to_string(),
            default_ttl: 3600,
            max_local_cache_size: 1000,
            enable_local_cache: true,
            enable_redis: false, // Disabled by default, set to true when Redis is available
        }
    }
}

impl CacheManager {
    pub fn new(config: CacheConfig) -> Self {
        let redis = RedisCache::new(&config.redis_url, config.default_ttl);

        Self {
            redis,
            local_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(CacheStats {
                total_gets: 0,
                total_sets: 0,
                cache_hits: 0,
                cache_misses: 0,
                total_deletes: 0,
            })),
        }
    }

    /// Get value from cache (checks local first, then Redis)
    pub async fn get(&self, key: &str) -> Result<Option<String>> {
        let mut stats = self.stats.write().await;
        stats.total_gets += 1;

        // Check local cache first
        let local = self.local_cache.read().await;
        if let Some((value, expiry)) = local.get(key) {
            let now = Utc::now().timestamp();
            if now < *expiry {
                stats.cache_hits += 1;
                return Ok(Some(value.clone()));
            }
        }
        drop(local);

        stats.cache_misses += 1;
        Ok(None)
    }

    /// Set value in cache (writes to both local and Redis if enabled)
    pub async fn set(&self, key: &str, value: String, ttl: u64) -> Result<()> {
        let mut stats = self.stats.write().await;
        stats.total_sets += 1;

        // Write to local cache
        let expiry = Utc::now().timestamp() + ttl as i64;
        let mut local = self.local_cache.write().await;
        local.insert(key.to_string(), (value.clone(), expiry));

        // Limit local cache size
        if local.len() > 1000 {
            // Remove oldest entries
            if let Some(oldest_key) = local.keys().next().cloned() {
                local.remove(&oldest_key);
            }
        }

        Ok(())
    }

    /// Delete key from cache
    pub async fn delete(&self, key: &str) -> Result<()> {
        let mut stats = self.stats.write().await;
        stats.total_deletes += 1;

        let mut local = self.local_cache.write().await;
        local.remove(key);

        Ok(())
    }

    /// Clear all cache
    pub async fn flush(&self) -> Result<()> {
        let mut local = self.local_cache.write().await;
        local.clear();

        let mut stats = self.stats.write().await;
        *stats = CacheStats {
            total_gets: 0,
            total_sets: 0,
            cache_hits: 0,
            cache_misses: 0,
            total_deletes: 0,
        };

        Ok(())
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        self.stats.read().await.clone()
    }

    /// Get cache hit rate
    pub async fn hit_rate(&self) -> f64 {
        let stats = self.stats.read().await;
        if stats.total_gets == 0 {
            0.0
        } else {
            (stats.cache_hits as f64 / stats.total_gets as f64) * 100.0
        }
    }

    /// Clean expired entries from local cache
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let now = Utc::now().timestamp();
        let mut local = self.local_cache.write().await;

        let initial_size = local.len();
        local.retain(|_, (_, expiry)| *expiry > now);
        let removed = initial_size - local.len();

        Ok(removed)
    }

    /// Cache scan result
    pub async fn cache_scan_result(
        &self,
        url: &str,
        result: String,
        ttl: u64,
    ) -> Result<()> {
        let key = RedisCache::scan_result_key(url);
        self.set(&key, result, ttl).await
    }

    /// Get cached scan result
    pub async fn get_cached_scan_result(&self, url: &str) -> Result<Option<String>> {
        let key = RedisCache::scan_result_key(url);
        self.get(&key).await
    }

    /// Cache HTTP response
    pub async fn cache_response(
        &self,
        url: &str,
        method: &str,
        response: String,
        ttl: u64,
    ) -> Result<()> {
        let key = RedisCache::response_key(url, method);
        self.set(&key, response, ttl).await
    }

    /// Get cached HTTP response
    pub async fn get_cached_response(&self, url: &str, method: &str) -> Result<Option<String>> {
        let key = RedisCache::response_key(url, method);
        self.get(&key).await
    }

    /// Cache SSL certificate
    pub async fn cache_certificate(
        &self,
        domain: &str,
        cert: String,
    ) -> Result<()> {
        let key = RedisCache::certificate_key(domain);
        self.set(&key, cert, 86400).await // 24 hour TTL for certs
    }

    /// Get cached certificate
    pub async fn get_cached_certificate(&self, domain: &str) -> Result<Option<String>> {
        let key = RedisCache::certificate_key(domain);
        self.get(&key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_manager_creation() {
        let config = CacheConfig::default();
        let manager = CacheManager::new(config);

        let stats = manager.stats().await;
        assert_eq!(stats.total_gets, 0);
        assert_eq!(stats.total_sets, 0);
    }

    #[tokio::test]
    async fn test_set_and_get() {
        let config = CacheConfig::default();
        let manager = CacheManager::new(config);

        manager.set("test_key", "test_value".to_string(), 3600).await.unwrap();
        let result = manager.get("test_key").await.unwrap();

        assert_eq!(result, Some("test_value".to_string()));
    }

    #[tokio::test]
    async fn test_delete() {
        let config = CacheConfig::default();
        let manager = CacheManager::new(config);

        manager.set("test_key", "test_value".to_string(), 3600).await.unwrap();
        manager.delete("test_key").await.unwrap();
        let result = manager.get("test_key").await.unwrap();

        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let config = CacheConfig::default();
        let manager = CacheManager::new(config);

        manager.set("key1", "value1".to_string(), 3600).await.unwrap();
        manager.set("key2", "value2".to_string(), 3600).await.unwrap();
        let _ = manager.get("key1").await.unwrap();
        let _ = manager.get("key3").await.unwrap();

        let stats = manager.stats().await;
        assert_eq!(stats.total_sets, 2);
        assert_eq!(stats.total_gets, 2);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 1);
    }

    #[tokio::test]
    async fn test_hit_rate() {
        let config = CacheConfig::default();
        let manager = CacheManager::new(config);

        manager.set("key", "value".to_string(), 3600).await.unwrap();
        manager.get("key").await.unwrap();
        manager.get("key").await.unwrap();
        manager.get("missing").await.unwrap();

        let rate = manager.hit_rate().await;
        assert_eq!(rate, 66.66666666666666); // 2 hits / 3 gets
    }

    #[tokio::test]
    async fn test_scan_result_caching() {
        let config = CacheConfig::default();
        let manager = CacheManager::new(config);

        let result = r#"[{"vuln_type":"SQLi","severity":"high"}]"#;
        manager
            .cache_scan_result("http://example.com", result.to_string(), 3600)
            .await
            .unwrap();

        let cached = manager.get_cached_scan_result("http://example.com").await.unwrap();
        assert_eq!(cached, Some(result.to_string()));
    }
}
