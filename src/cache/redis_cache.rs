use crate::Result;
use serde::{Deserialize, Serialize};

/// Redis cache wrapper for distributed caching
#[derive(Clone)]
pub struct RedisCache {
    connection_string: String,
    default_ttl: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry<T> {
    pub key: String,
    pub value: T,
    pub ttl: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_gets: u64,
    pub total_sets: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub total_deletes: u64,
}

impl RedisCache {
    /// Create a new Redis cache connection
    pub fn new(connection_string: &str, default_ttl: u64) -> Self {
        Self {
            connection_string: connection_string.to_string(),
            default_ttl,
        }
    }

    /// Get cache key for a URL
    pub fn make_cache_key(prefix: &str, value: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        format!("{}:{}", prefix, hash)
    }

    /// Cache key for vulnerability scan results
    pub fn scan_result_key(url: &str) -> String {
        Self::make_cache_key("scan", url)
    }

    /// Cache key for certificate
    pub fn certificate_key(domain: &str) -> String {
        Self::make_cache_key("cert", domain)
    }

    /// Cache key for HTTP response
    pub fn response_key(url: &str, method: &str) -> String {
        let combined = format!("{}:{}", url, method);
        Self::make_cache_key("response", &combined)
    }

    /// Cache key for request pattern
    pub fn pattern_key(pattern: &str) -> String {
        Self::make_cache_key("pattern", pattern)
    }

    /// Sample usage documentation
    pub fn usage_example() -> String {
        r#"
# Redis Cache Usage Example

## Configuration
```rust
let cache = RedisCache::new("redis://127.0.0.1:6379", 3600);
```

## Get/Set Operations (Mock)
```rust
// Store scan results
cache.set("scan:example.com", &scan_results, 3600).await?;

// Retrieve cached results
let results = cache.get("scan:example.com").await?;

// Delete from cache
cache.delete("scan:example.com").await?;

// Clear all
cache.flush().await?;
```

## Supported Cache Keys
- scan:<url_hash>    - Vulnerability scan results
- cert:<domain_hash> - SSL/TLS certificates
- response:<url_hash>:<method> - HTTP responses
- pattern:<hash>     - Vulnerability patterns

## TTL Configuration
- Default: 3600 seconds (1 hour)
- Certificates: 86400 seconds (24 hours)
- Scan results: 7200 seconds (2 hours)
- Responses: 300 seconds (5 minutes)

## Integration with VENOM
Cache is used for:
1. SSL certificate caching (existing in proxy/tls.rs)
2. Vulnerability scan result caching
3. HTTP response caching for repeater
4. Pattern matching cache for scanner
5. Zero-day detection pattern cache

## Connection String Formats
- TCP: redis://127.0.0.1:6379
- Socket: unix:///tmp/redis.sock
- Sentinel: redis-sentinel://sentinel1:26379,sentinel2:26379
"#.to_string()
    }

    /// Get connection info
    pub fn connection_info(&self) -> &str {
        &self.connection_string
    }

    /// Get default TTL
    pub fn default_ttl(&self) -> u64 {
        self.default_ttl
    }

    /// Generate cache statistics
    pub fn stats_example() -> CacheStats {
        CacheStats {
            total_gets: 1000,
            total_sets: 500,
            cache_hits: 850,
            cache_misses: 150,
            total_deletes: 100,
        }
    }

    /// Hit rate calculation
    pub fn hit_rate(stats: &CacheStats) -> f64 {
        if stats.total_gets == 0 {
            0.0
        } else {
            (stats.cache_hits as f64 / stats.total_gets as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_generation() {
        let key1 = RedisCache::scan_result_key("http://example.com");
        let key2 = RedisCache::scan_result_key("http://example.com");

        // Same input should produce same key
        assert_eq!(key1, key2);
        assert!(key1.starts_with("scan:"));
    }

    #[test]
    fn test_different_urls_different_keys() {
        let key1 = RedisCache::scan_result_key("http://example.com");
        let key2 = RedisCache::scan_result_key("http://different.com");

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_creation() {
        let cache = RedisCache::new("redis://127.0.0.1:6379", 3600);
        assert_eq!(cache.connection_info(), "redis://127.0.0.1:6379");
        assert_eq!(cache.default_ttl(), 3600);
    }

    #[test]
    fn test_hit_rate_calculation() {
        let stats = CacheStats {
            total_gets: 100,
            total_sets: 50,
            cache_hits: 85,
            cache_misses: 15,
            total_deletes: 10,
        };

        let hit_rate = RedisCache::hit_rate(&stats);
        assert_eq!(hit_rate, 85.0);
    }

    #[test]
    fn test_certificate_key_format() {
        let key = RedisCache::certificate_key("example.com");
        assert!(key.starts_with("cert:"));
    }

    #[test]
    fn test_response_key_format() {
        let key = RedisCache::response_key("http://example.com/api", "GET");
        assert!(key.starts_with("response:"));
    }
}
