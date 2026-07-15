use crate::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};

/// Simple in-memory cache with TTL
pub struct Cache<K: Clone + Eq + std::hash::Hash, V: Clone> {
    data: Arc<RwLock<HashMap<K, (V, Instant)>>>,
    ttl: Duration,
}

impl<K: Clone + Eq + std::hash::Hash, V: Clone> Cache<K, V> {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Get value from cache if exists and not expired
    pub async fn get(&self, key: &K) -> Option<V> {
        let data = self.data.read().await;
        if let Some((value, inserted_at)) = data.get(key) {
            if inserted_at.elapsed() < self.ttl {
                return Some(value.clone());
            }
        }
        None
    }

    /// Set value in cache
    pub async fn set(&self, key: K, value: V) {
        let mut data = self.data.write().await;
        data.insert(key, (value, Instant::now()));
    }

    /// Clear all expired entries
    pub async fn cleanup(&self) {
        let mut data = self.data.write().await;
        let now = Instant::now();
        data.retain(|_, (_, inserted_at)| now.duration_since(*inserted_at) < self.ttl);
    }

    /// Get size of cache
    pub async fn size(&self) -> usize {
        let data = self.data.read().await;
        data.len()
    }
}

/// Connection pool for managing concurrent connections
pub struct ConnectionPool {
    max_connections: usize,
    current_connections: Arc<RwLock<usize>>,
}

impl ConnectionPool {
    pub fn new(max_connections: usize) -> Self {
        Self {
            max_connections,
            current_connections: Arc::new(RwLock::new(0)),
        }
    }

    /// Acquire a connection slot
    pub async fn acquire(&self) -> Result<ConnectionGuard> {
        let mut conns = self.current_connections.write().await;

        if *conns >= self.max_connections {
            return Err(crate::Error::ProxyError("Connection pool exhausted".into()));
        }

        *conns += 1;
        Ok(ConnectionGuard {
            counter: Arc::clone(&self.current_connections),
        })
    }

    /// Get current connection count
    pub async fn connection_count(&self) -> usize {
        *self.current_connections.read().await
    }
}

/// RAII guard for connection management
pub struct ConnectionGuard {
    counter: Arc<RwLock<usize>>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let counter = Arc::clone(&self.counter);
        tokio::spawn(async move {
            let mut conns = counter.write().await;
            if *conns > 0 {
                *conns -= 1;
            }
        });
    }
}

/// Payload obfuscation engine
pub struct PayloadObfuscator;

impl PayloadObfuscator {
    /// Base64 encode payload
    pub fn encode_base64(payload: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(payload)
    }

    /// Base64 decode payload
    pub fn decode_base64(encoded: &str) -> Result<String> {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| crate::Error::ProxyError(format!("Decode error: {}", e)))?;
        String::from_utf8(decoded)
            .map_err(|e| crate::Error::ProxyError(format!("UTF8 error: {}", e)))
    }

    /// XOR obfuscation
    pub fn xor_obfuscate(payload: &[u8], key: u8) -> Vec<u8> {
        payload.iter().map(|b| b ^ key).collect()
    }

    /// Hex encoding
    pub fn hex_encode(payload: &[u8]) -> String {
        hex::encode(payload)
    }

    /// Hex decoding
    pub fn hex_decode(hex_str: &str) -> Result<Vec<u8>> {
        hex::decode(hex_str)
            .map_err(|e| crate::Error::ProxyError(format!("Hex decode error: {}", e)))
    }

    /// Multi-layer obfuscation
    pub fn multi_layer_obfuscate(payload: &str) -> String {
        // Layer 1: XOR with 0x42
        let xored = Self::xor_obfuscate(payload.as_bytes(), 0x42);

        // Layer 2: Base64
        Self::encode_base64(&String::from_utf8_lossy(&xored))
    }

    /// Multi-layer deobfuscation
    pub fn multi_layer_deobfuscate(obfuscated: &str) -> Result<String> {
        // Layer 1: Base64 decode
        let decoded_b64 = Self::decode_base64(obfuscated)?;

        // Layer 2: XOR decode
        let xored_bytes = decoded_b64.as_bytes();
        let deobfuscated = Self::xor_obfuscate(xored_bytes, 0x42);

        String::from_utf8(deobfuscated)
            .map_err(|e| crate::Error::ProxyError(format!("UTF8 error: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache() {
        let cache: Cache<String, String> = Cache::new(1);

        cache.set("key1".to_string(), "value1".to_string()).await;
        assert_eq!(cache.get(&"key1".to_string()).await, Some("value1".to_string()));

        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(cache.get(&"key1".to_string()).await, None);
    }

    #[tokio::test]
    async fn test_connection_pool() {
        let pool = ConnectionPool::new(3);

        let _conn1 = pool.acquire().await.unwrap();
        let _conn2 = pool.acquire().await.unwrap();
        let _conn3 = pool.acquire().await.unwrap();

        assert!(pool.acquire().await.is_err());
        assert_eq!(pool.connection_count().await, 3);
    }

    #[test]
    fn test_payload_obfuscation() {
        let payload = "SELECT * FROM users WHERE id=1";

        let obfuscated = PayloadObfuscator::multi_layer_obfuscate(payload);
        let deobfuscated = PayloadObfuscator::multi_layer_deobfuscate(&obfuscated).unwrap();

        assert_eq!(deobfuscated, payload);
    }
}
