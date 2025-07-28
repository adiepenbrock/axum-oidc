//! In-memory cache implementation using standard library types.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use super::JwksCache;

/// Default in-memory implementation of `JwksCache` using standard library types.
///
/// This implementation provides a simple, thread-safe cache that automatically
/// cleans up expired entries. It's suitable for single-instance deployments
/// where cache persistence across restarts is not required.
#[derive(Debug)]
pub struct InMemoryCache {
    storage: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

/// Internal cache entry with expiration tracking.
#[derive(Debug, Clone)]
struct CacheEntry {
    data: String,
    expires_at: Instant,
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryCache {
    /// Creates a new in-memory cache instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Removes expired entries from the cache.
    ///
    /// This is called automatically during get operations to maintain
    /// cache hygiene without requiring a separate cleanup thread.
    fn cleanup_expired(&self) {
        if let Ok(mut storage) = self.storage.write() {
            let now = Instant::now();
            storage.retain(|_, entry| entry.expires_at > now);
        }
    }
}

impl JwksCache for InMemoryCache {
    fn get(&self, key: &str) -> Option<String> {
        self.cleanup_expired();

        self.storage.read().map_or(None, |storage| {
            storage
                .get(key)
                .filter(|entry| entry.expires_at > Instant::now())
                .map(|entry| entry.data.clone())
        })
    }

    fn set(&self, key: &str, value: String, ttl: Duration) {
        if let Ok(mut storage) = self.storage.write() {
            let entry = CacheEntry {
                data: value,
                expires_at: Instant::now() + ttl,
            };
            storage.insert(key.to_string(), entry);
        }
    }
}