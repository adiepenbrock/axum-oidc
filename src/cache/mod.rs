//! Caching functionality for OIDC authentication.
//!
//! This module provides caching traits and type-safe cache key wrappers
//! to efficiently store OIDC configuration, JWKS keys, and token validation results.

use std::{collections::hash_map::DefaultHasher, hash::{Hash, Hasher}, time::Duration};

pub mod memory;

pub use memory::InMemoryCache;

/// Trait for caching `JWKS` keys and `OIDC` configuration.
///
/// This trait allows users to implement custom caching strategies,
/// such as Redis, database, or custom in-memory implementations.
pub trait JwksCache: Send + Sync {
    /// Retrieves a cached value by key.
    /// Returns `None` if the key doesn't exist or has expired.
    fn get(&self, key: &str) -> Option<String>;

    /// Stores a value in the cache with the specified TTL.
    fn set(&self, key: &str, value: String, ttl: Duration);
}

/// Type-safe cache key for JWT tokens.
///
/// Prevents accidentally mixing token cache keys with other cache key types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenCacheKey(String);

impl TokenCacheKey {
    /// Creates a cache key from a JWT token by hashing it.
    #[must_use]
    pub fn from_token(token: &str) -> Self {
        let mut hasher = DefaultHasher::new();
        token.hash(&mut hasher);
        Self(format!("token:{}", hasher.finish()))
    }

    /// Returns the cache key as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Type-safe cache key for OIDC configuration.
///
/// Prevents accidentally mixing config cache keys with other cache key types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConfigCacheKey(String);

impl ConfigCacheKey {
    /// Creates a cache key for OIDC configuration.
    #[must_use]
    pub fn from_url(url: &str) -> Self {
        Self(format!("config:{url}"))
    }

    /// Returns the cache key as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Type-safe cache key for individual JWK keys.
///
/// Prevents accidentally mixing JWK cache keys with other cache key types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JwkCacheKey(String);

impl JwkCacheKey {
    /// Creates a cache key for a specific JWK.
    #[must_use]
    pub fn from_jwks_uri_and_kid(jwks_uri: &str, kid: &str) -> Self {
        Self(format!("jwk:{jwks_uri}:{kid}"))
    }

    /// Returns the cache key as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}