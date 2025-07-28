//! High-level token validation and OIDC configuration management.

use std::sync::Arc;

use jsonwebtoken::decode_header;
use serde::de::DeserializeOwned;

use crate::{
    cache::{ConfigCacheKey, JwkCacheKey, JwksCache, TokenCacheKey},
    config::{AuthenticationConfigProvider, OidcConfiguration},
    error::OidcError,
    jwks::{fetch_and_cache_jwks, validate_token_with_jwk},
    token::extract_token_ttl,
};

/// Fetches or retrieves OIDC configuration from cache.
///
/// This function first checks the cache for existing OIDC configuration.
/// If not found or expired, it fetches the configuration from the provider's
/// well-known endpoint and caches it for future use.
///
/// # Arguments
/// * `cache` - The cache implementation to use
/// * `config_url` - The URL to fetch the OIDC configuration from
/// * `config` - Configuration provider for cache TTL settings
///
/// # Returns
/// The OIDC configuration containing the JWKS URI and other provider information
pub async fn get_oidc_config(
    cache: &Arc<dyn JwksCache>,
    config_url: &str,
    config: &(impl AuthenticationConfigProvider + Send + Sync),
) -> Result<OidcConfiguration, OidcError> {
    let config_cache_key = ConfigCacheKey::from_url(config_url);
    
    // Try cache first
    if let Some(cached_config) = cache.get(config_cache_key.as_str()) {
        return serde_json::from_str(&cached_config)
            .map_err(|e| OidcError::CacheError(format!("Failed to deserialize cached config: {e}")));
    }

    // Cache miss - fetch from remote
    let response = reqwest::get(config_url)
        .await
        .map_err(|e| OidcError::ConfigurationError(format!("Failed to fetch OIDC config: {e}")))?;

    let config_doc: OidcConfiguration = response
        .json()
        .await
        .map_err(|e| OidcError::ConfigurationError(format!("Failed to parse OIDC config: {e}")))?;

    // Cache the result
    if let Ok(serialized) = serde_json::to_string(&config_doc) {
        cache.set(config_cache_key.as_str(), serialized, config.get_config_cache_ttl());
    }

    Ok(config_doc)
}

/// Validates a JWT token and caches the validation result.
///
/// This is the main validation orchestration function that:
/// 1. Checks if the token's claims are already cached
/// 2. If not cached, extracts the key ID from the token header
/// 3. Retrieves the appropriate JWK (from cache or by fetching JWKS)
/// 4. Validates the token and caches the result
///
/// # Arguments
/// * `cache` - The cache implementation to use
/// * `token` - The JWT token to validate
/// * `jwks_uri` - The URI where JWKs can be fetched
/// * `config` - Configuration provider for cache TTL settings
///
/// # Returns
/// The validated and deserialized token claims
pub async fn validate_and_cache_token<T>(
    cache: &Arc<dyn JwksCache>,
    token: &str,
    jwks_uri: &str,
    config: &(impl AuthenticationConfigProvider + Send + Sync),
) -> Result<T, OidcError>
where
    T: DeserializeOwned + serde::Serialize + Clone + Send + Sync + 'static,
{
    let token_cache_key = TokenCacheKey::from_token(token);
    
    // Check token cache first
    if let Some(cached_claims) = cache.get(token_cache_key.as_str()) {
        return serde_json::from_str(&cached_claims)
            .map_err(|e| OidcError::CacheError(format!("Failed to deserialize cached token: {e}")));
    }

    // Extract kid from token header
    let header = decode_header(token)
        .map_err(|e| OidcError::InvalidToken(format!("Failed to decode JWT header: {e}")))?;

    let kid = header.kid.ok_or(OidcError::MissingKid)?;

    // Check if we have this specific JWK key cached
    let jwk_cache_key = JwkCacheKey::from_jwks_uri_and_kid(jwks_uri, &kid);
    let jwk = match cache.get(jwk_cache_key.as_str()) {
        Some(cached_jwk) => serde_json::from_str(&cached_jwk)
            .map_err(|e| OidcError::CacheError(format!("Failed to deserialize cached JWK: {e}")))?,
        None => {
            // Cache miss - fetch full JWKS and cache individual keys
            fetch_and_cache_jwks(cache, jwks_uri, config, &kid).await?
        }
    };

    // Validate token with JWK
    let validated_claims = validate_token_with_jwk::<T>(token, &jwk, header.alg)
        .map_err(OidcError::ValidationError)?;

    // Cache the validated token
    if let Ok(serialized) = serde_json::to_string(&validated_claims) {
        let token_ttl = extract_token_ttl(token);
        cache.set(token_cache_key.as_str(), serialized, token_ttl);
    }

    Ok(validated_claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::InMemoryCache;
    use crate::config::{AuthenticationConfigProvider, DEFAULT_CONFIG_TTL, DEFAULT_JWKS_TTL};
    use std::time::Duration;

    struct TestConfig;
    
    impl AuthenticationConfigProvider for TestConfig {
        fn get_provider_url(&self) -> String {
            "https://example.com".to_string()
        }
        
        fn get_openid_configuration_url(&self) -> Option<String> {
            None
        }
        
        fn get_jwks_cache_ttl(&self) -> Duration {
            DEFAULT_JWKS_TTL
        }
        
        fn get_config_cache_ttl(&self) -> Duration {
            DEFAULT_CONFIG_TTL
        }
    }

    #[test]
    fn test_token_cache_key_consistency() {
        let token = "test.token.here";
        let key1 = TokenCacheKey::from_token(token);
        let key2 = TokenCacheKey::from_token(token);
        assert_eq!(key1, key2);
    }
}