//! JWKS (JSON Web Key Set) fetching and JWT validation operations.

use std::sync::Arc;

use jsonwebtoken::{jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;

use crate::{
    cache::{JwkCacheKey, JwksCache},
    config::AuthenticationConfigProvider,
    error::OidcError,
};

/// Validates a JWT token using a specific JWK key.
///
/// This function performs the actual cryptographic validation of the JWT
/// using the provided JWK and algorithm. It returns the decoded claims
/// if validation succeeds.
pub fn validate_token_with_jwk<T: DeserializeOwned>(
    token: &str,
    jwk: &jsonwebtoken::jwk::Jwk,
    alg: Algorithm,
) -> Result<T, String> {
    let mut validation = Validation::new(alg);
    validation.validate_aud = false;

    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| format!("Failed to create DecodingKey from JWK: {e}"))?;

    let token_data = jsonwebtoken::decode::<T>(token, &decoding_key, &validation)
        .map_err(|e| format!("JWT validation failed: {e}"))?;

    Ok(token_data.claims)
}

/// Fetches `JWKS` from the URI and caches individual JWK keys.
///
/// This function retrieves the complete JWKS from the provider, caches each
/// individual key separately for efficient future lookups, and returns the
/// specific JWK needed for the current token validation.
///
/// # Arguments
/// * `cache` - The cache implementation to store JWK keys
/// * `jwks_uri` - The URI to fetch the JWKS from
/// * `config` - Configuration provider for cache TTL settings
/// * `requested_kid` - The specific key ID needed for validation
///
/// # Returns
/// The JWK corresponding to the requested key ID, or an error if not found
pub async fn fetch_and_cache_jwks(
    cache: &Arc<dyn JwksCache>,
    jwks_uri: &str,
    config: &(impl AuthenticationConfigProvider + Send + Sync),
    requested_kid: &str,
) -> Result<jsonwebtoken::jwk::Jwk, OidcError> {
    // Fetch the complete JWKS from the provider
    let response = reqwest::get(jwks_uri)
        .await
        .map_err(|e| OidcError::JwksError(format!("Failed to fetch JWKS: {e}")))?;

    let jwks: JwkSet = response
        .json()
        .await
        .map_err(|e| OidcError::JwksError(format!("Failed to parse JWKS: {e}")))?;

    // Cache each individual JWK key for future use
    let jwks_cache_ttl = config.get_jwks_cache_ttl();
    for jwk in &jwks.keys {
        if let Some(kid) = &jwk.common.key_id {
            let jwk_cache_key = JwkCacheKey::from_jwks_uri_and_kid(jwks_uri, kid);
            if let Ok(serialized) = serde_json::to_string(jwk) {
                cache.set(jwk_cache_key.as_str(), serialized, jwks_cache_ttl);
            }
        }
    }

    // Return the specific JWK requested
    jwks.find(requested_kid)
        .cloned()
        .ok_or_else(|| OidcError::JwksError(format!("No JWK found for kid: {requested_kid}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestClaims {
        sub: String,
        exp: usize,
    }

    #[test]
    fn test_validate_token_with_invalid_jwk() {
        // Create a simple test case that should fail with invalid JWK
        let token = "invalid.token.here";
        let mut jwk = jsonwebtoken::jwk::Jwk::default();
        jwk.common.key_type = Some(jsonwebtoken::jwk::KeyType::RSA);
        
        let result = validate_token_with_jwk::<TestClaims>(token, &jwk, Algorithm::RS256);
        assert!(result.is_err());
    }
}