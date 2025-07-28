//! JWT token handling and parsing utilities.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum_core::extract::Request;
use base64::Engine;

use crate::{config::DEFAULT_TOKEN_TTL, error::OidcError};

/// Extracts Bearer token from the Authorization header.
///
/// This function looks for the "Authorization" header and extracts the token
/// from a "Bearer \<token\>" format. Returns an error if the header is missing
/// or doesn't follow the expected format.
pub fn extract_bearer_token(req: &Request) -> Result<String, OidcError> {
    req.headers()
        .get("authorization")
        .and_then(|val| val.to_str().ok())
        .and_then(|val| {
            if val.starts_with("Bearer ") {
                Some(val.trim_start_matches("Bearer ").to_string())
            } else {
                None
            }
        })
        .ok_or(OidcError::MissingToken)
}

/// Extracts the expiration time from a JWT token's claims.
///
/// This function decodes the JWT payload (without signature verification)
/// to extract the `exp` claim and calculate the remaining time until expiration.
/// Returns a default duration if extraction fails or the token is already expired.
pub fn extract_token_ttl(token: &str) -> Duration {
    // Decode without verification to extract the exp claim
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return DEFAULT_TOKEN_TTL;
    }

    // Decode the payload (second part)
    let Ok(payload) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) else {
        return DEFAULT_TOKEN_TTL;
    };

    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&payload) else {
        return DEFAULT_TOKEN_TTL;
    };

    // Extract exp claim (expiration timestamp)
    claims.get("exp").and_then(serde_json::Value::as_u64).map_or_else(
        || DEFAULT_TOKEN_TTL,
        |exp| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if exp > now {
                Duration::from_secs(exp - now)
            } else {
                Duration::from_secs(0) // Token already expired
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_core::body::Body;
    use http::{HeaderMap, HeaderValue};

    #[test]
    fn test_extract_bearer_token_success() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer test-token"));
        
        let req = Request::builder()
            .body(Body::empty())
            .unwrap()
            .into_parts().0;
        
        let mut req = Request::from_parts(req, Body::empty());
        *req.headers_mut() = headers;
        
        let result = extract_bearer_token(&req);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test-token");
    }

    #[test]
    fn test_extract_bearer_token_missing() {
        let req = Request::builder()
            .body(Body::empty())
            .unwrap();
        
        let result = extract_bearer_token(&req);
        assert!(matches!(result, Err(OidcError::MissingToken)));
    }

    #[test]
    fn test_extract_token_ttl_invalid_format() {
        let result = extract_token_ttl("invalid-token");
        assert_eq!(result, DEFAULT_TOKEN_TTL);
    }
}