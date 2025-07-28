use std::{
    collections::HashMap,
    collections::hash_map::DefaultHasher,
    future::Future,
    hash::{Hash, Hasher},
    marker::PhantomData,
    pin::Pin,
    sync::{Arc, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum_core::{body::Body, extract::Request, response::Response};
use base64::Engine;
use jsonwebtoken::{Validation, decode_header, jwk::JwkSet};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use tower::{BoxError, Layer, Service};

/// Creates a cache key from a JWT token by hashing it.
fn create_token_cache_key(token: &str) -> String {
    let mut hasher = DefaultHasher::new();
    token.hash(&mut hasher);
    format!("token:{}", hasher.finish())
}

/// Extracts the expiration time from a JWT token's claims.
/// Returns the duration until expiration, or a default duration if extraction fails.
fn extract_token_ttl(token: &str) -> Duration {
    // Decode without verification to extract the exp claim
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Duration::from_secs(300); // Default 5 minutes
    }

    // Decode the payload (second part)
    let payload = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
        Ok(payload) => payload,
        Err(_) => return Duration::from_secs(300),
    };

    let claims: serde_json::Value = match serde_json::from_slice(&payload) {
        Ok(claims) => claims,
        Err(_) => return Duration::from_secs(300),
    };

    // Extract exp claim (expiration timestamp)
    if let Some(exp) = claims.get("exp").and_then(|v| v.as_u64()) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if exp > now {
            Duration::from_secs(exp - now)
        } else {
            Duration::from_secs(0) // Token already expired
        }
    } else {
        Duration::from_secs(300) // Default 5 minutes if no exp claim
    }
}

/// Trait for caching JWKS keys and OIDC configuration.
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

/// Default in-memory implementation of JwksCache using standard library types.
#[derive(Debug)]
pub struct InMemoryCache {
    storage: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

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
    pub fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Removes expired entries from the cache.
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

        if let Ok(storage) = self.storage.read() {
            storage
                .get(key)
                .filter(|entry| entry.expires_at > Instant::now())
                .map(|entry| entry.data.clone())
        } else {
            None
        }
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

/// Trait for providing OIDC authentication configuration.
pub trait AuthenticationConfigProvider {
    /// Returns the URL of the OIDC provider.
    ///
    /// This URL should be the base URL of the OIDC provider, such as `https://example.com`.
    fn get_provider_url(&self) -> String;
    /// Returns the URL for the OpenID Connect configuration.
    /// If `None`, the default URL will be constructed as `<provider_url>/.well-known/openid-configuration`.
    fn get_openid_configuration_url(&self) -> Option<String>;

    /// Returns the TTL (time-to-live) for JWKS keys in the cache.
    /// Defaults to 1 hour if not implemented.
    fn get_jwks_cache_ttl(&self) -> Duration {
        Duration::from_secs(3600) // 1 hour
    }

    /// Returns the TTL (time-to-live) for OIDC configuration in the cache.
    /// Defaults to 24 hours if not implemented.
    fn get_config_cache_ttl(&self) -> Duration {
        Duration::from_secs(86400) // 24 hours
    }
}

/// A layer that provides OIDC authentication for Axum services.
/// It extracts the Bearer token from the request headers, validates it against
/// the OIDC provider's JWKS, and injects the decoded claims into the request
/// extensions.
///
/// This layer is generic over the configuration type `C` and the type of claims `T`.
/// The configuration type must implement `AuthenticationConfigProvider`, and the
/// claims type `T` must implement `DeserializeOwned`.
#[derive(Clone)]
pub struct OidcAuthenticationLayer<C, T> {
    config: C,
    cache: Arc<dyn JwksCache>,
    _ty: PhantomData<T>,
}

impl<C, T> OidcAuthenticationLayer<C, T>
where
    C: AuthenticationConfigProvider + Clone + Send + Sync + 'static,
{
    /// Creates a new `OidcAuthenticationLayer` with the given configuration and a default in-memory cache.
    pub fn new(config: C) -> Self {
        Self::with_cache(config, Arc::new(InMemoryCache::new()))
    }

    /// Creates a new `OidcAuthenticationLayer` with the given configuration and custom cache implementation.
    pub fn with_cache(config: C, cache: Arc<dyn JwksCache>) -> Self {
        Self {
            config,
            cache,
            _ty: PhantomData,
        }
    }
}

impl<S, C, T> Layer<S> for OidcAuthenticationLayer<C, T>
where
    C: AuthenticationConfigProvider + Clone + Send + Sync + 'static,
{
    type Service = OidcAuthenticationService<S, C, T>;

    fn layer(&self, inner: S) -> Self::Service {
        OidcAuthenticationService {
            inner,
            config: self.config.clone(),
            cache: Arc::clone(&self.cache),
            _ty: self._ty,
        }
    }
}

/// A service that implements OIDC authentication for Axum requests.
/// It extracts the Bearer token from the request headers, validates it against
/// the OIDC provider's JWKS, and injects the decoded claims into the request
/// extensions.
///
/// This service is generic over the inner service `S`, the configuration type `C`,
/// and the type of claims `T`. The configuration type must implement
/// `AuthenticationConfigProvider`, and the claims type `T` must implement `DeserializeOwned`.
#[derive(Clone)]
pub struct OidcAuthenticationService<S, C, T> {
    inner: S,
    config: C,
    cache: Arc<dyn JwksCache>,
    _ty: PhantomData<T>,
}

impl<S, C, T> Service<Request> for OidcAuthenticationService<S, C, T>
where
    S: Service<Request, Response = Response> + Send + 'static + Clone,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
    C: AuthenticationConfigProvider + Clone + Send + Sync + 'static,
    T: DeserializeOwned + serde::Serialize + Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let token = req
            .headers()
            .get("authorization")
            .and_then(|val| val.to_str().ok())
            .and_then(|val| {
                if val.starts_with("Bearer ") {
                    Some(val.trim_start_matches("Bearer ").to_string())
                } else {
                    None
                }
            });

        if token.is_none() {
            return Box::pin(async {
                Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::from(""))
                    .unwrap_or_default())
            });
        }

        let config_url = match self.config.get_openid_configuration_url() {
            Some(url) => url,
            None => {
                format!(
                    "{}/.well-known/openid-configuration",
                    self.config.get_provider_url()
                )
            }
        };

        let cache = Arc::clone(&self.cache);
        let config = self.config.clone();
        let inner = self.inner.clone();
        Box::pin(async move {
            let config_cache_key = format!("config:{}", config_url);
            let config_doc: OidcConfiguration = match cache.get(&config_cache_key) {
                Some(cached_config) => match serde_json::from_str(&cached_config) {
                    Ok(doc) => doc,
                    Err(_) => {
                        return Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::from(""))
                            .unwrap());
                    }
                },
                None => match reqwest::get(&config_url).await {
                    Ok(response) => match response.json::<OidcConfiguration>().await {
                        Ok(doc) => {
                            if let Ok(serialized) = serde_json::to_string(&doc) {
                                cache.set(
                                    &config_cache_key,
                                    serialized,
                                    config.get_config_cache_ttl(),
                                );
                            }
                            doc
                        }
                        Err(_) => {
                            return Ok(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from(""))
                                .unwrap());
                        }
                    },
                    Err(_) => {
                        return Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::from(""))
                            .unwrap());
                    }
                },
            };

            let token_str = token.expect("Bearer token should be present");
            let token_cache_key = create_token_cache_key(&token_str);

            // First check if we have the validated token in cache
            let data: T = match cache.get(&token_cache_key) {
                Some(cached_claims) => match serde_json::from_str(&cached_claims) {
                    Ok(claims) => claims,
                    Err(_) => {
                        return Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::from(""))
                            .unwrap());
                    }
                },
                None => {
                    // Extract kid from token header for individual key lookup
                    let header = match decode_header(&token_str) {
                        Ok(header) => header,
                        Err(_) => {
                            return Ok(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from(""))
                                .unwrap());
                        }
                    };

                    let kid = match header.kid {
                        Some(kid) => kid,
                        None => {
                            return Ok(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from(""))
                                .unwrap());
                        }
                    };

                    // Check if we have this specific JWK key cached
                    let jwk_cache_key = format!("jwk:{}:{}", config_doc.jwks_uri, kid);
                    let jwk = match cache.get(&jwk_cache_key) {
                        Some(cached_jwk) => match serde_json::from_str(&cached_jwk) {
                            Ok(jwk) => jwk,
                            Err(_) => {
                                return Ok(Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Body::from(""))
                                    .unwrap());
                            }
                        },
                        None => {
                            // Cache miss - fetch full JWKS and cache individual keys
                            match fetch_and_cache_jwks(&cache, &config_doc.jwks_uri, &config, &kid)
                                .await
                            {
                                Ok(jwk) => jwk,
                                Err(_) => {
                                    return Ok(Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from(""))
                                        .unwrap());
                                }
                            }
                        }
                    };

                    match validate_token_with_jwk::<T>(&token_str, &jwk, header.alg).await {
                        Ok(validated_claims) => {
                            if let Ok(serialized) = serde_json::to_string(&validated_claims) {
                                let token_ttl = extract_token_ttl(&token_str);
                                cache.set(&token_cache_key, serialized, token_ttl);
                            }
                            validated_claims
                        }
                        Err(_) => {
                            return Ok(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from(""))
                                .unwrap());
                        }
                    }
                }
            };

            req.extensions_mut().insert(data.clone());

            let mut inner = inner;
            inner.call(req).await
        })
    }
}

/// Fetches JWKS from the URI and caches individual JWK keys.
/// Returns the specific JWK for the requested kid.
async fn fetch_and_cache_jwks(
    cache: &Arc<dyn JwksCache>,
    jwks_uri: &str,
    config: &impl AuthenticationConfigProvider,
    requested_kid: &str,
) -> Result<jsonwebtoken::jwk::Jwk, String> {
    let response = reqwest::get(jwks_uri)
        .await
        .map_err(|e| format!("Failed to fetch JWKS: {}", e))?;

    let jwks: JwkSet = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse JWKS: {}", e))?;

    // Cache each individual JWK key
    let jwks_cache_ttl = config.get_jwks_cache_ttl();
    for jwk in &jwks.keys {
        if let Some(kid) = &jwk.common.key_id {
            let jwk_cache_key = format!("jwk:{}:{}", jwks_uri, kid);
            if let Ok(serialized) = serde_json::to_string(jwk) {
                cache.set(&jwk_cache_key, serialized, jwks_cache_ttl);
            }
        }
    }

    // Return the requested JWK
    jwks.find(requested_kid)
        .cloned()
        .ok_or_else(|| format!("No JWK found for kid: {}", requested_kid))
}

/// Validates a token using a specific JWK key.
async fn validate_token_with_jwk<T: DeserializeOwned>(
    token: &str,
    jwk: &jsonwebtoken::jwk::Jwk,
    alg: jsonwebtoken::Algorithm,
) -> Result<T, String> {
    let mut validation = Validation::new(alg);
    validation.validate_aud = false;

    let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk)
        .map_err(|e| format!("Failed to create DecodingKey from JWK: {}", e))?;

    let token_data = jsonwebtoken::decode::<T>(token, &decoding_key, &validation)
        .map_err(|e| format!("JWT validation failed: {}", e))?;

    Ok(token_data.claims)
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct OidcConfiguration {
    pub jwks_uri: String,
}
