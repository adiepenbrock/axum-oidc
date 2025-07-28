//! Axum layer and service implementation for OIDC authentication.

use std::{future::Future, marker::PhantomData, pin::Pin, sync::Arc};

use axum_core::{extract::Request, response::{IntoResponse, Response}};
use serde::de::DeserializeOwned;
use tower::{BoxError, Layer, Service};

use crate::{
    cache::{InMemoryCache, JwksCache},
    config::AuthenticationConfigProvider,
    token::extract_bearer_token,
    validation::{get_oidc_config, validate_and_cache_token},
};

/// A layer that provides `OIDC` authentication for Axum services.
///
/// It extracts the Bearer token from the request headers, validates it against
/// the `OIDC` provider's `JWKS`, and injects the decoded claims into the request
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
    #[must_use]
    pub fn new(config: C) -> Self {
        Self::with_cache(config, Arc::new(InMemoryCache::new()))
    }

    /// Creates a new `OidcAuthenticationLayer` with the given configuration and custom cache implementation.
    #[must_use]
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

/// A service that implements `OIDC` authentication for Axum requests.
///
/// It extracts the Bearer token from the request headers, validates it against
/// the `OIDC` provider's `JWKS`, and injects the decoded claims into the request
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
        // Extract token early and return error if missing
        let token = match extract_bearer_token(&req) {
            Ok(token) => token,
            Err(err) => {
                return Box::pin(async move { Ok(err.into_response()) });
            }
        };

        // Determine the OIDC configuration URL
        let config_url = match self.config.get_openid_configuration_url() {
            Some(url) => url,
            None => format!(
                "{}/.well-known/openid-configuration",
                self.config.get_provider_url()
            ),
        };

        let cache = Arc::clone(&self.cache);
        let config = self.config.clone();
        let inner = self.inner.clone();
        
        Box::pin(async move {
            // Get OIDC configuration from cache or fetch from provider
            let config_doc = match get_oidc_config(&cache, &config_url, &config).await {
                Ok(doc) => doc,
                Err(err) => return Ok(err.into_response()),
            };

            // Validate token and extract claims
            let data: T = match validate_and_cache_token(&cache, &token, &config_doc.jwks_uri, &config).await {
                Ok(claims) => claims,
                Err(err) => return Ok(err.into_response()),
            };

            // Insert validated claims into request extensions
            req.extensions_mut().insert(data);

            // Call the inner service with the authenticated request
            let mut inner = inner;
            inner.call(req).await
        })
    }
}