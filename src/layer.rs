use std::{future::Future, marker::PhantomData, pin::Pin};

use axum_core::{body::Body, extract::Request, response::Response};
use jsonwebtoken::{Validation, decode_header, jwk::JwkSet};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use tower::{BoxError, Layer, Service};

/// Trait for providing OIDC authentication configuration.
pub trait AuthenticationConfigProvider {
    /// Returns the URL of the OIDC provider.
    ///
    /// This URL should be the base URL of the OIDC provider, such as `https://example.com`.
    fn get_provider_url(&self) -> String;
    /// Returns the URL for the OpenID Connect configuration.
    /// If `None`, the default URL will be constructed as `<provider_url>/.well-known/openid-configuration`.
    fn get_openid_configuration_url(&self) -> Option<String>;
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
    _ty: PhantomData<T>,
}

impl<C, T> OidcAuthenticationLayer<C, T>
where
    C: AuthenticationConfigProvider + Clone + Send + Sync + 'static,
{
    /// Creates a new `OidcAuthenticationLayer` with the given configuration.
    pub fn new(config: C) -> Self {
        Self {
            config,
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
    _ty: PhantomData<T>,
}

impl<S, C, T> Service<Request> for OidcAuthenticationService<S, C, T>
where
    S: Service<Request, Response = Response> + Send + 'static + Clone,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
    C: AuthenticationConfigProvider + Clone + Send + Sync + 'static,
    T: DeserializeOwned + Clone + Send + Sync + 'static,
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

        let inner = self.inner.clone();
        Box::pin(async move {
            let config_doc: OidcConfiguration = match reqwest::get(&config_url).await {
                Ok(response) => match response.json::<OidcConfiguration>().await {
                    Ok(doc) => doc,
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
            };

            let jwks = reqwest::get(&config_doc.jwks_uri).await;
            let jwks = match jwks {
                Ok(response) => match response.json::<JwkSet>().await {
                    Ok(jwks) => jwks,
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
            };

            let data =
                match validate_token::<T>(&token.expect("Bearer token should be present"), &jwks)
                    .await
                {
                    Ok(data) => data,
                    Err(_) => {
                        return Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::from(""))
                            .unwrap());
                    }
                };

            req.extensions_mut().insert(data.clone());

            let mut inner = inner;
            inner.call(req).await
        })
    }
}

async fn validate_token<T: DeserializeOwned>(token: &str, jwks: &JwkSet) -> Result<T, String> {
    let header = decode_header(token).map_err(|e| format!("Failed to decode JWT header: {}", e))?;

    let kid = header.kid.ok_or("JWT header missing 'kid' field")?;
    let jwk = jwks.find(&kid).ok_or("No matching JWK found for 'kid'")?;

    let mut validation = Validation::new(header.alg);
    validation.validate_aud = false;

    let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk)
        .map_err(|e| format!("Failed to create DecodingKey from JWK: {}", e))?;

    let token_data = jsonwebtoken::decode::<T>(token, &decoding_key, &validation)
        .map_err(|e| format!("JWT validation failed: {}", e))?;

    let claims = token_data.claims;
    Ok(claims)
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct OidcConfiguration {
    pub jwks_uri: String,
}
