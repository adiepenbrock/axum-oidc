//! Axum OIDC Authentication Layer
//!
//! This crate provides a configurable OIDC (OpenID Connect) authentication layer for Axum applications.
//! It supports JWT token validation with caching for improved performance and includes pluggable cache backends.
//!
//! # Features
//!
//! - **Automatic Token Validation**: Validates JWT tokens against OIDC provider's JWKS
//! - **Multi-tier Caching**: Caches OIDC configuration, individual JWK keys, and token validation results
//! - **Type-safe Cache Keys**: Prevents mixing different cache key types
//! - **Pluggable Cache Backends**: Implement custom cache strategies (Redis, database, etc.)
//! - **Configurable TTL**: Control cache lifetimes for different data types
//! - **Proper Error Handling**: Comprehensive error types with appropriate HTTP responses
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use axum_oidc_layer::{OidcAuthenticationLayer, AuthenticationConfigProvider, Claims};
//! use std::time::Duration;
//!
//! #[derive(Clone)]
//! struct MyConfig;
//!
//! impl AuthenticationConfigProvider for MyConfig {
//!     fn get_provider_url(&self) -> String {
//!         "https://your-oidc-provider.com".to_string()
//!     }
//!     
//!     fn get_openid_configuration_url(&self) -> Option<String> {
//!         None // Uses default /.well-known/openid-configuration
//!     }
//! }
//!
//! let layer = OidcAuthenticationLayer::<MyConfig, Claims>::new(MyConfig);
//! ```

use axum_core::{
    extract::FromRequestParts,
    response::{IntoResponse, Response},
};
use http::request::Parts;
use reqwest::StatusCode;

// Module declarations
pub mod cache;
pub mod config;
pub mod error;
pub mod jwks;
pub mod layer;
pub mod token;
pub mod validation;

// Public re-exports for convenience
pub use cache::{ConfigCacheKey, InMemoryCache, JwkCacheKey, JwksCache, TokenCacheKey};
pub use config::{AuthenticationConfigProvider, OidcConfiguration};
pub use error::OidcError;
pub use layer::{OidcAuthenticationLayer, OidcAuthenticationService};

/// Default JWT claims structure.
///
/// This provides a basic claims structure that can be used out-of-the-box.
/// For custom claims, implement your own struct that derives `serde::Deserialize` and `serde::Serialize`.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Claims {
    /// Subject (user identifier)
    pub sub: String,
}

impl<S: Sync> FromRequestParts<S> for Claims {
    type Rejection = AuthenticationError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(AuthenticationError::InvalidToken)
    }
}

/// Legacy authentication error type for backward compatibility.
///
/// For new code, prefer using `OidcError` directly.
#[derive(Debug, Clone)]
pub enum AuthenticationError {
    /// Token is invalid or malformed
    InvalidToken,
    /// Authorization header is missing
    MissingToken,
}

impl std::fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidToken => write!(f, "Invalid token"),
            Self::MissingToken => write!(f, "Missing token"),
        }
    }
}

impl IntoResponse for AuthenticationError {
    fn into_response(self) -> axum_core::response::Response {
        let (status, message) = match self {
            Self::InvalidToken => {
                (StatusCode::UNAUTHORIZED, "Invalid authorization token")
            }
            Self::MissingToken => {
                (StatusCode::UNAUTHORIZED, "Missing authorization token")
            }
        };

        Response::builder()
            .status(status)
            .body(axum_core::body::Body::from(message))
            .unwrap_or_default()
    }
}

impl std::error::Error for AuthenticationError {}