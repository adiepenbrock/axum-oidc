//! Error types for OIDC authentication.

use axum_core::{body::Body, response::{IntoResponse, Response}};
use reqwest::StatusCode;

/// Errors that can occur during OIDC authentication
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("Invalid JWT token: {0}")]
    InvalidToken(String),
    #[error("Missing authorization header")]
    MissingToken,
    #[error("JWT header missing 'kid' field")]
    MissingKid,
    #[error("OIDC configuration error: {0}")]
    ConfigurationError(String),
    #[error("JWKS fetch error: {0}")]
    JwksError(String),
    #[error("Token validation error: {0}")]
    ValidationError(String),
    #[error("Cache error: {0}")]
    CacheError(String),
}

impl IntoResponse for OidcError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::InvalidToken(_) | Self::ValidationError(_) => {
                (StatusCode::UNAUTHORIZED, "Invalid authorization token")
            }
            Self::MissingToken | Self::MissingKid => {
                (StatusCode::UNAUTHORIZED, "Missing or invalid authorization token")
            }
            Self::ConfigurationError(_) | Self::JwksError(_) | Self::CacheError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Authentication service error")
            }
        };

        Response::builder()
            .status(status)
            .body(Body::from(message))
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap()
            })
    }
}