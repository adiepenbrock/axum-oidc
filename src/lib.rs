use axum_core::{
    body::Body,
    extract::FromRequestParts,
    response::{IntoResponse, Response},
};
use http::request::Parts;
use reqwest::StatusCode;

pub mod layer;

pub use layer::{InMemoryCache, JwksCache};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Claims {
    pub sub: String,
}

impl<S: Sync> FromRequestParts<S> for Claims {
    type Rejection = AuthenticationError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Claims>()
            .cloned()
            .ok_or(AuthenticationError::InvalidToken)
    }
}

#[derive(Debug, Clone)]
pub enum AuthenticationError {
    InvalidToken,
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
            AuthenticationError::InvalidToken => {
                (StatusCode::UNAUTHORIZED, "Invalid authorization token")
            }
            AuthenticationError::MissingToken => {
                (StatusCode::UNAUTHORIZED, "Missing authorization token")
            }
        };

        Response::builder()
            .status(status)
            .body(Body::from(message))
            .unwrap_or_default()
    }
}

impl std::error::Error for AuthenticationError {}
