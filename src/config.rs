//! Configuration types and traits for OIDC authentication.

use std::time::Duration;

/// Default TTL for token validation results (5 minutes)
pub const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(300);
/// Default TTL for JWKS keys (1 hour) 
pub const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(3600);
/// Default TTL for OIDC configuration (24 hours)
pub const DEFAULT_CONFIG_TTL: Duration = Duration::from_secs(86400);

/// Trait for providing `OIDC` authentication configuration.
pub trait AuthenticationConfigProvider {
    /// Returns the URL of the `OIDC` provider.
    ///
    /// This URL should be the base URL of the `OIDC` provider, such as `https://example.com`.
    fn get_provider_url(&self) -> String;
    
    /// Returns the URL for the `OpenID` Connect configuration.
    /// If `None`, the default URL will be constructed as `<provider_url>/.well-known/openid-configuration`.
    fn get_openid_configuration_url(&self) -> Option<String>;

    /// Returns the TTL (time-to-live) for `JWKS` keys in the cache.
    /// Defaults to 1 hour if not implemented.
    fn get_jwks_cache_ttl(&self) -> Duration {
        DEFAULT_JWKS_TTL
    }

    /// Returns the TTL (time-to-live) for `OIDC` configuration in the cache.
    /// Defaults to 24 hours if not implemented.
    fn get_config_cache_ttl(&self) -> Duration {
        DEFAULT_CONFIG_TTL
    }
}

/// OIDC provider configuration document.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct OidcConfiguration {
    /// URI where the JWKS can be retrieved.
    pub jwks_uri: String,
}