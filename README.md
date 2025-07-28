# Axum OIDC Layer

[![Crates.io](https://img.shields.io/crates/v/axum-oidc-layer.svg)](https://crates.io/crates/axum-oidc-layer)
[![Documentation](https://docs.rs/axum-oidc-layer/badge.svg)](https://docs.rs/axum-oidc-layer)
[![License](https://img.shields.io/crates/l/axum-oidc-layer.svg)](LICENSE)

A high-performance, configurable OIDC (OpenID Connect) authentication layer for [Axum](https://github.com/tokio-rs/axum) web applications. This crate provides JWT token validation with intelligent caching for optimal performance and supports pluggable cache backends.

## Features

- **Automatic JWT Validation**: Validates JWT tokens against OIDC provider's JWKS
- **Multi-Tier Caching**: 
  - OIDC configuration caching (24h default TTL)
  - Individual JWK key caching by `kid` (1h default TTL)
  - Token validation result caching (based on token expiration)
- **Type-Safe Cache Keys**: Prevents mixing different cache key types
- **Pluggable Cache Backends**: Implement custom strategies (Redis, database, etc.)
- **Configurable TTL**: Control cache lifetimes for different data types
- **Comprehensive Error Handling**: Detailed error types with appropriate HTTP responses
- **Rust Idiomatic**: Zero-cost abstractions with compile-time safety

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
axum-oidc-layer = "0.1"
axum = "0.8"
tokio = { version = "1.0", features = ["full"] }
```

### Basic Usage

```rust
use axum::{routing::get, Router};
use axum_oidc_layer::{OidcAuthenticationLayer, AuthenticationConfigProvider, Claims};
use std::time::Duration;

#[derive(Clone)]
struct AppConfig {
    oidc_provider_url: String,
}

impl AuthenticationConfigProvider for AppConfig {
    fn get_provider_url(&self) -> String {
        self.oidc_provider_url.clone()
    }
    
    fn get_openid_configuration_url(&self) -> Option<String> {
        None // Uses /.well-known/openid-configuration
    }
    
    // Optional: customize cache TTL
    fn get_jwks_cache_ttl(&self) -> Duration {
        Duration::from_secs(3600) // 1 hour
    }
}

async fn protected_handler(claims: Claims) -> String {
    format!("Hello, user {}!", claims.sub)
}

#[tokio::main]
async fn main() {
    let config = AppConfig {
        oidc_provider_url: "https://your-oidc-provider.com".to_string(),
    };

    let app = Router::new()
        .route("/protected", get(protected_handler))
        .layer(OidcAuthenticationLayer::<AppConfig, Claims>::new(config));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### Custom Claims

Define your own claims structure:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CustomClaims {
    sub: String,
    email: String,
    roles: Vec<String>,
    exp: usize,
}

// Use with the layer
let layer = OidcAuthenticationLayer::<AppConfig, CustomClaims>::new(config);
```

### Custom Cache Backend

Implement your own cache (e.g., Redis):

```rust
use axum_oidc_layer::{JwksCache, OidcAuthenticationLayer};
use std::time::Duration;

struct RedisCache {
    client: redis::Client,
}

impl JwksCache for RedisCache {
    fn get(&self, key: &str) -> Option<String> {
        // Your Redis GET implementation
        todo!()
    }
    
    fn set(&self, key: &str, value: String, ttl: Duration) {
        // Your Redis SET with TTL implementation
        todo!()
    }
}

// Use custom cache
let redis_cache = Arc::new(RedisCache::new("redis://localhost"));
let layer = OidcAuthenticationLayer::with_cache(config, redis_cache);
```

## Configuration

### Environment-Based Configuration

```rust
#[derive(Clone)]
struct EnvConfig;

impl AuthenticationConfigProvider for EnvConfig {
    fn get_provider_url(&self) -> String {
        std::env::var("OIDC_PROVIDER_URL")
            .expect("OIDC_PROVIDER_URL must be set")
    }
    
    fn get_openid_configuration_url(&self) -> Option<String> {
        std::env::var("OIDC_CONFIG_URL").ok()
    }
    
    fn get_jwks_cache_ttl(&self) -> Duration {
        Duration::from_secs(
            std::env::var("JWKS_CACHE_TTL")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .unwrap_or(3600)
        )
    }
}
```

### Popular OIDC Providers

<details>
<summary><b>Auth0</b></summary>

```rust
impl AuthenticationConfigProvider for Auth0Config {
    fn get_provider_url(&self) -> String {
        format!("https://{}.auth0.com", self.domain)
    }
    
    fn get_openid_configuration_url(&self) -> Option<String> {
        Some(format!("https://{}.auth0.com/.well-known/openid-configuration", self.domain))
    }
}
```
</details>

<details>
<summary><b>Keycloak</b></summary>

```rust
impl AuthenticationConfigProvider for KeycloakConfig {
    fn get_provider_url(&self) -> String {
        format!("{}/realms/{}", self.base_url, self.realm)
    }
    
    fn get_openid_configuration_url(&self) -> Option<String> {
        Some(format!("{}/realms/{}/.well-known/openid-configuration", 
                    self.base_url, self.realm))
    }
}
```
</details>

<details>
<summary><b>Google</b></summary>

```rust
impl AuthenticationConfigProvider for GoogleConfig {
    fn get_provider_url(&self) -> String {
        "https://accounts.google.com".to_string()
    }
    
    fn get_openid_configuration_url(&self) -> Option<String> {
        Some("https://accounts.google.com/.well-known/openid-configuration".to_string())
    }
}
```
</details>

