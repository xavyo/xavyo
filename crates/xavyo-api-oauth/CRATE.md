# xavyo-api-oauth

> OAuth2/OIDC provider endpoints: authorize, token, userinfo, device code, discovery.

## Purpose

Implements OAuth2 and OpenID Connect provider functionality. Supports authorization code flow with PKCE, client credentials grant, refresh tokens, and RFC 8628 device code flow. Provides OIDC discovery (`.well-known/openid-configuration`) and JWKS endpoints for key distribution.

## Layer

api

## Status

🟢 **stable**

Production-ready with comprehensive test coverage (201 tests). Complete OAuth2/OIDC provider with PKCE, device code, and token revocation.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId, UserId types
- `xavyo-auth` - JWT encoding/decoding
- `xavyo-api-auth` - Shared auth services
- `xavyo-db` - OAuth client and token models
- `xavyo-tenant` - Multi-tenant middleware
- `xavyo-webhooks` - Event publishing

### External (key)
- `axum` - Web framework
- `jsonwebtoken` - JWT encoding
- `rsa` - RSA key handling
- `subtle` - Constant-time comparison

## Public API

### Routers

```rust
/// Main OAuth2 router
pub fn oauth_router() -> Router<OAuthState>;

/// Device code verification router
pub fn device_router() -> Router<OAuthState>;

/// OIDC discovery router
pub fn well_known_router() -> Router<OAuthState>;
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/oauth/authorize` | Authorization endpoint |
| POST | `/oauth/token` | Token endpoint |
| GET | `/oauth/userinfo` | UserInfo endpoint |
| POST | `/oauth/revoke` | Token revocation |
| POST | `/oauth/introspect` | Token introspection |
| POST | `/oauth/device/code` | Device authorization (RFC 8628) |
| GET | `/device/verify` | Device verification page |
| POST | `/device/authorize` | Device authorization decision |
| GET | `/.well-known/openid-configuration` | OIDC Discovery |
| GET | `/.well-known/jwks.json` | JSON Web Key Set |

### Types

```rust
/// OAuth2 state container
pub struct OAuthState {
    pub pool: PgPool,
    pub signing_key: OAuthSigningKey,
    pub issuer: String,
}

/// JWT signing key configuration
pub struct OAuthSigningKey {
    pub kid: String,
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
}
```

### Utilities

```rust
/// Session cookie management
pub fn create_session_cookie(session_id: &str) -> Cookie;
pub fn extract_session_cookie(jar: &CookieJar) -> Option<String>;
pub fn set_session_cookie(jar: &CookieJar, session_id: &str);
pub fn clear_session_cookie(jar: &CookieJar);

/// Request utilities
pub fn extract_origin_ip(headers: &HeaderMap) -> Option<IpAddr>;
pub fn extract_country_code(headers: &HeaderMap) -> Option<String>;
```

## Usage Example

```rust
use xavyo_api_oauth::{oauth_router, well_known_router, OAuthState, OAuthSigningKey};
use axum::Router;

// Generate or load signing key
let signing_key = OAuthSigningKey::generate()?;

// Create OAuth state
let oauth_state = OAuthState {
    pool: pool.clone(),
    signing_key,
    issuer: "https://auth.example.com".to_string(),
};

// Build application
let app = Router::new()
    .nest("/oauth", oauth_router())
    .merge(well_known_router())
    .with_state(oauth_state);

// OAuth flow:
// 1. Client redirects to /oauth/authorize?client_id=...&redirect_uri=...&scope=openid
// 2. User authenticates and consents
// 3. Redirect back with authorization code
// 4. Client exchanges code at POST /oauth/token
// 5. Client receives access_token, id_token, refresh_token
```

## Integration Points

- **Consumed by**: `idp-api` main application
- **Uses**: `xavyo-api-auth::AuthService` for user authentication
- **Provides**: OIDC tokens for federated applications

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `integration` | Enable integration tests | - |

## Anti-Patterns

- Never expose client secrets in responses
- Never allow redirect URIs that aren't pre-registered
- Never skip PKCE validation for public clients
- Never issue tokens without proper scope validation

## Related Crates

- `xavyo-api-auth` - User authentication services
- `xavyo-api-oidc-federation` - OIDC as relying party (inbound)
- `xavyo-auth` - JWT primitives
