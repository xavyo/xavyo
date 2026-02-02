# xavyo-api-social

> Social login API for Google, Microsoft, and Apple identity providers.

## Purpose

Implements social authentication flows for consumer identity scenarios. Supports Google, Microsoft (Azure AD), and Apple Sign In via OAuth2/OIDC. Includes account linking, CSRF protection with signed JWT state, PKCE support, and encrypted token storage.

## Layer

api

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId, UserId types
- `xavyo-db` - Social connection models
- `xavyo-auth` - JWT, session handling
- `xavyo-tenant` - Multi-tenant middleware

### External (key)
- `axum` - Web framework
- `reqwest` - HTTP client for OAuth2 flows
- `aes-gcm` - Token encryption
- `jsonwebtoken` - JWT state tokens

## Public API

### Routers

```rust
/// Social login router
pub fn social_router() -> Router<SocialState>;

/// Public endpoints (OAuth callbacks)
pub fn public_social_router() -> Router<SocialState>;

/// Authenticated user operations
pub fn authenticated_social_router() -> Router<SocialState>;

/// Admin configuration
pub fn admin_social_router() -> Router<SocialState>;
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/social/providers` | List enabled providers |
| GET | `/social/:provider/authorize` | Start OAuth flow |
| GET | `/social/:provider/callback` | OAuth callback |
| GET | `/social/connections` | List user's connected accounts |
| POST | `/social/:provider/link` | Link social account |
| DELETE | `/social/:provider/unlink` | Unlink social account |
| GET | `/admin/social/providers` | List provider configs |
| POST | `/admin/social/providers` | Create provider config |
| PATCH | `/admin/social/providers/:id` | Update provider config |
| DELETE | `/admin/social/providers/:id` | Delete provider config |

### Types

```rust
/// Supported social providers
pub enum ProviderType {
    Google,
    Microsoft,
    Apple,
}

/// Social state container
pub struct SocialState {
    pub pool: PgPool,
    pub providers: HashMap<ProviderType, ProviderConfig>,
    pub encryption_key: [u8; 32],
}

/// Social configuration
pub struct SocialConfig {
    pub google: Option<ProviderConfig>,
    pub microsoft: Option<ProviderConfig>,
    pub apple: Option<ProviderConfig>,
}

/// Provider configuration (per tenant)
pub struct ProviderConfig {
    pub client_id: String,
    pub client_secret: SecretString,
    pub scopes: Vec<String>,
    pub enabled: bool,
}

/// Authentication service for social flows
pub struct AuthService { ... }

/// Social errors
pub enum SocialError {
    ProviderNotConfigured(ProviderType),
    OAuthError(String),
    AccountAlreadyLinked,
    InvalidState,
    TokenExchangeFailed(String),
}
```

## Usage Example

```rust
use xavyo_api_social::{social_router, SocialState, SocialConfig, ProviderType};
use axum::Router;

// Configure social providers
let config = SocialConfig {
    google: Some(ProviderConfig {
        client_id: "google-client-id".to_string(),
        client_secret: "google-secret".into(),
        scopes: vec!["openid", "email", "profile"].into_iter().map(String::from).collect(),
        enabled: true,
    }),
    microsoft: Some(ProviderConfig {
        client_id: "ms-client-id".to_string(),
        client_secret: "ms-secret".into(),
        scopes: vec!["openid", "email", "profile"].into_iter().map(String::from).collect(),
        enabled: true,
    }),
    apple: None, // Not configured
};

// Create state
let social_state = SocialState::new(pool.clone(), config, &encryption_key);

// Build application
let app = Router::new()
    .nest("/social", social_router())
    .with_state(social_state);

// Social login flow:
// 1. Frontend calls GET /social/google/authorize
// 2. Backend redirects to Google with CSRF state
// 3. User authenticates at Google
// 4. Google redirects to GET /social/google/callback?code=...&state=...
// 5. Backend exchanges code for tokens, creates/links user, returns JWT
```

## Integration Points

- **Consumed by**: `idp-api` main application
- **Calls**: Google OAuth, Microsoft Graph, Apple ID APIs
- **Uses**: `xavyo-api-auth` services for user creation

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `integration` | Enable integration tests | - |

## Anti-Patterns

- Never store OAuth tokens unencrypted
- Never skip state parameter validation (CSRF)
- Never trust provider claims without verification
- Never allow automatic account linking without consent

## Related Crates

- `xavyo-api-auth` - Core authentication
- `xavyo-api-oidc-federation` - Enterprise OIDC federation
- `xavyo-api-oauth` - xavyo as OAuth provider
