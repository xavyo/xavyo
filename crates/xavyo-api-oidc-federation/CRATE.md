# xavyo-api-oidc-federation

> OIDC federation API: enterprise IdP integration as relying party.

## Purpose

Implements OpenID Connect relying party (RP) functionality for federating with enterprise identity providers. Supports discovery, PKCE, encrypted token storage, and automatic account linking for B2B scenarios.

## Layer

api

## Status

🟡 **beta**

Functional with limited test coverage (13 tests). Core OIDC RP flows working; needs more IdP interoperability testing.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId types
- `xavyo-db` - IdP configuration models
- `xavyo-auth` - JWT handling
- `xavyo-tenant` - Multi-tenant middleware

### External (key)
- `axum` - Web framework
- `reqwest` - HTTP client
- `aes-gcm` - Token encryption

## Public API

### Routers

```rust
pub fn oidc_federation_router() -> Router<OidcFedState>;
pub fn oidc_admin_router() -> Router<OidcFedState>;
```

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/federation/:provider_id/authorize` | Start federation |
| GET | `/federation/:provider_id/callback` | Federation callback |
| GET | `/admin/federation/providers` | List providers |
| POST | `/admin/federation/providers` | Create provider |
| GET | `/admin/federation/providers/:id` | Get provider |
| PATCH | `/admin/federation/providers/:id` | Update provider |
| DELETE | `/admin/federation/providers/:id` | Delete provider |
| POST | `/admin/federation/providers/:id/discover` | Auto-discover config |

## Usage Example

```rust
use xavyo_api_oidc_federation::{oidc_federation_router, OidcFedState};
use axum::Router;

let state = OidcFedState::new(pool.clone(), encryption_key);

let app = Router::new()
    .nest("/federation", oidc_federation_router())
    .with_state(state);
```

## Integration Points

- **Consumed by**: `idp-api` main application
- **Federates with**: Okta, Azure AD, Ping Identity, etc.

## Feature Flags

None

## Anti-Patterns

- Never skip issuer validation
- Never store tokens unencrypted
- Never trust claims without verification

## Related Crates

- `xavyo-api-oauth` - xavyo as OIDC provider
- `xavyo-api-social` - Consumer social login
