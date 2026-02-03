# xavyo-api-oidc-federation

> OIDC federation API: enterprise IdP integration as relying party.

## Purpose

Implements OpenID Connect relying party (RP) functionality for federating with enterprise identity providers. Supports discovery, PKCE, encrypted token storage, automatic account linking for B2B scenarios, and proper JWT issuance with RS256 signatures.

## Layer

api

## Status

🟡 **beta**

Functional with comprehensive test coverage (37 tests). Core OIDC RP flows working with JWT integration. Includes JWKS caching and token verification.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId types
- `xavyo-db` - IdP configuration models
- `xavyo-auth` - JWT encoding/decoding with RS256
- `xavyo-tenant` - Multi-tenant middleware

### External (key)
- `axum` - Web framework
- `reqwest` - HTTP client for JWKS fetching
- `aes-gcm` - Token encryption
- `jsonwebtoken` - JWT parsing (via xavyo-auth)

## Public API

### Services (F-045)

```rust
// Token issuance with RS256 signing
pub struct TokenIssuerService { ... }
pub struct TokenIssuerConfig { ... }
pub struct IssuedTokens { access_token, expires_in, refresh_token, token_type }

// Token verification with JWKS
pub struct TokenVerifierService { ... }
pub struct VerificationConfig { ... }
pub struct VerifiedToken { claims, kid, issuer }

// JWKS caching
pub struct JwksCache { ... }
```

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
use xavyo_api_oidc_federation::{
    TokenIssuerService, TokenIssuerConfig,
    TokenVerifierService, VerificationConfig,
    JwksCache,
};
use uuid::Uuid;

// Configure token issuer with private key
let config = TokenIssuerConfig {
    private_key_pem: include_bytes!("keys/private_key.pem").to_vec(),
    access_token_ttl: 900,  // 15 minutes
    refresh_token_ttl: 604800,  // 7 days
    issuer: "https://auth.example.com".to_string(),
    audience: vec!["https://api.example.com".to_string()],
};

let issuer = TokenIssuerService::new(config);

// Issue tokens after successful federation
let tokens = issuer.issue_tokens(
    user_id,
    tenant_id,
    vec!["user".to_string()],
    None,  // Optional federation claims
).await?;

// Verify tokens from federated IdPs
let verifier = TokenVerifierService::new(
    VerificationConfig::default().issuer("https://idp.example.com")
);

let verified = verifier.verify_token(
    &idp_token,
    "https://idp.example.com/.well-known/jwks.json"
).await?;
```

## Integration Points

- **Consumed by**: `idp-api` main application
- **Federates with**: Okta, Azure AD, Ping Identity, Google Workspace, etc.
- **Uses**: `xavyo-auth` for JWT encoding/decoding

## Feature Flags

None

## Anti-Patterns

- Never skip issuer validation
- Never store tokens unencrypted
- Never trust claims without verification
- Never use default/empty private keys in production

## Related Crates

- `xavyo-api-oauth` - xavyo as OIDC provider
- `xavyo-api-social` - Consumer social login
- `xavyo-auth` - JWT infrastructure
