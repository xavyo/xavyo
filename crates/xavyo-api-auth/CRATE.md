# xavyo-api-auth

> Authentication API endpoints: login, MFA, sessions, password reset, WebAuthn, passwordless.

## Purpose

Provides REST endpoints for user authentication including registration, login, password reset, email verification, MFA (TOTP/SMS), WebAuthn/FIDO2, passwordless (magic links), and session management. Also exposes shared services and middleware used by other API crates.

## Layer

api

## Status

🟢 **stable**

Production-ready with extensive test coverage (254 tests). Complete authentication stack including MFA, WebAuthn, and passwordless flows.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId, UserId types
- `xavyo-auth` - JWT, password hashing
- `xavyo-db` - User and session models
- `xavyo-tenant` - Multi-tenant middleware
- `xavyo-webhooks` - Event publishing

### External (key)
- `axum` - Web framework
- `webauthn-rs` - WebAuthn/FIDO2 protocol
- `totp-rs` - TOTP code generation/validation
- `lettre` - SMTP email delivery
- `moka` - Async LRU caching

## Public API

### Router

```rust
/// Main authentication router
pub fn auth_router() -> Router<AuthState>;
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | User registration |
| POST | `/auth/login` | Password login |
| POST | `/auth/refresh` | Token refresh |
| POST | `/auth/logout` | Session logout |
| POST | `/auth/forgot-password` | Request password reset |
| POST | `/auth/reset-password` | Complete password reset |
| POST | `/auth/verify-email` | Verify email address |
| POST | `/auth/mfa/setup` | Setup MFA (TOTP) |
| POST | `/auth/mfa/verify` | Verify MFA code |
| POST | `/auth/webauthn/register/start` | Start WebAuthn registration |
| POST | `/auth/webauthn/register/finish` | Complete WebAuthn registration |
| POST | `/auth/webauthn/login/start` | Start WebAuthn login |
| POST | `/auth/webauthn/login/finish` | Complete WebAuthn login |
| POST | `/auth/magic-link/request` | Request passwordless link |
| POST | `/auth/magic-link/verify` | Verify magic link |

### Services (reusable)

```rust
pub struct AuthService { ... }        // Core authentication
pub struct SessionService { ... }     // Session management
pub struct MfaService { ... }         // MFA operations
pub struct WebAuthnService { ... }    // WebAuthn/FIDO2
pub struct TokenService { ... }       // Token generation
pub struct AuditService { ... }       // Security audit logging
pub struct LockoutService { ... }     // Account lockout
pub struct KeyService { ... }         // JWT key rotation
```

### Middleware (reusable)

```rust
/// JWT authentication middleware
pub fn jwt_auth_middleware<S>(state: AuthState) -> impl Layer<S>;

/// API key authentication middleware
pub fn api_key_auth_middleware<S>(state: AuthState) -> impl Layer<S>;

/// Rate limiter middleware
pub struct RateLimiter { ... }
pub struct EmailRateLimiter { ... }
```

## Usage Example

```rust
use xavyo_api_auth::{auth_router, AuthState, AuthService};
use axum::Router;

// Create auth state
let auth_state = AuthState::new(
    pool.clone(),
    jwt_keys,
    email_config,
);

// Build application with auth routes
let app = Router::new()
    .nest("/auth", auth_router())
    .with_state(auth_state);

// Use AuthService directly
let auth_service = AuthService::new(pool.clone(), config);
let user = auth_service.authenticate_password(
    tenant_id,
    "user@example.com",
    "password123",
).await?;
```

## Integration Points

- **Consumed by**: `idp-api` main application
- **Provides**: Shared auth services to `xavyo-api-oauth`, `xavyo-api-social`
- **Emits**: Webhook events for `user.login`, `user.registered`, `mfa.enabled`

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `integration` | Enable integration tests | - |

## Anti-Patterns

- Never expose raw database errors to clients
- Never log passwords or password hashes
- Never skip rate limiting on auth endpoints
- Never return different error messages for valid vs invalid usernames

## Related Crates

- `xavyo-api-oauth` - Uses AuthService for token issuance
- `xavyo-api-social` - Uses AuthService for social account linking
- `xavyo-auth` - Core JWT and password primitives
