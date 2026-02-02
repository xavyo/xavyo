# xavyo-auth

> JWT RS256 authentication, JWKS key rotation, and Argon2id password hashing.

## Purpose

Provides authentication primitives for the xavyo platform. This includes JWT token encoding/decoding with RS256, JWKS endpoint fetching for key rotation, and secure password hashing using Argon2id with OWASP-recommended parameters. JWT claims include standard fields plus custom tenant and role claims.

## Layer

foundation

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId for JWT claims

### External (key)
- `jsonwebtoken` - JWT encoding/decoding
- `argon2` - Password hashing (Argon2id)
- `reqwest` - HTTP client for JWKS fetching
- `chrono` - Timestamp handling

## Public API

### Types

```rust
/// JWT claims with standard and custom fields
pub struct JwtClaims {
    pub sub: String,           // Subject (user ID)
    pub iss: String,           // Issuer
    pub aud: Vec<String>,      // Audience
    pub exp: i64,              // Expiration timestamp
    pub iat: i64,              // Issued at
    pub jti: String,           // JWT ID (unique)
    pub tid: Option<TenantId>, // Tenant ID (custom)
    pub roles: Vec<String>,    // User roles (custom)
}

/// Builder for creating JwtClaims
pub struct JwtClaimsBuilder { ... }

/// JWKS key set for key rotation
pub struct JwkSet { ... }

/// Client for fetching JWKS from remote endpoints
pub struct JwksClient { ... }

/// Configuration for token validation
pub struct ValidationConfig { ... }

/// Password hasher with configurable parameters
pub struct PasswordHasher { ... }

/// Authentication errors
pub enum AuthError { ... }
```

### Traits

None exported.

### Functions

```rust
/// Encode claims into a signed JWT token
pub fn encode_token(claims: &JwtClaims, private_key_pem: &str) -> Result<String, AuthError>;

/// Encode with specific key ID for key rotation
pub fn encode_token_with_kid(claims: &JwtClaims, private_key_pem: &str, kid: &str) -> Result<String, AuthError>;

/// Decode and validate a JWT token
pub fn decode_token(token: &str, public_key_pem: &str) -> Result<JwtClaims, AuthError>;

/// Decode with custom validation config
pub fn decode_token_with_config(token: &str, public_key_pem: &str, config: &ValidationConfig) -> Result<JwtClaims, AuthError>;

/// Extract key ID from token header
pub fn extract_kid(token: &str) -> Result<Option<String>, AuthError>;

/// Hash a password using Argon2id
pub fn hash_password(password: &str) -> Result<String, AuthError>;

/// Verify a password against its hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthError>;
```

## Usage Example

```rust
use xavyo_auth::{JwtClaims, encode_token, decode_token, hash_password, verify_password};
use xavyo_core::TenantId;

// Create JWT claims
let claims = JwtClaims::builder()
    .subject("user-123")
    .issuer("xavyo")
    .audience(vec!["xavyo-api"])
    .tenant_id(TenantId::new())
    .roles(vec!["admin"])
    .expires_in_secs(3600)
    .build();

// Encode token
let token = encode_token(&claims, PRIVATE_KEY_PEM)?;

// Decode and validate token
let decoded = decode_token(&token, PUBLIC_KEY_PEM)?;
let tenant_id = decoded.tenant_id().ok_or("missing tenant")?;

// Password hashing
let hash = hash_password("my-secure-password")?;
let is_valid = verify_password("my-secure-password", &hash)?;
```

## Integration Points

- **Consumed by**: `xavyo-api-auth`, `xavyo-api-oauth`, all API crates
- **Provides**: JWT validation for Axum middleware
- **Requires**: RSA key pair for RS256 signing

## Feature Flags

None - all features are enabled by default.

## Anti-Patterns

- Never store private keys in code or environment variables in plaintext
- Never disable token expiration validation in production
- Never use weak passwords (enforce minimum complexity)
- Never log JWT tokens or password hashes

## Related Crates

- `xavyo-api-auth` - REST endpoints for authentication
- `xavyo-api-oauth` - OAuth2/OIDC token issuance
- `xavyo-secrets` - Secure key storage
