# xavyo-api-saml

> SAML 2.0 Identity Provider endpoints for enterprise SSO.

## Purpose

Implements SAML 2.0 Identity Provider functionality for enterprise single sign-on. Supports SP-initiated SSO (receiving AuthnRequest), IdP-initiated SSO (unsolicited responses), metadata publishing, service provider configuration, certificate management, and **AuthnRequest session tracking for replay attack prevention**.

## Layer

api

## Status

🟡 **beta**

Functional with comprehensive security test coverage (52 tests). Has 2 remaining TODOs; needs SP interoperability testing.

### Test Coverage

| Test Suite | Count | Description |
|------------|-------|-------------|
| Unit tests | 24 | Core service tests |
| Security tests | 28 | Session storage, expiration, replay attack prevention |
| **Total** | **52** | Full coverage for session security |

### Security Features (F-038)

- **Replay Attack Prevention**: AuthnRequest IDs tracked with single-use enforcement
- **TTL Expiration**: 5-minute default with 30-second grace period for clock skew
- **Tenant Isolation**: Request sessions scoped to tenant via RLS
- **InResponseTo Validation**: SAML responses validated against stored request IDs

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId, UserId types
- `xavyo-db` - SP configuration models
- `xavyo-auth` - User authentication
- `xavyo-tenant` - Multi-tenant middleware

### External (key)
- `samael` - SAML 2.0 protocol library
- `openssl` - Certificate/signature handling
- `axum` - Web framework
- `quick-xml` - XML parsing
- `base64` / `flate2` - Encoding/compression
- `async-trait` - Async trait support

## Public API

### Routers

```rust
/// SAML IdP router (SSO endpoints)
pub fn saml_router() -> Router<SamlState>;

/// Public SAML endpoints (metadata, SSO)
pub fn saml_public_router() -> Router<SamlState>;

/// Admin SAML endpoints (SP configuration)
pub fn saml_admin_router() -> Router<SamlState>;
```

### Session Management

```rust
/// Session store trait for AuthnRequest tracking
pub trait SessionStore: Send + Sync {
    /// Store a new AuthnRequest session
    async fn store(&self, session: AuthnRequestSession) -> Result<(), SessionError>;

    /// Validate and consume a session atomically
    async fn validate_and_consume(
        &self,
        tenant_id: Uuid,
        request_id: &str,
    ) -> Result<AuthnRequestSession, SessionError>;

    /// Clean up expired sessions
    async fn cleanup_expired(&self) -> Result<u64, SessionError>;
}

/// In-memory session store (for testing)
pub struct InMemorySessionStore;

/// PostgreSQL-backed session store (for production)
pub struct PostgresSessionStore;

/// AuthnRequest session for replay prevention
pub struct AuthnRequestSession {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub request_id: String,
    pub sp_entity_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub relay_state: Option<String>,
}
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/saml/metadata` | IdP metadata (XML) |
| GET | `/saml/sso` | SP-initiated SSO (redirect binding) |
| POST | `/saml/sso` | SP-initiated SSO (POST binding) |
| GET | `/saml/idp-init/:sp_id` | IdP-initiated SSO |
| POST | `/saml/slo` | Single Logout |
| GET | `/admin/saml/sp` | List service providers |
| POST | `/admin/saml/sp` | Register service provider |
| GET | `/admin/saml/sp/:id` | Get SP configuration |
| PATCH | `/admin/saml/sp/:id` | Update SP configuration |
| DELETE | `/admin/saml/sp/:id` | Delete SP |
| POST | `/admin/saml/sp/:id/certificate` | Upload SP certificate |

### Types

```rust
/// SAML state container
pub struct SamlState {
    pub pool: PgPool,
    pub idp_certificate: X509,
    pub idp_private_key: PKey,
    pub entity_id: String,
}

/// Create SAML state
pub fn create_saml_state(pool: PgPool, config: SamlConfig) -> Result<SamlState>;

/// Service Provider configuration
pub struct ServiceProvider {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub entity_id: String,
    pub name: String,
    pub acs_url: String,
    pub slo_url: Option<String>,
    pub certificate: Option<String>,
    pub name_id_format: NameIdFormat,
    pub attribute_mappings: Vec<AttributeMapping>,
}

/// SAML errors
pub enum SamlError {
    InvalidRequest(String),
    InvalidSignature,
    UnknownServiceProvider(String),
    AuthenticationFailed,
    CertificateError(String),
    SessionError(SessionError),  // NEW: Session-related errors
}

/// Session-related errors
pub enum SessionError {
    NotFound(String),
    Expired { request_id: String, expired_at: DateTime<Utc> },
    AlreadyConsumed { request_id: String, consumed_at: DateTime<Utc> },
    DuplicateRequestId(String),
    StorageError(String),
}
```

## Usage Example

```rust
use xavyo_api_saml::{saml_router, saml_admin_router, create_saml_state, SamlConfig};
use axum::Router;

// Load IdP certificate and key
let config = SamlConfig {
    certificate_pem: std::fs::read_to_string("idp.crt")?,
    private_key_pem: std::fs::read_to_string("idp.key")?,
    entity_id: "https://auth.example.com/saml".to_string(),
};

// Create SAML state
let saml_state = create_saml_state(pool.clone(), config)?;

// Build application
let app = Router::new()
    .nest("/saml", saml_router())
    .nest("/admin/saml", saml_admin_router())
    .with_state(saml_state);

// SAML flow:
// 1. User accesses SP (e.g., Salesforce)
// 2. SP redirects to /saml/sso?SAMLRequest=...
// 3. IdP stores AuthnRequest ID for replay prevention
// 4. User authenticates at IdP
// 5. IdP validates session, marks as consumed
// 6. IdP POSTs SAMLResponse to SP's ACS URL with InResponseTo
// 7. SP validates response and creates session
```

## Integration Points

- **Consumed by**: `idp-api` main application
- **Integrates with**: Salesforce, ServiceNow, Workday, custom SPs
- **Uses**: `xavyo-api-auth` for user authentication

## Feature Flags

None - all features are enabled by default.

## Anti-Patterns

- Never accept unsigned AuthnRequests in production
- Never skip certificate validation for SP responses
- Never use weak signing algorithms (SHA-1)
- Never expose private keys in logs or errors
- Never bypass session validation for replay attack prevention

## Related Crates

- `xavyo-api-oauth` - OAuth2/OIDC provider (alternative SSO)
- `xavyo-api-oidc-federation` - OIDC relying party
- `xavyo-api-auth` - User authentication services
