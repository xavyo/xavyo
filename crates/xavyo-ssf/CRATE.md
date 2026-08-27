# xavyo-ssf

> CAEP / Shared Signals transmitter primitives: Security Event Tokens, RFC 9493 subject identifiers, and the `CaepEmitter` sink.

## Purpose

The DB-free domain core for emitting Continuous Access Evaluation Profile (CAEP 1.0) signals over the OpenID Shared Signals Framework (SSF 1.0). It builds and RS256-signs Security Event Tokens (RFC 8417, `typ: secevent+jwt`), models the five CAEP event types, and exposes a `CaepEmitter` trait that application flows call to broadcast signals without knowing how (or whether) delivery is wired.

Storage (`ssf_streams` / `ssf_subjects`), the stream-management HTTP API, and the push transmitter live in `xavyo-db` and `xavyo-api-ssf`. This crate stays pure and unit-testable.

## Layer

domain

## Status

🟡 **beta**

18 unit tests covering event payloads (incl. the SSF `verification` event), subject-identifier serialization, SET signing, and the `NoopEmitter`. Domain core is DB-free and production-used via `xavyo-api-ssf`; API surface may still evolve.

## Dependencies

### Internal (xavyo)
- None — deliberately DB-free and dependency-light so any layer can emit.

### External (key)
- `jsonwebtoken` — RS256 JWS signing of the SET
- `serde` / `serde_json` — claim and event-payload modelling
- `chrono` — `iat` timestamps
- `uuid` — tenant/user identifiers in the emitter API

## Public API

### Types

```rust
/// CAEP event (one per SET). Carries its `events` payload and type URI.
pub enum CaepEvent { /* SessionRevoked, CredentialChange, TokenClaimsChange, ... */ }

/// Direction of a credential-change event.
pub enum CredentialChangeType { Create, Revoke, Update, Delete }

/// RFC 9493 Subject Identifier — the SET `sub_id`.
pub enum SubjectId {
    IssSub { iss: String, sub: String }, // §3.2.1
    Email  { email: String },            // §3.2.2
}

/// A CAEP Security Event Token, signed into a compact JWS.
pub struct SecurityEventToken { /* issuer, audience, subject, event */ }

/// Errors from SET construction/signing.
pub enum SsfError { InvalidKey(String), Signing(String) }

/// The sink application flows call to broadcast CAEP signals.
pub trait CaepEmitter: Send + Sync { /* see below */ }

/// A `CaepEmitter` that drops every signal (SSF not configured).
pub struct NoopEmitter;
```

### Constants

```rust
pub const SESSION_REVOKED_URI: &str;          // CAEP session-revoked
pub const CREDENTIAL_CHANGE_URI: &str;        // CAEP credential-change
pub const TOKEN_CLAIMS_CHANGE_URI: &str;      // CAEP token-claims-change
pub const ASSURANCE_LEVEL_CHANGE_URI: &str;   // CAEP assurance-level-change
pub const DEVICE_COMPLIANCE_CHANGE_URI: &str; // CAEP device-compliance-change
pub const SET_TYP: &str;                      // "secevent+jwt"
```

### Key methods

```rust
impl SecurityEventToken {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>,
               subject: SubjectId, event: CaepEvent) -> Self;
    /// RS256 compact JWS, `typ: secevent+jwt`, with `kid`. No `sub`/`exp`.
    pub fn sign(&self, private_key_pem: &[u8], kid: &str, now: i64, jti: &str)
        -> Result<String, SsfError>;
}

pub trait CaepEmitter: Send + Sync {
    fn session_revoked(&self, tenant_id: Uuid, user_id: Uuid, reason: Option<String>);
    fn credential_change(&self, tenant_id: Uuid, user_id: Uuid,
                         credential_type: String, change_type: CredentialChangeType);
    fn token_claims_change(&self, tenant_id: Uuid, user_id: Uuid, claims: serde_json::Value);
}
```

## Usage Example

```rust
use xavyo_ssf::{SecurityEventToken, SubjectId, CaepEvent};

let token = SecurityEventToken::new(
    "https://idp.xavyo.example",      // issuer
    "https://rp.example.com",         // audience (the receiver)
    SubjectId::IssSub {
        iss: "https://idp.xavyo.example".into(),
        sub: user_id.to_string(),
    },
    CaepEvent::session_revoked(None),
);
let jws = token.sign(private_key_pem, kid, chrono::Utc::now().timestamp(), &jti)?;
// → deliver `jws` to the receiver's push endpoint (see xavyo-api-ssf).
```

## Integration Points

- **Consumed by**: `xavyo-api-ssf` (push transmitter + stream emitter), `xavyo-api-auth` (session/credential flows hold an `Arc<dyn CaepEmitter>`).
- **Provides**: signed SETs and the emitter abstraction; `NoopEmitter` so call sites can hold a `CaepEmitter` unconditionally.
- **Requires**: an RSA signing key (the IdP's SET-signing key) supplied by the transmitter layer.

## Feature Flags

None.

## Anti-Patterns

- Don't add `sub` or `exp` claims to a SET — SSF §4.1.2/§4.1.7 forbid them; the subject is `sub_id`.
- Don't sign with a per-request key; SETs use the IdP's stable signing key (rotated via `kid`).
- Don't block the request path on emission — emitters are fire-and-forget; delivery is the transmitter's job.
- Don't reuse a `jti` — receivers dedupe on it.

## Related Crates

- `xavyo-api-ssf` — stream-management API + push transmitter that delivers these SETs
- `xavyo-auth` — JWT/JWKS (the same signing-key material)
- `xavyo-api-auth` — session/credential flows that emit signals
