//! The [`CaepEmitter`] sink — the seam between application flows and SSF delivery.
//!
//! Auth flows (session revocation, credential change, …) call a `CaepEmitter`
//! on their success path to broadcast a CAEP signal. The methods are
//! **fire-and-forget**: an implementation MUST NOT block or fail the calling
//! operation — delivery happens asynchronously and best-effort. Depending on
//! this trait (rather than the SSF HTTP transmitter) keeps `xavyo-api-auth` free
//! of any outbound-delivery dependency.

use crate::events::CredentialChangeType;
use uuid::Uuid;

/// A best-effort sink for CAEP events emitted from application flows.
///
/// The subject is identified by `tenant_id` + `user_id`; the implementation
/// builds the RFC 9493 Subject Identifier (it owns the issuer), so call sites
/// in auth flows need only pass the user they are acting on.
pub trait CaepEmitter: Send + Sync {
    /// Broadcast a CAEP `session-revoked` signal for `user_id` in `tenant_id`.
    fn session_revoked(&self, tenant_id: Uuid, user_id: Uuid, reason: Option<String>);

    /// Broadcast a CAEP `credential-change` signal for `user_id` in `tenant_id`.
    fn credential_change(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        credential_type: String,
        change_type: CredentialChangeType,
    );

    /// Broadcast a CAEP `token-claims-change` signal for `user_id` in
    /// `tenant_id` — e.g. when roles/scopes change, so relying parties
    /// re-evaluate access. `claims` is the map of changed claim → new value.
    fn token_claims_change(&self, tenant_id: Uuid, user_id: Uuid, claims: serde_json::Value);
}

/// A no-op emitter: drops every signal. Used where SSF is not configured, so
/// call sites can hold a `CaepEmitter` unconditionally.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopEmitter;

impl CaepEmitter for NoopEmitter {
    fn session_revoked(&self, _tenant_id: Uuid, _user_id: Uuid, _reason: Option<String>) {}
    fn credential_change(
        &self,
        _tenant_id: Uuid,
        _user_id: Uuid,
        _credential_type: String,
        _change_type: CredentialChangeType,
    ) {
    }
    fn token_claims_change(&self, _tenant_id: Uuid, _user_id: Uuid, _claims: serde_json::Value) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_emitter_is_inert() {
        // Compiles + runs without panicking; the value is that call sites can
        // depend on `CaepEmitter` without an SSF backend.
        let e = NoopEmitter;
        e.session_revoked(Uuid::nil(), Uuid::nil(), None);
        e.credential_change(
            Uuid::nil(),
            Uuid::nil(),
            "password".into(),
            CredentialChangeType::Update,
        );
    }
}
