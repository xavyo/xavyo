//! Shared Signals Framework (SSF) + CAEP transmitter primitives for xavyo.
//!
//! This crate is the DB-free domain core for emitting Continuous Access
//! Evaluation signals (OpenID SSF 1.0 / CAEP 1.0):
//! - [`subject`]: RFC 9493 Subject Identifiers (the SET `sub_id`).
//! - [`events`]: the five CAEP event types (`session-revoked`,
//!   `credential-change`, `token-claims-change`, `assurance-level-change`,
//!   `device-compliance-change`).
//! - [`set`]: the Security Event Token builder/signer (RFC 8417, `secevent+jwt`).
//!
//! Storage (`ssf_streams`/`ssf_subjects`), the stream-management API, and the
//! push transmitter live in the `xavyo-db` / `xavyo-api-ssf` layers (later
//! increments); this crate stays pure and unit-testable.

/// The `CaepEmitter` sink (application flows → SSF delivery).
pub mod emitter;
/// CAEP event types.
pub mod events;
/// Security Event Token builder/signer.
pub mod set;
/// RFC 9493 Subject Identifiers.
pub mod subject;

pub use emitter::{CaepEmitter, NoopEmitter};
pub use events::{
    CaepEvent, CredentialChangeType, ASSURANCE_LEVEL_CHANGE_URI, CREDENTIAL_CHANGE_URI,
    DEVICE_COMPLIANCE_CHANGE_URI, SESSION_REVOKED_URI, TOKEN_CLAIMS_CHANGE_URI, VERIFICATION_URI,
};
pub use set::{SecurityEventToken, SsfError, SET_TYP};
pub use subject::SubjectId;
