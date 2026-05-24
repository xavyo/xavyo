//! Shared Signals Framework (SSF) + CAEP transmitter primitives for xavyo.
//!
//! This crate is the DB-free domain core for emitting Continuous Access
//! Evaluation signals (OpenID SSF 1.0 / CAEP 1.0):
//! - [`subject`]: RFC 9493 Subject Identifiers (the SET `sub_id`).
//! - [`events`]: CAEP event types (v1: `session-revoked`, `credential-change`).
//! - [`set`]: the Security Event Token builder/signer (RFC 8417, `secevent+jwt`).
//!
//! Storage (`ssf_streams`/`ssf_subjects`), the stream-management API, and the
//! push transmitter live in the `xavyo-db` / `xavyo-api-ssf` layers (later
//! increments); this crate stays pure and unit-testable.

/// CAEP event types.
pub mod events;
/// Security Event Token builder/signer.
pub mod set;
/// RFC 9493 Subject Identifiers.
pub mod subject;

pub use events::{CaepEvent, CredentialChangeType, CREDENTIAL_CHANGE_URI, SESSION_REVOKED_URI};
pub use set::{SecurityEventToken, SsfError, SET_TYP};
pub use subject::SubjectId;
