//! SAML `AuthnRequest` session management
//!
//! This module provides session tracking for SAML `AuthnRequest` IDs
//! to prevent replay attacks. When an SP sends an `AuthnRequest`, the
//! request ID is stored. When processing the response, we validate
//! that the `InResponseTo` matches a known, valid, unused request ID.
//!
//! # Security Features
//!
//! - **Replay Prevention**: Each request ID can only be used once
//! - **TTL Expiration**: Requests expire after 5 minutes (configurable)
//! - **Clock Skew Grace**: 30-second grace period for clock drift
//! - **Tenant Isolation**: Request IDs are scoped to tenants
//!
//! # Example
//!
//! ```ignore
//! use xavyo_api_saml::session::{AuthnRequestSession, InMemorySessionStore, SessionStore};
//!
//! let store = InMemorySessionStore::new();
//!
//! // Store a new session when AuthnRequest is received
//! let session = AuthnRequestSession::new(
//!     tenant_id,
//!     authn_request.id,
//!     authn_request.issuer,
//!     relay_state,
//! );
//! store.store(session).await?;
//!
//! // Validate and consume when generating response
//! let session = store.validate_and_consume(tenant_id, &request_id).await?;
//! // Use session.request_id as InResponseTo in SAMLResponse
//! ```

mod store;
mod types;

pub use store::{InMemorySessionStore, PostgresSessionStore, SessionStore};
pub use types::{
    AuthnRequestSession, SessionError, CLOCK_SKEW_GRACE_SECONDS, DEFAULT_SESSION_TTL_SECONDS,
};
