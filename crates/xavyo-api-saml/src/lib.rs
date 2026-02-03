//! SAML 2.0 Identity Provider library for xavyo
//!
//! This crate provides SAML 2.0 IdP functionality including:
//! - SP-initiated SSO (AuthnRequest processing)
//! - IdP-initiated SSO (unsolicited response)
//! - Metadata publishing
//! - Admin endpoints for SP configuration
//! - Certificate management
//! - Replay attack prevention via AuthnRequest session tracking

pub mod error;
pub mod handlers;
pub mod models;
pub mod router;
pub mod saml;
pub mod services;
pub mod session;

pub use error::{SamlError, SamlResult};
pub use handlers::metadata::SamlState;
#[allow(deprecated)]
pub use router::{create_saml_state, saml_admin_router, saml_public_router, saml_router};
pub use session::{AuthnRequestSession, InMemorySessionStore, PostgresSessionStore, SessionStore};
