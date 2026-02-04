//! Security tests for SAML `AuthnRequest` session management
//!
//! These tests verify:
//! - Session storage and retrieval
//! - TTL expiration with grace period
//! - Replay attack prevention
//! - Tenant isolation

pub mod expiration_tests;
pub mod replay_tests;
pub mod session_tests;
