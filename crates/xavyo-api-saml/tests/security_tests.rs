//! Security Test Suite for SAML AuthnRequest Session Management
//!
//! Run with: cargo test -p xavyo-api-saml --test security_tests
//!
//! This test suite verifies:
//! - Session storage and retrieval (FR-001, FR-002)
//! - TTL expiration with grace period (FR-003, FR-006, FR-010)
//! - Replay attack prevention (FR-007, FR-008)
//! - InResponseTo validation (FR-004, FR-005)
//! - Tenant isolation (FR-014)

mod security;

// Re-export for test access
pub use security::*;
