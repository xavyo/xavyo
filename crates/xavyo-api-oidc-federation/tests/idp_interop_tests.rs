//! IdP Interoperability Tests
//!
//! Integration tests for OIDC federation with major Identity Providers.
//! These tests verify correct handling of IdP-specific token formats,
//! JWKS structures, and claim patterns.
//!
//! Run with: `cargo test -p xavyo-api-oidc-federation --test idp_interop_tests`

mod interop;
