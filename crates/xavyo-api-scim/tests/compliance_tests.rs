//! RFC 7644 Protocol Compliance Test Suite
//!
//! This test file pulls in all SCIM protocol compliance tests.
//! Run with: cargo test -p xavyo-api-scim --test `compliance_tests`

mod compliance;

// Re-export for test access
pub use compliance::*;
