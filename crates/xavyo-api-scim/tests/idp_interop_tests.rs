//! IdP Interoperability Test Suite
//!
//! This test file pulls in all IdP-specific interoperability tests.
//! Run with: cargo test -p xavyo-api-scim --test idp_interop_tests

mod common;
mod mocks;

// Include the interop test modules
mod interop;

// Re-export for test access
#[allow(ambiguous_glob_reexports)]
pub use common::*;
pub use mocks::*;
