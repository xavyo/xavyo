//! SAML Service Provider Interoperability Tests
//!
//! Entry point for all SP interoperability tests.

mod interop;

// Re-export tests from submodules
pub use interop::*;
