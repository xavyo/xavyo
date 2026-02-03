//! Social Provider Integration Tests
//!
//! This module contains integration tests for all supported social OAuth2 providers:
//! - Google OAuth2
//! - Microsoft OAuth2 (Azure AD)
//! - Apple Sign In
//! - GitHub OAuth2
//!
//! Tests use mock servers to simulate provider responses without external dependencies.

pub mod common;
pub mod mock_server;

pub mod apple_tests;
pub mod error_tests;
pub mod github_tests;
pub mod google_tests;
pub mod microsoft_tests;
