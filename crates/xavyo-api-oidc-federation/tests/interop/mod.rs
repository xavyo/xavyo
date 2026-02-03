//! OIDC IdP Interoperability Tests
//!
//! This module contains interoperability tests for major Identity Providers:
//! - Okta
//! - Azure AD (Entra ID)
//! - Google Workspace
//! - Ping Identity
//! - Auth0

pub mod common;

mod auth0_tests;
mod azure_ad_tests;
mod google_tests;
mod okta_tests;
mod ping_tests;
