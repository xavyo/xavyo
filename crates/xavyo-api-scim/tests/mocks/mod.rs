//! Mock SCIM clients for `IdP` interoperability testing.
//!
//! This module provides mock implementations of SCIM clients that simulate
//! the behavior of major identity providers (Okta, Azure AD, `OneLogin`).

pub mod base_client;
pub mod fixtures;
pub mod quirks;

pub mod azure_ad_client;
pub mod okta_client;
pub mod onelogin_client;

pub use azure_ad_client::AzureAdClient;
pub use base_client::*;
pub use fixtures::{TestGroup, TestUser};
pub use okta_client::OktaClient;
pub use onelogin_client::OneLoginClient;
pub use quirks::*;
