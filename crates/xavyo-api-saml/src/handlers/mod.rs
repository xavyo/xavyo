//! HTTP handlers for SAML endpoints

pub mod admin;
pub mod initiate;
pub mod metadata;
pub mod sso;

pub use initiate::initiate_sso;
pub use metadata::get_metadata;
pub use sso::{sso_post, sso_redirect};
