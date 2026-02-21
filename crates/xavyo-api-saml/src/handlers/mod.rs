//! HTTP handlers for SAML endpoints

pub mod admin;
pub mod initiate;
pub mod metadata;
pub mod slo;
pub mod sso;

pub use initiate::initiate_sso;
pub use metadata::get_metadata;
pub use slo::{slo_initiate, slo_post};
pub use sso::{sso_post, sso_redirect};
