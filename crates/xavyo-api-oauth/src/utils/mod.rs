//! Utility modules for xavyo-api-oauth.
//!
//! Contains helper functions for IP and country extraction (Storm-2372 remediation).

pub mod country_extraction;
pub mod ip_extraction;

pub use country_extraction::{extract_country_code, UNKNOWN_COUNTRY};
pub use ip_extraction::extract_origin_ip;
