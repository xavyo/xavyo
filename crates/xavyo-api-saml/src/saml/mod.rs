//! SAML-specific utilities

pub mod attributes;
pub mod signing;

pub use attributes::{
    default_attributes, get_name_id_value, get_nameid_for_format, is_supported_nameid_format,
    resolve_attributes, ResolvedAttribute, UserAttributes, NAMEID_FORMAT_EMAIL,
    NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_TRANSIENT,
};
pub use signing::{
    parse_sp_certificate, verify_signature, verify_signature_with_algorithm, SigningCredentials,
};
