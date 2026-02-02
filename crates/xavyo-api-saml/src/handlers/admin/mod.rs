//! Admin handlers for SAML configuration

pub mod certificates;
pub mod service_providers;

pub use certificates::{activate_certificate, list_certificates, upload_certificate};
pub use service_providers::{
    create_service_provider, delete_service_provider, get_service_provider, list_service_providers,
    update_service_provider,
};
