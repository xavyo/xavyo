//! SAML route definitions

use crate::handlers::metadata::SamlState;
use crate::handlers::{
    admin::{
        activate_certificate, create_service_provider, delete_service_provider,
        get_service_provider, list_certificates, list_service_providers, update_service_provider,
        upload_certificate,
    },
    get_metadata, initiate_sso, sso_post, sso_redirect,
};
use axum::{
    routing::{get, post},
    Router,
};

/// Create public SAML router (metadata + SSO endpoints)
/// These endpoints require tenant context but not authentication
pub fn saml_public_router(state: SamlState) -> Router {
    Router::new()
        // Public SAML endpoints
        .route("/saml/metadata", get(get_metadata))
        .route("/saml/sso", get(sso_redirect).post(sso_post))
        // IdP-initiated SSO (requires auth - handled by calling code)
        .route("/saml/initiate/:sp_id", post(initiate_sso))
        .with_state(state)
}

/// Create SAML admin router (service provider and certificate management)
/// These endpoints require authentication and admin role
pub fn saml_admin_router(state: SamlState) -> Router {
    Router::new()
        .route(
            "/service-providers",
            get(list_service_providers).post(create_service_provider),
        )
        .route(
            "/service-providers/:sp_id",
            get(get_service_provider)
                .put(update_service_provider)
                .delete(delete_service_provider),
        )
        .route(
            "/certificates",
            get(list_certificates).post(upload_certificate),
        )
        .route(
            "/certificates/:cert_id/activate",
            post(activate_certificate),
        )
        .with_state(state)
}

/// Create SAML router with all routes (deprecated - use `saml_public_router` and `saml_admin_router`)
#[deprecated(
    note = "Use saml_public_router and saml_admin_router for proper middleware separation"
)]
pub fn saml_router(state: SamlState) -> Router {
    Router::new()
        // Public SAML endpoints
        .route("/saml/metadata", get(get_metadata))
        .route("/saml/sso", get(sso_redirect).post(sso_post))
        // IdP-initiated SSO (requires auth)
        .route("/saml/initiate/:sp_id", post(initiate_sso))
        // Admin endpoints
        .route(
            "/admin/saml/service-providers",
            get(list_service_providers).post(create_service_provider),
        )
        .route(
            "/admin/saml/service-providers/:sp_id",
            get(get_service_provider)
                .put(update_service_provider)
                .delete(delete_service_provider),
        )
        .route(
            "/admin/saml/certificates",
            get(list_certificates).post(upload_certificate),
        )
        .route(
            "/admin/saml/certificates/:cert_id/activate",
            post(activate_certificate),
        )
        .with_state(state)
}

/// Create SAML state from configuration
#[must_use]
pub fn create_saml_state(
    pool: sqlx::PgPool,
    base_url: String,
    encryption_key: [u8; 32],
) -> SamlState {
    SamlState {
        pool,
        base_url,
        encryption_key: std::sync::Arc::new(encryption_key),
    }
}
