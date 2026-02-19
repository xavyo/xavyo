//! Router for OIDC Federation API.

use axum::{
    routing::{delete, get, post, put},
    Router,
};
use sqlx::PgPool;

use crate::handlers::{admin, federation};
use crate::services::{
    AuthFlowService, EncryptionService, HrdService, IdpConfigService, ProvisioningService,
    TokenIssuerService, ValidationService,
};

/// Shared state for federation handlers.
///
/// Note: Tenant ID is NOT stored in state. It is extracted per-request from
/// the `TenantLayer` middleware via `Extension<xavyo_core::TenantId>`.
#[derive(Clone)]
pub struct FederationState {
    /// Database connection pool (for role lookups, etc.).
    pub pool: PgPool,
    /// `IdP` configuration service.
    pub idp_config: IdpConfigService,
    /// Validation service.
    pub validation: ValidationService,
    /// Home Realm Discovery service.
    pub hrd: HrdService,
    /// Auth flow service.
    pub auth_flow: AuthFlowService,
    /// Provisioning service.
    pub provisioning: ProvisioningService,
    /// Token issuer service.
    pub token_issuer: TokenIssuerService,
}

/// Configuration for federation router.
#[derive(Clone)]
pub struct FederationConfig {
    /// Database connection pool.
    pub pool: PgPool,
    /// Master encryption key for client secrets.
    pub master_key: [u8; 32],
    /// Base URL for callbacks (e.g., "<https://idp.example.com>").
    pub callback_base_url: String,
    /// PEM-encoded RSA private key for signing federation JWTs.
    /// Must be provided — federation login will fail without a valid signing key.
    pub jwt_private_key_pem: Vec<u8>,
}

impl FederationState {
    /// Create a new federation state.
    #[must_use]
    pub fn new(config: &FederationConfig) -> Self {
        let encryption = EncryptionService::new(config.master_key);
        let idp_config = IdpConfigService::new(config.pool.clone(), encryption.clone());
        let validation = ValidationService::new(config.pool.clone());
        let hrd = HrdService::new(config.pool.clone());
        let auth_flow = AuthFlowService::new(
            config.pool.clone(),
            encryption,
            config.callback_base_url.clone(),
        );
        let provisioning = ProvisioningService::new(config.pool.clone());
        let token_issuer = TokenIssuerService::new(crate::services::TokenIssuerConfig {
            private_key_pem: config.jwt_private_key_pem.clone(),
            ..Default::default()
        });

        Self {
            pool: config.pool.clone(),
            idp_config,
            validation,
            hrd,
            auth_flow,
            provisioning,
            token_issuer,
        }
    }
}

/// Create the admin routes for federation management.
///
/// These routes are protected and require admin authentication.
///
/// Routes:
/// - GET /admin/federation/identity-providers - List `IdPs`
/// - POST /admin/federation/identity-providers - Create `IdP`
/// - GET /admin/federation/identity-providers/:idp_id - Get `IdP`
/// - PUT /admin/federation/identity-providers/:idp_id - Update `IdP`
/// - DELETE /admin/federation/identity-providers/:idp_id - Delete `IdP`
/// - POST /admin/federation/identity-providers/:idp_id/validate - Validate `IdP`
/// - POST /admin/federation/identity-providers/:idp_id/toggle - Toggle `IdP` enabled
/// - GET /admin/federation/identity-providers/:idp_id/domains - List domains
/// - POST /admin/federation/identity-providers/:idp_id/domains - Add domain
/// - DELETE /admin/federation/identity-providers/:idp_id/domains/:domain_id - Remove domain
pub fn admin_routes() -> Router<FederationState> {
    Router::new()
        .route("/identity-providers", get(admin::list_identity_providers))
        .route("/identity-providers", post(admin::create_identity_provider))
        .route(
            "/identity-providers/:idp_id",
            get(admin::get_identity_provider),
        )
        .route(
            "/identity-providers/:idp_id",
            put(admin::update_identity_provider),
        )
        .route(
            "/identity-providers/:idp_id",
            delete(admin::delete_identity_provider),
        )
        .route(
            "/identity-providers/:idp_id/validate",
            post(admin::validate_identity_provider),
        )
        .route(
            "/identity-providers/:idp_id/toggle",
            post(admin::toggle_identity_provider),
        )
        .route(
            "/identity-providers/:idp_id/domains",
            get(admin::list_domains),
        )
        .route(
            "/identity-providers/:idp_id/domains",
            post(admin::add_domain),
        )
        .route(
            "/identity-providers/:idp_id/domains/:domain_id",
            delete(admin::remove_domain),
        )
}

/// Create the public federation routes for user authentication.
///
/// Routes:
/// - POST /auth/federation/discover - Discover realm for email
/// - GET /auth/federation/authorize - Initiate auth flow
/// - GET /auth/federation/callback - Handle `IdP` callback
/// - POST /auth/federation/logout - Logout (cleanup)
pub fn auth_routes() -> Router<FederationState> {
    Router::new()
        .route("/discover", post(federation::discover_realm))
        .route("/authorize", get(federation::authorize))
        .route("/callback", get(federation::callback))
        .route("/logout", post(federation::logout))
}

/// Create the full federation router with all routes.
///
/// Tenant ID is extracted per-request by the `TenantLayer` middleware,
/// not baked into the state at creation time.
pub fn create_federation_router(config: FederationConfig) -> Router {
    let state = FederationState::new(&config);

    Router::new()
        .nest("/admin/federation", admin_routes())
        .nest("/auth/federation", auth_routes())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_routes_created() {
        // Just verify routes can be created without panic
        let _routes = admin_routes();
    }

    #[test]
    fn test_auth_routes_created() {
        let _routes = auth_routes();
    }
}
