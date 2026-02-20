//! Router configuration for social authentication endpoints.

use axum::{
    routing::{delete, get, post, put},
    Router,
};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::handlers;
use crate::providers::IdTokenVerifier;
use crate::services::{ConnectionService, EncryptionService, OAuthService, TenantProviderService};

/// Shared state for social authentication handlers.
#[derive(Clone)]
pub struct SocialState {
    /// Database connection pool.
    pub pool: PgPool,
    /// Base URL for building redirect URIs.
    pub base_url: String,
    /// Frontend URL for redirects.
    pub frontend_url: String,
    /// OAuth state management service.
    pub oauth_service: OAuthService,
    /// Connection management service.
    pub connection_service: ConnectionService,
    /// Tenant provider configuration service.
    pub tenant_provider_service: TenantProviderService,
    /// Auth service for issuing tokens (interface to xavyo-auth).
    pub auth_service: Arc<dyn AuthService + Send + Sync>,
    /// Defense-in-depth ID token verifier for OIDC providers.
    pub id_token_verifier: IdTokenVerifier,
}

/// Interface for the authentication service.
///
/// This allows the social login module to issue xavyo JWT tokens
/// and create users without depending directly on xavyo-auth internals.
#[async_trait::async_trait]
pub trait AuthService: Send + Sync {
    /// Issue JWT tokens for a user.
    async fn issue_tokens(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<crate::handlers::JwtTokens, crate::error::SocialError>;

    /// Create a new user from social login.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - The tenant to create the user in
    /// * `email` - User's email address (may be None for private email providers)
    /// * `display_name` - User's display name
    /// * `email_verified` - Whether the email was verified by the provider (F116: pass through actual value)
    async fn create_social_user(
        &self,
        tenant_id: Uuid,
        email: Option<&str>,
        display_name: &str,
        email_verified: bool,
    ) -> Result<Uuid, crate::error::SocialError>;
}

/// Configuration for building social state.
pub struct SocialConfig {
    pub pool: PgPool,
    pub base_url: String,
    pub frontend_url: String,
    pub encryption_key: String,
    pub state_secret: String,
}

impl SocialState {
    /// Create a new social state from configuration.
    pub fn new(
        config: SocialConfig,
        auth_service: Arc<dyn AuthService + Send + Sync>,
    ) -> Result<Self, crate::error::SocialError> {
        let encryption = EncryptionService::new(&config.encryption_key)?;
        let oauth_service = OAuthService::new(&config.state_secret);
        let connection_service = ConnectionService::new(config.pool.clone(), encryption.clone());
        let tenant_provider_service = TenantProviderService::new(config.pool.clone(), encryption);
        let id_token_verifier = IdTokenVerifier::new();

        Ok(Self {
            pool: config.pool,
            base_url: config.base_url,
            frontend_url: config.frontend_url,
            oauth_service,
            connection_service,
            tenant_provider_service,
            auth_service,
            id_token_verifier,
        })
    }
}

/// Create the public social authentication router.
///
/// These routes are used for the OAuth flow and don't require authentication.
/// Tenant context comes from the OAuth state token.
pub fn public_social_router() -> Router<SocialState> {
    Router::new()
        // Public endpoints
        .route("/available", get(handlers::available_providers))
        .route("/:provider/authorize", get(handlers::authorize))
        .route("/:provider/callback", get(handlers::callback_get))
        // Apple uses POST for callback (form_post)
        .route("/apple/callback", post(handlers::callback_apple_post))
}

/// Create the authenticated social router.
///
/// These routes require the user to be authenticated.
/// User and tenant context come from JWT claims in request extensions.
pub fn authenticated_social_router() -> Router<SocialState> {
    Router::new()
        // Account linking (requires auth)
        .route("/connections", get(handlers::list_connections))
        .route("/link/:provider/authorize", get(handlers::initiate_link))
        .route("/link/:provider", post(handlers::link_account))
        .route("/unlink/:provider", delete(handlers::unlink_account))
}

/// Create the admin social router.
///
/// These routes require admin permissions.
/// Tenant context comes from JWT claims in request extensions.
pub fn admin_social_router() -> Router<SocialState> {
    Router::new()
        .route("/", get(handlers::list_providers))
        .route("/:provider", put(handlers::update_provider))
        .route("/:provider", delete(handlers::disable_provider))
}

/// Create the complete social router with all routes.
///
/// Typically, you would mount this at `/api/v1/auth/social` for public/auth routes
/// and `/api/v1/admin/social-providers` for admin routes.
pub fn social_router() -> Router<SocialState> {
    Router::new()
        .merge(public_social_router())
        .merge(authenticated_social_router())
}
