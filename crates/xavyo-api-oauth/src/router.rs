//! OAuth2/OIDC API router configuration.
//!
//! Configures routes for OAuth2/OIDC endpoints:
//! - GET /oauth/authorize - Authorization endpoint
//! - POST /oauth/authorize/consent - Consent submission
//! - POST /oauth/token - Token endpoint (includes `device_code` grant)
//! - GET /oauth/userinfo - `UserInfo` endpoint
//! - POST /oauth/device/code - RFC 8628 Device Authorization endpoint
//! - GET /device - Device verification page
//! - POST /device/verify - Verify user code
//! - POST /device/authorize - Authorize device
//! - GET /.well-known/openid-configuration - OIDC Discovery
//! - GET /.well-known/jwks.json - JSON Web Key Set

use crate::handlers::{
    admin_revoke_user_handler, authorize_handler, consent_handler, create_client_handler,
    delete_client_handler, delete_session_handler, device_authorization_handler,
    device_authorize_handler, device_confirm_handler, device_login_handler,
    device_login_page_handler, device_mfa_handler, device_mfa_page_handler,
    device_resend_confirmation_handler, device_verification_page_handler,
    device_verify_code_handler, discovery_handler, get_client_handler, introspect_token_handler,
    jwks_handler, list_active_sessions_handler, list_clients_handler, regenerate_secret_handler,
    revoke_token_handler, token_handler, update_client_handler, userinfo_handler,
};
use crate::services::{
    AuthorizationService, DeviceConfirmationService, DeviceRiskService, OAuth2ClientService,
    TokenService, UserInfoService,
};
use axum::{
    routing::{delete, get, post, put},
    Router,
};
use sqlx::PgPool;
use std::sync::Arc;
use xavyo_api_auth::RevocationCache;

/// A JWT signing key for multi-key rotation support (F069-S5).
#[derive(Debug, Clone)]
pub struct OAuthSigningKey {
    /// Key ID (kid) for JWKS identification.
    pub kid: String,
    /// PEM-encoded RSA private key.
    pub private_key_pem: String,
    /// PEM-encoded RSA public key.
    pub public_key_pem: String,
    /// Whether this is the active signing key (used for new tokens).
    pub is_active: bool,
}

/// Application state for OAuth2/OIDC routes.
#[derive(Clone)]
pub struct OAuthState {
    /// Database connection pool.
    pub pool: PgPool,
    /// `OAuth2` client service.
    pub client_service: Arc<OAuth2ClientService>,
    /// Authorization service.
    pub authorization_service: Arc<AuthorizationService>,
    /// Token service.
    pub token_service: Arc<TokenService>,
    /// `UserInfo` service.
    pub userinfo_service: Arc<UserInfoService>,
    /// Issuer URL (e.g., "<https://idp.xavyo.com>").
    pub issuer: String,
    /// JWT private key (PEM format) for signing tokens (active key).
    pub private_key: Vec<u8>,
    /// JWT public key (PEM format) for JWKS (active key).
    pub public_key: Vec<u8>,
    /// Key ID for JWKS (active key).
    pub key_id: String,
    /// All signing keys for key rotation support (F069-S5).
    pub signing_keys: Vec<OAuthSigningKey>,
    /// In-memory + DB revocation cache for JTI blacklist (F084).
    pub revocation_cache: Option<RevocationCache>,
    /// CSRF secret for consent form protection (F082-US6).
    /// SECURITY: This MUST be independent of the JWT signing key.
    csrf_secret: Vec<u8>,
    /// F117: Device confirmation service for Storm-2372 remediation.
    pub device_confirmation_service: Option<Arc<DeviceConfirmationService>>,
    /// F117: Device risk service for Storm-2372 risk scoring.
    pub device_risk_service: Option<Arc<DeviceRiskService>>,
    /// F117: System tenant ID for device code confirmations.
    pub system_tenant_id: uuid::Uuid,
}

impl OAuthState {
    /// Create a new OAuth state (single-key backward-compatible constructor).
    ///
    /// # Arguments
    ///
    /// * `pool` - Database connection pool
    /// * `issuer` - Issuer URL (e.g., "<https://idp.xavyo.com>")
    /// * `private_key` - JWT private key in PEM format
    /// * `public_key` - JWT public key in PEM format
    /// * `key_id` - Key ID for JWKS
    /// * `csrf_secret` - CSRF secret for consent form protection (MUST be independent of JWT key)
    #[must_use] 
    pub fn new(
        pool: PgPool,
        issuer: String,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        key_id: String,
        csrf_secret: Vec<u8>,
    ) -> Self {
        let signing_keys = vec![OAuthSigningKey {
            kid: key_id.clone(),
            private_key_pem: String::from_utf8_lossy(&private_key).to_string(),
            public_key_pem: String::from_utf8_lossy(&public_key).to_string(),
            is_active: true,
        }];
        Self::with_signing_keys(
            pool,
            issuer,
            private_key,
            public_key,
            key_id,
            signing_keys,
            csrf_secret,
        )
    }

    /// Create a new OAuth state with multiple signing keys (F069-S5).
    ///
    /// # Arguments
    ///
    /// * `pool` - Database connection pool
    /// * `issuer` - Issuer URL
    /// * `private_key` - Active private key in PEM format
    /// * `public_key` - Active public key in PEM format
    /// * `key_id` - Active key ID
    /// * `signing_keys` - All signing keys (active + rotated)
    /// * `csrf_secret` - CSRF secret for consent form protection (MUST be independent of JWT key)
    #[must_use] 
    pub fn with_signing_keys(
        pool: PgPool,
        issuer: String,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        key_id: String,
        signing_keys: Vec<OAuthSigningKey>,
        csrf_secret: Vec<u8>,
    ) -> Self {
        let client_service = Arc::new(OAuth2ClientService::new(pool.clone()));
        let authorization_service = Arc::new(AuthorizationService::new(pool.clone()));
        let token_service = Arc::new(TokenService::new(
            pool.clone(),
            issuer.clone(),
            private_key.clone(),
            key_id.clone(),
        ));
        let userinfo_service = Arc::new(UserInfoService::new(pool.clone()));

        Self {
            pool,
            client_service,
            authorization_service,
            token_service,
            userinfo_service,
            issuer,
            private_key,
            public_key,
            key_id,
            signing_keys,
            revocation_cache: None,
            csrf_secret,
            device_confirmation_service: None,
            device_risk_service: None,
            system_tenant_id: uuid::Uuid::nil(), // Default to nil, set via with_system_tenant_id
        }
    }

    /// Set the revocation cache (F084).
    ///
    /// Call this after construction to share the `RevocationCache` instance
    /// used by `jwt_auth_middleware` with the `OAuth2` revocation/introspection handlers.
    #[must_use]
    pub fn with_revocation_cache(mut self, cache: RevocationCache) -> Self {
        self.revocation_cache = Some(cache);
        self
    }

    /// Set the device confirmation service (F117 Storm-2372).
    ///
    /// Call this after construction to enable email confirmation for suspicious
    /// device code approvals.
    #[must_use]
    pub fn with_device_confirmation_service(
        mut self,
        service: Arc<DeviceConfirmationService>,
    ) -> Self {
        self.device_confirmation_service = Some(service);
        self
    }

    /// Set the device risk service (F117 Storm-2372 Phase 3).
    ///
    /// Call this after construction to enable risk-based approval scoring.
    #[must_use]
    pub fn with_device_risk_service(mut self, service: Arc<DeviceRiskService>) -> Self {
        self.device_risk_service = Some(service);
        self
    }

    /// Set the system tenant ID (F117).
    ///
    /// Used for device code confirmations which operate at the system level.
    #[must_use]
    pub fn with_system_tenant_id(mut self, tenant_id: uuid::Uuid) -> Self {
        self.system_tenant_id = tenant_id;
        self
    }

    /// Returns the active signing key.
    #[must_use] 
    pub fn active_signing_key(&self) -> Option<&OAuthSigningKey> {
        self.signing_keys.iter().find(|k| k.is_active)
    }

    /// Find a signing key by its kid.
    #[must_use] 
    pub fn find_key_by_kid(&self, kid: &str) -> Option<&OAuthSigningKey> {
        self.signing_keys.iter().find(|k| k.kid == kid)
    }

    /// Get the CSRF secret for consent form protection (F082-US6).
    ///
    /// SECURITY: Returns an independently-generated secret that is NOT derived
    /// from the JWT signing key. This prevents key material reuse vulnerabilities.
    #[must_use] 
    pub fn csrf_secret(&self) -> &[u8] {
        &self.csrf_secret
    }

    /// Check if running in production environment.
    ///
    /// Returns `true` if the issuer URL indicates a production deployment
    /// (i.e., not localhost). Used to determine cookie security flags.
    #[inline]
    #[must_use] 
    pub fn is_production(&self) -> bool {
        !self.issuer.starts_with("http://localhost")
    }
}

/// Create the OAuth2/OIDC router with all endpoints.
///
/// # Endpoints
///
/// ## Public Endpoints (no auth required)
///
/// - `GET /.well-known/openid-configuration` - OIDC Discovery document
/// - `GET /.well-known/jwks.json` - JSON Web Key Set
/// - `GET /oauth/authorize` - Authorization endpoint (redirects to login)
/// - `POST /oauth/token` - Token endpoint (supports `device_code` grant)
/// - `POST /oauth/device/code` - RFC 8628 Device Authorization endpoint
///
/// ## Protected Endpoints (require valid access token)
///
/// - `GET /oauth/userinfo` - `UserInfo` endpoint (requires openid scope)
///
/// ## Admin Endpoints (require admin role)
///
/// - `GET /admin/oauth/clients` - List `OAuth2` clients
/// - `POST /admin/oauth/clients` - Create `OAuth2` client
/// - `GET /admin/oauth/clients/:id` - Get `OAuth2` client by ID
/// - `PUT /admin/oauth/clients/:id` - Update `OAuth2` client
/// - `DELETE /admin/oauth/clients/:id` - Deactivate `OAuth2` client
/// - `POST /admin/oauth/clients/:id/regenerate-secret` - Regenerate client secret
///
/// # Arguments
///
/// * `state` - The OAuth state containing services
///
/// # Returns
///
/// A configured Axum router.
pub fn oauth_router(state: OAuthState) -> Router {
    Router::new()
        // Authorization endpoint
        .route("/authorize", get(authorize_handler))
        .route("/authorize/consent", post(consent_handler))
        // Token endpoint (supports authorization_code, refresh_token, client_credentials, device_code)
        .route("/token", post(token_handler))
        // UserInfo endpoint (protected - will add auth middleware)
        .route("/userinfo", get(userinfo_handler))
        // F084: RFC 7009 Token Revocation (client-authenticated, no JWT auth)
        .route("/revoke", post(revoke_token_handler))
        // F084: RFC 7662 Token Introspection (client-authenticated, no JWT auth)
        .route("/introspect", post(introspect_token_handler))
        // F096: RFC 8628 Device Authorization endpoint
        .route("/device/code", post(device_authorization_handler))
        .with_state(state)
}

/// Create the well-known routes router.
///
/// These routes are mounted at the root level, not under /oauth.
pub fn well_known_router(state: OAuthState) -> Router {
    Router::new()
        .route("/openid-configuration", get(discovery_handler))
        .route("/jwks.json", get(jwks_handler))
        .with_state(state)
}

/// Create the device verification router (F096: RFC 8628 + F112: Login Integration + F117: Storm-2372).
///
/// These routes handle the user-facing device verification flow.
/// This is mounted at `/device` at the root level.
///
/// # Routes
///
/// - `GET /` - Device verification page (enter user code)
/// - `POST /verify` - Verify user code and show approval page
/// - `POST /authorize` - Authorize or deny the device
/// - `GET /login` - F112: Display login form during device flow
/// - `POST /login` - F112: Authenticate user during device flow
/// - `GET /mfa` - F112: Display MFA form during device flow
/// - `POST /login/mfa` - F112: Complete MFA verification during device login
/// - `GET /confirm/:token` - F117: Validate email confirmation token
/// - `POST /resend-confirmation` - F117: Resend confirmation email
///
/// # Note
///
/// These routes render minimal server-side HTML pages as required by RFC 8628.
/// This is the only UI in the API-first platform, necessary for the device code flow.
/// The login endpoints (F112) allow users to authenticate directly during the flow.
/// The confirmation endpoints (F117) implement Storm-2372 remediation via email verification.
pub fn device_router(state: OAuthState) -> Router {
    Router::new()
        // GET /device - Verification page where user enters user_code
        .route("/", get(device_verification_page_handler))
        // POST /device/verify - Verify user code and show approval page
        .route("/verify", post(device_verify_code_handler))
        // POST /device/authorize - User authorizes or denies the device
        .route("/authorize", post(device_authorize_handler))
        // F112: GET /device/login - Display login form
        .route("/login", get(device_login_page_handler))
        // F112: POST /device/login - Authenticate user during device flow
        .route("/login", post(device_login_handler))
        // F112: GET /device/mfa - Display MFA form
        .route("/mfa", get(device_mfa_page_handler))
        // F112: POST /device/login/mfa - Complete MFA verification
        .route("/login/mfa", post(device_mfa_handler))
        // F117: GET /device/confirm/:token - Validate email confirmation token
        .route("/confirm/:token", get(device_confirm_handler))
        // F117: POST /device/resend-confirmation - Resend confirmation email
        .route(
            "/resend-confirmation",
            post(device_resend_confirmation_handler),
        )
        .with_state(state)
}

/// Create the admin routes router.
///
/// These routes require admin authentication.
///
/// # Routes
///
/// - `GET /clients` - List all clients
/// - `POST /clients` - Create a new client
/// - `GET /clients/:id` - Get a client by ID
/// - `PUT /clients/:id` - Update a client
/// - `DELETE /clients/:id` - Deactivate a client (soft delete)
/// - `POST /clients/:id/regenerate-secret` - Regenerate client secret (confidential only)
pub fn admin_oauth_router(state: OAuthState) -> Router {
    Router::new()
        .route("/clients", get(list_clients_handler))
        .route("/clients", post(create_client_handler))
        .route("/clients/:id", get(get_client_handler))
        .route("/clients/:id", put(update_client_handler))
        .route("/clients/:id", delete(delete_client_handler))
        .route(
            "/clients/:id/regenerate-secret",
            post(regenerate_secret_handler),
        )
        // F084: Admin token management endpoints
        .route("/revoke-user", post(admin_revoke_user_handler))
        .route("/active-sessions", get(list_active_sessions_handler))
        .route("/sessions/:token_id", delete(delete_session_handler))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    #[test]
    fn oauth_state_creation() {
        // This test verifies the OAuthState struct can be created
        // Full testing requires database connections
    }
}
