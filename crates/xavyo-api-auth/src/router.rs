//! Authentication API router configuration.
//!
//! Configures routes for the authentication endpoints:
//! - POST /auth/signup (F111)
//! - POST /auth/register
//! - POST /auth/login
//! - POST /auth/refresh
//! - POST /auth/logout
//! - POST /auth/forgot-password
//! - POST /auth/reset-password
//! - POST /auth/verify-email
//! - POST /auth/resend-verification
//! - PUT /auth/password - Change password
//! - POST /auth/mfa/totp/setup
//! - POST /auth/mfa/totp/verify-setup
//! - POST /auth/mfa/totp/verify
//! - DELETE /auth/mfa/totp
//! - POST /auth/mfa/recovery/generate
//! - POST /auth/mfa/recovery/verify
//! - POST /auth/mfa/webauthn/register/start (F032)
//! - POST /auth/mfa/webauthn/register/finish (F032)
//! - POST /auth/mfa/webauthn/authenticate/start (F032)
//! - POST /auth/mfa/webauthn/authenticate/finish (F032)
//! - GET /auth/mfa/webauthn/credentials (F032)
//! - PATCH /auth/mfa/webauthn/credentials/:id (F032)
//! - DELETE /auth/mfa/webauthn/credentials/:id (F032)
//! - GET /users/me/mfa/status
//! - GET /users/me/sessions
//! - DELETE /users/me/sessions/:id
//! - DELETE /users/me/sessions
//! - GET /admin/tenants/:id/session-policy
//! - PUT /admin/tenants/:id/session-policy
//! - GET /admin/tenants/:id/password-policy
//! - PUT /admin/tenants/:id/password-policy
//! - GET /admin/tenants/:id/lockout-policy
//! - PUT /admin/tenants/:id/lockout-policy
//! - GET /admin/tenants/:id/mfa-policy (F022)
//! - PUT /admin/tenants/:id/mfa-policy (F022)
//! - GET /`admin/users/:user_id/mfa/status` (F022)
//! - POST /admin/users/:id/unlock
//! - GET /audit/login-history (F025)
//! - GET /security-alerts (F025)
//! - POST /security-alerts/:id/acknowledge (F025)
//! - GET /admin/audit/login-attempts (F025)
//! - GET /admin/audit/login-attempts/stats (F025)
//! - GET /admin/ip-restrictions/settings (F028)
//! - PUT /admin/ip-restrictions/settings (F028)
//! - GET /admin/ip-restrictions/rules (F028)
//! - POST /admin/ip-restrictions/rules (F028)
//! - GET /admin/ip-restrictions/rules/:id (F028)
//! - PUT /admin/ip-restrictions/rules/:id (F028)
//! - DELETE /admin/ip-restrictions/rules/:id (F028)
//! - POST /admin/ip-restrictions/validate (F028)
//! - GET /admin/delegation/permissions (F029)
//! - GET /admin/delegation/role-templates (F029)
//! - POST /admin/delegation/role-templates (F029)
//! - GET /admin/delegation/role-templates/:id (F029)
//! - PUT /admin/delegation/role-templates/:id (F029)
//! - DELETE /admin/delegation/role-templates/:id (F029)
//! - GET /admin/delegation/assignments (F029)
//! - POST /admin/delegation/assignments (F029)
//! - GET /admin/delegation/assignments/:id (F029)
//! - DELETE /admin/delegation/assignments/:id (F029)
//! - GET /admin/delegation/audit-log (F029)
//! - GET /admin/branding (F030)
//! - PUT /admin/branding (F030)
//! - POST /admin/branding/assets/upload (F030)
//! - GET /admin/branding/assets (F030)
//! - GET /admin/branding/assets/:id (F030)
//! - DELETE /admin/branding/assets/:id (F030)
//! - GET /admin/branding/email-templates (F030)
//! - GET /admin/branding/email-templates/:type (F030)
//! - PUT /admin/branding/email-templates/:type (F030)
//! - POST /admin/branding/email-templates/:type/preview (F030)
//! - POST /admin/branding/email-templates/:type/reset (F030)
//! - GET /`public/branding/:tenant_slug` (F030)
//! - POST /auth/passwordless/magic-link (F079)
//! - POST /auth/passwordless/magic-link/verify (F079)
//! - POST /auth/passwordless/email-otp (F079)
//! - POST /auth/passwordless/email-otp/verify (F079)
//! - GET /auth/passwordless/methods (F079)
//! - GET /auth/passwordless/policy (F079)
//! - PUT /auth/passwordless/policy (F079)
//! - POST /admin/invitations (F-ADMIN-INVITE)
//! - GET /admin/invitations (F-ADMIN-INVITE)
//! - POST /admin/invitations/:id/resend (F-ADMIN-INVITE)
//! - DELETE /admin/invitations/:id (F-ADMIN-INVITE)
//! - POST /admin/invitations/accept (F-ADMIN-INVITE, public)

use crate::error::ApiAuthError;
use crate::handlers::{
    // F-ADMIN-INVITE handlers
    accept_invitation_handler,
    acknowledge_alert,
    admin_list_user_devices,
    // F032 WebAuthn admin handlers
    admin_list_webauthn_credentials,
    admin_revoke_device,
    admin_revoke_webauthn_credential,
    // F-ADMIN-INVITE handlers
    cancel_invitation_handler,
    // F029 handlers
    check_permission,
    create_assignment,
    create_invitation_handler,
    // F028 handlers
    create_ip_rule,
    // F-066 Organization policy handlers
    create_org_policy,
    create_role_template,
    // F030 handlers
    delete_asset,
    delete_ip_rule,
    delete_org_policy,
    delete_role_template,
    // F032 WebAuthn handlers
    delete_webauthn_credential,
    disable_mfa,
    finish_webauthn_authentication,
    finish_webauthn_registration,
    forgot_password_handler,
    get_admin_login_attempts,
    get_asset,
    get_assignment,
    get_audit_log,
    // F079 Passwordless handlers
    get_available_methods_handler,
    get_branding,
    get_device_policy,
    // F-066 Organization policy handlers
    get_effective_org_policy,
    get_effective_user_policy,
    get_ip_rule,
    get_ip_settings,
    get_lockout_policy,
    get_login_attempt_stats,
    get_login_history,
    get_me_devices,
    // F027 handlers
    get_me_mfa_status,
    get_me_sessions,
    get_mfa_policy,
    get_mfa_status,
    get_org_policy,
    get_password_policy,
    get_passwordless_policy_handler,
    get_permissions_by_category,
    get_profile,
    get_public_branding,
    get_role_template,
    get_security_alerts,
    get_security_overview,
    get_session_policy,
    get_template,
    get_user_mfa_status,
    get_user_permissions,
    get_webauthn_policy,
    initiate_email_change,
    list_assets,
    list_assignments,
    list_devices,
    list_invitations_handler,
    list_ip_rules,
    list_org_policies,
    list_permissions,
    list_role_templates,
    list_sessions,
    list_templates,
    list_webauthn_credentials,
    login_handler,
    logout_handler,
    me_password_change,
    password_change_handler,
    preview_template,
    refresh_handler,
    regenerate_recovery_codes,
    register_handler,
    rename_device,
    request_email_otp_handler,
    request_magic_link_handler,
    resend_invitation_handler,
    resend_verification_handler,
    reset_password_handler,
    reset_template,
    revoke_all_sessions,
    revoke_assignment,
    revoke_device,
    revoke_session,
    setup_totp,
    // F111 Self-service signup handler
    signup_handler,
    start_webauthn_authentication,
    start_webauthn_registration,
    trust_device,
    admin_reset_password,
    unlock_user,
    untrust_device,
    update_branding,
    update_device_policy,
    update_ip_rule,
    update_ip_settings,
    update_lockout_policy,
    update_mfa_policy,
    update_password_policy,
    update_passwordless_policy_handler,
    update_profile,
    update_role_template,
    update_session_policy,
    update_template,
    update_webauthn_credential,
    update_webauthn_policy,
    upload_asset,
    upsert_org_policy,
    validate_ip,
    validate_org_policy,
    verify_email_change,
    verify_email_handler,
    verify_email_otp_handler,
    verify_magic_link_handler,
    verify_recovery_code,
    verify_totp,
    verify_totp_setup,
};
use crate::middleware::{
    rate_limit_middleware, require_super_admin_middleware, sensitive_rate_limiter,
    signup_rate_limit_middleware, signup_rate_limiter, AllowPartialToken, EmailRateLimiter,
    RateLimiter,
};
use crate::services::{
    AdminInviteService, AlertService, AssetService, AssetStorage, AuditService, AuthService,
    BrandingService, DelegatedAdminService, DevicePolicyService, DeviceService, EmailChangeService,
    EmailSender, EmailTemplateService, IpRestrictionService, LocalAssetStorage, LockoutService,
    MfaService, PasswordPolicyService, PasswordlessRateLimiter, PasswordlessService,
    ProfileService, RiskEnforcementService, SessionService, TokenConfig, TokenService,
    WebAuthnService,
};
use axum::{
    middleware,
    routing::{delete, get, post, put},
    Extension, Router,
};
use sqlx::PgPool;
use std::sync::Arc;

/// Application state for authentication routes.
#[derive(Clone)]
pub struct AuthState {
    /// Database connection pool.
    pub pool: PgPool,
    /// Authentication service.
    pub auth_service: Arc<AuthService>,
    /// Token service for JWT and refresh token management.
    pub token_service: Arc<TokenService>,
    /// Rate limiter for login endpoint.
    pub rate_limiter: Arc<RateLimiter>,
    /// Rate limiter for signup endpoint (F111).
    pub signup_rate_limiter: Arc<RateLimiter>,
    /// Email rate limiter for password reset and verification endpoints.
    pub email_rate_limiter: Arc<EmailRateLimiter>,
    /// Rate limiter for sensitive endpoints (MFA, password change, email change).
    pub sensitive_rate_limiter: Arc<RateLimiter>,
    /// Email sender service.
    pub email_sender: Arc<dyn EmailSender>,
    /// MFA service for TOTP authentication.
    pub mfa_service: Arc<MfaService>,
    /// Session service for session management.
    pub session_service: Arc<SessionService>,
    /// Password policy service for password validation.
    pub password_policy_service: Arc<PasswordPolicyService>,
    /// Lockout service for account lockout management.
    pub lockout_service: Arc<LockoutService>,
    /// Audit service for login history (F025).
    pub audit_service: Arc<AuditService>,
    /// Alert service for security alerts (F025).
    pub alert_service: Arc<AlertService>,
    /// Device service for device management (F026).
    pub device_service: Arc<DeviceService>,
    /// Device policy service for device policies (F026).
    pub device_policy_service: Arc<DevicePolicyService>,
    /// Profile service for self-service profile (F027).
    pub profile_service: Arc<ProfileService>,
    /// Email change service for email change flow (F027).
    pub email_change_service: Arc<EmailChangeService>,
    /// IP restriction service for IP-based access control (F028).
    pub ip_restriction_service: Arc<IpRestrictionService>,
    /// Delegated admin service for permission management (F029).
    pub delegated_admin_service: Arc<DelegatedAdminService>,
    /// Branding service for tenant branding (F030).
    pub branding_service: Arc<BrandingService>,
    /// Asset service for branding assets (F030).
    pub asset_service: Arc<AssetService>,
    /// Email template service for email customization (F030).
    pub email_template_service: Arc<EmailTemplateService>,
    /// `WebAuthn` service for FIDO2/WebAuthn MFA (F032).
    pub webauthn_service: Arc<WebAuthnService>,
    /// Risk enforcement service for adaptive authentication (F073).
    pub risk_enforcement_service: Arc<RiskEnforcementService>,
    /// Passwordless authentication service (F079).
    pub passwordless_service: Arc<PasswordlessService>,
    /// Admin invitation service (F-ADMIN-INVITE).
    pub admin_invite_service: Arc<AdminInviteService>,
    /// Frontend base URL for invitation links.
    pub frontend_base_url: String,
    /// Token configuration.
    pub token_config: TokenConfig,
}

impl AuthState {
    /// Create a new auth state.
    ///
    /// # Errors
    ///
    /// Returns an error if `WebAuthn` service creation fails (e.g., invalid configuration).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: PgPool,
        auth_service: AuthService,
        token_service: TokenService,
        rate_limiter: RateLimiter,
        email_rate_limiter: EmailRateLimiter,
        email_sender: Arc<dyn EmailSender>,
        mfa_service: MfaService,
        session_service: SessionService,
        token_config: TokenConfig,
    ) -> Result<Self, ApiAuthError> {
        // Create password policy and lockout services
        let password_policy_service = Arc::new(PasswordPolicyService::new(pool.clone()));
        let lockout_service = Arc::new(LockoutService::new(pool.clone()));
        // Create audit and alert services (F025)
        let audit_service = Arc::new(AuditService::new(pool.clone()));
        let alert_service = Arc::new(AlertService::new(pool.clone()));
        // Create device services (F026)
        let device_service = Arc::new(DeviceService::new(pool.clone()));
        let device_policy_service = Arc::new(DevicePolicyService::new(pool.clone()));
        // Frontend base URL for email links (used by email change and admin invite)
        let frontend_base_url = std::env::var("FRONTEND_BASE_URL")
            .unwrap_or_else(|_| "https://app.xavyo.net".to_string());
        // Create profile services (F027)
        let profile_service = Arc::new(ProfileService::new(pool.clone()));
        let email_change_service = Arc::new(EmailChangeService::new(
            pool.clone(),
            frontend_base_url.clone(),
        ));
        // Create IP restriction service (F028)
        let ip_restriction_service = Arc::new(IpRestrictionService::new(pool.clone()));
        // Create delegated admin service (F029)
        let delegated_admin_service = Arc::new(DelegatedAdminService::new(pool.clone()));
        // Create branding services (F030)
        let branding_service = Arc::new(BrandingService::new(pool.clone()));
        let asset_storage: Arc<dyn AssetStorage> =
            Arc::new(LocalAssetStorage::new("data/assets", "/assets"));
        let asset_service = Arc::new(AssetService::new(pool.clone(), asset_storage));
        let email_template_service = Arc::new(EmailTemplateService::new(pool.clone()));
        // Create WebAuthn service (F032)
        let webauthn_service = Arc::new(WebAuthnService::from_env(pool.clone())?);
        // Create risk enforcement service (F073)
        let risk_enforcement_service = Arc::new(RiskEnforcementService::new(pool.clone()));

        // Create signup rate limiter (F111)
        let signup_limiter = signup_rate_limiter();

        // Create sensitive endpoint rate limiter (MFA, password change, email change)
        let sensitive_limiter = sensitive_rate_limiter();

        // Create passwordless service (F079)
        let token_service_arc = Arc::new(token_service);
        let passwordless_rate_limiter =
            Arc::new(parking_lot::Mutex::new(PasswordlessRateLimiter::new()));
        let passwordless_service = Arc::new(PasswordlessService::new(
            pool.clone(),
            email_sender.clone(),
            token_service_arc.clone(),
            passwordless_rate_limiter,
        ));

        // Create admin invite service (F-ADMIN-INVITE)
        let admin_invite_service = Arc::new(AdminInviteService::new(
            pool.clone(),
            email_sender.clone(),
            frontend_base_url.clone(),
        ));

        Ok(Self {
            pool,
            auth_service: Arc::new(auth_service),
            token_service: token_service_arc,
            rate_limiter: Arc::new(rate_limiter),
            signup_rate_limiter: Arc::new(signup_limiter),
            email_rate_limiter: Arc::new(email_rate_limiter),
            sensitive_rate_limiter: Arc::new(sensitive_limiter),
            email_sender,
            mfa_service: Arc::new(mfa_service),
            session_service: Arc::new(session_service),
            password_policy_service,
            lockout_service,
            audit_service,
            alert_service,
            device_service,
            device_policy_service,
            profile_service,
            email_change_service,
            ip_restriction_service,
            delegated_admin_service,
            branding_service,
            asset_service,
            email_template_service,
            webauthn_service,
            risk_enforcement_service,
            passwordless_service,
            admin_invite_service,
            frontend_base_url,
            token_config,
        })
    }
}

/// Create the authentication router for tenant-required endpoints.
///
/// These routes require `TenantLayer` because handlers extract `Extension<TenantId>`.
///
/// # Endpoints
///
/// - `POST /auth/login` - User login (rate limited)
/// - `POST /auth/register` - User registration
/// - `POST /auth/forgot-password` - Initiate password reset (email rate limited)
/// - `POST /auth/resend-verification` - Resend verification email (email rate limited)
/// - `POST /auth/reset-password` - Complete password reset
/// - `POST /auth/verify-email` - Verify email address
/// - `PUT /auth/password` - Change password
pub fn auth_router(state: AuthState) -> Router {
    // Login route with rate limiting
    let login_route = Router::new()
        .route("/login", post(login_handler))
        .layer(middleware::from_fn(rate_limit_middleware))
        .layer(Extension(state.rate_limiter.clone()));

    // Email-rate-limited routes (forgot-password, resend-verification)
    let email_rate_limited_routes = Router::new()
        .route("/forgot-password", post(forgot_password_handler))
        .route("/resend-verification", post(resend_verification_handler))
        .layer(Extension(state.email_rate_limiter.clone()))
        .layer(Extension(state.email_sender.clone()));

    // Register route (needs email sender for verification)
    let register_route = Router::new()
        .route("/register", post(register_handler))
        .layer(Extension(state.email_sender.clone()));

    // Rate-limited password change route (5 attempts/min/IP)
    let password_change_route = Router::new()
        .route("/password", put(password_change_handler))
        .layer(middleware::from_fn(rate_limit_middleware))
        .layer(Extension(state.sensitive_rate_limiter.clone()));

    // Routes without rate limiting
    let other_routes = Router::new()
        .route("/reset-password", post(reset_password_handler))
        .route("/verify-email", post(verify_email_handler));

    Router::new()
        .merge(login_route)
        .merge(email_rate_limited_routes)
        .merge(register_route)
        .merge(password_change_route)
        .merge(other_routes)
        .layer(Extension(state.pool))
        .layer(Extension(state.auth_service))
        .layer(Extension(state.token_service))
        .layer(Extension(state.mfa_service))
        .layer(Extension(state.webauthn_service))
        .layer(Extension(state.session_service))
        .layer(Extension(state.password_policy_service))
        .layer(Extension(state.lockout_service))
        .layer(Extension(state.audit_service))
        .layer(Extension(state.alert_service))
        .layer(Extension(state.device_service))
        .layer(Extension(state.device_policy_service))
        .layer(Extension(state.risk_enforcement_service))
}

/// Create the public authentication router for endpoints that don't require a tenant header.
///
/// These routes don't need `TenantLayer` because:
/// - `signup_handler` hardcodes `SYSTEM_TENANT_ID`
/// - `refresh_handler` extracts tenant from the refresh token
/// - `logout_handler` extracts tenant from the refresh token
///
/// # Endpoints
///
/// - `POST /auth/signup` - Self-service signup (F111, rate limited)
/// - `POST /auth/refresh` - Token refresh
/// - `POST /auth/logout` - User logout
pub fn public_auth_router(state: AuthState) -> Router {
    // Signup route for self-service system tenant signup (F111)
    // Rate limited to 10 requests per IP per hour
    let signup_route = Router::new()
        .route("/signup", post(signup_handler))
        .layer(middleware::from_fn(signup_rate_limit_middleware))
        .layer(Extension(state.signup_rate_limiter.clone()))
        .layer(Extension(state.email_sender.clone()));

    let other_routes = Router::new()
        .route("/refresh", post(refresh_handler))
        .route("/logout", post(logout_handler));

    Router::new()
        .merge(signup_route)
        .merge(other_routes)
        .layer(Extension(state.pool))
        .layer(Extension(state.auth_service))
        .layer(Extension(state.token_service))
        .layer(Extension(state.mfa_service))
        .layer(Extension(state.webauthn_service))
        .layer(Extension(state.session_service))
        .layer(Extension(state.password_policy_service))
        .layer(Extension(state.lockout_service))
        .layer(Extension(state.audit_service))
        .layer(Extension(state.alert_service))
        .layer(Extension(state.device_service))
        .layer(Extension(state.device_policy_service))
        .layer(Extension(state.risk_enforcement_service))
}

/// Create the MFA router for TOTP and `WebAuthn` authentication (F022, F032).
///
/// JWT authentication is applied internally with `AllowPartialToken` on verification routes.
/// Callers should NOT apply `jwt_auth_middleware` externally — pass the JWT public key instead.
pub fn mfa_router(state: AuthState, jwt_public_key: String) -> Router {
    // Rate-limited verification routes (brute-force protection: 5 attempts/min/IP)
    // These routes accept partial (MFA) tokens via AllowPartialToken marker.
    // Layer order (outer→inner): AllowPartialToken → jwt_auth → rate_limit → handler
    // AllowPartialToken must be outermost so it's set before jwt_auth_middleware checks it.
    let verification_routes = Router::new()
        .route("/totp/verify", post(verify_totp))
        .route("/recovery/verify", post(verify_recovery_code))
        .route(
            "/webauthn/authenticate/start",
            post(start_webauthn_authentication),
        )
        .route(
            "/webauthn/authenticate/finish",
            post(finish_webauthn_authentication),
        )
        .layer(middleware::from_fn(rate_limit_middleware))
        .layer(Extension(state.sensitive_rate_limiter.clone()))
        .layer(middleware::from_fn(
            crate::middleware::jwt_auth::jwt_auth_middleware,
        ))
        .layer(Extension(AllowPartialToken));

    // Management routes (require full auth, no additional rate limiting)
    let management_routes = Router::new()
        .route("/totp/setup", post(setup_totp))
        .route("/totp/verify-setup", post(verify_totp_setup))
        .route("/totp", delete(disable_mfa))
        .route("/recovery/generate", post(regenerate_recovery_codes))
        .route(
            "/webauthn/register/start",
            post(start_webauthn_registration),
        )
        .route(
            "/webauthn/register/finish",
            post(finish_webauthn_registration),
        )
        .route("/webauthn/credentials", get(list_webauthn_credentials))
        .route(
            "/webauthn/credentials/:credential_id",
            axum::routing::patch(update_webauthn_credential).delete(delete_webauthn_credential),
        )
        .layer(middleware::from_fn(
            crate::middleware::jwt_auth::jwt_auth_middleware,
        ));

    Router::new()
        .merge(verification_routes)
        .merge(management_routes)
        .layer(Extension(crate::middleware::jwt_auth::JwtPublicKey(
            jwt_public_key,
        )))
        .layer(Extension(state.mfa_service.clone()))
        .layer(Extension(state.webauthn_service.clone()))
        .layer(Extension(state.pool.clone()))
        .layer(Extension(state.audit_service.clone()))
        .layer(Extension(state.alert_service.clone()))
        .with_state(state)
}

/// Create the users router with MFA, session, and device endpoints.
pub fn users_router(state: AuthState) -> Router {
    Router::new()
        .route("/me/mfa/status", get(get_mfa_status))
        .route(
            "/me/sessions",
            get(list_sessions).delete(revoke_all_sessions),
        )
        .route("/me/sessions/:id", delete(revoke_session))
        .layer(Extension(state.session_service.clone()))
        .layer(Extension(state.mfa_service.clone()))
        .layer(Extension(state.pool.clone()))
        .with_state(state)
}

/// Create the devices router for user device management (F026).
pub fn devices_router(state: AuthState) -> Router {
    Router::new()
        .route("/", get(list_devices))
        .route("/:id", put(rename_device).delete(revoke_device))
        .route("/:id/trust", post(trust_device).delete(untrust_device))
        .layer(Extension(state.device_service.clone()))
        .layer(Extension(state.device_policy_service.clone()))
        .layer(Extension(state.pool.clone()))
        .with_state(state)
}

/// Create the admin router with session policy, password policy, lockout policy, user unlock, audit, and device endpoints.
pub fn admin_router(state: AuthState) -> Router {
    Router::new()
        .route(
            "/tenants/:id/session-policy",
            get(get_session_policy).put(update_session_policy),
        )
        .route(
            "/tenants/:id/password-policy",
            get(get_password_policy).put(update_password_policy),
        )
        .route(
            "/tenants/:id/lockout-policy",
            get(get_lockout_policy).put(update_lockout_policy),
        )
        // MFA policy endpoint (F022)
        .route(
            "/tenants/:id/mfa-policy",
            get(get_mfa_policy).put(update_mfa_policy),
        )
        // WebAuthn policy endpoint (F032)
        .route(
            "/tenants/:id/webauthn-policy",
            get(get_webauthn_policy).put(update_webauthn_policy),
        )
        // Device policy endpoint (F026)
        .route(
            "/tenants/:id/device-policy",
            get(get_device_policy).put(update_device_policy),
        )
        .route("/users/:id/unlock", post(unlock_user))
        .route("/users/:id/reset-password", post(admin_reset_password))
        // Admin MFA status endpoint (F022)
        .route("/users/:user_id/mfa/status", get(get_user_mfa_status))
        // Admin device management endpoints (F026)
        .route("/users/:user_id/devices", get(admin_list_user_devices))
        .route(
            "/users/:user_id/devices/:device_id",
            delete(admin_revoke_device),
        )
        // Admin WebAuthn credential management endpoints (F032)
        .route(
            "/users/:user_id/webauthn/credentials",
            get(admin_list_webauthn_credentials),
        )
        .route(
            "/users/:user_id/webauthn/credentials/:credential_id",
            delete(admin_revoke_webauthn_credential),
        )
        // Audit endpoints (F025)
        .route("/audit/login-attempts", get(get_admin_login_attempts))
        .route("/audit/login-attempts/stats", get(get_login_attempt_stats))
        // IP restriction endpoints (F028)
        .route(
            "/ip-restrictions/settings",
            get(get_ip_settings).put(update_ip_settings),
        )
        .route(
            "/ip-restrictions/rules",
            get(list_ip_rules).post(create_ip_rule),
        )
        .route(
            "/ip-restrictions/rules/:id",
            get(get_ip_rule).put(update_ip_rule).delete(delete_ip_rule),
        )
        .route("/ip-restrictions/validate", post(validate_ip))
        .layer(Extension(state.session_service.clone()))
        .layer(Extension(state.password_policy_service.clone()))
        .layer(Extension(state.lockout_service.clone()))
        .layer(Extension(state.audit_service.clone()))
        .layer(Extension(state.device_service.clone()))
        .layer(Extension(state.device_policy_service.clone()))
        .layer(Extension(state.ip_restriction_service.clone()))
        .layer(Extension(state.webauthn_service.clone()))
        .layer(Extension(state.pool.clone()))
        .with_state(state)
}

/// Create the audit router for user login history (F025).
pub fn audit_router(state: AuthState) -> Router {
    Router::new()
        .route("/login-history", get(get_login_history))
        .layer(Extension(state.audit_service.clone()))
        .layer(Extension(state.pool.clone()))
        .with_state(state)
}

/// Create the security alerts router (F025).
pub fn alerts_router(state: AuthState) -> Router {
    Router::new()
        .route("/", get(get_security_alerts))
        .route("/:id/acknowledge", post(acknowledge_alert))
        .layer(Extension(state.alert_service.clone()))
        .layer(Extension(state.pool.clone()))
        .with_state(state)
}

/// Create the self-service profile router for /me endpoints (F027).
///
/// # Endpoints
///
/// - `GET /me/profile` - Get current user's profile
/// - `PUT /me/profile` - Update current user's profile
/// - `POST /me/email/change` - Initiate email change
/// - `POST /me/email/verify` - Verify email change
/// - `PUT /me/password` - Change password
/// - `GET /me/security` - Get security overview
/// - `GET /me/mfa` - Get MFA status
/// - `GET /me/sessions` - List active sessions (alias)
/// - `GET /me/devices` - List devices (alias)
pub fn me_router(state: AuthState) -> Router {
    // Rate-limited email change routes (5 attempts/min/IP)
    let email_change_routes = Router::new()
        .route("/email/change", post(initiate_email_change))
        .route("/email/verify", post(verify_email_change))
        .layer(middleware::from_fn(rate_limit_middleware))
        .layer(Extension(state.sensitive_rate_limiter.clone()));

    Router::new()
        // Profile endpoints
        .route("/profile", get(get_profile).put(update_profile))
        // Password change endpoint
        .route("/password", put(me_password_change))
        // Email change endpoints (rate limited)
        .merge(email_change_routes)
        // Security overview endpoints
        .route("/security", get(get_security_overview))
        .route("/mfa", get(get_me_mfa_status))
        // Shortcut endpoints for sessions and devices
        .route("/sessions", get(get_me_sessions))
        .route("/devices", get(get_me_devices))
        .layer(Extension(state.profile_service.clone()))
        .layer(Extension(state.email_change_service.clone()))
        .layer(Extension(state.email_sender.clone()))
        .layer(Extension(state.mfa_service.clone()))
        .layer(Extension(state.webauthn_service.clone()))
        .layer(Extension(state.session_service.clone()))
        .layer(Extension(state.device_service.clone()))
        .layer(Extension(state.alert_service.clone()))
        .layer(Extension(state.password_policy_service.clone()))
        .layer(Extension(state.pool.clone()))
        .with_state(state)
}

/// Create the delegated administration router (F029).
///
/// # Endpoints
///
/// Permissions:
/// - `GET /delegation/permissions` - List all permissions
/// - `GET /delegation/permissions/:category` - Get permissions by category
///
/// Role Templates:
/// - `GET /delegation/role-templates` - List role templates
/// - `POST /delegation/role-templates` - Create role template
/// - `GET /delegation/role-templates/:id` - Get role template
/// - `PUT /delegation/role-templates/:id` - Update role template
/// - `DELETE /delegation/role-templates/:id` - Delete role template
///
/// Assignments:
/// - `GET /delegation/assignments` - List assignments
/// - `POST /delegation/assignments` - Create assignment
/// - `GET /delegation/assignments/:id` - Get assignment
/// - `DELETE /delegation/assignments/:id` - Revoke assignment
///
/// Users:
/// - `GET /delegation/users/:user_id/permissions` - Get user's effective permissions
///
/// Audit:
/// - `GET /delegation/audit-log` - Get audit log
///
/// Utilities:
/// - `POST /delegation/check-permission` - Check if user has permission
pub fn delegation_router(state: AuthState) -> Router {
    Router::new()
        // Permission endpoints
        .route("/permissions", get(list_permissions))
        .route("/permissions/:category", get(get_permissions_by_category))
        // Role template endpoints
        .route(
            "/role-templates",
            get(list_role_templates).post(create_role_template),
        )
        .route(
            "/role-templates/:id",
            get(get_role_template)
                .put(update_role_template)
                .delete(delete_role_template),
        )
        // Assignment endpoints
        .route(
            "/assignments",
            get(list_assignments).post(create_assignment),
        )
        .route(
            "/assignments/:id",
            get(get_assignment).delete(revoke_assignment),
        )
        // User effective permissions
        .route("/users/:user_id/permissions", get(get_user_permissions))
        // Audit log
        .route("/audit-log", get(get_audit_log))
        // Utility endpoints
        .route("/check-permission", post(check_permission))
        // Apply super_admin requirement to all delegation endpoints
        .layer(middleware::from_fn(require_super_admin_middleware))
        .layer(Extension(state.delegated_admin_service.clone()))
        .layer(Extension(state.pool.clone()))
        .with_state(state)
}

/// Create the branding router for tenant branding management (F030).
///
/// Requires `super_admin` role for all endpoints.
///
/// # Endpoints
///
/// Branding Configuration:
/// - `GET /branding` - Get current branding
/// - `PUT /branding` - Update branding
///
/// Assets:
/// - `POST /branding/assets/upload` - Upload asset
/// - `GET /branding/assets` - List assets
/// - `GET /branding/assets/:id` - Get asset details
/// - `DELETE /branding/assets/:id` - Delete asset
///
/// Email Templates:
/// - `GET /branding/email-templates` - List templates
/// - `GET /branding/email-templates/:type` - Get template
/// - `PUT /branding/email-templates/:type` - Update template
/// - `POST /branding/email-templates/:type/preview` - Preview template
/// - `POST /branding/email-templates/:type/reset` - Reset template to default
pub fn branding_router(state: AuthState) -> Router {
    Router::new()
        // Branding configuration endpoints
        .route("/", get(get_branding).put(update_branding))
        // Asset endpoints
        .route("/assets/upload", post(upload_asset))
        .route("/assets", get(list_assets))
        .route("/assets/:id", get(get_asset).delete(delete_asset))
        // Email template endpoints
        .route("/email-templates", get(list_templates))
        .route(
            "/email-templates/:template_type",
            get(get_template).put(update_template),
        )
        .route(
            "/email-templates/:template_type/preview",
            post(preview_template),
        )
        .route(
            "/email-templates/:template_type/reset",
            post(reset_template),
        )
        // Apply super_admin requirement to all branding endpoints
        .layer(middleware::from_fn(require_super_admin_middleware))
        .layer(Extension(state.branding_service.clone()))
        .layer(Extension(state.asset_service.clone()))
        .layer(Extension(state.email_template_service.clone()))
        .layer(Extension(state.pool.clone()))
        .with_state(state)
}

/// Create the passwordless authentication router (F079).
///
/// Provides two groups of routes:
/// - **Public routes** (`TenantLayer` only, no JWT): request/verify magic link and email OTP,
///   plus GET /methods for login UI.
/// - **Admin routes** (JWT + admin role): GET/PUT /policy for tenant policy management.
///
/// # Endpoints
///
/// Public (no JWT):
/// - `POST /passwordless/magic-link` — Request a magic link
/// - `POST /passwordless/magic-link/verify` — Verify a magic link token
/// - `POST /passwordless/email-otp` — Request an email OTP
/// - `POST /passwordless/email-otp/verify` — Verify an email OTP
/// - `GET /passwordless/methods` — Get available methods for login UI
///
/// Admin (JWT + admin role):
/// - `GET /passwordless/policy` — Get tenant passwordless policy
/// - `PUT /passwordless/policy` — Update tenant passwordless policy
pub fn passwordless_router(state: AuthState) -> Router {
    Router::new()
        // Public passwordless endpoints (no JWT required)
        .route("/magic-link", post(request_magic_link_handler))
        .route("/magic-link/verify", post(verify_magic_link_handler))
        .route("/email-otp", post(request_email_otp_handler))
        .route("/email-otp/verify", post(verify_email_otp_handler))
        .route("/methods", get(get_available_methods_handler))
        .layer(Extension(state.passwordless_service.clone()))
        .layer(Extension(state.pool.clone()))
}

/// Create the passwordless policy admin router (F079).
///
/// These routes require JWT authentication with admin role.
///
/// # Endpoints
///
/// - `GET /passwordless/policy` — Get tenant passwordless policy
/// - `PUT /passwordless/policy` — Update tenant passwordless policy
pub fn passwordless_admin_router(state: AuthState) -> Router {
    Router::new()
        .route(
            "/policy",
            get(get_passwordless_policy_handler).put(update_passwordless_policy_handler),
        )
        .layer(Extension(state.pool.clone()))
}

/// Create the public router for unauthenticated endpoints (F030).
///
/// # Endpoints
///
/// - `GET /branding/:tenant_slug` - Get public branding for login page
pub fn public_router(state: AuthState) -> Router {
    Router::new()
        .route("/branding/:tenant_slug", get(get_public_branding))
        .layer(Extension(state.branding_service.clone()))
        .layer(Extension(state.pool.clone()))
        .with_state(state)
}

/// Key management admin router (F082-US5).
///
/// Routes:
/// - POST /rotate — Generate new key, retire current
/// - DELETE /:kid — Revoke a retiring key
/// - GET / — List all keys for the tenant
pub fn key_management_router() -> Router {
    use crate::handlers::key_management::{
        list_keys_handler, revoke_key_handler, rotate_key_handler,
    };

    Router::new()
        .route("/rotate", post(rotate_key_handler))
        .route("/:kid", delete(revoke_key_handler))
        .route("/", get(list_keys_handler))
}

/// Create the admin invitation router (F-ADMIN-INVITE).
///
/// This router contains the authenticated admin endpoints.
///
/// # Endpoints
///
/// - `POST /invitations` - Create new invitation (requires JWT)
/// - `POST /invitations/{id}/resend` - Resend invitation (requires JWT)
/// - `DELETE /invitations/{id}` - Cancel invitation (requires JWT)
/// - `GET /invitations` - List invitations (requires JWT)
pub fn admin_invite_router(state: AuthState) -> Router {
    use crate::handlers::AdminInviteState;

    let invite_state = Arc::new(AdminInviteState {
        service: (*state.admin_invite_service).clone(),
    });

    Router::new()
        // Create and list invitations (authenticated)
        .route(
            "/invitations",
            get(list_invitations_handler).post(create_invitation_handler),
        )
        // Resend invitation (authenticated)
        .route("/invitations/:id/resend", post(resend_invitation_handler))
        // Cancel invitation (authenticated)
        .route("/invitations/:id", delete(cancel_invitation_handler))
        .layer(Extension(state.pool.clone()))
        .with_state(invite_state)
}

/// Create the public admin invitation router (F-ADMIN-INVITE).
///
/// This router contains the public endpoint for accepting invitations.
/// Invitees don't have accounts yet, so this must be unauthenticated.
///
/// # Endpoints
///
/// - `POST /invitations/accept` - Accept invitation and set password (public)
pub fn admin_invite_public_router(state: AuthState) -> Router {
    use crate::handlers::AdminInviteState;

    let invite_state = Arc::new(AdminInviteState {
        service: (*state.admin_invite_service).clone(),
    });

    Router::new()
        .route("/invitations/accept", post(accept_invitation_handler))
        .with_state(invite_state)
}

/// Organization security policy router (F-066).
///
/// Provides routes for managing organization-level security policies
/// with inheritance from parent organizations.
///
/// # Endpoints
///
/// Policy CRUD:
/// - `GET /organizations/:org_id/security-policies` — List policies for organization
/// - `POST /organizations/:org_id/security-policies` — Create policy for organization
/// - `GET /organizations/:org_id/security-policies/:policy_type` — Get specific policy
/// - `PUT /organizations/:org_id/security-policies/:policy_type` — Upsert policy
/// - `DELETE /organizations/:org_id/security-policies/:policy_type` — Delete policy
///
/// Effective Policy Resolution:
/// - `GET /organizations/:org_id/effective-policy/:policy_type` — Get effective policy with source
/// - `GET /users/:user_id/effective-policy/:policy_type` — Get effective policy for user
///
/// Validation:
/// - `POST /organizations/:org_id/security-policies/validate` — Validate policy for conflicts
pub fn org_security_policy_router(state: AuthState) -> Router {
    Router::new()
        // Policy CRUD endpoints
        .route(
            "/organizations/:org_id/security-policies",
            get(list_org_policies).post(create_org_policy),
        )
        .route(
            "/organizations/:org_id/security-policies/validate",
            post(validate_org_policy),
        )
        .route(
            "/organizations/:org_id/security-policies/:policy_type",
            get(get_org_policy)
                .put(upsert_org_policy)
                .delete(delete_org_policy),
        )
        // Effective policy resolution endpoints
        .route(
            "/organizations/:org_id/effective-policy/:policy_type",
            get(get_effective_org_policy),
        )
        .route(
            "/users/:user_id/effective-policy/:policy_type",
            get(get_effective_user_policy),
        )
        .layer(Extension(state.pool.clone()))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::RateLimitConfig;
    use std::time::Duration;

    // Note: Full router tests require database setup
    // These are placeholder tests for the module structure

    #[test]
    fn auth_state_creation() {
        // This test verifies the AuthState struct can be created
        // Full testing requires integration test setup
        let config = RateLimitConfig {
            max_attempts: 5,
            window: Duration::from_secs(60),
        };
        let _limiter = RateLimiter::new(config);
        // AuthState creation requires AuthService and TokenService
        // which need database connections
    }
}
