//! Authentication API endpoints for xavyo.
// TODO: Upgrade generic-array to 1.x when aes-gcm supports it
#![allow(deprecated)]
//!
//! This crate provides REST API endpoints for user authentication:
//! - Registration (POST /auth/register)
//! - Login (POST /auth/login)
//! - Token refresh (POST /auth/refresh)
//! - Logout (POST /auth/logout)
//! - Password reset (POST /auth/forgot-password, POST /auth/reset-password)
//! - Email verification (POST /auth/verify-email, POST /auth/resend-verification)
//!
//! # Example
//!
//! ```rust,ignore
//! use xavyo_api_auth::router::auth_router;
//! use axum::Router;
//!
//! let app = Router::new()
//!     .nest("/auth", auth_router(state));
//! ```

pub mod crypto;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod router;
pub mod services;

// Re-export public API
pub use crypto::{TotpEncryption, TotpEncryptionError};
pub use error::{ApiAuthError, ProblemDetails};
pub use handlers::revocation_router;
pub use middleware::{
    api_key_auth_middleware, jwt_auth_middleware, session_activity_middleware, ApiKeyContext,
    ApiKeyError, EmailRateLimiter, JwtPublicKey, JwtPublicKeys, RateLimitConfig, RateLimiter,
};
pub use models::{
    ForgotPasswordRequest, ForgotPasswordResponse, LoginRequest, LogoutRequest, RefreshRequest,
    RegisterRequest, RegisterResponse, ResendVerificationRequest, ResendVerificationResponse,
    ResetPasswordRequest, ResetPasswordResponse, RevokeAllSessionsResponse, SessionInfoResponse,
    SessionListResponse, SessionPolicyResponse, TokenResponse, UpdateSessionPolicyRequest,
    VerifyEmailRequest, VerifyEmailResponse,
};
pub use router::{
    admin_invite_public_router, admin_invite_router, admin_router, alerts_router, audit_router,
    auth_router, branding_router, delegation_router, devices_router, key_management_router,
    me_router, mfa_router, org_security_policy_router, passwordless_admin_router,
    passwordless_router, public_auth_router, public_router, users_router, AuthState,
};
pub use services::{
    generate_email_verification_token,
    generate_password_reset_token,
    hash_token,
    normalize_email,
    parse_user_agent,
    validate_email,
    validate_password,
    verify_token_hash_constant_time,
    // Audit service exports (F112)
    AuditService,
    AuthService,
    DeviceInfo,
    EmailConfig,
    EmailError,
    EmailSender,
    // Risk enforcement exports (F073)
    EnforcementAction,
    EnforcementDecision,
    // Security Hardening exports (F082)
    KeyService,
    KeyServiceError,
    // Lockout service exports (F112)
    LockoutService,
    LockoutStatus,
    LoginRiskContext,
    MfaService,
    MfaStatus,
    MockEmailSender,
    RecordLoginAttemptInput,
    RevocationCache,
    RiskEnforcementError,
    RiskEnforcementService,
    SecurityAudit,
    SecurityEventType,
    SessionService,
    SmtpEmailSender,
    TokenConfig,
    TokenService,
    TotpSetupData,
    // WebAuthn exports (F032)
    WebAuthnConfig,
    WebAuthnService,
    WEBAUTHN_LOCKOUT_MINUTES,
    WEBAUTHN_MAX_FAILED_ATTEMPTS,
};

#[cfg(feature = "aws-ses")]
pub use services::{SesEmailConfig, SesEmailSender};
