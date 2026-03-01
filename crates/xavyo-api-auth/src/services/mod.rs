//! Business logic services for authentication.

pub mod admin_invite_service;
pub mod alert_service;
pub mod asset_service;
pub mod hibp;
pub mod asset_storage;
pub mod audit_service;
pub mod auth_service;
pub mod branding_service;
pub mod css_sanitizer;
pub mod delegated_admin_service;
pub mod device_policy_service;
pub mod device_service;
pub mod email_change_service;
pub mod email_service;
pub mod email_template_defaults;
pub mod email_template_service;
pub mod image_validator;
pub mod ip_restriction_service;
pub mod lockout_service;
pub mod mfa_service;
pub mod password_policy_service;
pub mod passwordless_service;
pub mod profile_service;
pub mod risk_enforcement_service;
pub mod session_service;
pub mod token_service;
pub mod user_agent_parser;
pub mod validation;
pub mod validators;
pub mod webauthn_service;

// Security Hardening services (F082)
pub mod key_service;
pub mod revocation_cache;
pub mod security_audit;

pub use alert_service::AlertService;
pub use asset_service::AssetService;
pub use asset_storage::{AssetStorage, LocalAssetStorage};
pub use audit_service::{
    AuditService, FailureReasonCount, HourlyCount, LoginAttemptStats, RecordLoginAttemptInput,
    RecordLoginAttemptResult,
};
pub use auth_service::AuthService;
pub use branding_service::BrandingService;
pub use delegated_admin_service::DelegatedAdminService;
pub use device_policy_service::{DevicePolicy, DevicePolicyService, DEFAULT_TRUST_DURATION_DAYS};
pub use device_service::DeviceService;
pub use email_change_service::{EmailChangeService, EMAIL_CHANGE_TOKEN_VALIDITY_HOURS};
#[cfg(feature = "aws-ses")]
pub mod ses_email_service;

pub use email_service::{EmailConfig, EmailError, EmailSender, MockEmailSender, SmtpEmailSender};
pub use email_template_service::EmailTemplateService;
pub use ip_restriction_service::{
    ip_matches_cidr, validate_cidr, IpRestrictionService, DEFAULT_CACHE_TTL_SECS,
};
pub use lockout_service::{LockoutService, LockoutStatus};
pub use mfa_service::{
    MfaRequirement, MfaService, MfaStatus, TotpSetupData, LOCKOUT_MINUTES, MAX_FAILED_ATTEMPTS,
    SETUP_EXPIRY_MINUTES,
};
pub use password_policy_service::{
    PasswordPolicyError, PasswordPolicyService, PasswordValidationResult as PolicyValidationResult,
    SPECIAL_CHARS as POLICY_SPECIAL_CHARS,
};
pub use passwordless_service::{
    PasswordlessRateLimiter, PasswordlessService, PasswordlessVerifyResult,
};
pub use profile_service::ProfileService;
pub use risk_enforcement_service::{
    EnforcementAction, EnforcementDecision, LoginRiskContext, RiskEnforcementError,
    RiskEnforcementService,
};
#[cfg(feature = "aws-ses")]
pub use ses_email_service::{SesEmailConfig, SesEmailSender};
pub use session_service::SessionService;
pub use token_service::{
    generate_email_verification_token, generate_password_reset_token, generate_secure_token,
    hash_token, verify_token_hash_constant_time, TokenConfig, TokenService,
    ACCESS_TOKEN_VALIDITY_MINUTES, EMAIL_VERIFICATION_TOKEN_VALIDITY_HOURS,
    PASSWORD_RESET_TOKEN_VALIDITY_HOURS, REFRESH_TOKEN_VALIDITY_DAYS, SECURE_TOKEN_BYTES,
};
pub use user_agent_parser::{parse_user_agent, DeviceInfo};
pub use validation::{
    normalize_email, validate_email, validate_password, EmailValidationError,
    EmailValidationResult, PasswordValidationError, PasswordValidationResult, MAX_EMAIL_LENGTH,
    MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, SPECIAL_CHARS,
};
pub use webauthn_service::{
    WebAuthnConfig, WebAuthnService, LOCKOUT_MINUTES as WEBAUTHN_LOCKOUT_MINUTES,
    MAX_FAILED_ATTEMPTS as WEBAUTHN_MAX_FAILED_ATTEMPTS,
};

// Security Hardening exports (F082)
pub use key_service::{KeyService, KeyServiceError};
pub use revocation_cache::RevocationCache;
pub use security_audit::{SecurityAudit, SecurityEventType};

// Admin Invitation exports (F-ADMIN-INVITE)
pub use admin_invite_service::AdminInviteService;

// Organization Security Policy service (F-066)
pub mod org_policy_service;

// Organization Security Policy exports (F-066)
pub use org_policy_service::{OrgPolicyError, OrgPolicyService};
