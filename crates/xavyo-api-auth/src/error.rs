//! Error types for the authentication API.
//!
//! Uses RFC 7807 Problem Details for HTTP APIs for structured error responses.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Base URL for error type URIs.
const ERROR_BASE_URL: &str = "https://xavyo.net/errors";

/// RFC 7807 Problem Details structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemDetails {
    /// URI identifying the problem type.
    #[serde(rename = "type")]
    pub error_type: String,

    /// Short human-readable summary.
    pub title: String,

    /// HTTP status code.
    pub status: u16,

    /// Human-readable explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,

    /// URI of the specific occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

impl ProblemDetails {
    /// Create a new `ProblemDetails` instance.
    #[must_use]
    pub fn new(error_type: &str, title: &str, status: StatusCode) -> Self {
        Self {
            error_type: format!("{ERROR_BASE_URL}/{error_type}"),
            title: title.to_string(),
            status: status.as_u16(),
            detail: None,
            instance: None,
        }
    }

    /// Add detail message.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Add instance URI.
    #[must_use]
    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.instance = Some(instance.into());
        self
    }
}

/// Authentication API errors.
#[derive(Debug, Error)]
pub enum ApiAuthError {
    /// Invalid credentials (generic to prevent email enumeration).
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// Email already in use for this tenant.
    #[error("Email already in use")]
    EmailInUse,

    /// Password does not meet strength requirements.
    #[error("Weak password: {0:?}")]
    WeakPassword(Vec<String>),

    /// Invalid email format.
    #[error("Invalid email format: {0}")]
    InvalidEmail(String),

    /// Refresh token expired.
    #[error("Refresh token expired")]
    TokenExpired,

    /// Refresh token revoked.
    #[error("Refresh token revoked")]
    TokenRevoked,

    /// Invalid refresh token.
    #[error("Invalid refresh token")]
    InvalidToken,

    /// Password reset token has been used already.
    #[error("Token already used")]
    TokenUsed,

    /// Account is not active.
    #[error("Account is not active")]
    AccountInactive,

    /// Email has not been verified.
    #[error("Email not verified")]
    EmailNotVerified,

    /// Rate limit exceeded.
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Internal server error.
    #[error("Internal server error: {0}")]
    Internal(String),

    /// Database error (`SQLx`).
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Database error (`DbError` wrapper).
    #[error("Database error: {0}")]
    DatabaseInternal(#[from] xavyo_db::DbError),

    /// Validation error.
    #[error("Validation error: {0}")]
    Validation(String),

    /// Unauthorized (missing or invalid auth header).
    #[error("Unauthorized")]
    Unauthorized,

    /// Email sending failed.
    #[error("Failed to send email: {0}")]
    EmailSendFailed(String),

    // MFA errors
    /// MFA is already enabled for this user.
    #[error("MFA is already enabled")]
    MfaAlreadyEnabled,

    /// MFA setup was not initiated.
    #[error("MFA setup not initiated")]
    MfaSetupNotInitiated,

    /// MFA setup has expired.
    #[error("MFA setup expired")]
    MfaSetupExpired,

    /// MFA is disabled by tenant policy.
    #[error("MFA is disabled by tenant policy")]
    MfaDisabledByPolicy,

    /// MFA is not enabled for this user.
    #[error("MFA is not enabled")]
    MfaNotEnabled,

    /// Invalid TOTP code.
    #[error("Invalid TOTP code")]
    InvalidTotpCode,

    /// TOTP verification is temporarily locked.
    #[error("TOTP verification is temporarily locked")]
    TotpVerificationLocked,

    /// Partial token expired.
    #[error("MFA verification token expired")]
    PartialTokenExpired,

    /// Invalid partial token.
    #[error("Invalid MFA verification token")]
    PartialTokenInvalid,

    /// Invalid recovery code.
    #[error("Invalid recovery code")]
    InvalidRecoveryCode,

    /// No recovery codes remaining.
    #[error("No recovery codes remaining")]
    NoRecoveryCodesRemaining,

    /// MFA is required by tenant policy.
    #[error("MFA is required by tenant policy")]
    MfaRequiredByPolicy,

    /// Cannot disable MFA when policy requires it.
    #[error("Cannot disable MFA when required by tenant policy")]
    CannotDisableMfaRequired,

    // Session errors
    /// Session not found.
    #[error("Session not found")]
    SessionNotFound,

    /// Cannot revoke current session.
    #[error("Cannot revoke the current session")]
    CannotRevokeCurrentSession,

    /// Session has expired.
    #[error("Session expired")]
    SessionExpired,

    /// Session has been revoked.
    #[error("Session revoked")]
    SessionRevoked,

    // Lockout errors (F024)
    /// Account is locked due to too many failed attempts.
    #[error("Account locked")]
    AccountLocked,

    /// Account locked with unlock time.
    #[error("Account locked until {0}")]
    AccountLockedUntil(String),

    /// Password has expired.
    #[error("Password expired")]
    PasswordExpired,

    /// User not found.
    #[error("User not found")]
    UserNotFound,

    // Audit/Alert errors (F025)
    /// Alert not found.
    #[error("Alert not found")]
    AlertNotFound,

    /// Alert has already been acknowledged.
    #[error("Alert already acknowledged")]
    AlertAlreadyAcknowledged,

    // Device errors (F026)
    /// Device not found.
    #[error("Device not found")]
    DeviceNotFound,

    /// Device has been revoked.
    #[error("Device revoked")]
    DeviceRevoked,

    /// Device trust not allowed by tenant policy.
    #[error("Device trust not allowed")]
    TrustNotAllowed,

    // Email change errors (F027)
    /// Email already exists (for email change).
    #[error("Email already exists")]
    EmailAlreadyExists,

    /// A pending email change request already exists.
    #[error("Email change pending")]
    EmailChangePending,

    /// Email change token has expired.
    #[error("Email change token expired")]
    EmailChangeTokenExpired,

    /// Email change token is invalid.
    #[error("Email change token invalid")]
    EmailChangeTokenInvalid,

    /// Cannot change to the same email.
    #[error("Same email")]
    SameEmail,

    // IP restriction errors (F028)
    /// IP address is blocked.
    #[error("IP blocked: {0}")]
    IpBlocked(String),

    /// Invalid CIDR notation.
    #[error("Invalid CIDR: {0}")]
    InvalidCidr(String),

    /// IP restriction rule name already exists.
    #[error("Rule name already exists")]
    RuleNameExists,

    /// IP restriction rule not found.
    #[error("Rule not found")]
    RuleNotFound,

    // Delegated administration errors (F029)
    /// User does not have the required permission.
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Role template name already exists.
    #[error("Template name already exists")]
    TemplateNameExists,

    /// Role template not found.
    #[error("Template not found")]
    TemplateNotFound,

    /// Assignment not found.
    #[error("Assignment not found")]
    AssignmentNotFound,

    /// Cannot delete system role template.
    #[error("Cannot delete system template")]
    CannotDeleteSystemTemplate,

    /// Resource is outside user's assigned scope.
    #[error("Scope violation: {0}")]
    ScopeViolation(String),

    /// Invalid permission code.
    #[error("Invalid permission: {0}")]
    InvalidPermission(String),

    // Custom branding errors (F030)
    /// File exceeds maximum size.
    #[error("File too large: {0}")]
    FileTooLarge(String),

    /// Invalid image format.
    #[error("Invalid image format: {0}")]
    InvalidImageFormat(String),

    /// Image dimensions exceed maximum.
    #[error("Image dimensions too large")]
    DimensionsTooLarge,

    /// Asset is referenced in branding and cannot be deleted.
    #[error("Asset is in use: {0}")]
    AssetInUse(String),

    /// Invalid CSS (contains disallowed content).
    #[error("Invalid CSS: {0}")]
    InvalidCss(String),

    /// Email template not found.
    #[error("Email template not found")]
    EmailTemplateNotFound,

    /// Invalid Handlebars template syntax.
    #[error("Invalid template syntax: {0}")]
    InvalidTemplateSyntax(String),

    /// Tenant slug not found.
    #[error("Tenant not found")]
    TenantSlugNotFound,

    /// Asset not found.
    #[error("Asset not found")]
    AssetNotFound,

    // WebAuthn errors (F032)
    /// `WebAuthn` is disabled for this tenant.
    #[error("WebAuthn is disabled")]
    WebAuthnDisabled,

    /// Maximum number of `WebAuthn` credentials reached.
    #[error("Maximum WebAuthn credentials reached")]
    MaxWebAuthnCredentials,

    /// `WebAuthn` challenge not found or expired.
    #[error("WebAuthn challenge not found")]
    WebAuthnChallengeNotFound,

    /// `WebAuthn` challenge has expired.
    #[error("WebAuthn challenge expired")]
    WebAuthnChallengeExpired,

    /// `WebAuthn` credential verification failed.
    #[error("WebAuthn verification failed: {0}")]
    WebAuthnVerificationFailed(String),

    /// `WebAuthn` credential already exists.
    #[error("WebAuthn credential already exists")]
    WebAuthnCredentialExists,

    /// `WebAuthn` credential not found.
    #[error("WebAuthn credential not found")]
    WebAuthnCredentialNotFound,

    /// No `WebAuthn` credentials registered.
    #[error("No WebAuthn credentials registered")]
    WebAuthnNoCredentials,

    /// `WebAuthn` rate limit exceeded.
    #[error("WebAuthn rate limit exceeded")]
    WebAuthnRateLimited,

    /// `WebAuthn` counter anomaly detected (possible cloned credential).
    #[error("WebAuthn counter anomaly detected")]
    WebAuthnCounterAnomaly,

    /// `WebAuthn` attestation is required by tenant policy.
    #[error("WebAuthn attestation required")]
    WebAuthnAttestationRequired,

    /// `WebAuthn` authenticator type is not allowed by tenant policy.
    #[error("WebAuthn authenticator type not allowed: {0}")]
    WebAuthnAuthenticatorTypeNotAllowed(String),

    /// `WebAuthn` user verification is required by tenant policy.
    #[error("WebAuthn user verification required")]
    WebAuthnUserVerificationRequired,

    // Risk enforcement errors (F073)
    /// Account temporarily restricted due to elevated risk.
    #[error("Account restricted due to elevated risk")]
    AccountRestricted,

    /// Risk evaluation service is unavailable (fail-closed mode).
    #[error("Risk evaluation unavailable")]
    RiskServiceUnavailable,

    // Admin invitation errors (F-ADMIN-INVITE)
    /// Invitation not found.
    #[error("Invitation not found")]
    InvitationNotFound,

    /// Invitation has expired.
    #[error("Invitation expired")]
    InvitationExpired,

    /// Invitation has already been accepted.
    #[error("Invitation already accepted")]
    InvitationAlreadyAccepted,

    /// Invitation has been cancelled.
    #[error("Invitation cancelled")]
    InvitationCancelled,

    /// Invalid invitation token.
    #[error("Invalid invitation token")]
    InvalidInvitationToken,

    /// User already exists with this email.
    #[error("User already exists: {0}")]
    UserAlreadyExists(String),

    /// Pending invitation already exists.
    #[error("Pending invitation exists: {0}")]
    PendingInvitationExists(String),

    /// Maximum pending invitations reached.
    #[error("Maximum invitations reached: {0}")]
    MaxInvitationsReached(String),

    // Organization security policy errors (F-066)
    /// Organization not found.
    #[error("Organization not found")]
    OrgNotFound,

    /// Organization security policy not found.
    #[error("Organization policy not found")]
    OrgPolicyNotFound,

    /// Organization policy already exists for this type.
    #[error("Policy already exists for this organization and type")]
    OrgPolicyAlreadyExists,

    /// Invalid policy configuration.
    #[error("Invalid policy configuration: {0}")]
    InvalidPolicyConfig(String),

    /// Invalid policy type.
    #[error("Invalid policy type: {0}")]
    InvalidPolicyType(String),

    /// Organization policy service error.
    #[error("Organization policy error: {0}")]
    OrgPolicyError(String),
}

impl ApiAuthError {
    /// Convert to `ProblemDetails`.
    #[must_use]
    pub fn to_problem_details(&self) -> ProblemDetails {
        match self {
            ApiAuthError::InvalidCredentials => ProblemDetails::new(
                "invalid-credentials",
                "Invalid Credentials",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail("The provided credentials are invalid."),
            ApiAuthError::EmailInUse => {
                ProblemDetails::new("email-in-use", "Email Already In Use", StatusCode::CONFLICT)
                    .with_detail("An account with this email already exists.")
            }
            ApiAuthError::WeakPassword(errors) => ProblemDetails::new(
                "weak-password",
                "Weak Password",
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .with_detail(errors.join("; ")),
            ApiAuthError::InvalidEmail(msg) => ProblemDetails::new(
                "invalid-email",
                "Invalid Email",
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .with_detail(msg.clone()),
            ApiAuthError::TokenExpired => {
                ProblemDetails::new("token-expired", "Token Expired", StatusCode::UNAUTHORIZED)
                    .with_detail("The refresh token has expired. Please login again.")
            }
            ApiAuthError::TokenRevoked => {
                ProblemDetails::new("token-revoked", "Token Revoked", StatusCode::UNAUTHORIZED)
                    .with_detail("This refresh token has been revoked. Please login again.")
            }
            ApiAuthError::InvalidToken => {
                ProblemDetails::new("invalid-token", "Invalid Token", StatusCode::UNAUTHORIZED)
                    .with_detail("The provided token is invalid.")
            }
            ApiAuthError::TokenUsed => {
                ProblemDetails::new("token-used", "Token Already Used", StatusCode::UNAUTHORIZED)
                    .with_detail("This token has already been used.")
            }
            ApiAuthError::AccountInactive => ProblemDetails::new(
                "account-inactive",
                "Account Inactive",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail("This account is not active."),
            ApiAuthError::EmailNotVerified => ProblemDetails::new(
                "email-not-verified",
                "Email Not Verified",
                StatusCode::FORBIDDEN,
            )
            .with_detail("Please verify your email address before proceeding."),
            ApiAuthError::RateLimitExceeded => ProblemDetails::new(
                "rate-limited",
                "Rate Limit Exceeded",
                StatusCode::TOO_MANY_REQUESTS,
            )
            .with_detail("Too many login attempts. Please try again later."),
            ApiAuthError::Internal(msg) => ProblemDetails::new(
                "internal-error",
                "Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .with_detail(msg.clone()),
            ApiAuthError::Database(err) => ProblemDetails::new(
                "database-error",
                "Database Error",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .with_detail(err.to_string()),
            ApiAuthError::DatabaseInternal(err) => ProblemDetails::new(
                "database-error",
                "Database Error",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .with_detail(err.to_string()),
            ApiAuthError::Validation(msg) => ProblemDetails::new(
                "validation-error",
                "Validation Error",
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .with_detail(msg.clone()),
            ApiAuthError::Unauthorized => {
                ProblemDetails::new("unauthorized", "Unauthorized", StatusCode::UNAUTHORIZED)
                    .with_detail("Authentication required.")
            }
            ApiAuthError::EmailSendFailed(msg) => ProblemDetails::new(
                "email-send-failed",
                "Email Send Failed",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .with_detail(msg.clone()),

            // MFA errors
            ApiAuthError::MfaAlreadyEnabled => ProblemDetails::new(
                "mfa-already-enabled",
                "MFA Already Enabled",
                StatusCode::CONFLICT,
            )
            .with_detail("Multi-factor authentication is already enabled for this account."),
            ApiAuthError::MfaSetupNotInitiated => ProblemDetails::new(
                "mfa-setup-not-initiated",
                "MFA Setup Not Initiated",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("Please initiate MFA setup before verifying."),
            ApiAuthError::MfaSetupExpired => ProblemDetails::new(
                "mfa-setup-expired",
                "MFA Setup Expired",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("MFA setup has expired. Please initiate setup again."),
            ApiAuthError::MfaDisabledByPolicy => ProblemDetails::new(
                "mfa-disabled-by-policy",
                "MFA Disabled By Policy",
                StatusCode::FORBIDDEN,
            )
            .with_detail("Multi-factor authentication is disabled for this tenant."),
            ApiAuthError::MfaNotEnabled => ProblemDetails::new(
                "mfa-not-enabled",
                "MFA Not Enabled",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("Multi-factor authentication is not enabled for this account."),
            ApiAuthError::InvalidTotpCode => ProblemDetails::new(
                "invalid-totp-code",
                "Invalid TOTP Code",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail("The verification code is invalid or expired."),
            ApiAuthError::TotpVerificationLocked => ProblemDetails::new(
                "totp-verification-locked",
                "Verification Locked",
                StatusCode::TOO_MANY_REQUESTS,
            )
            .with_detail("Too many failed attempts. Please try again later."),
            ApiAuthError::PartialTokenExpired => ProblemDetails::new(
                "partial-token-expired",
                "Verification Session Expired",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail("MFA verification session has expired. Please login again."),
            ApiAuthError::PartialTokenInvalid => ProblemDetails::new(
                "partial-token-invalid",
                "Invalid Verification Session",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail("Invalid MFA verification session."),
            ApiAuthError::InvalidRecoveryCode => ProblemDetails::new(
                "invalid-recovery-code",
                "Invalid Recovery Code",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail("The recovery code is invalid or has already been used."),
            ApiAuthError::NoRecoveryCodesRemaining => ProblemDetails::new(
                "no-recovery-codes",
                "No Recovery Codes Remaining",
                StatusCode::FORBIDDEN,
            )
            .with_detail("All recovery codes have been used. Please contact support."),
            ApiAuthError::MfaRequiredByPolicy => ProblemDetails::new(
                "mfa-required",
                "MFA Required",
                StatusCode::FORBIDDEN,
            )
            .with_detail("Multi-factor authentication is required by your organization."),
            ApiAuthError::CannotDisableMfaRequired => ProblemDetails::new(
                "cannot-disable-mfa",
                "Cannot Disable MFA",
                StatusCode::FORBIDDEN,
            )
            .with_detail("Cannot disable MFA when required by organization policy."),

            // Session errors
            ApiAuthError::SessionNotFound => ProblemDetails::new(
                "session-not-found",
                "Session Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested session was not found or does not belong to you."),
            ApiAuthError::CannotRevokeCurrentSession => ProblemDetails::new(
                "cannot-revoke-current-session",
                "Cannot Revoke Current Session",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("You cannot revoke your current active session. Use logout instead."),
            ApiAuthError::SessionExpired => ProblemDetails::new(
                "session-expired",
                "Session Expired",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail("Your session has expired. Please login again."),
            ApiAuthError::SessionRevoked => ProblemDetails::new(
                "session-revoked",
                "Session Revoked",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail("Your session has been revoked. Please login again."),

            // Lockout errors (F024)
            ApiAuthError::AccountLocked => ProblemDetails::new(
                "account-locked",
                "Account Locked",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail("Your account has been locked due to too many failed login attempts."),
            ApiAuthError::AccountLockedUntil(until) => ProblemDetails::new(
                "account-locked",
                "Account Locked",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail(format!("Your account has been locked until {until}. Please try again later or contact an administrator.")),
            ApiAuthError::PasswordExpired => ProblemDetails::new(
                "password-expired",
                "Password Expired",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail("Your password has expired. Please change your password to continue."),
            ApiAuthError::UserNotFound => ProblemDetails::new(
                "user-not-found",
                "User Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested user was not found."),

            // Audit/Alert errors (F025)
            ApiAuthError::AlertNotFound => ProblemDetails::new(
                "alert-not-found",
                "Alert Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested alert was not found or does not belong to you."),
            ApiAuthError::AlertAlreadyAcknowledged => ProblemDetails::new(
                "alert-already-acknowledged",
                "Alert Already Acknowledged",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("This alert has already been acknowledged."),

            // Device errors (F026)
            ApiAuthError::DeviceNotFound => ProblemDetails::new(
                "device-not-found",
                "Device Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested device was not found or does not belong to you."),
            ApiAuthError::DeviceRevoked => ProblemDetails::new(
                "device-revoked",
                "Device Revoked",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("This device has been revoked and cannot be modified."),
            ApiAuthError::TrustNotAllowed => ProblemDetails::new(
                "trust-not-allowed",
                "Device Trust Not Allowed",
                StatusCode::FORBIDDEN,
            )
            .with_detail("Tenant policy does not allow trusted devices."),

            // Email change errors (F027)
            ApiAuthError::EmailAlreadyExists => ProblemDetails::new(
                "email-already-exists",
                "Email Already Exists",
                StatusCode::CONFLICT,
            )
            .with_detail("The email address is already in use by another account."),
            ApiAuthError::EmailChangePending => ProblemDetails::new(
                "email-change-pending",
                "Email Change Pending",
                StatusCode::CONFLICT,
            )
            .with_detail("A pending email change request already exists. Please verify the pending request or wait for it to expire."),
            ApiAuthError::EmailChangeTokenExpired => ProblemDetails::new(
                "email-change-token-expired",
                "Token Expired",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("The verification token has expired. Please request a new email change."),
            ApiAuthError::EmailChangeTokenInvalid => ProblemDetails::new(
                "email-change-token-invalid",
                "Invalid Token",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("The verification token is invalid or has already been used."),
            ApiAuthError::SameEmail => ProblemDetails::new(
                "same-email",
                "Same Email",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("New email must be different from current email."),

            // IP restriction errors (F028)
            ApiAuthError::IpBlocked(reason) => ProblemDetails::new(
                "ip-blocked",
                "IP Blocked",
                StatusCode::FORBIDDEN,
            )
            .with_detail(reason.clone()),
            ApiAuthError::InvalidCidr(msg) => ProblemDetails::new(
                "invalid-cidr",
                "Invalid CIDR",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),
            ApiAuthError::RuleNameExists => ProblemDetails::new(
                "rule-name-exists",
                "Rule Name Exists",
                StatusCode::CONFLICT,
            )
            .with_detail("A rule with this name already exists for this tenant."),
            ApiAuthError::RuleNotFound => ProblemDetails::new(
                "rule-not-found",
                "Rule Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested IP restriction rule was not found."),

            // Delegated administration errors (F029)
            ApiAuthError::PermissionDenied(reason) => ProblemDetails::new(
                "permission-denied",
                "Permission Denied",
                StatusCode::FORBIDDEN,
            )
            .with_detail(reason.clone()),
            ApiAuthError::TemplateNameExists => ProblemDetails::new(
                "template-name-exists",
                "Template Name Exists",
                StatusCode::CONFLICT,
            )
            .with_detail("A role template with this name already exists."),
            ApiAuthError::TemplateNotFound => ProblemDetails::new(
                "template-not-found",
                "Template Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested role template was not found."),
            ApiAuthError::AssignmentNotFound => ProblemDetails::new(
                "assignment-not-found",
                "Assignment Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested assignment was not found."),
            ApiAuthError::CannotDeleteSystemTemplate => ProblemDetails::new(
                "cannot-delete-system-template",
                "Cannot Delete System Template",
                StatusCode::FORBIDDEN,
            )
            .with_detail("System role templates cannot be deleted."),
            ApiAuthError::ScopeViolation(reason) => ProblemDetails::new(
                "scope-violation",
                "Scope Violation",
                StatusCode::FORBIDDEN,
            )
            .with_detail(reason.clone()),
            ApiAuthError::InvalidPermission(msg) => ProblemDetails::new(
                "invalid-permission",
                "Invalid Permission",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),

            // Custom branding errors (F030)
            ApiAuthError::FileTooLarge(msg) => ProblemDetails::new(
                "file-too-large",
                "File Too Large",
                StatusCode::PAYLOAD_TOO_LARGE,
            )
            .with_detail(msg.clone()),
            ApiAuthError::InvalidImageFormat(msg) => ProblemDetails::new(
                "invalid-image-format",
                "Invalid Image Format",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),
            ApiAuthError::DimensionsTooLarge => ProblemDetails::new(
                "dimensions-too-large",
                "Dimensions Too Large",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("Image dimensions exceed maximum of 4096x4096 pixels."),
            ApiAuthError::AssetInUse(fields) => ProblemDetails::new(
                "asset-in-use",
                "Asset In Use",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(format!("Cannot delete asset: referenced in {fields}")),
            ApiAuthError::InvalidCss(msg) => ProblemDetails::new(
                "invalid-css",
                "Invalid CSS",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),
            ApiAuthError::EmailTemplateNotFound => ProblemDetails::new(
                "email-template-not-found",
                "Email Template Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested email template was not found."),
            ApiAuthError::InvalidTemplateSyntax(msg) => ProblemDetails::new(
                "invalid-template-syntax",
                "Invalid Template Syntax",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),
            ApiAuthError::TenantSlugNotFound => ProblemDetails::new(
                "tenant-not-found",
                "Tenant Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested tenant was not found."),
            ApiAuthError::AssetNotFound => ProblemDetails::new(
                "asset-not-found",
                "Asset Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested asset was not found."),

            // WebAuthn errors (F032)
            ApiAuthError::WebAuthnDisabled => ProblemDetails::new(
                "webauthn-disabled",
                "WebAuthn Disabled",
                StatusCode::FORBIDDEN,
            )
            .with_detail("WebAuthn is disabled for this tenant."),
            ApiAuthError::MaxWebAuthnCredentials => ProblemDetails::new(
                "max-webauthn-credentials",
                "Maximum Credentials Reached",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("Maximum number of WebAuthn credentials has been reached."),
            ApiAuthError::WebAuthnChallengeNotFound => ProblemDetails::new(
                "webauthn-challenge-not-found",
                "Challenge Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("No pending WebAuthn challenge found. Please start the ceremony again."),
            ApiAuthError::WebAuthnChallengeExpired => ProblemDetails::new(
                "webauthn-challenge-expired",
                "Challenge Expired",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("The WebAuthn challenge has expired. Please start the ceremony again."),
            ApiAuthError::WebAuthnVerificationFailed(msg) => ProblemDetails::new(
                "webauthn-verification-failed",
                "Verification Failed",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(format!("WebAuthn verification failed: {msg}")),
            ApiAuthError::WebAuthnCredentialExists => ProblemDetails::new(
                "webauthn-credential-exists",
                "Credential Already Registered",
                StatusCode::CONFLICT,
            )
            .with_detail("This credential is already registered."),
            ApiAuthError::WebAuthnCredentialNotFound => ProblemDetails::new(
                "webauthn-credential-not-found",
                "Credential Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested WebAuthn credential was not found."),
            ApiAuthError::WebAuthnNoCredentials => ProblemDetails::new(
                "webauthn-no-credentials",
                "No Credentials Registered",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("No WebAuthn credentials are registered for this user."),
            ApiAuthError::WebAuthnRateLimited => ProblemDetails::new(
                "webauthn-rate-limited",
                "Too Many Attempts",
                StatusCode::TOO_MANY_REQUESTS,
            )
            .with_detail("Too many failed WebAuthn authentication attempts. Please try again later."),
            ApiAuthError::WebAuthnCounterAnomaly => ProblemDetails::new(
                "webauthn-counter-anomaly",
                "Security Alert",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail("A security anomaly was detected with this credential. It may have been cloned."),
            ApiAuthError::WebAuthnAttestationRequired => ProblemDetails::new(
                "webauthn-attestation-required",
                "Attestation Required",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("Attestation is required by tenant policy. Please use an authenticator that supports attestation."),
            ApiAuthError::WebAuthnAuthenticatorTypeNotAllowed(auth_type) => ProblemDetails::new(
                "webauthn-authenticator-type-not-allowed",
                "Authenticator Type Not Allowed",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(format!("Authenticator type '{auth_type}' is not allowed by tenant policy.")),
            ApiAuthError::WebAuthnUserVerificationRequired => ProblemDetails::new(
                "webauthn-user-verification-required",
                "User Verification Required",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("User verification is required by tenant policy. Please use an authenticator that supports user verification (e.g., biometric or PIN)."),

            // Risk enforcement errors (F073)
            ApiAuthError::AccountRestricted => ProblemDetails::new(
                "account-restricted",
                "Account Restricted",
                StatusCode::FORBIDDEN,
            )
            .with_detail("Account temporarily restricted due to elevated risk. Please contact your administrator."),
            ApiAuthError::RiskServiceUnavailable => ProblemDetails::new(
                "risk-service-unavailable",
                "Service Unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .with_detail("Risk evaluation service is temporarily unavailable. Please try again later."),

            // Admin invitation errors (F-ADMIN-INVITE)
            ApiAuthError::InvitationNotFound => ProblemDetails::new(
                "invitation-not-found",
                "Invitation Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested invitation was not found."),
            ApiAuthError::InvitationExpired => ProblemDetails::new(
                "invitation-expired",
                "Invitation Expired",
                StatusCode::GONE,
            )
            .with_detail("This invitation has expired."),
            ApiAuthError::InvitationAlreadyAccepted => ProblemDetails::new(
                "invitation-already-accepted",
                "Invitation Already Accepted",
                StatusCode::GONE,
            )
            .with_detail("This invitation has already been accepted."),
            ApiAuthError::InvitationCancelled => ProblemDetails::new(
                "invitation-cancelled",
                "Invitation Cancelled",
                StatusCode::GONE,
            )
            .with_detail("This invitation has been cancelled."),
            ApiAuthError::InvalidInvitationToken => ProblemDetails::new(
                "invalid-invitation-token",
                "Invalid Invitation Token",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("The invitation token is invalid."),
            ApiAuthError::UserAlreadyExists(msg) => ProblemDetails::new(
                "user-already-exists",
                "User Already Exists",
                StatusCode::CONFLICT,
            )
            .with_detail(msg.clone()),
            ApiAuthError::PendingInvitationExists(msg) => ProblemDetails::new(
                "pending-invitation-exists",
                "Pending Invitation Exists",
                StatusCode::CONFLICT,
            )
            .with_detail(msg.clone()),
            ApiAuthError::MaxInvitationsReached(msg) => ProblemDetails::new(
                "max-invitations-reached",
                "Maximum Invitations Reached",
                StatusCode::TOO_MANY_REQUESTS,
            )
            .with_detail(msg.clone()),

            // Organization security policy errors (F-066)
            ApiAuthError::OrgNotFound => ProblemDetails::new(
                "organization-not-found",
                "Organization Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested organization was not found."),
            ApiAuthError::OrgPolicyNotFound => ProblemDetails::new(
                "org-policy-not-found",
                "Organization Policy Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("No policy found for this organization and policy type."),
            ApiAuthError::OrgPolicyAlreadyExists => ProblemDetails::new(
                "org-policy-already-exists",
                "Policy Already Exists",
                StatusCode::CONFLICT,
            )
            .with_detail("A policy of this type already exists for this organization."),
            ApiAuthError::InvalidPolicyConfig(msg) => ProblemDetails::new(
                "invalid-policy-config",
                "Invalid Policy Configuration",
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .with_detail(msg.clone()),
            ApiAuthError::InvalidPolicyType(msg) => ProblemDetails::new(
                "invalid-policy-type",
                "Invalid Policy Type",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),
            ApiAuthError::OrgPolicyError(msg) => ProblemDetails::new(
                "org-policy-error",
                "Organization Policy Error",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .with_detail(msg.clone()),
        }
    }

    /// Get the HTTP status code for this error.
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiAuthError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            ApiAuthError::EmailInUse => StatusCode::CONFLICT,
            ApiAuthError::WeakPassword(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiAuthError::InvalidEmail(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiAuthError::TokenExpired => StatusCode::UNAUTHORIZED,
            ApiAuthError::TokenRevoked => StatusCode::UNAUTHORIZED,
            ApiAuthError::InvalidToken => StatusCode::UNAUTHORIZED,
            ApiAuthError::TokenUsed => StatusCode::UNAUTHORIZED,
            ApiAuthError::AccountInactive => StatusCode::UNAUTHORIZED,
            ApiAuthError::EmailNotVerified => StatusCode::FORBIDDEN,
            ApiAuthError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            ApiAuthError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiAuthError::Database { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            ApiAuthError::DatabaseInternal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            ApiAuthError::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiAuthError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiAuthError::EmailSendFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            // MFA errors
            ApiAuthError::MfaAlreadyEnabled => StatusCode::CONFLICT,
            ApiAuthError::MfaSetupNotInitiated => StatusCode::BAD_REQUEST,
            ApiAuthError::MfaSetupExpired => StatusCode::BAD_REQUEST,
            ApiAuthError::MfaDisabledByPolicy => StatusCode::FORBIDDEN,
            ApiAuthError::MfaNotEnabled => StatusCode::BAD_REQUEST,
            ApiAuthError::InvalidTotpCode => StatusCode::UNAUTHORIZED,
            ApiAuthError::TotpVerificationLocked => StatusCode::TOO_MANY_REQUESTS,
            ApiAuthError::PartialTokenExpired => StatusCode::UNAUTHORIZED,
            ApiAuthError::PartialTokenInvalid => StatusCode::UNAUTHORIZED,
            ApiAuthError::InvalidRecoveryCode => StatusCode::UNAUTHORIZED,
            ApiAuthError::NoRecoveryCodesRemaining => StatusCode::FORBIDDEN,
            ApiAuthError::MfaRequiredByPolicy => StatusCode::FORBIDDEN,
            ApiAuthError::CannotDisableMfaRequired => StatusCode::FORBIDDEN,
            // Session errors
            ApiAuthError::SessionNotFound => StatusCode::NOT_FOUND,
            ApiAuthError::CannotRevokeCurrentSession => StatusCode::BAD_REQUEST,
            ApiAuthError::SessionExpired => StatusCode::UNAUTHORIZED,
            ApiAuthError::SessionRevoked => StatusCode::UNAUTHORIZED,
            // Lockout errors (F024)
            ApiAuthError::AccountLocked => StatusCode::UNAUTHORIZED,
            ApiAuthError::AccountLockedUntil(_) => StatusCode::UNAUTHORIZED,
            ApiAuthError::PasswordExpired => StatusCode::UNAUTHORIZED,
            ApiAuthError::UserNotFound => StatusCode::NOT_FOUND,
            // Audit/Alert errors (F025)
            ApiAuthError::AlertNotFound => StatusCode::NOT_FOUND,
            ApiAuthError::AlertAlreadyAcknowledged => StatusCode::BAD_REQUEST,
            // Device errors (F026)
            ApiAuthError::DeviceNotFound => StatusCode::NOT_FOUND,
            ApiAuthError::DeviceRevoked => StatusCode::BAD_REQUEST,
            ApiAuthError::TrustNotAllowed => StatusCode::FORBIDDEN,
            // Email change errors (F027)
            ApiAuthError::EmailAlreadyExists => StatusCode::CONFLICT,
            ApiAuthError::EmailChangePending => StatusCode::CONFLICT,
            ApiAuthError::EmailChangeTokenExpired => StatusCode::BAD_REQUEST,
            ApiAuthError::EmailChangeTokenInvalid => StatusCode::BAD_REQUEST,
            ApiAuthError::SameEmail => StatusCode::BAD_REQUEST,
            // IP restriction errors (F028)
            ApiAuthError::IpBlocked(_) => StatusCode::FORBIDDEN,
            ApiAuthError::InvalidCidr(_) => StatusCode::BAD_REQUEST,
            ApiAuthError::RuleNameExists => StatusCode::CONFLICT,
            ApiAuthError::RuleNotFound => StatusCode::NOT_FOUND,
            // Delegated administration errors (F029)
            ApiAuthError::PermissionDenied(_) => StatusCode::FORBIDDEN,
            ApiAuthError::TemplateNameExists => StatusCode::CONFLICT,
            ApiAuthError::TemplateNotFound => StatusCode::NOT_FOUND,
            ApiAuthError::AssignmentNotFound => StatusCode::NOT_FOUND,
            ApiAuthError::CannotDeleteSystemTemplate => StatusCode::FORBIDDEN,
            ApiAuthError::ScopeViolation(_) => StatusCode::FORBIDDEN,
            ApiAuthError::InvalidPermission(_) => StatusCode::BAD_REQUEST,
            // Custom branding errors (F030)
            ApiAuthError::FileTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ApiAuthError::InvalidImageFormat(_) => StatusCode::BAD_REQUEST,
            ApiAuthError::DimensionsTooLarge => StatusCode::BAD_REQUEST,
            ApiAuthError::AssetInUse(_) => StatusCode::BAD_REQUEST,
            ApiAuthError::InvalidCss(_) => StatusCode::BAD_REQUEST,
            ApiAuthError::EmailTemplateNotFound => StatusCode::NOT_FOUND,
            ApiAuthError::InvalidTemplateSyntax(_) => StatusCode::BAD_REQUEST,
            ApiAuthError::TenantSlugNotFound => StatusCode::NOT_FOUND,
            ApiAuthError::AssetNotFound => StatusCode::NOT_FOUND,
            // WebAuthn errors (F032)
            ApiAuthError::WebAuthnDisabled => StatusCode::FORBIDDEN,
            ApiAuthError::MaxWebAuthnCredentials => StatusCode::BAD_REQUEST,
            ApiAuthError::WebAuthnChallengeNotFound => StatusCode::NOT_FOUND,
            ApiAuthError::WebAuthnChallengeExpired => StatusCode::BAD_REQUEST,
            ApiAuthError::WebAuthnVerificationFailed(_) => StatusCode::BAD_REQUEST,
            ApiAuthError::WebAuthnCredentialExists => StatusCode::CONFLICT,
            ApiAuthError::WebAuthnCredentialNotFound => StatusCode::NOT_FOUND,
            ApiAuthError::WebAuthnNoCredentials => StatusCode::BAD_REQUEST,
            ApiAuthError::WebAuthnRateLimited => StatusCode::TOO_MANY_REQUESTS,
            ApiAuthError::WebAuthnCounterAnomaly => StatusCode::UNAUTHORIZED,
            ApiAuthError::WebAuthnAttestationRequired => StatusCode::BAD_REQUEST,
            ApiAuthError::WebAuthnAuthenticatorTypeNotAllowed(_) => StatusCode::BAD_REQUEST,
            ApiAuthError::WebAuthnUserVerificationRequired => StatusCode::BAD_REQUEST,
            // Risk enforcement errors (F073)
            ApiAuthError::AccountRestricted => StatusCode::FORBIDDEN,
            ApiAuthError::RiskServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            // Admin invitation errors (F-ADMIN-INVITE)
            ApiAuthError::InvitationNotFound => StatusCode::NOT_FOUND,
            ApiAuthError::InvitationExpired => StatusCode::GONE,
            ApiAuthError::InvitationAlreadyAccepted => StatusCode::GONE,
            ApiAuthError::InvitationCancelled => StatusCode::GONE,
            ApiAuthError::InvalidInvitationToken => StatusCode::BAD_REQUEST,
            ApiAuthError::UserAlreadyExists(_) => StatusCode::CONFLICT,
            ApiAuthError::PendingInvitationExists(_) => StatusCode::CONFLICT,
            ApiAuthError::MaxInvitationsReached(_) => StatusCode::TOO_MANY_REQUESTS,
            // Organization security policy errors (F-066)
            ApiAuthError::OrgNotFound => StatusCode::NOT_FOUND,
            ApiAuthError::OrgPolicyNotFound => StatusCode::NOT_FOUND,
            ApiAuthError::OrgPolicyAlreadyExists => StatusCode::CONFLICT,
            ApiAuthError::InvalidPolicyConfig(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiAuthError::InvalidPolicyType(_) => StatusCode::BAD_REQUEST,
            ApiAuthError::OrgPolicyError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ApiAuthError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let problem = self.to_problem_details();

        let mut response = (status, Json(problem)).into_response();
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/problem+json"),
        );

        // Add Retry-After header for rate limiting
        if matches!(self, ApiAuthError::RateLimitExceeded) {
            response.headers_mut().insert(
                http::header::RETRY_AFTER,
                http::HeaderValue::from_static("60"),
            );
        }

        // Add Retry-After header for TOTP lockout (5 minutes)
        if matches!(self, ApiAuthError::TotpVerificationLocked) {
            response.headers_mut().insert(
                http::header::RETRY_AFTER,
                http::HeaderValue::from_static("300"),
            );
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_problem_details_serialization() {
        let problem = ProblemDetails::new("test-error", "Test Error", StatusCode::BAD_REQUEST)
            .with_detail("This is a test error")
            .with_instance("/test/path");

        let json = serde_json::to_string(&problem).unwrap();
        assert!(json.contains("\"type\":\"https://xavyo.net/errors/test-error\""));
        assert!(json.contains("\"title\":\"Test Error\""));
        assert!(json.contains("\"status\":400"));
        assert!(json.contains("\"detail\":\"This is a test error\""));
        assert!(json.contains("\"instance\":\"/test/path\""));
    }

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            ApiAuthError::InvalidCredentials.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(ApiAuthError::EmailInUse.status_code(), StatusCode::CONFLICT);
        assert_eq!(
            ApiAuthError::WeakPassword(vec!["test".to_string()]).status_code(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            ApiAuthError::RateLimitExceeded.status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn test_problem_details_types() {
        let error = ApiAuthError::InvalidCredentials;
        let problem = error.to_problem_details();
        assert_eq!(
            problem.error_type,
            "https://xavyo.net/errors/invalid-credentials"
        );
        assert_eq!(problem.title, "Invalid Credentials");
    }
}
