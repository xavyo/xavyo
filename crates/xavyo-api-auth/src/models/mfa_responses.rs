//! MFA-related response models.

use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;

/// Response from TOTP setup initiation.
#[derive(Debug, Serialize, ToSchema)]
pub struct TotpSetupResponse {
    /// Base32-encoded secret for manual entry.
    pub secret: String,

    /// otpauth:// URI for scanning.
    pub otpauth_uri: String,

    /// QR code as base64-encoded PNG image.
    pub qr_code: String,
}

/// Response from TOTP setup verification.
#[derive(Debug, Serialize, ToSchema)]
pub struct TotpVerifySetupResponse {
    /// Recovery codes (displayed only once).
    pub recovery_codes: Vec<String>,

    /// Message indicating MFA is now enabled.
    pub message: String,
}

/// Response from recovery code regeneration.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecoveryCodesResponse {
    /// New recovery codes (displayed only once).
    pub recovery_codes: Vec<String>,

    /// Message indicating codes were regenerated.
    pub message: String,
}

/// MFA status for a user.
#[derive(Debug, Serialize, ToSchema)]
pub struct MfaStatusResponse {
    /// Whether TOTP is enabled.
    pub totp_enabled: bool,

    /// Whether WebAuthn is enabled (F032).
    pub webauthn_enabled: bool,

    /// Number of unused recovery codes remaining.
    pub recovery_codes_remaining: i64,

    /// Available MFA methods for this user (T070).
    pub available_methods: Vec<MfaMethod>,

    /// When MFA was set up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_at: Option<DateTime<Utc>>,

    /// When MFA was last used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Response when login requires MFA.
#[derive(Debug, Serialize, ToSchema)]
pub struct MfaRequiredResponse {
    /// Partial token for MFA verification.
    pub partial_token: String,

    /// Indicates MFA is required.
    pub mfa_required: bool,

    /// Token expiry in seconds.
    pub expires_in: i64,

    /// Available MFA methods for this user.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub available_methods: Vec<MfaMethod>,
}

/// Available MFA method.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MfaMethod {
    /// Time-based One-Time Password (TOTP).
    Totp,
    /// WebAuthn/FIDO2 (security keys or passkeys).
    Webauthn,
    /// Recovery code.
    Recovery,
}

impl MfaRequiredResponse {
    /// Create a new MFA required response.
    pub fn new(partial_token: String, expires_in: i64) -> Self {
        Self {
            partial_token,
            mfa_required: true,
            expires_in,
            available_methods: vec![MfaMethod::Totp], // Default to TOTP for backwards compat
        }
    }

    /// Create a new MFA required response with specific methods.
    pub fn with_methods(partial_token: String, expires_in: i64, methods: Vec<MfaMethod>) -> Self {
        Self {
            partial_token,
            mfa_required: true,
            expires_in,
            available_methods: methods,
        }
    }
}
