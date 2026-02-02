//! MFA-related request models.

use serde::Deserialize;
use utoipa::ToSchema;
use validator::Validate;
use xavyo_db::MfaPolicy;

/// Request to verify TOTP setup.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct TotpVerifySetupRequest {
    /// The 6-digit TOTP code from the authenticator app.
    #[validate(length(equal = 6, message = "TOTP code must be 6 digits"))]
    pub code: String,
}

/// Request to verify TOTP during login.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct TotpVerifyRequest {
    /// The 6-digit TOTP code from the authenticator app.
    #[validate(length(equal = 6, message = "TOTP code must be 6 digits"))]
    pub code: String,
}

/// Request to disable MFA.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct TotpDisableRequest {
    /// User's current password for verification.
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,

    /// The 6-digit TOTP code for verification.
    #[validate(length(equal = 6, message = "TOTP code must be 6 digits"))]
    pub code: String,
}

/// Request to regenerate recovery codes.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RecoveryRegenerateRequest {
    /// User's current password for verification.
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

/// Request to verify a recovery code during login.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RecoveryVerifyRequest {
    /// The 16-character recovery code.
    #[validate(length(min = 1, message = "Recovery code is required"))]
    pub code: String,
}

/// Request to update tenant MFA policy.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct MfaPolicyRequest {
    /// The MFA policy to set.
    pub mfa_policy: MfaPolicy,
}
