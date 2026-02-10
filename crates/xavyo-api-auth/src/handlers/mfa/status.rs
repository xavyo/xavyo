//! MFA status handler.

use axum::{extract::State, http::StatusCode, Extension, Json};
use xavyo_core::UserId;

use crate::{
    error::ApiAuthError,
    models::{MfaMethod, MfaStatusResponse},
    router::AuthState,
};

/// GET /users/me/mfa/status or GET /users/:id/mfa/status (admin)
///
/// Get MFA status for a user.
#[utoipa::path(
    get,
    path = "/users/me/mfa/status",
    responses(
        (status = 200, description = "MFA status retrieved", body = MfaStatusResponse),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "MFA"
)]
pub async fn get_mfa_status(
    State(state): State<AuthState>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<xavyo_core::TenantId>,
) -> Result<(StatusCode, Json<MfaStatusResponse>), ApiAuthError> {
    let status = state
        .mfa_service
        .get_status(*user_id.as_uuid(), *tenant_id.as_uuid())
        .await?;

    // Check WebAuthn status (T070)
    let webauthn_enabled = state
        .webauthn_service
        .has_webauthn_enabled(*user_id.as_uuid(), *tenant_id.as_uuid())
        .await
        .unwrap_or(false);

    // Build available methods list (T069)
    let mut available_methods = Vec::new();
    if status.totp_enabled {
        available_methods.push(MfaMethod::Totp);
    }
    if webauthn_enabled {
        available_methods.push(MfaMethod::Webauthn);
    }
    if status.recovery_codes_remaining > 0 {
        available_methods.push(MfaMethod::Recovery);
    }

    Ok((
        StatusCode::OK,
        Json(MfaStatusResponse {
            totp_enabled: status.totp_enabled,
            webauthn_enabled,
            recovery_codes_remaining: status.recovery_codes_remaining,
            available_methods,
            setup_at: status.setup_at,
            last_used_at: status.last_used_at,
        }),
    ))
}
