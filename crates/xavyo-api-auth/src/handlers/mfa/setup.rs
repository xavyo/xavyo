//! TOTP setup handler.

use axum::{extract::State, http::StatusCode, Extension, Json};
use std::net::IpAddr;
use tracing::info;
use xavyo_core::UserId;
use xavyo_db::{MfaPolicy, TenantMfaPolicy};

use crate::{error::ApiAuthError, models::TotpSetupResponse, router::AuthState};

/// POST /auth/mfa/totp/setup
///
/// Initiate TOTP setup for the authenticated user.
/// Returns a QR code and secret for the authenticator app.
pub async fn setup_totp(
    State(state): State<AuthState>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<xavyo_core::TenantId>,
    Extension(ip_address): Extension<Option<IpAddr>>,
    Extension(user_agent): Extension<Option<String>>,
) -> Result<(StatusCode, Json<TotpSetupResponse>), ApiAuthError> {
    // Get user email for TOTP URI (include tenant_id for defense-in-depth)
    let user =
        xavyo_db::User::find_by_id_in_tenant(&state.pool, *tenant_id.as_uuid(), *user_id.as_uuid())
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::InvalidCredentials)?;

    // Check tenant MFA policy - block setup if MFA is disabled
    let policy = TenantMfaPolicy::get(&state.pool, *tenant_id.as_uuid())
        .await
        .map_err(ApiAuthError::Database)?;

    if policy.mfa_policy == MfaPolicy::Disabled {
        return Err(ApiAuthError::MfaDisabledByPolicy);
    }

    // Initiate setup
    let setup_data = state
        .mfa_service
        .initiate_setup(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            &user.email,
            ip_address,
            user_agent,
        )
        .await?;

    info!(
        user_id = %user_id.as_uuid(),
        "TOTP setup initiated"
    );

    Ok((
        StatusCode::OK,
        Json(TotpSetupResponse {
            secret: setup_data.secret_base32,
            otpauth_uri: setup_data.otpauth_uri,
            qr_code: setup_data.qr_code_base64,
        }),
    ))
}
