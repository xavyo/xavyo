//! MFA disable handler.

use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::Serialize;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::info;
use utoipa::ToSchema;
use validator::Validate;
use xavyo_core::UserId;

use crate::{
    error::ApiAuthError, models::TotpDisableRequest, router::AuthState, services::AlertService,
};

/// Response for MFA disable.
#[derive(Debug, Serialize, ToSchema)]
pub struct MfaDisableResponse {
    pub message: String,
}

/// DELETE /auth/mfa/totp
///
/// Disable MFA for the authenticated user.
/// Requires password and TOTP code verification.
#[utoipa::path(
    delete,
    path = "/auth/mfa/totp",
    request_body = TotpDisableRequest,
    responses(
        (status = 200, description = "MFA disabled", body = MfaDisableResponse),
        (status = 400, description = "Cannot disable MFA when policy requires it"),
        (status = 401, description = "Invalid credentials"),
    ),
    tag = "MFA"
)]
pub async fn disable_mfa(
    State(state): State<AuthState>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<xavyo_core::TenantId>,
    Extension(ip_address): Extension<Option<IpAddr>>,
    Extension(user_agent): Extension<Option<String>>,
    Extension(alert_service): Extension<Arc<AlertService>>,
    Json(request): Json<TotpDisableRequest>,
) -> Result<(StatusCode, Json<MfaDisableResponse>), ApiAuthError> {
    // Validate request
    request
        .validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    // Verify password (include tenant_id for defense-in-depth)
    let user =
        xavyo_db::User::find_by_id_in_tenant(&state.pool, *tenant_id.as_uuid(), *user_id.as_uuid())
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::InvalidCredentials)?;

    let password_valid = xavyo_auth::verify_password(&request.password, &user.password_hash)
        .map_err(|_| ApiAuthError::InvalidCredentials)?;

    if !password_valid {
        return Err(ApiAuthError::InvalidCredentials);
    }

    // Check tenant MFA policy - reject if 'required'
    let mfa_policy = xavyo_db::TenantMfaPolicy::get(&state.pool, *tenant_id.as_uuid())
        .await
        .map_err(ApiAuthError::Database)?;
    if mfa_policy.mfa_policy == xavyo_db::MfaPolicy::Required {
        return Err(ApiAuthError::CannotDisableMfaRequired);
    }

    // Disable MFA (verifies TOTP code internally)
    state
        .mfa_service
        .disable_mfa(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            &request.code,
            ip_address,
            user_agent,
        )
        .await?;

    // Revoke sessions and refresh tokens — MFA removal is a security-sensitive change
    let revoked = crate::services::revoke_auth::revoke_user_sessions_and_refresh_tokens(
        &state.pool,
        *tenant_id.as_uuid(),
        *user_id.as_uuid(),
    )
    .await
    .map_err(ApiAuthError::Database)?;

    info!(
        user_id = %user_id.as_uuid(),
        tokens_revoked = revoked,
        "Revoked sessions and refresh tokens after MFA disable"
    );

    // Generate MFA disabled alert (F025)
    let ip_str = ip_address.map(|ip| ip.to_string());
    let _ = alert_service
        .generate_mfa_disabled_alert(*tenant_id.as_uuid(), *user_id.as_uuid(), ip_str.as_deref())
        .await;

    info!(
        user_id = %user_id.as_uuid(),
        "MFA disabled"
    );

    Ok((
        StatusCode::OK,
        Json(MfaDisableResponse {
            message: "MFA has been disabled.".to_string(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn mfa_disable_revokes_sessions_and_refresh_tokens() {
        let src = include_str!("disable.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("revoke_user_sessions_and_refresh_tokens("),
            "MFA disable must revoke sessions and refresh tokens"
        );
        assert!(
            !production.contains("UPDATE sessions SET"),
            "must not revoke sessions without refresh tokens"
        );
    }
}
