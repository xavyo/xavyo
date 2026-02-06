//! Recovery code handlers.

use axum::{extract::State, http::StatusCode, Extension, Json};
use std::net::IpAddr;
use tracing::info;
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;
use xavyo_core::UserId;

use crate::{
    error::ApiAuthError,
    models::{
        RecoveryCodesResponse, RecoveryRegenerateRequest, RecoveryVerifyRequest, TokenResponse,
    },
    router::AuthState,
};

/// POST /auth/mfa/recovery/verify
///
/// Verify a recovery code during login to complete MFA authentication.
/// Requires a `partial_token` from the initial login response.
pub async fn verify_recovery_code(
    State(state): State<AuthState>,
    Extension(claims): Extension<JwtClaims>,
    Extension(ip_address): Extension<Option<IpAddr>>,
    Extension(user_agent): Extension<Option<String>>,
    Json(request): Json<RecoveryVerifyRequest>,
) -> Result<(StatusCode, Json<TokenResponse>), ApiAuthError> {
    // Validate request
    request
        .validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    // Verify this is a partial token for MFA verification
    if claims.purpose.as_deref() != Some("mfa_verification") {
        return Err(ApiAuthError::PartialTokenInvalid);
    }

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthError::PartialTokenInvalid)?;

    let tenant_id = claims.tid.ok_or(ApiAuthError::PartialTokenInvalid)?;

    // Verify recovery code
    state
        .mfa_service
        .verify_recovery_code(
            user_id,
            tenant_id,
            &request.code,
            ip_address,
            user_agent.clone(),
        )
        .await?;

    // Get user for token generation (include tenant_id for defense-in-depth)
    let user = xavyo_db::User::find_by_id_in_tenant(&state.pool, tenant_id, user_id)
        .await
        .map_err(ApiAuthError::Database)?
        .ok_or(ApiAuthError::InvalidCredentials)?;

    // Generate full tokens using the shared token_service
    let roles = xavyo_db::UserRole::get_user_roles(&state.pool, user_id)
        .await
        .unwrap_or_else(|_| vec!["user".to_string()]);
    let tokens = state
        .token_service
        .create_tokens(
            user.user_id(),
            user.tenant_id(),
            roles,
            Some(user.email.clone()),
            user_agent,
            ip_address,
        )
        .await?;

    let token_response = TokenResponse::new(tokens.0, tokens.1, tokens.2);

    info!(
        user_id = %user_id,
        "Recovery code used for MFA verification, tokens issued"
    );

    Ok((StatusCode::OK, Json(token_response)))
}

/// POST /auth/mfa/recovery/generate
///
/// Regenerate recovery codes. Requires password verification.
/// Invalidates all previous recovery codes.
pub async fn regenerate_recovery_codes(
    State(state): State<AuthState>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<xavyo_core::TenantId>,
    Extension(ip_address): Extension<Option<IpAddr>>,
    Extension(user_agent): Extension<Option<String>>,
    Json(request): Json<RecoveryRegenerateRequest>,
) -> Result<(StatusCode, Json<RecoveryCodesResponse>), ApiAuthError> {
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

    // Regenerate codes
    let codes = state
        .mfa_service
        .regenerate_recovery_codes(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            ip_address,
            user_agent,
        )
        .await?;

    info!(
        user_id = %user_id.as_uuid(),
        "Recovery codes regenerated"
    );

    Ok((
        StatusCode::OK,
        Json(RecoveryCodesResponse {
            recovery_codes: codes,
            message:
                "Recovery codes regenerated. Store them safely - previous codes are now invalid."
                    .to_string(),
        }),
    ))
}
