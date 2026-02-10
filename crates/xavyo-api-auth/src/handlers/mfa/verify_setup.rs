//! TOTP setup verification handler.

use axum::{extract::State, http::StatusCode, Extension, Json};
use std::net::IpAddr;
use tracing::info;
use uuid::Uuid;
use validator::Validate;
use xavyo_core::UserId;
use xavyo_webhooks::{EventPublisher, WebhookEvent};

use crate::{
    error::ApiAuthError,
    models::{TotpVerifySetupRequest, TotpVerifySetupResponse},
    router::AuthState,
};

/// POST /auth/mfa/totp/verify-setup
///
/// Complete TOTP setup by verifying a code from the authenticator app.
/// Returns recovery codes on success (displayed only once).
#[utoipa::path(
    post,
    path = "/auth/mfa/totp/verify-setup",
    request_body = TotpVerifySetupRequest,
    responses(
        (status = 200, description = "TOTP setup verified, MFA enabled", body = TotpVerifySetupResponse),
        (status = 400, description = "Invalid verification code"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "MFA"
)]
pub async fn verify_totp_setup(
    State(state): State<AuthState>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<xavyo_core::TenantId>,
    Extension(ip_address): Extension<Option<IpAddr>>,
    Extension(user_agent): Extension<Option<String>>,
    publisher: Option<Extension<EventPublisher>>,
    Json(request): Json<TotpVerifySetupRequest>,
) -> Result<(StatusCode, Json<TotpVerifySetupResponse>), ApiAuthError> {
    // Validate request
    request
        .validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    // Verify setup
    let recovery_codes = state
        .mfa_service
        .verify_setup(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            &request.code,
            ip_address,
            user_agent,
        )
        .await?;

    // Revoke all sessions — MFA enrollment is a security-sensitive change
    let revoked = sqlx::query(
        "UPDATE sessions SET revoked_at = NOW(), revoked_reason = 'security' \
         WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL AND expires_at > NOW()",
    )
    .bind(user_id.as_uuid())
    .bind(tenant_id.as_uuid())
    .execute(&state.pool)
    .await
    .map_err(ApiAuthError::Database)?;

    info!(
        user_id = %user_id.as_uuid(),
        sessions_revoked = revoked.rows_affected(),
        "TOTP setup completed, MFA enabled, sessions revoked"
    );

    // F085: Publish auth.mfa.enrolled webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "auth.mfa.enrolled".to_string(),
            tenant_id: *tenant_id.as_uuid(),
            actor_id: Some(*user_id.as_uuid()),
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "user_id": user_id.as_uuid(),
                "factor_type": "totp",
            }),
        });
    }

    Ok((
        StatusCode::OK,
        Json(TotpVerifySetupResponse {
            recovery_codes,
            message: "MFA has been enabled. Store your recovery codes safely - they will not be shown again.".to_string(),
        }),
    ))
}
