//! TOTP verification handler for login flow.

use axum::{extract::State, http::StatusCode, Extension, Json};
use std::net::IpAddr;
use tracing::info;
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;
use xavyo_webhooks::{EventPublisher, WebhookEvent};

use crate::{
    error::ApiAuthError,
    models::{TokenResponse, TotpVerifyRequest},
    router::AuthState,
};

/// POST /auth/mfa/totp/verify
///
/// Verify TOTP code during login to complete MFA authentication.
/// Requires a `partial_token` from the initial login response.
#[utoipa::path(
    post,
    path = "/auth/mfa/totp/verify",
    request_body = TotpVerifyRequest,
    responses(
        (status = 200, description = "MFA verification successful, tokens issued", body = TokenResponse),
        (status = 400, description = "Invalid TOTP code"),
        (status = 401, description = "Invalid or expired partial token"),
    ),
    tag = "MFA"
)]
pub async fn verify_totp(
    State(state): State<AuthState>,
    Extension(claims): Extension<JwtClaims>,
    Extension(ip_address): Extension<Option<IpAddr>>,
    Extension(user_agent): Extension<Option<String>>,
    publisher: Option<Extension<EventPublisher>>,
    Json(request): Json<TotpVerifyRequest>,
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

    // Verify TOTP code
    state
        .mfa_service
        .verify_login_code(
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
    let roles = xavyo_db::UserRole::get_user_roles(&state.pool, user_id, tenant_id)
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
        "MFA verification successful, tokens issued"
    );

    // F085: Publish auth.mfa.verified webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "auth.mfa.verified".to_string(),
            tenant_id,
            actor_id: Some(user_id),
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "user_id": user_id,
                "factor_type": "totp",
            }),
        });
    }

    Ok((StatusCode::OK, Json(token_response)))
}
