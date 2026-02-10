//! Revoke all sessions handler.

use axum::{http::StatusCode, Extension, Json};
use std::sync::Arc;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::{TenantId, UserId};

use crate::{error::ApiAuthError, models::RevokeAllSessionsResponse, services::SessionService};

/// DELETE /users/me/sessions
///
/// Revoke all sessions except the current one.
#[utoipa::path(
    delete,
    path = "/users/me/sessions",
    responses(
        (status = 200, description = "All other sessions revoked", body = RevokeAllSessionsResponse),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "User Sessions"
)]
pub async fn revoke_all_sessions(
    Extension(session_service): Extension<Arc<SessionService>>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<(StatusCode, Json<RevokeAllSessionsResponse>), ApiAuthError> {
    // Get current session ID from JWT jti
    let current_session_id = Uuid::parse_str(&claims.jti)
        .map_err(|_| ApiAuthError::Internal("Invalid JWT ID".to_string()))?;

    let revoked_count = session_service
        .revoke_all_except_current(*user_id.as_uuid(), *tenant_id.as_uuid(), current_session_id)
        .await?;

    Ok((
        StatusCode::OK,
        Json(RevokeAllSessionsResponse::new(revoked_count)),
    ))
}
