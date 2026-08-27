//! List user sessions handler.

use axum::{http::StatusCode, Extension, Json};
use std::sync::Arc;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::{TenantId, UserId};

use crate::{
    error::ApiAuthError,
    models::{SessionInfoResponse, SessionListResponse},
    services::SessionService,
};

/// GET /users/me/sessions
///
/// List all active sessions for the current user.
#[utoipa::path(
    get,
    path = "/users/me/sessions",
    responses(
        (status = 200, description = "Sessions listed successfully", body = SessionListResponse),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "User Sessions"
)]
pub async fn list_sessions(
    Extension(session_service): Extension<Arc<SessionService>>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<(StatusCode, Json<SessionListResponse>), ApiAuthError> {
    // Current session is identified by JWT jti. A malformed jti must not hide it.
    let current_session_id =
        Uuid::parse_str(&claims.jti).map_err(|_| ApiAuthError::Unauthorized)?;

    let sessions = session_service
        .get_user_sessions(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            Some(current_session_id),
        )
        .await?;

    let session_responses: Vec<SessionInfoResponse> =
        sessions.into_iter().map(std::convert::Into::into).collect();

    let total = session_responses.len();

    Ok((
        StatusCode::OK,
        Json(SessionListResponse {
            sessions: session_responses,
            total,
        }),
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn list_sessions_does_not_hide_current_session_on_malformed_jti() {
        let src = include_str!("list.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            !production.contains("Uuid::parse_str(&claims.jti).ok()"),
            "session list must refuse a malformed JWT jti"
        );
    }
}
