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
pub async fn list_sessions(
    Extension(session_service): Extension<Arc<SessionService>>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<(StatusCode, Json<SessionListResponse>), ApiAuthError> {
    // Get current session ID from JWT jti if available
    let current_session_id = Uuid::parse_str(&claims.jti).ok();

    let sessions = session_service
        .get_user_sessions(*user_id.as_uuid(), *tenant_id.as_uuid(), current_session_id)
        .await?;

    let session_responses: Vec<SessionInfoResponse> =
        sessions.into_iter().map(|s| s.into()).collect();

    let total = session_responses.len();

    Ok((
        StatusCode::OK,
        Json(SessionListResponse {
            sessions: session_responses,
            total,
        }),
    ))
}
