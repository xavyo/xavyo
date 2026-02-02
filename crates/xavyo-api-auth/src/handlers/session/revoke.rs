//! Revoke single session handler.

use axum::{extract::Path, http::StatusCode, Extension};
use std::sync::Arc;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::{TenantId, UserId};
use xavyo_db::RevokeReason;

use crate::{error::ApiAuthError, services::SessionService};

/// DELETE /users/me/sessions/:id
///
/// Revoke a specific session.
/// Users cannot revoke their current session via this endpoint.
pub async fn revoke_session(
    Extension(session_service): Extension<Arc<SessionService>>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, ApiAuthError> {
    // Check if trying to revoke current session
    if let Ok(current_jti) = Uuid::parse_str(&claims.jti) {
        if current_jti == session_id {
            return Err(ApiAuthError::CannotRevokeCurrentSession);
        }
    }

    // Verify session exists and belongs to user
    let session = session_service
        .get_session(session_id, *tenant_id.as_uuid())
        .await?
        .ok_or(ApiAuthError::SessionNotFound)?;

    // Verify session belongs to this user
    if session.user_id != *user_id.as_uuid() {
        return Err(ApiAuthError::SessionNotFound);
    }

    // Revoke the session
    let revoked = session_service
        .revoke_session(session_id, *tenant_id.as_uuid(), RevokeReason::UserLogout)
        .await?;

    if !revoked {
        return Err(ApiAuthError::SessionNotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}
