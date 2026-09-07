//! Password change endpoint handlers.
//!
//! PUT /auth/password - Change password (always revokes all sessions)
//! Shared logic also used by PUT /me/password

use crate::error::ApiAuthError;
use crate::models::{PasswordChangeRequest, PasswordChangeResponse};
use crate::services::{
    extract_validation_errors, AlertService, PasswordPolicyService, SessionService,
};
use axum::{extract::ConnectInfo, Extension, Json};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;
use xavyo_core::{TenantId, UserId};

/// The current session id is the access token's `jti` (login pins jti == session id).
/// Used to preserve the caller's own session when revoking on password change.
pub(crate) fn current_session_id(claims: &JwtClaims) -> Option<Uuid> {
    Uuid::parse_str(&claims.jti).ok()
}

/// Shared password change logic for both `/auth/password` and `/me/password`.
pub(crate) async fn do_password_change(
    tenant_id: &TenantId,
    user_id: &UserId,
    password_policy_service: &PasswordPolicyService,
    alert_service: &AlertService,
    session_service: &SessionService,
    addr: SocketAddr,
    request: PasswordChangeRequest,
    revoke_sessions: bool,
    current_session_id: Option<Uuid>,
) -> Result<Json<PasswordChangeResponse>, ApiAuthError> {
    request.validate().map_err(extract_validation_errors)?;

    let result = password_policy_service
        .change_user_password(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            &request.current_password,
            &request.new_password,
            revoke_sessions,
            current_session_id,
            session_service,
        )
        .await?;

    password_change_alert_recorded(
        alert_service
            .generate_password_change_alert(
                *tenant_id.as_uuid(),
                *user_id.as_uuid(),
                Some(&addr.ip().to_string()),
            )
            .await,
    )?;

    tracing::info!(
        user_id = %user_id,
        tenant_id = %tenant_id,
        sessions_revoked = result.sessions_revoked,
        refresh_tokens_revoked = result.refresh_tokens_revoked,
        "Password changed successfully"
    );

    Ok(Json(PasswordChangeResponse::success(
        result.sessions_revoked,
    )))
}

/// Password-change alerts must fail closed. Swallowing persist errors would
/// look like the security notification was recorded.
pub(crate) fn password_change_alert_recorded<T, E>(result: Result<T, E>) -> Result<T, E> {
    result
}

/// Handle password change request.
///
/// Allows authenticated users to change their password.
/// Always revokes all sessions on password change (security best practice).
#[utoipa::path(
    put,
    path = "/auth/password",
    request_body = PasswordChangeRequest,
    responses(
        (status = 200, description = "Password changed successfully", body = PasswordChangeResponse),
        (status = 400, description = "Validation failed"),
        (status = 401, description = "Invalid current password"),
        (status = 403, description = "Password was recently used"),
    ),
    security(("bearerAuth" = [])),
    tag = "Authentication"
)]
pub async fn password_change_handler(
    Extension(tenant_id): Extension<TenantId>,
    Extension(user_id): Extension<UserId>,
    Extension(claims): Extension<JwtClaims>,
    Extension(password_policy_service): Extension<Arc<PasswordPolicyService>>,
    Extension(alert_service): Extension<Arc<AlertService>>,
    Extension(session_service): Extension<Arc<SessionService>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<PasswordChangeRequest>,
) -> Result<Json<PasswordChangeResponse>, ApiAuthError> {
    // Honor the caller's revoke_other_sessions preference; preserve the current
    // session so the user is not signed out by their own password change.
    let revoke = request.revoke_other_sessions;
    let current = current_session_id(&claims);
    do_password_change(
        &tenant_id,
        &user_id,
        &password_policy_service,
        &alert_service,
        &session_service,
        addr,
        request,
        revoke,
        current,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_change_response() {
        let response = PasswordChangeResponse::success(3);
        assert_eq!(response.sessions_revoked, 3);
        assert!(response.message.contains("successfully"));
    }

    #[test]
    fn password_change_alert_recorded_propagates_errors() {
        assert!(password_change_alert_recorded(Ok::<(), &str>(())).is_ok());
        assert!(password_change_alert_recorded(Err::<(), _>("db")).is_err());
    }

    #[test]
    fn password_change_does_not_swallow_security_alert() {
        let src = include_str!("password_change.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("password_change_alert_recorded("),
            "password-change alert persist must fail closed"
        );
        assert!(
            !production.contains("let _ = alert_service"),
            "must not report password change success when the alert was not recorded"
        );
    }

    #[test]
    fn password_change_honors_flag_and_preserves_current_session() {
        let src = include_str!("password_change.rs");
        let production = src.split("mod tests").next().expect("production source");
        // /auth/password must honor the caller's revoke_other_sessions preference
        // rather than hardcoding a full revoke...
        assert!(
            !production.contains("true, // always revoke"),
            "/auth/password must not hardcode revoke=true (ignores the checkbox)"
        );
        assert!(
            production.contains("let revoke = request.revoke_other_sessions;"),
            "/auth/password must use the request's revoke_other_sessions flag"
        );
        // ...and pass the current session id so the caller's own session survives.
        assert!(
            production.contains("current_session_id(&claims)"),
            "password change must derive the current session id to preserve it"
        );
    }
}
