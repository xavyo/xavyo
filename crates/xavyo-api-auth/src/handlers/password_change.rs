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
use validator::Validate;
use xavyo_core::{TenantId, UserId};

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
) -> Result<Json<PasswordChangeResponse>, ApiAuthError> {
    request.validate().map_err(extract_validation_errors)?;

    let result = password_policy_service
        .change_user_password(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            &request.current_password,
            &request.new_password,
            revoke_sessions,
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
    Extension(password_policy_service): Extension<Arc<PasswordPolicyService>>,
    Extension(alert_service): Extension<Arc<AlertService>>,
    Extension(session_service): Extension<Arc<SessionService>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<PasswordChangeRequest>,
) -> Result<Json<PasswordChangeResponse>, ApiAuthError> {
    do_password_change(
        &tenant_id,
        &user_id,
        &password_policy_service,
        &alert_service,
        &session_service,
        addr,
        request,
        true, // always revoke
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
}
