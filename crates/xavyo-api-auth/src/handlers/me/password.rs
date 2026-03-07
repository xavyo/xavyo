//! Password change handler for /me/password.
//!
//! PUT /me/password - Change password for authenticated user.
//! Delegates to the shared `do_password_change` logic.

use crate::error::ApiAuthError;
use crate::handlers::password_change::do_password_change;
use crate::models::{PasswordChangeRequest, PasswordChangeResponse};
use crate::services::{AlertService, PasswordPolicyService, SessionService};
use axum::{extract::ConnectInfo, Extension, Json};
use std::net::SocketAddr;
use std::sync::Arc;
use xavyo_core::{TenantId, UserId};

/// Handle PUT /me/password request.
///
/// Allows authenticated users to change their password via the /me namespace.
/// Respects `revoke_other_sessions` flag (defaults to true).
#[utoipa::path(
    put,
    path = "/me/password",
    request_body = PasswordChangeRequest,
    responses(
        (status = 200, description = "Password changed successfully", body = PasswordChangeResponse),
        (status = 400, description = "Validation failed"),
        (status = 401, description = "Invalid current password"),
    ),
    tag = "User Profile"
)]
pub async fn me_password_change(
    Extension(tenant_id): Extension<TenantId>,
    Extension(user_id): Extension<UserId>,
    Extension(password_policy_service): Extension<Arc<PasswordPolicyService>>,
    Extension(alert_service): Extension<Arc<AlertService>>,
    Extension(session_service): Extension<Arc<SessionService>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<PasswordChangeRequest>,
) -> Result<Json<PasswordChangeResponse>, ApiAuthError> {
    let revoke = request.revoke_other_sessions;
    do_password_change(
        &tenant_id,
        &user_id,
        &password_policy_service,
        &alert_service,
        &session_service,
        addr,
        request,
        revoke,
    )
    .await
}
