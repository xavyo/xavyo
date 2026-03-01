//! Admin password reset handler.
//!
//! POST /admin/users/:user_id/reset-password

use crate::error::ApiAuthError;
use crate::services::{PasswordPolicyService, SessionService};
use axum::http::StatusCode;
use axum::{extract::Path, Extension, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;
use xavyo_auth::{hash_password, JwtClaims};
use xavyo_core::TenantId;
use xavyo_db::{set_tenant_context, RevokeReason};

#[derive(Debug, Deserialize, ToSchema)]
pub struct AdminResetPasswordRequest {
    pub new_password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AdminResetPasswordResponse {
    pub user_id: Uuid,
    pub message: String,
    pub sessions_revoked: i64,
}

/// Reset a user's password (admin action).
///
/// POST /admin/users/{user_id}/reset-password
#[utoipa::path(
    post,
    path = "/admin/users/{id}/reset-password",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    request_body = AdminResetPasswordRequest,
    responses(
        (status = 200, description = "Password reset", body = AdminResetPasswordResponse),
        (status = 400, description = "Weak password"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "User not found"),
    ),
    tag = "Admin - User Management"
)]
pub async fn admin_reset_password(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(password_policy_service): Extension<Arc<PasswordPolicyService>>,
    Extension(session_service): Extension<Arc<SessionService>>,
    Path(user_id): Path<Uuid>,
    Json(request): Json<AdminResetPasswordRequest>,
) -> Result<(StatusCode, Json<AdminResetPasswordResponse>), ApiAuthError> {
    if !claims.has_role("admin") {
        return Err(ApiAuthError::PermissionDenied(
            "Admin role required".to_string(),
        ));
    }

    // Validate password against tenant policy
    let policy = password_policy_service
        .get_password_policy(*tenant_id.as_uuid())
        .await?;

    let validation = PasswordPolicyService::validate_password(&request.new_password, &policy);
    if !validation.is_valid {
        let errors: Vec<String> = validation
            .errors
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        return Err(ApiAuthError::WeakPassword(errors));
    }

    // Check against HIBP breached password database (NIST 800-63B)
    if let Err(e) = PasswordPolicyService::check_breached(&request.new_password, &policy).await {
        return Err(ApiAuthError::WeakPassword(vec![e.to_string()]));
    }

    // Check user exists in this tenant
    let user_exists: Option<(bool,)> = sqlx::query_as(
        "SELECT is_active FROM users WHERE id = $1 AND tenant_id = $2",
    )
    .bind(user_id)
    .bind(*tenant_id.as_uuid())
    .fetch_optional(&pool)
    .await?;

    let (is_active,) = user_exists.ok_or(ApiAuthError::UserNotFound)?;

    if !is_active {
        return Err(ApiAuthError::AccountInactive);
    }

    // Hash the new password
    let new_password_hash = hash_password(&request.new_password)
        .map_err(|e| ApiAuthError::Internal(format!("Failed to hash password: {e}")))?;

    // Update password in a transaction with tenant context
    let mut tx = pool.begin().await?;
    set_tenant_context(&mut *tx, tenant_id).await?;

    sqlx::query(
        "UPDATE users SET password_hash = $1, failed_login_count = 0, locked_at = NULL, locked_until = NULL, updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
    )
    .bind(&new_password_hash)
    .bind(user_id)
    .bind(*tenant_id.as_uuid())
    .execute(&mut *tx)
    .await?;

    // Revoke all refresh tokens
    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(*tenant_id.as_uuid())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // Revoke all active sessions
    let sessions_revoked = session_service
        .revoke_all_user_sessions(user_id, *tenant_id.as_uuid(), RevokeReason::PasswordChange)
        .await
        .unwrap_or(0) as i64;

    tracing::info!(
        admin_id = %claims.sub,
        user_id = %user_id,
        tenant_id = %tenant_id,
        sessions_revoked = sessions_revoked,
        "Admin reset password for user"
    );

    Ok((
        StatusCode::OK,
        Json(AdminResetPasswordResponse {
            user_id,
            message: "Password reset successfully".to_string(),
            sessions_revoked,
        }),
    ))
}
