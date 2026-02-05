//! Password change endpoint handler.
//!
//! PUT /auth/password - Change password for authenticated user.

use crate::error::ApiAuthError;
use crate::models::{PasswordChangeRequest, PasswordChangeResponse};
use crate::services::{AlertService, PasswordPolicyService};
use axum::{extract::ConnectInfo, http::HeaderMap, Extension, Json};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;
use validator::Validate;
use xavyo_auth::{hash_password, verify_password};
use xavyo_core::{TenantId, UserId};
use xavyo_db::User;

/// Handle password change request.
///
/// Allows authenticated users to change their password.
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
#[allow(clippy::too_many_arguments)]
pub async fn password_change_handler(
    Extension(pool): Extension<PgPool>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(user_id): Extension<UserId>,
    Extension(password_policy_service): Extension<Arc<PasswordPolicyService>>,
    Extension(alert_service): Extension<Arc<AlertService>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<PasswordChangeRequest>,
) -> Result<Json<PasswordChangeResponse>, ApiAuthError> {
    // Extract client info for audit (F025)
    let ip_str = Some(addr.ip().to_string());
    let _user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    // Validate request format
    request.validate().map_err(|e| {
        let errors: Vec<String> = e
            .field_errors()
            .values()
            .flat_map(|errors| {
                errors
                    .iter()
                    .filter_map(|e| e.message.as_ref().map(std::string::ToString::to_string))
            })
            .collect();
        ApiAuthError::Validation(errors.join(", "))
    })?;

    // Get the current user
    let user: User = sqlx::query_as("SELECT * FROM users WHERE id = $1 AND tenant_id = $2")
        .bind(user_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_optional(&pool)
        .await?
        .ok_or_else(|| ApiAuthError::Internal("User not found".to_string()))?;

    // Verify current password
    let valid = verify_password(&request.current_password, &user.password_hash)
        .map_err(|e| ApiAuthError::Internal(format!("Password verification failed: {e}")))?;

    if !valid {
        tracing::debug!(user_id = %user_id, "Invalid current password during password change");
        return Err(ApiAuthError::InvalidCredentials);
    }

    // Get the tenant's password policy
    let policy = password_policy_service
        .get_password_policy(*tenant_id.as_uuid())
        .await?;

    // Check minimum password age (if applicable)
    if let Err(e) = PasswordPolicyService::check_min_password_age(
        user.password_changed_at,
        policy.min_age_hours,
    ) {
        return Err(ApiAuthError::Validation(e.to_string()));
    }

    // Validate new password against policy
    let validation = PasswordPolicyService::validate_password(&request.new_password, &policy);
    if !validation.is_valid {
        let errors: Vec<String> = validation
            .errors
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        return Err(ApiAuthError::WeakPassword(errors));
    }

    // Check password history
    if policy.history_count > 0 {
        let in_history = password_policy_service
            .check_password_history(
                *user_id.as_uuid(),
                *tenant_id.as_uuid(),
                &request.new_password,
                policy.history_count,
            )
            .await?;

        if in_history {
            return Err(ApiAuthError::Validation(
                "Password was recently used. Please choose a different password.".to_string(),
            ));
        }
    }

    // Hash the new password
    let new_password_hash = hash_password(&request.new_password)
        .map_err(|e| ApiAuthError::Internal(format!("Failed to hash password: {e}")))?;

    // Add old password to history (before updating)
    if policy.history_count > 0 {
        password_policy_service
            .add_to_password_history(
                *user_id.as_uuid(),
                *tenant_id.as_uuid(),
                &user.password_hash,
                policy.history_count,
            )
            .await?;
    }

    // Update the password (include tenant_id for defense-in-depth)
    sqlx::query(
        "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
    )
    .bind(&new_password_hash)
    .bind(user_id.as_uuid())
    .bind(tenant_id.as_uuid())
    .execute(&pool)
    .await?;

    // Update password timestamps
    password_policy_service
        .update_password_timestamps(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            policy.expiration_days,
        )
        .await?;

    // Revoke other sessions if requested
    let sessions_revoked = if request.revoke_other_sessions {
        // Note: This requires knowing the current session ID to exclude it
        // For now, we revoke all refresh tokens. A more complete implementation
        // would take the current refresh token and exclude it.
        let result = sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id.as_uuid())
        .execute(&pool)
        .await?;

        result.rows_affected() as i64
    } else {
        0
    };

    // Generate password change alert (F025)
    let _ = alert_service
        .generate_password_change_alert(*tenant_id.as_uuid(), *user_id.as_uuid(), ip_str.as_deref())
        .await;

    tracing::info!(
        user_id = %user_id,
        tenant_id = %tenant_id,
        sessions_revoked = sessions_revoked,
        "Password changed successfully"
    );

    Ok(Json(PasswordChangeResponse::success(sessions_revoked)))
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
}
