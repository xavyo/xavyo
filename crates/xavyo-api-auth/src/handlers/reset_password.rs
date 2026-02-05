//! Reset password endpoint handler.
//!
//! POST /auth/reset-password - Complete password reset with token.

use crate::error::ApiAuthError;
use crate::models::{ResetPasswordRequest, ResetPasswordResponse};
use crate::services::{hash_token, verify_token_hash_constant_time, PasswordPolicyService};
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use validator::Validate;
use xavyo_auth::hash_password;
use xavyo_core::TenantId;

/// Password reset token row from database query.
type PasswordResetTokenRow = (
    uuid::Uuid,            // id
    uuid::Uuid,            // tenant_id
    uuid::Uuid,            // user_id
    String,                // token_hash
    DateTime<Utc>,         // expires_at
    Option<DateTime<Utc>>, // used_at
);

/// Handle reset password request.
///
/// Completes the password reset flow using the token from email.
/// Validates the token, checks expiration, and updates the password.
/// Also invalidates all existing refresh tokens for the user.
#[utoipa::path(
    post,
    path = "/auth/reset-password",
    request_body = ResetPasswordRequest,
    responses(
        (status = 200, description = "Password reset successful", body = ResetPasswordResponse),
        (status = 400, description = "Invalid request or weak password"),
        (status = 401, description = "Invalid, expired, or already used token"),
    ),
    tag = "Authentication"
)]
pub async fn reset_password_handler(
    Extension(pool): Extension<PgPool>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(password_policy_service): Extension<Arc<PasswordPolicyService>>,
    Json(request): Json<ResetPasswordRequest>,
) -> Result<Json<ResetPasswordResponse>, ApiAuthError> {
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

    // Get tenant's password policy and validate password against it
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

    // Hash the provided token to look up in database
    let token_hash = hash_token(&request.token);

    // Look up the token
    let token_row: Option<PasswordResetTokenRow> = sqlx::query_as(
        r"
        SELECT id, tenant_id, user_id, token_hash, expires_at, used_at
        FROM password_reset_tokens
        WHERE token_hash = $1
        ",
    )
    .bind(&token_hash)
    .fetch_optional(&pool)
    .await?;

    let (token_id, token_tenant_id, user_id, stored_hash, expires_at, used_at) =
        token_row.ok_or(ApiAuthError::InvalidToken)?;

    // Verify token hash with constant-time comparison
    if !verify_token_hash_constant_time(&request.token, &stored_hash) {
        return Err(ApiAuthError::InvalidToken);
    }

    // Check tenant isolation
    if token_tenant_id != *tenant_id.as_uuid() {
        tracing::warn!(
            token_tenant = %token_tenant_id,
            request_tenant = %tenant_id,
            "Token tenant mismatch"
        );
        return Err(ApiAuthError::InvalidToken);
    }

    // Check if token already used
    if used_at.is_some() {
        tracing::warn!(
            token_id = %token_id,
            tenant_id = %tenant_id,
            "Attempted use of already-used password reset token"
        );
        return Err(ApiAuthError::TokenUsed);
    }

    // Check if token expired
    if expires_at <= Utc::now() {
        tracing::warn!(
            token_id = %token_id,
            tenant_id = %tenant_id,
            "Attempted use of expired password reset token"
        );
        return Err(ApiAuthError::TokenExpired);
    }

    // Check if user is active and get current password hash for history (include tenant_id for defense-in-depth)
    let user_row: Option<(bool, String)> = sqlx::query_as(
        "SELECT is_active, password_hash FROM users WHERE id = $1 AND tenant_id = $2",
    )
    .bind(user_id)
    .bind(*tenant_id.as_uuid())
    .fetch_optional(&pool)
    .await?;

    let (is_active, old_password_hash) = user_row.ok_or(ApiAuthError::InvalidToken)?;

    if !is_active {
        return Err(ApiAuthError::AccountInactive);
    }

    // Check password history if enabled
    if policy.history_count > 0 {
        let in_history = password_policy_service
            .check_password_history(
                user_id,
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
                user_id,
                *tenant_id.as_uuid(),
                &old_password_hash,
                policy.history_count,
            )
            .await?;
    }

    // Update user's password (include tenant_id for defense-in-depth)
    sqlx::query(
        "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
    )
    .bind(&new_password_hash)
    .bind(user_id)
    .bind(*tenant_id.as_uuid())
    .execute(&pool)
    .await?;

    // Update password timestamps
    password_policy_service
        .update_password_timestamps(user_id, *tenant_id.as_uuid(), policy.expiration_days)
        .await?;

    // Mark token as used
    sqlx::query("UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1")
        .bind(token_id)
        .execute(&pool)
        .await?;

    // Revoke all refresh tokens for this user (security measure)
    let revoked = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(&pool)
    .await?;

    tracing::info!(
        user_id = %user_id,
        tenant_id = %tenant_id,
        tokens_revoked = %revoked.rows_affected(),
        "Password reset completed successfully"
    );

    Ok(Json(ResetPasswordResponse::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reset_password_response_default() {
        let response = ResetPasswordResponse::default();
        assert!(response.message.contains("reset successfully"));
    }
}
