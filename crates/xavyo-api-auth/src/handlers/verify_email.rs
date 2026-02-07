//! Verify email endpoint handler.
//!
//! POST /auth/verify-email - Verify user's email address.

use crate::error::ApiAuthError;
use crate::models::{VerifyEmailRequest, VerifyEmailResponse};
use crate::services::{hash_token, verify_token_hash_constant_time};
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use validator::Validate;
use xavyo_core::TenantId;
use xavyo_db::set_tenant_context;

/// Email verification token row from database query.
type EmailVerificationTokenRow = (
    uuid::Uuid,            // id
    uuid::Uuid,            // tenant_id
    uuid::Uuid,            // user_id
    String,                // token_hash
    DateTime<Utc>,         // expires_at
    Option<DateTime<Utc>>, // verified_at
);

/// Handle verify email request.
///
/// Verifies the user's email address using the token from email.
/// Idempotent - succeeds gracefully if already verified.
#[utoipa::path(
    post,
    path = "/auth/verify-email",
    request_body = VerifyEmailRequest,
    responses(
        (status = 200, description = "Email verified", body = VerifyEmailResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Invalid or expired token"),
    ),
    tag = "Authentication"
)]
pub async fn verify_email_handler(
    Extension(pool): Extension<PgPool>,
    Extension(tenant_id): Extension<TenantId>,
    Json(request): Json<VerifyEmailRequest>,
) -> Result<Json<VerifyEmailResponse>, ApiAuthError> {
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

    // Hash the provided token to look up in database
    let token_hash = hash_token(&request.token);

    // Look up the token
    let token_row: Option<EmailVerificationTokenRow> = sqlx::query_as(
        r"
        SELECT id, tenant_id, user_id, token_hash, expires_at, verified_at
        FROM email_verification_tokens
        WHERE token_hash = $1
        ",
    )
    .bind(&token_hash)
    .fetch_optional(&pool)
    .await?;

    let (token_id, token_tenant_id, user_id, stored_hash, expires_at, verified_at) =
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

    // Check if user is already verified (include tenant_id for defense-in-depth)
    let (is_active, email_verified): (bool, bool) = sqlx::query_as(
        "SELECT is_active, email_verified FROM users WHERE id = $1 AND tenant_id = $2",
    )
    .bind(user_id)
    .bind(*tenant_id.as_uuid())
    .fetch_optional(&pool)
    .await?
    .ok_or(ApiAuthError::InvalidToken)?;

    // If already verified, return success (idempotent)
    if email_verified {
        tracing::debug!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            "Email already verified, returning success"
        );
        return Ok(Json(VerifyEmailResponse::already_verified()));
    }

    // Check if user is active
    if !is_active {
        return Err(ApiAuthError::AccountInactive);
    }

    // Check if token already used (different from user being verified)
    if verified_at.is_some() {
        tracing::debug!(
            token_id = %token_id,
            tenant_id = %tenant_id,
            "Token already used but user not verified - unusual state"
        );
        // This is an edge case - token used but user not verified
        // Could happen if verification was partially processed
        return Err(ApiAuthError::TokenUsed);
    }

    // Check if token expired
    if expires_at <= Utc::now() {
        tracing::warn!(
            token_id = %token_id,
            tenant_id = %tenant_id,
            "Attempted use of expired verification token"
        );
        return Err(ApiAuthError::TokenExpired);
    }

    // Use a transaction with tenant context for RLS compliance
    let mut tx = pool.begin().await?;
    set_tenant_context(&mut *tx, tenant_id).await?;

    // Mark user as verified (include tenant_id for defense-in-depth)
    sqlx::query(
        "UPDATE users SET email_verified = true, email_verified_at = NOW(), updated_at = NOW() WHERE id = $1 AND tenant_id = $2"
    )
    .bind(user_id)
    .bind(*tenant_id.as_uuid())
    .execute(&mut *tx)
    .await?;

    // Mark token as used
    sqlx::query("UPDATE email_verification_tokens SET verified_at = NOW() WHERE id = $1")
        .bind(token_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    tracing::info!(
        user_id = %user_id,
        tenant_id = %tenant_id,
        "Email verification completed successfully"
    );

    Ok(Json(VerifyEmailResponse::verified()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_email_response_verified() {
        let response = VerifyEmailResponse::verified();
        assert!(response.message.contains("verified"));
        assert!(!response.already_verified);
    }

    #[test]
    fn test_verify_email_response_already_verified() {
        let response = VerifyEmailResponse::already_verified();
        assert!(response.message.contains("verified"));
        assert!(response.already_verified);
    }
}
