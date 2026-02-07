//! Forgot password endpoint handler.
//!
//! POST /auth/forgot-password - Initiate password reset flow.

use crate::error::ApiAuthError;
use crate::middleware::EmailRateLimiter;
use crate::models::{ForgotPasswordRequest, ForgotPasswordResponse};
use crate::services::{
    generate_password_reset_token, EmailSender, PASSWORD_RESET_TOKEN_VALIDITY_HOURS,
};
use axum::{extract::ConnectInfo, http::HeaderMap, Extension, Json};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use validator::Validate;
use xavyo_core::TenantId;
use xavyo_db::set_tenant_context;

/// Handle forgot password request.
///
/// Initiates password reset flow by generating a token and sending an email.
/// Always returns success to prevent email enumeration.
#[utoipa::path(
    post,
    path = "/auth/forgot-password",
    request_body = ForgotPasswordRequest,
    responses(
        (status = 200, description = "Request processed", body = ForgotPasswordResponse),
        (status = 429, description = "Rate limit exceeded"),
        (status = 400, description = "Invalid email format"),
    ),
    tag = "Authentication"
)]
pub async fn forgot_password_handler(
    Extension(pool): Extension<PgPool>,
    Extension(email_sender): Extension<Arc<dyn EmailSender>>,
    Extension(rate_limiter): Extension<Arc<EmailRateLimiter>>,
    Extension(tenant_id): Extension<TenantId>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<ForgotPasswordRequest>,
) -> Result<Json<ForgotPasswordResponse>, ApiAuthError> {
    // Validate request
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

    let email = request.email.trim().to_lowercase();
    let ip: IpAddr = addr.ip();

    // Check rate limit
    if !rate_limiter.record_attempt(&email, ip) {
        tracing::warn!(
            email = %email,
            ip = %ip,
            tenant_id = %tenant_id,
            "Password reset rate limit exceeded"
        );
        return Err(ApiAuthError::RateLimitExceeded);
    }

    // Process the reset request
    // Always return success to prevent email enumeration
    if let Err(e) = process_forgot_password(
        &pool,
        email_sender.as_ref(),
        tenant_id,
        &email,
        ip,
        &headers,
    )
    .await
    {
        // Log the error but don't return it to prevent enumeration
        tracing::warn!(
            email = %email,
            tenant_id = %tenant_id,
            error = %e,
            "Failed to process password reset (not returned to user)"
        );
    }

    Ok(Json(ForgotPasswordResponse::default()))
}

/// Process the forgot password request internally.
async fn process_forgot_password(
    pool: &PgPool,
    email_sender: &dyn EmailSender,
    tenant_id: TenantId,
    email: &str,
    ip: IpAddr,
    headers: &HeaderMap,
) -> Result<(), ApiAuthError> {
    // Look up user by email and tenant
    let user_row: Option<(uuid::Uuid, bool)> = sqlx::query_as(
        "SELECT id, is_active FROM users WHERE tenant_id = $1 AND LOWER(email) = LOWER($2)",
    )
    .bind(tenant_id.as_uuid())
    .bind(email)
    .fetch_optional(pool)
    .await?;

    let (user_id, is_active) = if let Some((id, active)) = user_row {
        (id, active)
    } else {
        tracing::debug!(
            email = %email,
            tenant_id = %tenant_id,
            "Password reset requested for non-existent email"
        );
        return Ok(()); // Don't leak that user doesn't exist
    };

    // Check if user is active
    if !is_active {
        tracing::debug!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            "Password reset requested for inactive account"
        );
        return Ok(()); // Don't leak account status
    }

    // Generate new token
    let (token, token_hash) = generate_password_reset_token();
    let expires_at = Utc::now() + Duration::hours(PASSWORD_RESET_TOKEN_VALIDITY_HOURS);

    // Extract user agent for audit
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Use a transaction with tenant context for RLS compliance
    let mut tx = pool.begin().await?;
    set_tenant_context(&mut *tx, tenant_id).await?;

    // Invalidate any existing unused tokens for this user
    sqlx::query(
        "UPDATE password_reset_tokens SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    // Store token hash in database
    sqlx::query(
        r"
        INSERT INTO password_reset_tokens (tenant_id, user_id, token_hash, expires_at, ip_address, user_agent)
        VALUES ($1, $2, $3, $4, $5, $6)
        ",
    )
    .bind(tenant_id.as_uuid())
    .bind(user_id)
    .bind(&token_hash)
    .bind(expires_at)
    .bind(ip.to_string())
    .bind(user_agent)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // Send email
    email_sender
        .send_password_reset(email, &token, tenant_id)
        .await
        .map_err(|e| ApiAuthError::EmailSendFailed(e.to_string()))?;

    tracing::info!(
        user_id = %user_id,
        tenant_id = %tenant_id,
        "Password reset email sent"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::MockEmailSender;

    #[test]
    fn test_forgot_password_response_default() {
        let response = ForgotPasswordResponse::default();
        assert!(response.message.contains("If an account exists"));
    }

    #[tokio::test]
    async fn test_mock_email_sender_records_reset() {
        let sender = MockEmailSender::new();
        let tenant_id = TenantId::new();

        sender
            .send_password_reset("test@example.com", "token123", tenant_id)
            .await
            .unwrap();

        let resets = sender.get_password_resets();
        assert_eq!(resets.len(), 1);
        assert_eq!(resets[0].0, "test@example.com");
        assert_eq!(resets[0].1, "token123");
    }
}
