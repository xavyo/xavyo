//! Resend verification endpoint handler.
//!
//! POST /auth/resend-verification - Resend email verification link.

use crate::error::ApiAuthError;
use crate::middleware::EmailRateLimiter;
use crate::models::{ResendVerificationRequest, ResendVerificationResponse};
use crate::services::{
    generate_email_verification_token, EmailSender, EMAIL_VERIFICATION_TOKEN_VALIDITY_HOURS,
};
use axum::{extract::ConnectInfo, http::HeaderMap, Extension, Json};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use validator::Validate;
use xavyo_core::TenantId;

/// Handle resend verification request.
///
/// Resends the email verification link for unverified accounts.
/// Invalidates any previous verification tokens.
/// Always returns success to prevent email enumeration.
#[utoipa::path(
    post,
    path = "/auth/resend-verification",
    request_body = ResendVerificationRequest,
    responses(
        (status = 200, description = "Request processed", body = ResendVerificationResponse),
        (status = 429, description = "Rate limit exceeded"),
        (status = 400, description = "Invalid email format"),
    ),
    tag = "Authentication"
)]
pub async fn resend_verification_handler(
    Extension(pool): Extension<PgPool>,
    Extension(email_sender): Extension<Arc<dyn EmailSender>>,
    Extension(rate_limiter): Extension<Arc<EmailRateLimiter>>,
    Extension(tenant_id): Extension<TenantId>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<ResendVerificationRequest>,
) -> Result<Json<ResendVerificationResponse>, ApiAuthError> {
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
            "Resend verification rate limit exceeded"
        );
        return Err(ApiAuthError::RateLimitExceeded);
    }

    // Process the resend request
    // Always return success to prevent email enumeration
    if let Err(e) = process_resend_verification(
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
            "Failed to process resend verification (not returned to user)"
        );
    }

    Ok(Json(ResendVerificationResponse::default()))
}

/// Process the resend verification request internally.
async fn process_resend_verification(
    pool: &PgPool,
    email_sender: &dyn EmailSender,
    tenant_id: TenantId,
    email: &str,
    ip: IpAddr,
    _headers: &HeaderMap,
) -> Result<(), ApiAuthError> {
    // Look up user by email and tenant
    let user_row: Option<(uuid::Uuid, bool, bool)> = sqlx::query_as(
        "SELECT id, is_active, email_verified FROM users WHERE tenant_id = $1 AND LOWER(email) = LOWER($2)"
    )
    .bind(tenant_id.as_uuid())
    .bind(email)
    .fetch_optional(pool)
    .await?;

    let (user_id, is_active, email_verified) = if let Some((id, active, verified)) = user_row { (id, active, verified) } else {
        tracing::debug!(
            email = %email,
            tenant_id = %tenant_id,
            "Resend verification requested for non-existent email"
        );
        return Ok(()); // Don't leak that user doesn't exist
    };

    // Check if user is active
    if !is_active {
        tracing::debug!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            "Resend verification requested for inactive account"
        );
        return Ok(()); // Don't leak account status
    }

    // Check if already verified
    if email_verified {
        tracing::debug!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            "Resend verification requested for already verified email"
        );
        return Ok(()); // Don't send email if already verified
    }

    // Invalidate any existing unused tokens for this user
    sqlx::query(
        "UPDATE email_verification_tokens SET verified_at = NOW() WHERE user_id = $1 AND verified_at IS NULL"
    )
    .bind(user_id)
    .execute(pool)
    .await?;

    // Generate new token
    let (token, token_hash) = generate_email_verification_token();
    let expires_at = Utc::now() + Duration::hours(EMAIL_VERIFICATION_TOKEN_VALIDITY_HOURS);

    // Store token hash in database
    sqlx::query(
        r"
        INSERT INTO email_verification_tokens (tenant_id, user_id, token_hash, expires_at, ip_address)
        VALUES ($1, $2, $3, $4, $5)
        ",
    )
    .bind(tenant_id.as_uuid())
    .bind(user_id)
    .bind(&token_hash)
    .bind(expires_at)
    .bind(ip.to_string())
    .execute(pool)
    .await?;

    // Send email
    email_sender
        .send_verification(email, &token, tenant_id)
        .await
        .map_err(|e| ApiAuthError::EmailSendFailed(e.to_string()))?;

    tracing::info!(
        user_id = %user_id,
        tenant_id = %tenant_id,
        "Verification email resent"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resend_verification_response_default() {
        let response = ResendVerificationResponse::default();
        assert!(response.message.contains("If an unverified account exists"));
    }
}
