//! Registration endpoint handler.
//!
//! POST /auth/register - Create a new user account.

use crate::error::ApiAuthError;
use crate::models::{RegisterRequest, RegisterResponse};
use crate::services::{
    generate_email_verification_token, AuthService, EmailSender, PasswordPolicyService,
    EMAIL_VERIFICATION_TOKEN_VALIDITY_HOURS,
};
use axum::{extract::ConnectInfo, http::StatusCode, Extension, Json};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;
use validator::Validate;
use xavyo_core::TenantId;

/// Handle user registration.
///
/// Creates a new user account with the provided email and password.
/// Validates input, checks for duplicate email within the tenant,
/// and sends a verification email to the user.
#[utoipa::path(
    post,
    path = "/auth/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "User created successfully", body = RegisterResponse),
        (status = 400, description = "Invalid email or weak password"),
        (status = 409, description = "Email already in use for this tenant"),
        (status = 500, description = "Server error"),
    ),
    tag = "Authentication"
)]
pub async fn register_handler(
    Extension(pool): Extension<PgPool>,
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(email_sender): Extension<Arc<dyn EmailSender>>,
    Extension(password_policy_service): Extension<Arc<PasswordPolicyService>>,
    Extension(tenant_id): Extension<TenantId>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiAuthError> {
    // Validate request using validator derive
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
        if errors.iter().any(|e| e.contains("email")) {
            ApiAuthError::InvalidEmail(errors.join(", "))
        } else {
            ApiAuthError::WeakPassword(errors)
        }
    })?;

    // Get tenant's password policy and validate password against it
    let policy = password_policy_service
        .get_password_policy(*tenant_id.as_uuid())
        .await?;

    let validation = PasswordPolicyService::validate_password(&request.password, &policy);
    if !validation.is_valid {
        let errors: Vec<String> = validation.errors.iter().map(std::string::ToString::to_string).collect();
        return Err(ApiAuthError::WeakPassword(errors));
    }

    // Register user
    let (user_id, email, created_at) = auth_service
        .register(tenant_id, &request.email, &request.password)
        .await?;

    // Send verification email (best effort - don't fail registration if email fails)
    if let Err(e) = send_verification_email(
        &pool,
        email_sender.as_ref(),
        tenant_id,
        *user_id.as_uuid(),
        &email,
        addr.ip(),
    )
    .await
    {
        tracing::warn!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            error = %e,
            "Failed to send verification email during registration"
        );
    }

    let response = RegisterResponse {
        id: *user_id.as_uuid(),
        email,
        created_at,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Send verification email to newly registered user.
async fn send_verification_email(
    pool: &PgPool,
    email_sender: &dyn EmailSender,
    tenant_id: TenantId,
    user_id: uuid::Uuid,
    email: &str,
    ip: std::net::IpAddr,
) -> Result<(), ApiAuthError> {
    // Generate verification token
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
        "Verification email sent during registration"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    // Handler tests require integration test setup with mock services
    // See tests/integration_test.rs for full handler tests
}
