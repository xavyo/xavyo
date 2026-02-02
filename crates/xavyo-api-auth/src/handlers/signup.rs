//! Self-service signup endpoint handler.
//!
//! POST /auth/signup - Create a new user account in the system tenant.
//!
//! This handler allows new users to create accounts without prior authentication.
//! It uses the pre-configured system tenant (SYSTEM_TENANT_ID) and returns a JWT
//! for immediate use in the device code flow.

use crate::error::ApiAuthError;
use crate::models::{SignupRequest, SignupResponse};
use crate::services::{
    generate_email_verification_token, AuthService, EmailSender, TokenService,
    EMAIL_VERIFICATION_TOKEN_VALIDITY_HOURS,
};
use axum::{extract::ConnectInfo, http::StatusCode, Extension, Json};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;
use validator::Validate;
use xavyo_core::TenantId;
use xavyo_db::SYSTEM_TENANT_ID;

/// Handle self-service signup.
///
/// Creates a new user account in the system tenant and returns a JWT
/// for immediate use. This endpoint does not require authentication.
///
/// # Validation
///
/// - Email must be valid format
/// - Password must meet complexity requirements:
///   - Minimum 8 characters
///   - At least one uppercase letter (A-Z)
///   - At least one lowercase letter (a-z)
///   - At least one digit (0-9)
/// - Display name (optional) must not exceed 255 characters
///
/// # Errors
///
/// - 400 Bad Request: Invalid input (weak password, invalid email, invalid display_name)
/// - 409 Conflict: Email already registered in system tenant
/// - 429 Too Many Requests: Rate limit exceeded
/// - 503 Service Unavailable: System tenant not configured
#[utoipa::path(
    post,
    path = "/auth/signup",
    request_body = SignupRequest,
    responses(
        (status = 201, description = "User created successfully", body = SignupResponse),
        (status = 400, description = "Validation error (weak password, invalid email, invalid display_name)"),
        (status = 409, description = "Email already registered"),
        (status = 429, description = "Rate limit exceeded"),
        (status = 503, description = "System tenant not configured"),
    ),
    tag = "Authentication"
)]
pub async fn signup_handler(
    Extension(pool): Extension<PgPool>,
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(token_service): Extension<Arc<TokenService>>,
    Extension(email_sender): Extension<Arc<dyn EmailSender>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<SignupRequest>,
) -> Result<(StatusCode, Json<SignupResponse>), ApiAuthError> {
    // Validate request using validator derive
    request.validate().map_err(|e| {
        let errors: Vec<String> = e
            .field_errors()
            .values()
            .flat_map(|errors| {
                errors
                    .iter()
                    .filter_map(|e| e.message.as_ref().map(|m| m.to_string()))
            })
            .collect();
        if errors.iter().any(|e| e.contains("email")) {
            ApiAuthError::InvalidEmail(errors.join(", "))
        } else {
            ApiAuthError::Validation(errors.join(", "))
        }
    })?;

    // Validate password complexity
    validate_password_complexity(&request.password)?;

    // Validate display name if provided
    if let Some(ref display_name) = request.display_name {
        validate_display_name(display_name)?;
    }

    // Use system tenant ID
    let tenant_id = TenantId::from_uuid(SYSTEM_TENANT_ID);

    // Check if email already exists in system tenant using get_user_by_email
    if auth_service
        .get_user_by_email(tenant_id, &request.email)
        .await?
        .is_some()
    {
        return Err(ApiAuthError::EmailInUse);
    }

    // Register user in system tenant
    let (user_id, email, _created_at) = auth_service
        .register(tenant_id, &request.email, &request.password)
        .await?;

    // Update display name if provided
    if let Some(ref display_name) = request.display_name {
        sqlx::query("UPDATE users SET display_name = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(display_name)
            .bind(user_id.as_uuid())
            .bind(SYSTEM_TENANT_ID)
            .execute(&pool)
            .await?;
    }

    // Generate tokens using TokenService
    let (access_token, _refresh_token, expires_in) = token_service
        .create_tokens(
            user_id,
            tenant_id,
            vec![], // No roles for new user
            Some(email.clone()),
            None, // No user agent
            Some(addr.ip()),
        )
        .await?;

    // Send verification email (async, non-blocking)
    // We spawn this as a background task to not block the response
    let email_sender_clone = email_sender.clone();
    let pool_clone = pool.clone();
    let user_id_uuid = *user_id.as_uuid();
    let email_clone = email.clone();
    let tenant_id_clone = tenant_id;
    let ip = addr.ip();

    tokio::spawn(async move {
        if let Err(e) = send_verification_email(
            &pool_clone,
            email_sender_clone.as_ref(),
            tenant_id_clone,
            user_id_uuid,
            &email_clone,
            ip,
        )
        .await
        {
            warn!(
                user_id = %user_id_uuid,
                tenant_id = %SYSTEM_TENANT_ID,
                error = %e,
                "Failed to send verification email during signup"
            );
        }
    });

    // Audit log
    info!(
        user_id = %user_id,
        tenant_id = %SYSTEM_TENANT_ID,
        email = %email,
        ip = %addr.ip(),
        "signup.success: New user signed up in system tenant"
    );

    let response = SignupResponse::new(*user_id.as_uuid(), email, access_token, expires_in);

    Ok((StatusCode::CREATED, Json(response)))
}

/// Validate password complexity.
///
/// Ensures password meets the following requirements:
/// - Minimum 8 characters
/// - At least one uppercase letter (A-Z)
/// - At least one lowercase letter (a-z)
/// - At least one digit (0-9)
pub fn validate_password_complexity(password: &str) -> Result<(), ApiAuthError> {
    let mut errors = Vec::new();

    if password.len() < 8 {
        errors.push("Password must be at least 8 characters".to_string());
    }

    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        errors.push("Password must contain at least one uppercase letter".to_string());
    }

    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        errors.push("Password must contain at least one lowercase letter".to_string());
    }

    if !password.chars().any(|c| c.is_ascii_digit()) {
        errors.push("Password must contain at least one digit".to_string());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ApiAuthError::WeakPassword(errors))
    }
}

/// Validate display name.
///
/// Ensures display name:
/// - Does not exceed 255 characters
/// - Contains no control characters (0x00-0x1F, 0x7F)
pub fn validate_display_name(display_name: &str) -> Result<(), ApiAuthError> {
    if display_name.len() > 255 {
        return Err(ApiAuthError::Validation(
            "Display name must not exceed 255 characters".to_string(),
        ));
    }

    // Check for control characters
    if display_name.chars().any(|c| c.is_control() || c == '\x7F') {
        return Err(ApiAuthError::Validation(
            "Display name contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

/// Send verification email to newly signed up user.
async fn send_verification_email(
    pool: &PgPool,
    email_sender: &dyn EmailSender,
    tenant_id: TenantId,
    user_id: Uuid,
    email: &str,
    ip: std::net::IpAddr,
) -> Result<(), ApiAuthError> {
    // Generate verification token
    let (token, token_hash) = generate_email_verification_token();
    let expires_at = Utc::now() + Duration::hours(EMAIL_VERIFICATION_TOKEN_VALIDITY_HOURS);

    // Store token hash in database
    sqlx::query(
        r#"
        INSERT INTO email_verification_tokens (tenant_id, user_id, token_hash, expires_at, ip_address)
        VALUES ($1, $2, $3, $4, $5)
        "#,
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

    info!(
        user_id = %user_id,
        tenant_id = %tenant_id,
        "Verification email sent during signup"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Password Complexity Tests ───────────────────────────────────────

    #[test]
    fn test_password_complexity_valid() {
        assert!(validate_password_complexity("SecureP@ss123").is_ok());
        assert!(validate_password_complexity("Abcdefg1").is_ok());
        assert!(validate_password_complexity("Password123").is_ok());
    }

    #[test]
    fn test_password_complexity_too_short() {
        let result = validate_password_complexity("Short1A");
        assert!(result.is_err());
        if let Err(ApiAuthError::WeakPassword(errors)) = result {
            assert!(errors.iter().any(|e| e.contains("at least 8 characters")));
        }
    }

    #[test]
    fn test_password_complexity_missing_uppercase() {
        let result = validate_password_complexity("lowercase123");
        assert!(result.is_err());
        if let Err(ApiAuthError::WeakPassword(errors)) = result {
            assert!(errors.iter().any(|e| e.contains("uppercase")));
        }
    }

    #[test]
    fn test_password_complexity_missing_lowercase() {
        let result = validate_password_complexity("UPPERCASE123");
        assert!(result.is_err());
        if let Err(ApiAuthError::WeakPassword(errors)) = result {
            assert!(errors.iter().any(|e| e.contains("lowercase")));
        }
    }

    #[test]
    fn test_password_complexity_missing_digit() {
        let result = validate_password_complexity("NoDigitsHere");
        assert!(result.is_err());
        if let Err(ApiAuthError::WeakPassword(errors)) = result {
            assert!(errors.iter().any(|e| e.contains("digit")));
        }
    }

    #[test]
    fn test_password_complexity_multiple_failures() {
        let result = validate_password_complexity("short");
        assert!(result.is_err());
        if let Err(ApiAuthError::WeakPassword(errors)) = result {
            // Should have multiple errors
            assert!(errors.len() >= 2);
        }
    }

    // ── Display Name Validation Tests ───────────────────────────────────

    #[test]
    fn test_display_name_valid() {
        assert!(validate_display_name("John Doe").is_ok());
        assert!(validate_display_name("名前").is_ok()); // Japanese
        assert!(validate_display_name("Émile Brönte").is_ok()); // Accented chars
        assert!(validate_display_name("").is_ok()); // Empty is valid
    }

    #[test]
    fn test_display_name_too_long() {
        let long_name = "a".repeat(256);
        let result = validate_display_name(&long_name);
        assert!(result.is_err());
        if let Err(ApiAuthError::Validation(msg)) = result {
            assert!(msg.contains("255 characters"));
        }
    }

    #[test]
    fn test_display_name_max_length_ok() {
        let max_name = "a".repeat(255);
        assert!(validate_display_name(&max_name).is_ok());
    }

    #[test]
    fn test_display_name_control_chars() {
        let result = validate_display_name("Name\x00With\x1FControl");
        assert!(result.is_err());
        if let Err(ApiAuthError::Validation(msg)) = result {
            assert!(msg.contains("invalid characters"));
        }
    }

    #[test]
    fn test_display_name_del_char() {
        let result = validate_display_name("Name\x7FWithDel");
        assert!(result.is_err());
        if let Err(ApiAuthError::Validation(msg)) = result {
            assert!(msg.contains("invalid characters"));
        }
    }

    #[test]
    fn test_display_name_newline_not_allowed() {
        let result = validate_display_name("Line1\nLine2");
        assert!(result.is_err());
    }

    #[test]
    fn test_display_name_tab_not_allowed() {
        let result = validate_display_name("Name\tWith\tTabs");
        assert!(result.is_err());
    }
}
