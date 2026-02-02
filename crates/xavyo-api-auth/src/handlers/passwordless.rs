//! Handlers for passwordless authentication endpoints (F079).
//!
//! - POST /auth/passwordless/magic-link — Request a magic link
//! - POST /auth/passwordless/magic-link/verify — Verify a magic link token
//! - POST /auth/passwordless/email-otp — Request an email OTP
//! - POST /auth/passwordless/email-otp/verify — Verify an email OTP code

use crate::error::ApiAuthError;
use crate::models::{
    EmailOtpVerifyRequest, MagicLinkVerifyRequest, PasswordlessInitResponse,
    PasswordlessMfaRequiredResponse, PasswordlessRequest, TokenResponse,
};
use crate::services::{PasswordlessService, PasswordlessVerifyResult};
use axum::{extract::ConnectInfo, Extension, Json};
use std::net::SocketAddr;
use std::sync::Arc;
use validator::Validate;
use xavyo_core::TenantId;

/// POST /auth/passwordless/magic-link
///
/// Request a magic link for passwordless login.
/// Always returns success to prevent email enumeration.
#[utoipa::path(
    post,
    path = "/auth/passwordless/magic-link",
    request_body = PasswordlessRequest,
    responses(
        (status = 200, description = "Magic link request accepted", body = PasswordlessInitResponse),
        (status = 422, description = "Validation error"),
        (status = 429, description = "Rate limit exceeded"),
    ),
    tag = "Passwordless Authentication"
)]
pub async fn request_magic_link_handler(
    Extension(tid): Extension<TenantId>,
    Extension(service): Extension<Arc<PasswordlessService>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<PasswordlessRequest>,
) -> Result<Json<PasswordlessInitResponse>, ApiAuthError> {
    body.validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    let tenant_id = *tid.as_uuid();
    let ip = Some(addr.ip());
    let user_agent = None; // Extracted from headers in production

    let expiry_minutes = service
        .request_magic_link(tenant_id, &body.email, ip, user_agent)
        .await?;

    Ok(Json(PasswordlessInitResponse::magic_link(expiry_minutes)))
}

/// POST /auth/passwordless/magic-link/verify
///
/// Verify a magic link token and return access/refresh tokens.
#[utoipa::path(
    post,
    path = "/auth/passwordless/magic-link/verify",
    request_body = MagicLinkVerifyRequest,
    responses(
        (status = 200, description = "Authentication successful", body = TokenResponse),
        (status = 400, description = "Invalid, expired, or used token"),
        (status = 401, description = "Account locked"),
    ),
    tag = "Passwordless Authentication"
)]
pub async fn verify_magic_link_handler(
    Extension(tid): Extension<TenantId>,
    Extension(service): Extension<Arc<PasswordlessService>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<MagicLinkVerifyRequest>,
) -> Result<axum::response::Response, ApiAuthError> {
    body.validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    let tenant_id = *tid.as_uuid();
    let ip = Some(addr.ip());
    let user_agent = None;

    let result = service
        .verify_magic_link(tenant_id, &body.token, ip, user_agent)
        .await?;

    match result {
        PasswordlessVerifyResult::Success {
            access_token,
            refresh_token,
            expires_in,
        } => {
            let response = TokenResponse::new(access_token, refresh_token, expires_in);
            Ok(Json(response).into_response())
        }
        PasswordlessVerifyResult::MfaRequired {
            partial_token,
            expires_in,
        } => {
            let response = PasswordlessMfaRequiredResponse::new(partial_token, expires_in);
            Ok(Json(response).into_response())
        }
    }
}

/// POST /auth/passwordless/email-otp
///
/// Request a 6-digit OTP code for passwordless login.
/// Always returns success to prevent email enumeration.
#[utoipa::path(
    post,
    path = "/auth/passwordless/email-otp",
    request_body = PasswordlessRequest,
    responses(
        (status = 200, description = "Email OTP request accepted", body = PasswordlessInitResponse),
        (status = 422, description = "Validation error"),
        (status = 429, description = "Rate limit exceeded"),
    ),
    tag = "Passwordless Authentication"
)]
pub async fn request_email_otp_handler(
    Extension(tid): Extension<TenantId>,
    Extension(service): Extension<Arc<PasswordlessService>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<PasswordlessRequest>,
) -> Result<Json<PasswordlessInitResponse>, ApiAuthError> {
    body.validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    let tenant_id = *tid.as_uuid();
    let ip = Some(addr.ip());
    let user_agent = None;

    let expiry_minutes = service
        .request_email_otp(tenant_id, &body.email, ip, user_agent)
        .await?;

    Ok(Json(PasswordlessInitResponse::email_otp(expiry_minutes)))
}

/// POST /auth/passwordless/email-otp/verify
///
/// Verify a 6-digit OTP code and return access/refresh tokens.
#[utoipa::path(
    post,
    path = "/auth/passwordless/email-otp/verify",
    request_body = EmailOtpVerifyRequest,
    responses(
        (status = 200, description = "Authentication successful", body = TokenResponse),
        (status = 400, description = "Invalid or expired code"),
        (status = 401, description = "Account locked"),
    ),
    tag = "Passwordless Authentication"
)]
pub async fn verify_email_otp_handler(
    Extension(tid): Extension<TenantId>,
    Extension(service): Extension<Arc<PasswordlessService>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<EmailOtpVerifyRequest>,
) -> Result<axum::response::Response, ApiAuthError> {
    body.validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    let tenant_id = *tid.as_uuid();
    let ip = Some(addr.ip());
    let user_agent = None;

    let result = service
        .verify_email_otp(tenant_id, &body.email, &body.code, ip, user_agent)
        .await?;

    match result {
        PasswordlessVerifyResult::Success {
            access_token,
            refresh_token,
            expires_in,
        } => {
            let response = TokenResponse::new(access_token, refresh_token, expires_in);
            Ok(Json(response).into_response())
        }
        PasswordlessVerifyResult::MfaRequired {
            partial_token,
            expires_in,
        } => {
            let response = PasswordlessMfaRequiredResponse::new(partial_token, expires_in);
            Ok(Json(response).into_response())
        }
    }
}

use axum::response::IntoResponse;
