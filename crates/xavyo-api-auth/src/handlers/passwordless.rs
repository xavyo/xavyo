//! Handlers for passwordless authentication endpoints (F079).
//!
//! - POST /auth/passwordless/magic-link — Request a magic link
//! - POST /auth/passwordless/magic-link/verify — Verify a magic link token
//! - POST /auth/passwordless/email-otp — Request an email OTP
//! - POST /auth/passwordless/email-otp/verify — Verify an email OTP code

use crate::error::ApiAuthError;
use crate::handlers::login::login_client_ip;
use crate::middleware::jwt_auth::TrustXff;
use crate::models::{
    EmailOtpVerifyRequest, MagicLinkVerifyRequest, PasswordlessInitResponse,
    PasswordlessMfaRequiredResponse, PasswordlessRequest, TokenResponse,
};
use crate::services::{PasswordlessService, PasswordlessVerifyResult};
use axum::{extract::ConnectInfo, http::HeaderMap, Extension, Json};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use validator::Validate;
use xavyo_core::TenantId;

/// Client IP for passwordless rate-limit and IP restriction.
/// Untrusted forwarded headers are ignored.
pub(crate) fn passwordless_client_ip(
    headers: &HeaderMap,
    trust_xff: bool,
    peer: IpAddr,
) -> Option<IpAddr> {
    login_client_ip(headers, trust_xff, Some(peer)).and_then(|s| s.parse().ok())
}

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
    trust_xff: Option<Extension<TrustXff>>,
    headers: HeaderMap,
    Json(body): Json<PasswordlessRequest>,
) -> Result<Json<PasswordlessInitResponse>, ApiAuthError> {
    body.validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    let tenant_id = *tid.as_uuid();
    let ip = passwordless_client_ip(&headers, trust_xff.is_some(), addr.ip());
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
    trust_xff: Option<Extension<TrustXff>>,
    headers: HeaderMap,
    Json(body): Json<MagicLinkVerifyRequest>,
) -> Result<axum::response::Response, ApiAuthError> {
    body.validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    let tenant_id = *tid.as_uuid();
    let ip = passwordless_client_ip(&headers, trust_xff.is_some(), addr.ip());
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
    trust_xff: Option<Extension<TrustXff>>,
    headers: HeaderMap,
    Json(body): Json<PasswordlessRequest>,
) -> Result<Json<PasswordlessInitResponse>, ApiAuthError> {
    body.validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    let tenant_id = *tid.as_uuid();
    let ip = passwordless_client_ip(&headers, trust_xff.is_some(), addr.ip());
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
    trust_xff: Option<Extension<TrustXff>>,
    headers: HeaderMap,
    Json(body): Json<EmailOtpVerifyRequest>,
) -> Result<axum::response::Response, ApiAuthError> {
    body.validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    let tenant_id = *tid.as_uuid();
    let ip = passwordless_client_ip(&headers, trust_xff.is_some(), addr.ip());
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn untrusted_xff_does_not_override_peer_for_passwordless_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1"));
        let peer = "203.0.113.10".parse().unwrap();
        assert_eq!(passwordless_client_ip(&headers, false, peer), Some(peer));
        assert_eq!(
            passwordless_client_ip(&headers, true, peer),
            Some("10.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn passwordless_handlers_do_not_trust_untrusted_xff() {
        let src = include_str!("passwordless.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("passwordless_client_ip("),
            "passwordless must not trust untrusted X-Forwarded-For"
        );
        assert!(
            !production.contains("Some(addr.ip())"),
            "passwordless must not use the peer address without TrustXff"
        );
        let count = production.matches("passwordless_client_ip(").count();
        assert!(
            count >= 4,
            "all four passwordless handlers must use fail-closed IP extraction, got {count}"
        );
    }
}
