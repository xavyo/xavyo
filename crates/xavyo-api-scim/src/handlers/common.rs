//! Shared helpers for SCIM handlers.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::net::IpAddr;

/// SCIM content type header.
pub const SCIM_CONTENT_TYPE: &str = "application/scim+json";

/// Wrap response with SCIM content type.
pub fn scim_response<T: serde::Serialize>(status: StatusCode, body: T) -> Response {
    let json = Json(body);
    let mut response = (status, json).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(SCIM_CONTENT_TYPE),
    );
    response
}

/// Extract client IP from request headers (for audit logging only).
///
/// Falls back to 127.0.0.1 if no forwarded header is present.
///
/// SECURITY: X-Forwarded-For is only trustworthy when the application runs
/// behind a reverse proxy that overwrites/sanitizes this header. In production,
/// this should be guaranteed by the deployment configuration. The extracted IP
/// is used exclusively for audit logging — never for security decisions like
/// rate limiting or access control. An attacker spoofing X-Forwarded-For can
/// only affect which IP appears in audit logs.
pub fn extract_client_ip(headers: &axum::http::HeaderMap) -> IpAddr {
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            if let Some(first_ip) = xff_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return ip;
                }
            }
        }
    }
    "127.0.0.1".parse().unwrap()
}

/// Maximum User-Agent length stored in audit logs.
const MAX_USER_AGENT_LEN: usize = 512;

/// Extract user agent from request headers.
///
/// Truncates to `MAX_USER_AGENT_LEN` characters to prevent oversized values
/// from being stored in audit log rows.
pub fn extract_user_agent(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            if s.len() > MAX_USER_AGENT_LEN {
                s[..MAX_USER_AGENT_LEN].to_string()
            } else {
                s.to_string()
            }
        })
}
