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
/// Forwarded headers are used only when `trust_xff` is true. Callers without
/// `TrustXff` must pass false so a client cannot spoof the audit IP.
pub fn extract_client_ip(headers: &axum::http::HeaderMap) -> IpAddr {
    scim_audit_ip(headers, false)
}

/// Audit IP extraction. Untrusted forwarded headers are ignored.
pub(crate) fn scim_audit_ip(headers: &axum::http::HeaderMap, trust_xff: bool) -> IpAddr {
    if trust_xff {
        if let Some(xff) = headers.get("x-forwarded-for") {
            if let Ok(xff_str) = xff.to_str() {
                if let Some(first_ip) = xff_str.split(',').next() {
                    if let Ok(ip) = first_ip.trim().parse() {
                        return ip;
                    }
                }
            }
        }
    }
    IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn untrusted_xff_is_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1"));
        assert_eq!(
            scim_audit_ip(&headers, false),
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(extract_client_ip(&headers), scim_audit_ip(&headers, false));
    }

    #[test]
    fn trusted_xff_is_used() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1"));
        assert_eq!(
            scim_audit_ip(&headers, true),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn extract_client_ip_does_not_trust_xff_by_default() {
        let src = include_str!("common.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("scim_audit_ip(headers, false)"),
            "SCIM audit IP must not trust client-supplied X-Forwarded-For"
        );
    }
}
