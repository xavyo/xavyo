//! Token refresh endpoint handler.
//!
//! POST /auth/refresh - Refresh access token using refresh token.

use crate::error::ApiAuthError;
use crate::handlers::login::login_client_ip;
use crate::middleware::jwt_auth::TrustXff;
use crate::models::{RefreshRequest, TokenResponse};
use crate::services::TokenService;
use axum::{extract::ConnectInfo, http::HeaderMap, Extension, Json};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// Handle token refresh.
///
/// Validates the refresh token, revokes it (token rotation),
/// and issues new access and refresh tokens.
#[utoipa::path(
    post,
    path = "/auth/refresh",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Tokens refreshed successfully", body = TokenResponse),
        (status = 401, description = "Invalid or expired refresh token"),
        (status = 403, description = "Token revoked or user inactive"),
    ),
    tag = "Authentication"
)]
pub async fn refresh_handler(
    Extension(token_service): Extension<Arc<TokenService>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    trust_xff: Option<Extension<TrustXff>>,
    headers: HeaderMap,
    Json(request): Json<RefreshRequest>,
) -> Result<Json<TokenResponse>, ApiAuthError> {
    // Extract client info for audit and IP restriction.
    // Forwarded headers are used only when TrustXff is present.
    let ip_str = login_client_ip(&headers, trust_xff.is_some(), Some(addr.ip()));
    let ip_address: Option<IpAddr> = ip_str.as_deref().and_then(|s| s.parse().ok());
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Refresh tokens (validates, revokes old, issues new)
    let (access_token, refresh_token, expires_in) = token_service
        .refresh_tokens(&request.refresh_token, user_agent, ip_address)
        .await?;

    let response = TokenResponse::new(access_token, refresh_token, expires_in);

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn refresh_handler_enforces_ip_restriction_via_create_tokens() {
        let src = include_str!("refresh.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("login_client_ip("),
            "refresh must not trust untrusted X-Forwarded-For"
        );
        assert!(
            production.contains("refresh_tokens("),
            "refresh issues tokens through TokenService (IP restriction at create_tokens)"
        );
    }

    #[test]
    fn untrusted_xff_does_not_override_peer_for_refresh_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1"));
        let peer = "203.0.113.10".parse().unwrap();
        assert_eq!(
            login_client_ip(&headers, false, Some(peer)).as_deref(),
            Some("203.0.113.10")
        );
        assert_eq!(
            login_client_ip(&headers, true, Some(peer)).as_deref(),
            Some("10.0.0.1")
        );
    }
}
