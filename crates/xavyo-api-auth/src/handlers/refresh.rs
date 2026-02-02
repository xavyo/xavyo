//! Token refresh endpoint handler.
//!
//! POST /auth/refresh - Refresh access token using refresh token.

use crate::error::ApiAuthError;
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
    headers: HeaderMap,
    Json(request): Json<RefreshRequest>,
) -> Result<Json<TokenResponse>, ApiAuthError> {
    // Extract client info for audit
    let ip_address: Option<IpAddr> = Some(addr.ip());
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
    // Handler tests require integration test setup
}
