//! Logout endpoint handler.
//!
//! POST /auth/logout - Invalidate refresh token.

use crate::error::ApiAuthError;
use crate::models::LogoutRequest;
use crate::services::TokenService;
use axum::{http::StatusCode, Extension, Json};
use std::sync::Arc;

/// Handle user logout.
///
/// Revokes the provided refresh token, preventing it from being
/// used to obtain new access tokens.
#[utoipa::path(
    post,
    path = "/auth/logout",
    request_body = LogoutRequest,
    responses(
        (status = 204, description = "Logout successful"),
        (status = 400, description = "Missing refresh token"),
    ),
    tag = "Authentication"
)]
pub async fn logout_handler(
    Extension(token_service): Extension<Arc<TokenService>>,
    Json(request): Json<LogoutRequest>,
) -> Result<StatusCode, ApiAuthError> {
    // Revoke the refresh token
    token_service.revoke_token(&request.refresh_token).await?;

    tracing::info!("User logged out successfully");

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    // Handler tests require integration test setup
}
