//! UserInfo endpoint handler.

use crate::error::OAuthError;
use crate::router::OAuthState;
use crate::services::userinfo::UserClaims;
use axum::{
    extract::State,
    http::{header, HeaderMap},
    Json,
};
use uuid::Uuid;
use xavyo_auth::decode_token;

/// Returns user claims based on the scopes in the access token.
#[utoipa::path(
    get,
    path = "/oauth/userinfo",
    responses(
        (status = 200, description = "User claims"),
        (status = 401, description = "Invalid or missing access token"),
        (status = 403, description = "Insufficient scope"),
    ),
    security(("bearerAuth" = [])),
    tag = "OAuth2"
)]
pub async fn userinfo_handler(
    State(state): State<OAuthState>,
    headers: HeaderMap,
) -> Result<Json<UserClaims>, OAuthError> {
    // Extract the access token from Authorization header
    let token = extract_bearer_token(&headers)?;

    // Decode and validate the JWT
    let claims = decode_token(&token, &state.public_key).map_err(|e| {
        tracing::warn!("Invalid access token: {}", e);
        OAuthError::InvalidToken("Invalid access token".to_string())
    })?;

    // Check token expiration is handled by decode_token

    // Extract user_id from subject
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| OAuthError::InvalidToken("Invalid subject in token".to_string()))?;

    // Extract tenant_id from claims
    let tenant_id = claims
        .tid
        .ok_or_else(|| OAuthError::InvalidToken("Missing tenant ID in token".to_string()))?;

    // Extract scope from roles (our implementation stores scopes as roles)
    let scope = claims.roles.join(" ");

    // Verify openid scope is present (required for userinfo)
    if !claims.roles.iter().any(|r| r == "openid") {
        return Err(OAuthError::InsufficientScope(
            "The access token must have openid scope for userinfo".to_string(),
        ));
    }

    // Get user claims from the service
    let user_claims = state
        .userinfo_service
        .get_user_claims(tenant_id, user_id, &scope)
        .await?;

    Ok(Json(user_claims))
}

/// Extract Bearer token from Authorization header.
fn extract_bearer_token(headers: &HeaderMap) -> Result<String, OAuthError> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| OAuthError::InvalidToken("Missing Authorization header".to_string()))?;

    let auth_str = auth_header
        .to_str()
        .map_err(|_| OAuthError::InvalidToken("Invalid Authorization header".to_string()))?;

    let token = auth_str
        .strip_prefix("Bearer ")
        .map(String::from)
        .ok_or_else(|| {
            OAuthError::InvalidToken("Authorization header must use Bearer scheme".to_string())
        })?;

    // SECURITY: Reject empty bearer tokens
    if token.is_empty() {
        return Err(OAuthError::InvalidToken(
            "Bearer token cannot be empty".to_string(),
        ));
    }

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_bearer_token_success() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test-token-123"),
        );

        let result = extract_bearer_token(&headers);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test-token-123");
    }

    #[test]
    fn test_extract_bearer_token_missing_header() {
        let headers = HeaderMap::new();
        let result = extract_bearer_token(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_bearer_token_wrong_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic dGVzdDp0ZXN0"),
        );

        let result = extract_bearer_token(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_bearer_token_empty_token() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer "));

        let result = extract_bearer_token(&headers);
        // SECURITY: Empty bearer tokens must be rejected
        assert!(result.is_err());
    }
}
