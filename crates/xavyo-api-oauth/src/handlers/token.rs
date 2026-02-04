//! Token endpoint handler.

use crate::error::OAuthError;
use crate::handlers::device::{check_device_authorization, exchange_device_code_for_tokens};
use crate::models::{TokenRequest, TokenResponse, DEVICE_CODE_GRANT_TYPE};
use crate::router::OAuthState;
use crate::services::DeviceAuthorizationStatus;
use axum::{
    extract::State,
    http::{header, HeaderMap},
    Form, Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use uuid::Uuid;

/// Exchange authorization code for tokens or refresh tokens.
#[utoipa::path(
    post,
    path = "/oauth/token",
    request_body = TokenRequest,
    responses(
        (status = 200, description = "Tokens issued", body = TokenResponse),
        (status = 400, description = "Invalid token request"),
        (status = 401, description = "Invalid client credentials"),
    ),
    tag = "OAuth2"
)]
pub async fn token_handler(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, OAuthError> {
    // Extract client credentials from header or request body
    let (client_id, client_secret) = extract_client_credentials(&headers, &request)?;

    match request.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code_grant(&state, &request, &client_id, client_secret.as_deref())
                .await
        }
        "client_credentials" => {
            handle_client_credentials_grant(
                &state,
                &headers,
                &request,
                &client_id,
                client_secret.as_deref(),
            )
            .await
        }
        "refresh_token" => {
            handle_refresh_token_grant(
                &state,
                &headers,
                &request,
                &client_id,
                client_secret.as_deref(),
            )
            .await
        }
        gt if gt == DEVICE_CODE_GRANT_TYPE => {
            handle_device_code_grant(&state, &headers, &request, &client_id).await
        }
        _ => Err(OAuthError::UnsupportedGrantType(request.grant_type)),
    }
}

/// Extract client credentials from Authorization header or request body.
fn extract_client_credentials(
    headers: &HeaderMap,
    request: &TokenRequest,
) -> Result<(String, Option<String>), OAuthError> {
    // Try HTTP Basic authentication first
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        let auth_str = auth_header
            .to_str()
            .map_err(|_| OAuthError::InvalidClient("Invalid authorization header".to_string()))?;

        if let Some(credentials) = auth_str.strip_prefix("Basic ") {
            let decoded = STANDARD.decode(credentials).map_err(|_| {
                OAuthError::InvalidClient("Invalid base64 in authorization header".to_string())
            })?;

            let decoded_str = String::from_utf8(decoded).map_err(|_| {
                OAuthError::InvalidClient("Invalid UTF-8 in credentials".to_string())
            })?;

            let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
            if parts.len() == 2 {
                return Ok((parts[0].to_string(), Some(parts[1].to_string())));
            }
            return Err(OAuthError::InvalidClient(
                "Invalid credential format".to_string(),
            ));
        }
    }

    // Fall back to request body
    let client_id = request
        .client_id
        .clone()
        .ok_or_else(|| OAuthError::InvalidRequest("client_id is required".to_string()))?;

    Ok((client_id, request.client_secret.clone()))
}

/// Handle `authorization_code` grant type.
///
/// This flow extracts `tenant_id` from the authorization code stored in the database,
/// eliminating the need for an X-Tenant-ID header in the token exchange request.
async fn handle_authorization_code_grant(
    state: &OAuthState,
    request: &TokenRequest,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<Json<TokenResponse>, OAuthError> {
    // Validate required parameters
    let code = request
        .code
        .as_ref()
        .ok_or_else(|| OAuthError::InvalidRequest("code is required".to_string()))?;

    let redirect_uri = request
        .redirect_uri
        .as_ref()
        .ok_or_else(|| OAuthError::InvalidRequest("redirect_uri is required".to_string()))?;

    let code_verifier = request
        .code_verifier
        .as_ref()
        .ok_or_else(|| OAuthError::InvalidRequest("code_verifier is required".to_string()))?;

    // Look up the authorization code to get tenant context
    // This query doesn't use RLS - it retrieves the tenant_id from the code itself
    let auth_code_info = lookup_authorization_code(state, code).await?;

    // Validate client_id matches
    let client_uuid = auth_code_info.client_id;
    let tenant_id = auth_code_info.tenant_id;

    // For confidential clients, verify the secret
    if let Some(secret) = client_secret {
        let _ = state
            .client_service
            .verify_client_credentials(tenant_id, client_id, secret)
            .await?;
    }

    // Validate and consume the authorization code (with PKCE verification)
    let (user_id, scope, nonce) = state
        .authorization_service
        .validate_and_consume_code(tenant_id, code, client_uuid, redirect_uri, code_verifier)
        .await?;

    // Look up the client to get its string ID for token generation
    let client = state
        .client_service
        .get_client_by_id(tenant_id, client_uuid)
        .await?;

    // Validate redirect_uri against registered URIs
    state
        .client_service
        .validate_redirect_uri(&client, redirect_uri)?;

    // Issue tokens
    let token_response = state
        .token_service
        .issue_authorization_code_tokens(
            user_id,
            &client.client_id,
            client_uuid,
            tenant_id,
            &scope,
            nonce.as_deref(),
        )
        .await?;

    Ok(Json(token_response))
}

/// Authorization code lookup result.
struct AuthCodeInfo {
    client_id: Uuid,
    tenant_id: Uuid,
}

/// Look up authorization code to get `client_id` and `tenant_id`.
///
/// This query runs WITHOUT tenant context (no RLS) to retrieve the `tenant_id`
/// from the authorization code itself. This allows the token endpoint to work
/// without requiring an X-Tenant-ID header.
async fn lookup_authorization_code(
    state: &OAuthState,
    code: &str,
) -> Result<AuthCodeInfo, OAuthError> {
    use sha2::{Digest, Sha256};

    // Hash the code to look it up
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    let code_hash = hex::encode(hasher.finalize());

    // Query WITHOUT setting RLS context - we need to find the tenant_id
    let result: Option<(Uuid, Uuid)> = sqlx::query_as(
        r"
        SELECT client_id, tenant_id
        FROM authorization_codes
        WHERE code_hash = $1
          AND used = FALSE
          AND expires_at > NOW()
        ",
    )
    .bind(&code_hash)
    .fetch_optional(state.authorization_service.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to lookup authorization code: {}", e);
        OAuthError::Internal("Database error".to_string())
    })?;

    match result {
        Some((client_id, tenant_id)) => Ok(AuthCodeInfo {
            client_id,
            tenant_id,
        }),
        None => Err(OAuthError::InvalidGrant(
            "Authorization code not found, expired, or already used".to_string(),
        )),
    }
}

/// Handle `client_credentials` grant type.
///
/// This grant is for service-to-service authentication where there is no user.
/// Only confidential clients can use this grant type.
///
/// # Flow
///
/// 1. Extract `tenant_id` from X-Tenant-ID header (required)
/// 2. Verify client credentials (`client_id` + `client_secret`)
/// 3. Validate the client is allowed to use `client_credentials` grant
/// 4. Issue access token (no ID token, no refresh token)
async fn handle_client_credentials_grant(
    state: &OAuthState,
    headers: &HeaderMap,
    request: &TokenRequest,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<Json<TokenResponse>, OAuthError> {
    // Client credentials requires a secret
    let secret = client_secret.ok_or_else(|| {
        OAuthError::InvalidClient(
            "client_secret is required for client_credentials grant".to_string(),
        )
    })?;

    // Extract tenant_id from X-Tenant-ID header
    let tenant_id = extract_tenant_id_from_headers(headers)?;

    // Verify client credentials
    let client = state
        .client_service
        .verify_client_credentials(tenant_id, client_id, secret)
        .await?;

    // Validate the client is allowed to use client_credentials grant
    if !client
        .grant_types
        .contains(&"client_credentials".to_string())
    {
        return Err(OAuthError::UnauthorizedClient(
            "Client is not authorized for client_credentials grant".to_string(),
        ));
    }

    // Determine the scope to grant
    // If scope is requested, validate against client's allowed scopes
    // Otherwise, use the client's default scopes
    let granted_scope = match &request.scope {
        Some(requested_scope) => {
            // Validate each requested scope
            let requested: Vec<&str> = requested_scope.split_whitespace().collect();
            for scope in &requested {
                if !client.scopes.contains(&scope.to_string()) {
                    return Err(OAuthError::InvalidScope(format!(
                        "Scope '{scope}' is not allowed for this client"
                    )));
                }
            }
            requested_scope.clone()
        }
        None => {
            // Use client's allowed scopes (excluding openid which requires a user)
            client
                .scopes
                .iter()
                .filter(|s| *s != "openid" && *s != "offline_access")
                .cloned()
                .collect::<Vec<_>>()
                .join(" ")
        }
    };

    // Issue tokens for client credentials grant
    let token_response = state
        .token_service
        .issue_client_credentials_tokens(&client.client_id, tenant_id, &granted_scope)
        .await?;

    Ok(Json(token_response))
}

/// Extract `tenant_id` from X-Tenant-ID header.
fn extract_tenant_id_from_headers(headers: &HeaderMap) -> Result<Uuid, OAuthError> {
    let tenant_header = headers
        .get("X-Tenant-ID")
        .ok_or_else(|| OAuthError::InvalidRequest("X-Tenant-ID header is required".to_string()))?;

    let tenant_str = tenant_header
        .to_str()
        .map_err(|_| OAuthError::InvalidRequest("Invalid X-Tenant-ID header value".to_string()))?;

    Uuid::parse_str(tenant_str)
        .map_err(|_| OAuthError::InvalidRequest("X-Tenant-ID must be a valid UUID".to_string()))
}

/// Handle `device_code` grant type (RFC 8628).
///
/// This grant is used by CLI/headless clients to obtain tokens after user authorization.
/// The client polls this endpoint with the `device_code` until the user completes authorization.
///
/// # Flow
///
/// 1. Extract `tenant_id` from X-Tenant-ID header (required)
/// 2. Check device code authorization status
/// 3. If authorized, exchange for tokens
/// 4. If pending, return `authorization_pending` error
/// 5. If denied, return `access_denied` error
/// 6. If expired, return `expired_token` error
async fn handle_device_code_grant(
    state: &OAuthState,
    headers: &HeaderMap,
    request: &TokenRequest,
    client_id: &str,
) -> Result<Json<TokenResponse>, OAuthError> {
    // Extract device_code from request
    let device_code = request
        .device_code
        .as_ref()
        .ok_or_else(|| OAuthError::InvalidRequest("device_code is required".to_string()))?;

    // Extract tenant_id from X-Tenant-ID header
    let tenant_id = extract_tenant_id_from_headers(headers)?;

    // Check authorization status
    let status = check_device_authorization(state, tenant_id, device_code, client_id).await?;

    match status {
        DeviceAuthorizationStatus::Pending => Err(OAuthError::AuthorizationPending),
        DeviceAuthorizationStatus::SlowDown { interval } => Err(OAuthError::SlowDown(interval)),
        DeviceAuthorizationStatus::Denied => Err(OAuthError::AccessDenied(
            "User denied the authorization request".to_string(),
        )),
        DeviceAuthorizationStatus::Expired => Err(OAuthError::ExpiredToken(
            "Device code has expired".to_string(),
        )),
        DeviceAuthorizationStatus::Authorized(_user_id) => {
            // Exchange for tokens
            let (user_id, scope) =
                exchange_device_code_for_tokens(state, tenant_id, device_code, client_id).await?;

            // Look up the client to get its internal ID
            let client = state
                .client_service
                .get_client_by_client_id(tenant_id, client_id)
                .await
                .map_err(|_| OAuthError::InvalidClient("Client not found".to_string()))?;

            // Issue tokens
            let token_response = state
                .token_service
                .issue_device_code_tokens(user_id, client_id, client.id, tenant_id, &scope)
                .await?;

            Ok(Json(token_response))
        }
    }
}

/// Handle `refresh_token` grant type.
///
/// This grant is used to obtain new access tokens without re-authenticating.
/// Implements refresh token rotation: the old token is invalidated and a new one is issued.
///
/// # Security
///
/// - If a previously-rotated token is reused (replay attack), the entire token family is revoked
/// - This protects against stolen refresh tokens
///
/// # Flow
///
/// 1. Extract `tenant_id` from X-Tenant-ID header (required)
/// 2. Validate and rotate the refresh token
/// 3. Issue new access token and refresh token
async fn handle_refresh_token_grant(
    state: &OAuthState,
    headers: &HeaderMap,
    request: &TokenRequest,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<Json<TokenResponse>, OAuthError> {
    // Extract the refresh token from the request
    let refresh_token = request
        .refresh_token
        .as_ref()
        .ok_or_else(|| OAuthError::InvalidRequest("refresh_token is required".to_string()))?;

    // Extract tenant_id from X-Tenant-ID header
    let tenant_id = extract_tenant_id_from_headers(headers)?;

    // For confidential clients, verify the secret
    // For public clients, validate the client exists and belongs to the tenant
    let client_internal_id = if let Some(secret) = client_secret {
        // Confidential client - verify credentials
        let client = state
            .client_service
            .verify_client_credentials(tenant_id, client_id, secret)
            .await?;
        client.id
    } else {
        // Public client - verify the client exists in this tenant
        let client_uuid = Uuid::parse_str(client_id)
            .map_err(|_| OAuthError::InvalidClient("Invalid client_id format".to_string()))?;
        // Validate the client belongs to the specified tenant
        let _client = state
            .client_service
            .get_client_by_client_id(tenant_id, client_id)
            .await
            .map_err(|_| {
                OAuthError::InvalidClient("Client not found in specified tenant".to_string())
            })?;
        client_uuid
    };

    // Validate and rotate the refresh token
    let (user_id, scope, new_refresh_token) = state
        .token_service
        .validate_and_rotate_refresh_token(tenant_id, refresh_token, client_internal_id)
        .await?;

    // Issue new access token
    let token_response = state
        .token_service
        .issue_refresh_tokens(
            user_id,
            client_id,
            client_internal_id,
            tenant_id,
            &scope,
            &new_refresh_token,
        )
        .await?;

    Ok(Json(token_response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_client_credentials_from_basic_auth() {
        let mut headers = HeaderMap::new();
        // "test-client:test-secret" in base64
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ="),
        );

        let request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: None,
            redirect_uri: None,
            client_id: None,
            client_secret: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            device_code: None,
        };

        let result = extract_client_credentials(&headers, &request);
        assert!(result.is_ok());
        let (client_id, client_secret) = result.unwrap();
        assert_eq!(client_id, "test-client");
        assert_eq!(client_secret, Some("test-secret".to_string()));
    }

    #[test]
    fn test_extract_client_credentials_from_body() {
        let headers = HeaderMap::new();
        let request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some("body-client".to_string()),
            client_secret: Some("body-secret".to_string()),
            code_verifier: None,
            refresh_token: None,
            scope: None,
            device_code: None,
        };

        let result = extract_client_credentials(&headers, &request);
        assert!(result.is_ok());
        let (client_id, client_secret) = result.unwrap();
        assert_eq!(client_id, "body-client");
        assert_eq!(client_secret, Some("body-secret".to_string()));
    }

    #[test]
    fn test_extract_client_credentials_public_client() {
        let headers = HeaderMap::new();
        let request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some("public-client".to_string()),
            client_secret: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            device_code: None,
        };

        let result = extract_client_credentials(&headers, &request);
        assert!(result.is_ok());
        let (client_id, client_secret) = result.unwrap();
        assert_eq!(client_id, "public-client");
        assert_eq!(client_secret, None);
    }

    #[test]
    fn test_extract_client_credentials_missing_client_id() {
        let headers = HeaderMap::new();
        let request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: None,
            redirect_uri: None,
            client_id: None,
            client_secret: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            device_code: None,
        };

        let result = extract_client_credentials(&headers, &request);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_tenant_id_from_headers_success() {
        let mut headers = HeaderMap::new();
        let tenant_id = Uuid::new_v4();
        headers.insert(
            "X-Tenant-ID",
            HeaderValue::from_str(&tenant_id.to_string()).unwrap(),
        );

        let result = extract_tenant_id_from_headers(&headers);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), tenant_id);
    }

    #[test]
    fn test_extract_tenant_id_from_headers_missing() {
        let headers = HeaderMap::new();
        let result = extract_tenant_id_from_headers(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_tenant_id_from_headers_invalid_uuid() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Tenant-ID", HeaderValue::from_static("not-a-uuid"));

        let result = extract_tenant_id_from_headers(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_client_credentials_basic_auth_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic !!!invalid-base64!!!"),
        );

        let request = TokenRequest {
            grant_type: "client_credentials".to_string(),
            code: None,
            redirect_uri: None,
            client_id: None,
            client_secret: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            device_code: None,
        };

        let result = extract_client_credentials(&headers, &request);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_client_credentials_basic_auth_no_colon() {
        let mut headers = HeaderMap::new();
        // "test-client" without colon in base64
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic dGVzdC1jbGllbnQ="),
        );

        let request = TokenRequest {
            grant_type: "client_credentials".to_string(),
            code: None,
            redirect_uri: None,
            client_id: None,
            client_secret: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            device_code: None,
        };

        let result = extract_client_credentials(&headers, &request);
        assert!(result.is_err());
    }
}
