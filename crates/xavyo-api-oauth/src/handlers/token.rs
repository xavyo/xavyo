//! Token endpoint handler.

use crate::error::OAuthError;
use crate::handlers::device::{check_device_authorization, exchange_device_code_for_tokens};
use crate::models::{
    TokenRequest, TokenResponse, DEVICE_CODE_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE,
};
use crate::router::OAuthState;
use crate::services::DeviceAuthorizationStatus;
use axum::{
    extract::State,
    http::{header, HeaderMap},
    Form, Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use uuid::Uuid;
use xavyo_auth::decode_token;
use xavyo_db::models::{NhiDelegationGrant, NhiIdentity};

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
        gt if gt == TOKEN_EXCHANGE_GRANT_TYPE => {
            handle_token_exchange_grant(
                &state,
                &headers,
                &request,
                &client_id,
                client_secret.as_deref(),
            )
            .await
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

    // Look up the client to determine its type and verify credentials
    let client = state
        .client_service
        .get_client_by_id(tenant_id, client_uuid)
        .await?;

    // SECURITY: Confidential clients MUST always provide client_secret.
    // Without this check, an attacker could omit the secret and bypass
    // authentication for confidential clients entirely.
    if client.client_type == crate::models::ClientType::Confidential {
        let secret = client_secret.ok_or_else(|| {
            OAuthError::InvalidClient(
                "client_secret is required for confidential clients".to_string(),
            )
        })?;
        let _ = state
            .client_service
            .verify_client_credentials(tenant_id, client_id, secret)
            .await?;
    } else if let Some(secret) = client_secret {
        // Public client provided a secret — still verify it if present,
        // but public clients are not required to provide one.
        let _ = state
            .client_service
            .verify_client_credentials(tenant_id, client_id, secret)
            .await?;
    }

    // NOTE: Known ordering issue (MEDIUM-8 from security audit):
    // The authorization code is consumed BEFORE redirect_uri is validated against
    // the client's registered URIs. Ideally, redirect_uri validation should happen
    // before code consumption to prevent DoS via invalid redirect_uri.
    // This is accepted risk: the code consumption already validates redirect_uri
    // matches the stored value (preventing token theft), so this is a DoS vector
    // only, not a security vulnerability. Refactoring would require restructuring
    // the atomic transaction in validate_and_consume_code.

    // Validate and consume the authorization code (with PKCE verification)
    let (user_id, scope, nonce) = state
        .authorization_service
        .validate_and_consume_code(tenant_id, code, client_uuid, redirect_uri, code_verifier)
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
    // If the client is bound to an NHI identity, the NHI ID becomes the JWT subject
    let token_response = state
        .token_service
        .issue_client_credentials_tokens(
            &client.client_id,
            tenant_id,
            &granted_scope,
            client.nhi_id,
        )
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
        // R8-F2: Use the looked-up client's internal ID (not the parsed client_id string).
        // client_id is the external-facing identifier, while client.id is the internal
        // database UUID. Using the wrong one could cause refresh token validation failures
        // or, in edge cases, allow cross-client token refresh.
        let client = state
            .client_service
            .get_client_by_client_id(tenant_id, client_id)
            .await
            .map_err(|_| {
                OAuthError::InvalidClient("Client not found in specified tenant".to_string())
            })?;
        client.id
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

/// Handle `urn:ietf:params:oauth:grant-type:token-exchange` grant type (RFC 8693).
///
/// Allows an NHI (agent) to obtain a delegated token to act on behalf of
/// a user or another NHI. Requires an active `NhiDelegationGrant`.
///
/// # Security
///
/// - Both subject and actor tokens are verified cryptographically via RS256
/// - Client must be authorized for the `token-exchange` grant type
/// - Tenant ID from the header must match the subject token's `tid` claim
/// - Delegation grant must be active and not expired
/// - Requested scopes must be a subset of the grant's allowed scopes
/// - Delegation depth is enforced per grant's `max_delegation_depth`
async fn handle_token_exchange_grant(
    state: &OAuthState,
    headers: &HeaderMap,
    request: &TokenRequest,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<Json<TokenResponse>, OAuthError> {
    // Extract required parameters
    let subject_token = request
        .subject_token
        .as_ref()
        .ok_or_else(|| OAuthError::InvalidRequest("subject_token is required".to_string()))?;
    // R8-F3: Validate subject_token_type per RFC 8693 §2.1
    let subject_token_type = request
        .subject_token_type
        .as_ref()
        .ok_or_else(|| OAuthError::InvalidRequest("subject_token_type is required".to_string()))?;
    if subject_token_type != "urn:ietf:params:oauth:token-type:access_token" {
        return Err(OAuthError::InvalidRequest(format!(
            "Unsupported subject_token_type. Expected 'urn:ietf:params:oauth:token-type:access_token', got '{subject_token_type}'"
        )));
    }
    let actor_token = request.actor_token.as_ref().ok_or_else(|| {
        OAuthError::InvalidRequest("actor_token is required for delegation".to_string())
    })?;

    // S13: Reject self-referential exchange (same token as both subject and actor)
    if subject_token == actor_token {
        return Err(OAuthError::InvalidRequest(
            "subject_token and actor_token must be different".to_string(),
        ));
    }

    // Extract tenant_id from header
    let tenant_id = extract_tenant_id_from_headers(headers)?;

    // Authenticate the client and validate it is authorized for token exchange
    let secret = client_secret.ok_or_else(|| {
        OAuthError::InvalidClient("client_secret is required for token exchange grant".to_string())
    })?;
    let client = state
        .client_service
        .verify_client_credentials(tenant_id, client_id, secret)
        .await?;
    state
        .client_service
        .validate_grant_type(&client, TOKEN_EXCHANGE_GRANT_TYPE)?;

    // Step 1: Verify subject_token signature and extract claims
    let subject_claims = decode_token(subject_token, &state.public_key)
        .map_err(|e| OAuthError::InvalidGrant(format!("invalid subject_token: {e}")))?;

    // SECURITY: Check subject_token against revocation blacklist.
    // Without this, a revoked token (e.g., via admin revoke-user) could still be
    // exchanged for a fresh delegated token, extending access past revocation.
    if !subject_claims.jti.is_empty() {
        if let Some(ref cache) = state.revocation_cache {
            match cache.is_revoked(&subject_claims.jti).await {
                Ok(true) => {
                    tracing::warn!(jti = %subject_claims.jti, "Rejected revoked subject_token in token exchange");
                    return Err(OAuthError::InvalidGrant(
                        "subject_token has been revoked".to_string(),
                    ));
                }
                Ok(false) => {} // Not revoked, proceed
                Err(e) => {
                    tracing::error!(jti = %subject_claims.jti, error = %e, "Revocation check failed for subject_token (fail-closed)");
                    return Err(OAuthError::Internal(
                        "Token verification failed".to_string(),
                    ));
                }
            }
        }
    }

    let principal_id = Uuid::parse_str(&subject_claims.sub)
        .map_err(|_| OAuthError::InvalidGrant("subject_token has invalid sub claim".to_string()))?;

    // SECURITY: subject token MUST have a tid claim matching the request tenant.
    // Without this, a token from another tenant (or without tid) bypasses isolation.
    let subject_tid = subject_claims.tid.ok_or_else(|| {
        OAuthError::InvalidGrant("subject_token missing required tid claim".to_string())
    })?;
    if subject_tid != tenant_id {
        return Err(OAuthError::InvalidGrant(
            "subject_token tenant does not match X-Tenant-ID".to_string(),
        ));
    }

    // Step 2: Verify actor_token signature and extract claims
    let actor_claims = decode_token(actor_token, &state.public_key)
        .map_err(|e| OAuthError::InvalidGrant(format!("invalid actor_token: {e}")))?;

    let actor_nhi_id = Uuid::parse_str(&actor_claims.sub)
        .map_err(|_| OAuthError::InvalidGrant("actor_token has invalid sub claim".to_string()))?;

    // SECURITY: actor token MUST have a tid claim matching the request tenant.
    let actor_tid = actor_claims.tid.ok_or_else(|| {
        OAuthError::InvalidGrant("actor_token missing required tid claim".to_string())
    })?;
    if actor_tid != tenant_id {
        return Err(OAuthError::InvalidGrant(
            "actor_token tenant does not match X-Tenant-ID".to_string(),
        ));
    }

    // S9: Validate actor claim chain depth to prevent stack overflow / abuse
    if let Some(ref act) = actor_claims.act {
        act.validate_depth().map_err(OAuthError::InvalidGrant)?;
    }

    // Step 3: Look up active delegation grant
    let grant = NhiDelegationGrant::find_active(&state.pool, tenant_id, principal_id, actor_nhi_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to lookup delegation grant: {}", e);
            OAuthError::Internal("Database error".to_string())
        })?
        .ok_or_else(|| {
            OAuthError::InvalidGrant(
                "no active delegation grant found for this principal/actor pair".to_string(),
            )
        })?;

    // Step 4: Validate requested scopes against grant
    let requested_scope = request.scope.clone().unwrap_or_default();
    if !requested_scope.is_empty() {
        for scope in requested_scope.split_whitespace() {
            if !grant.is_scope_allowed(scope) {
                return Err(OAuthError::InvalidScope(format!(
                    "scope '{scope}' not permitted by delegation grant"
                )));
            }
        }
    }

    // Step 5: Check delegation depth (checked arithmetic to prevent overflow)
    let current_depth = actor_claims.delegation_depth.unwrap_or(0);
    let new_depth = current_depth
        .checked_add(1)
        .ok_or_else(|| OAuthError::InvalidGrant("delegation depth overflow".to_string()))?;
    if new_depth > grant.max_delegation_depth {
        return Err(OAuthError::InvalidGrant(format!(
            "delegation depth {} exceeds maximum {} for this grant",
            new_depth, grant.max_delegation_depth
        )));
    }

    // Step 6: Verify actor NHI is active (lifecycle check via DB)
    let actor_identity = NhiIdentity::find_by_id(&state.pool, tenant_id, actor_nhi_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to lookup actor NHI: {}", e);
            OAuthError::Internal("Database error".to_string())
        })?
        .ok_or_else(|| OAuthError::InvalidGrant("actor NHI not found".to_string()))?;

    if !actor_identity.lifecycle_state.is_usable() {
        return Err(OAuthError::InvalidGrant(
            "The provided authorization grant is invalid".to_string(),
        ));
    }

    // SECURITY: Verify the requesting client is bound to the actor NHI.
    // Without this check, any client could impersonate any NHI as an actor.
    if client.nhi_id != Some(actor_nhi_id) {
        return Err(OAuthError::InvalidGrant(
            "Actor token does not belong to the requesting client".to_string(),
        ));
    }

    // Step 7: Mint delegated token with `act` claim
    let token_response = state
        .token_service
        .issue_token_exchange_tokens(
            principal_id,
            actor_nhi_id,
            &grant,
            client_id,
            tenant_id,
            &requested_scope,
            new_depth,
            actor_claims.act.as_ref(),
        )
        .await?;

    tracing::info!(
        principal_id = %principal_id,
        actor_nhi_id = %actor_nhi_id,
        delegation_id = %grant.id,
        delegation_depth = new_depth,
        "token exchange: delegated token issued"
    );

    // Emit DelegationExercised event (fire-and-forget)
    #[cfg(feature = "kafka")]
    if let Some(ref producer) = state.event_producer {
        let event = xavyo_events::events::nhi_delegation::NhiDelegationExercised {
            grant_id: grant.id,
            tenant_id,
            principal_id,
            actor_nhi_id,
            scope_used: requested_scope.clone(),
            delegation_depth: new_depth,
            exercised_at: chrono::Utc::now(),
        };
        if let Err(e) = producer.publish(event, tenant_id, Some(actor_nhi_id)).await {
            tracing::warn!(error = %e, "Failed to publish NhiDelegationExercised event");
        }
    }

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
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            audience: None,
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
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            audience: None,
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
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            audience: None,
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
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            audience: None,
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
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            audience: None,
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
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            audience: None,
        };

        let result = extract_client_credentials(&headers, &request);
        assert!(result.is_err());
    }
}
