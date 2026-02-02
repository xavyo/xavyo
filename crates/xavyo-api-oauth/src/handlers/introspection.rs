//! RFC 7662 Token Introspection handler (F084).
//!
//! POST /oauth/introspect — returns token metadata for active tokens,
//! or `{ "active": false }` for inactive/revoked/expired tokens.
//!
//! Per RFC 7662:
//! - Client authentication is required
//! - Form-encoded request body
//! - JSON response with `active` boolean field (always present)

use crate::error::OAuthError;
use crate::handlers::client_auth::{authenticate_client, extract_client_credentials};
use crate::models::{IntrospectionRequest, IntrospectionResponse};
use crate::router::OAuthState;
use axum::{extract::State, http::HeaderMap, Form, Json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Database row for a refresh token introspection lookup.
#[derive(sqlx::FromRow)]
struct RefreshTokenRow {
    #[allow(dead_code)]
    id: Uuid,
    user_id: Uuid,
    scope: String,
    revoked: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

/// Handle RFC 7662 token introspection.
pub async fn introspect_token_handler(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    Form(request): Form<IntrospectionRequest>,
) -> Result<Json<IntrospectionResponse>, OAuthError> {
    // Step 1: Extract and validate client credentials
    let (client_id, client_secret) = extract_client_credentials(
        &headers,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    )?;

    let tenant_id = super::client_auth::extract_tenant_from_header(&headers)?;

    // Authenticate the client
    let _client_internal_id = authenticate_client(
        &state.client_service,
        tenant_id,
        &client_id,
        client_secret.as_deref(),
    )
    .await?;

    // Step 2: Introspect the token
    let token = &request.token;
    let hint = request.token_type_hint.as_deref();

    let response = match hint {
        Some("access_token") => {
            // Try access token first, then refresh token
            if let Some(resp) = try_introspect_access_token(&state, tenant_id, token).await {
                resp
            } else if let Some(resp) = try_introspect_refresh_token(&state, tenant_id, token).await
            {
                resp
            } else {
                IntrospectionResponse::inactive()
            }
        }
        Some("refresh_token") => {
            // Try refresh token first, then access token
            if let Some(resp) = try_introspect_refresh_token(&state, tenant_id, token).await {
                resp
            } else if let Some(resp) = try_introspect_access_token(&state, tenant_id, token).await {
                resp
            } else {
                IntrospectionResponse::inactive()
            }
        }
        _ => {
            // No hint: try access token first (JWT decode is fast), then refresh token
            if let Some(resp) = try_introspect_access_token(&state, tenant_id, token).await {
                resp
            } else if let Some(resp) = try_introspect_refresh_token(&state, tenant_id, token).await
            {
                resp
            } else {
                IntrospectionResponse::inactive()
            }
        }
    };

    tracing::info!(
        target: "token_lifecycle",
        event_type = "token_introspected",
        client_id = %client_id,
        active = response.active,
        token_type_hint = ?hint,
        "Token introspection"
    );

    Ok(Json(response))
}

/// Try to introspect a token as an access token (JWT).
///
/// Decodes the JWT, validates signature + expiration, checks JTI blacklist,
/// and verifies the token's tenant matches the requesting client's tenant.
/// Returns Some(IntrospectionResponse) if the token is a valid JWT.
async fn try_introspect_access_token(
    state: &OAuthState,
    tenant_id: Uuid,
    token: &str,
) -> Option<IntrospectionResponse> {
    // Decode with full validation (including expiration)
    let claims = match xavyo_auth::decode_token_with_config(
        token,
        &state.public_key,
        &xavyo_auth::ValidationConfig::default(),
    ) {
        Ok(claims) => claims,
        Err(_) => return None, // Not a valid/unexpired JWT signed by us
    };

    // Verify the token belongs to the requesting client's tenant (RFC 7662 §2.1:
    // "the authorization server MUST be able to determine whether the token was
    // issued to the client making the introspection call")
    if let Some(token_tid) = claims.tid {
        if token_tid != tenant_id {
            // Token belongs to a different tenant — treat as unknown
            return Some(IntrospectionResponse::inactive());
        }
    }

    // Check JTI blacklist
    if !claims.jti.is_empty() {
        if let Some(ref cache) = state.revocation_cache {
            match cache.is_revoked(&claims.jti).await {
                Ok(true) => return Some(IntrospectionResponse::inactive()),
                Ok(false) => {} // Not revoked, continue
                Err(e) => {
                    // Fail-closed: treat cache errors as revoked
                    tracing::error!(
                        target: "token_lifecycle",
                        jti = %claims.jti,
                        error = %e,
                        "Revocation cache error during introspection — fail-closed"
                    );
                    return Some(IntrospectionResponse::inactive());
                }
            }
        }

        // Check for revoke-all sentinel: if a revoke-all sentinel was created
        // after this token was issued, the token should be treated as revoked.
        // Filter by tenant_id to prevent cross-tenant leakage.
        let sentinel_revoked: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM revoked_tokens
                WHERE jti LIKE 'revoke-all:' || $1 || ':%'
                  AND tenant_id = $3
                  AND created_at > to_timestamp($2)
            )
            "#,
        )
        .bind(&claims.sub)
        .bind(claims.iat as f64)
        .bind(tenant_id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(false);

        if sentinel_revoked {
            return Some(IntrospectionResponse::inactive());
        }
    }

    // Token is valid and not revoked — build active response
    let aud = if claims.aud.is_empty() {
        None
    } else {
        Some(claims.aud.join(" "))
    };

    let scope = if claims.roles.is_empty() {
        None
    } else {
        Some(claims.roles.join(" "))
    };

    Some(IntrospectionResponse {
        active: true,
        sub: Some(claims.sub),
        client_id: claims.aud.first().cloned(),
        scope,
        exp: Some(claims.exp),
        iat: Some(claims.iat),
        token_type: Some("Bearer".to_string()),
        aud,
        iss: Some(claims.iss),
        jti: Some(claims.jti),
        tid: claims.tid,
    })
}

/// Try to introspect a token as a refresh token (opaque).
///
/// Hashes the token, looks up in oauth_refresh_tokens, checks validity.
/// Returns Some(IntrospectionResponse) if the token is a known refresh token.
async fn try_introspect_refresh_token(
    state: &OAuthState,
    tenant_id: Uuid,
    token: &str,
) -> Option<IntrospectionResponse> {
    let token_hash = hash_token(token);

    // Set tenant context for RLS
    sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&state.pool)
        .await
        .ok()?;

    // Look up the refresh token
    let row: Option<RefreshTokenRow> = sqlx::query_as(
        r#"
        SELECT rt.id, rt.user_id, rt.scope, rt.revoked, rt.created_at, rt.expires_at
        FROM oauth_refresh_tokens rt
        WHERE rt.token_hash = $1 AND rt.tenant_id = $2
        "#,
    )
    .bind(&token_hash)
    .bind(tenant_id)
    .fetch_optional(&state.pool)
    .await
    .ok()?;

    let rt = row?;

    // Check if revoked or expired
    if rt.revoked || rt.expires_at < chrono::Utc::now() {
        return Some(IntrospectionResponse::inactive());
    }

    // Active refresh token
    Some(IntrospectionResponse {
        active: true,
        sub: Some(rt.user_id.to_string()),
        client_id: None, // Could join with oauth_clients if needed
        scope: Some(rt.scope),
        exp: Some(rt.expires_at.timestamp()),
        iat: Some(rt.created_at.timestamp()),
        token_type: Some("refresh_token".to_string()),
        aud: None,
        iss: None,
        jti: None,
        tid: Some(tenant_id),
    })
}

/// Hash a token value using SHA-256.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}
