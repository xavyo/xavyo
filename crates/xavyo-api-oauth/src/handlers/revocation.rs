//! RFC 7009 Token Revocation handler (F084).
//!
//! POST /oauth/revoke — revokes an access token or refresh token.
//!
//! Per RFC 7009:
//! - Client authentication is required (Basic Auth or body params)
//! - Always returns 200 OK regardless of whether the token existed
//! - Accepts form-encoded body with `token` and optional `token_type_hint`

use crate::error::OAuthError;
use crate::handlers::client_auth::{authenticate_client, extract_client_credentials};
use crate::models::RevocationRequest;
use crate::router::OAuthState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Form,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use xavyo_db::models::{CreateRevokedToken, RevokedToken};

/// Handle RFC 7009 token revocation.
///
/// Always returns 200 OK per RFC 7009 Section 2.1 — never leak information
/// about token validity to unauthenticated clients.
pub async fn revoke_token_handler(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    Form(request): Form<RevocationRequest>,
) -> Result<StatusCode, OAuthError> {
    // Step 1: Extract and validate client credentials
    let (client_id, client_secret) = extract_client_credentials(
        &headers,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    )?;

    let tenant_id = super::client_auth::extract_tenant_from_header(&headers)?;

    // Authenticate the client (returns internal UUID)
    let _client_internal_id = authenticate_client(
        &state.client_service,
        tenant_id,
        &client_id,
        client_secret.as_deref(),
    )
    .await
    .map_err(|e| {
        // Client auth failures return 401, not 200
        tracing::warn!(
            target: "token_lifecycle",
            event_type = "revocation_auth_failed",
            client_id = %client_id,
            error = %e,
            "Client authentication failed for revocation"
        );
        e
    })?;

    // Step 2: Attempt to revoke the token
    // Per RFC 7009: always return 200 OK even if token is invalid/unknown
    let token = &request.token;
    let hint = request.token_type_hint.as_deref();

    let result = match hint {
        Some("access_token") => {
            // Try access token first, then refresh token
            try_revoke_access_token(&state, tenant_id, token).await
                || try_revoke_refresh_token(&state, tenant_id, token).await
        }
        Some("refresh_token") => {
            // Try refresh token first, then access token
            try_revoke_refresh_token(&state, tenant_id, token).await
                || try_revoke_access_token(&state, tenant_id, token).await
        }
        _ => {
            // No hint: try access token first (JWT decode is fast), then refresh token
            try_revoke_access_token(&state, tenant_id, token).await
                || try_revoke_refresh_token(&state, tenant_id, token).await
        }
    };

    if result {
        tracing::info!(
            target: "token_lifecycle",
            event_type = "token_revoked",
            client_id = %client_id,
            tenant_id = %tenant_id,
            token_type_hint = ?hint,
            "Token revoked via RFC 7009"
        );
    } else {
        tracing::debug!(
            target: "token_lifecycle",
            event_type = "revocation_no_match",
            client_id = %client_id,
            "Token not recognized (returning 200 per RFC 7009)"
        );
    }

    // Always 200 OK per RFC 7009
    Ok(StatusCode::OK)
}

/// Try to revoke a token as an access token (JWT).
///
/// Decodes the JWT to extract the JTI, verifies tenant match,
/// then adds the JTI to the blacklist.
/// Returns true if the token was a valid JWT and was revoked.
async fn try_revoke_access_token(state: &OAuthState, tenant_id: Uuid, token: &str) -> bool {
    // Try to decode the JWT (don't validate expiry — we want to revoke expired tokens too)
    let config = xavyo_auth::ValidationConfig::default().skip_exp_validation();

    let claims = match xavyo_auth::decode_token_with_config(token, &state.public_key, &config) {
        Ok(claims) => claims,
        Err(_) => return false, // Not a valid JWT signed by us
    };

    // Verify the token belongs to the requesting client's tenant
    if let Some(token_tid) = claims.tid {
        if token_tid != tenant_id {
            // Token belongs to a different tenant — treat as unknown per RFC 7009
            return false;
        }
    }

    let jti = &claims.jti;
    if jti.is_empty() {
        return false; // No JTI to blacklist
    }

    // Extract user_id from subject — reject if not a valid UUID
    let user_id = if let Ok(uid) = claims.sub.parse::<Uuid>() {
        uid
    } else {
        tracing::warn!(
            target: "token_lifecycle",
            jti = %jti,
            sub = %claims.sub,
            "Cannot revoke access token: subject is not a valid UUID"
        );
        return false;
    };

    // Set tenant context for RLS before inserting into revoked_tokens
    if sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&state.pool)
        .await
        .is_err()
    {
        tracing::error!(
            target: "token_lifecycle",
            jti = %jti,
            "Failed to set tenant context for revocation insert"
        );
        return false;
    }

    // Insert JTI into revoked_tokens table
    let input = CreateRevokedToken {
        jti: jti.clone(),
        user_id,
        tenant_id,
        reason: Some("RFC 7009 revocation".to_string()),
        expires_at: chrono::DateTime::from_timestamp(claims.exp, 0)
            .unwrap_or_else(|| Utc::now() + chrono::Duration::hours(1)),
        revoked_by: None,
    };

    let inserted = match RevokedToken::insert(&state.pool, input).await {
        Ok(_) => true,
        Err(e) => {
            tracing::error!(
                target: "token_lifecycle",
                jti = %jti,
                error = %e,
                "Failed to insert revoked token record — revocation not persisted"
            );
            false
        }
    };

    // Invalidate in cache so subsequent requests are rejected immediately
    if let Some(ref cache) = state.revocation_cache {
        cache.invalidate(jti).await;
    }

    inserted
}

/// Try to revoke a token as a refresh token (opaque).
///
/// Hashes the token and looks it up in `oauth_refresh_tokens`.
/// If found, marks it as revoked and cascades to blacklist access tokens.
/// Returns true if the token was found and revoked.
async fn try_revoke_refresh_token(state: &OAuthState, tenant_id: Uuid, token: &str) -> bool {
    let token_hash = hash_token(token);

    // Set tenant context for RLS
    if sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&state.pool)
        .await
        .is_err()
    {
        return false;
    }

    // Look up the refresh token by hash
    let row: Option<(Uuid, Uuid, bool)> = sqlx::query_as(
        r"
        SELECT id, user_id, revoked
        FROM oauth_refresh_tokens
        WHERE token_hash = $1 AND tenant_id = $2
        ",
    )
    .bind(&token_hash)
    .bind(tenant_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    let (token_id, user_id, already_revoked) = match row {
        Some(r) => r,
        None => return false, // Not a known refresh token
    };

    if already_revoked {
        return true; // Already revoked, nothing to do
    }

    // Mark refresh token as revoked
    let _ = sqlx::query(
        r"
        UPDATE oauth_refresh_tokens
        SET revoked = TRUE, revoked_at = now()
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(token_id)
    .bind(tenant_id)
    .execute(&state.pool)
    .await;

    // Cascade: revoke all user's access tokens using sentinel pattern
    cascade_revoke_user_access_tokens(state, tenant_id, user_id).await;

    true
}

/// Cascade revocation: blacklist all access tokens for a user.
///
/// Inserts a `revoke-all:{user_id}:{timestamp}` sentinel into `revoked_tokens`.
/// The JWT auth middleware checks for these sentinels and rejects any token
/// issued before the sentinel timestamp.
async fn cascade_revoke_user_access_tokens(state: &OAuthState, tenant_id: Uuid, user_id: Uuid) {
    let sentinel_jti = format!("revoke-all:{}:{}", user_id, Utc::now().timestamp());

    // Ensure tenant context is set for RLS
    let _ = sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&state.pool)
        .await;

    let input = CreateRevokedToken {
        jti: sentinel_jti.clone(),
        user_id,
        tenant_id,
        reason: Some("Cascade from refresh token revocation".to_string()),
        // Sentinel expires after access token max lifetime (15 min + buffer)
        expires_at: Utc::now() + chrono::Duration::hours(1),
        revoked_by: None,
    };

    if let Err(e) = RevokedToken::insert(&state.pool, input).await {
        tracing::error!(
            target: "token_lifecycle",
            user_id = %user_id,
            error = %e,
            "Failed to insert cascade revocation sentinel"
        );
    }

    // Invalidate sentinel in cache
    if let Some(ref cache) = state.revocation_cache {
        cache.invalidate(&sentinel_jti).await;
    }
}

/// Hash a token value using SHA-256 (same algorithm as `TokenService`).
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::client_auth::extract_tenant_from_header;

    #[test]
    fn test_hash_token_deterministic() {
        let hash1 = hash_token("test-token");
        let hash2 = hash_token("test-token");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_token_sha256_length() {
        let hash = hash_token("test-token");
        assert_eq!(hash.len(), 64); // SHA-256 = 64 hex chars
    }

    #[test]
    fn test_extract_tenant_valid() {
        let mut headers = HeaderMap::new();
        let tid = Uuid::new_v4();
        headers.insert("x-tenant-id", tid.to_string().parse().unwrap());
        let result = extract_tenant_from_header(&headers);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), tid);
    }

    #[test]
    fn test_extract_tenant_missing() {
        let headers = HeaderMap::new();
        let result = extract_tenant_from_header(&headers);
        assert!(result.is_err());
    }
}
