//! RFC 7009 Token Revocation handler (F084).
//!
//! POST /oauth/revoke — revokes an access token or refresh token.
//!
//! Per RFC 7009:
//! - Client authentication is required (Basic Auth or body params)
//! - Returns 200 OK when the token is revoked or was unknown/invalid
//! - Persist failures return 500 — they are not "unknown token"
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
/// Returns 200 OK per RFC 7009 Section 2.2 when the token is revoked or unknown.
/// Persist failures are 500 — they must not look like a successful revoke.
#[utoipa::path(
    post,
    path = "/oauth/revoke",
    request_body = RevocationRequest,
    responses(
        (status = 200, description = "Token revoked or unknown (RFC 7009)"),
        (status = 401, description = "Invalid client credentials"),
        (status = 500, description = "Revocation could not be persisted"),
    ),
    tag = "OAuth2"
)]
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

    // Step 2: Attempt to revoke the token.
    // RFC 7009 §2.2: 200 for success or unknown/invalid tokens.
    // Persist failures are not unknown tokens — those must not look revoked.
    let token = &request.token;
    let hint = request.token_type_hint.as_deref();

    let attempt = match hint {
        Some("refresh_token") => {
            let first = try_revoke_refresh_token(&state, tenant_id, token).await;
            if first == RevokeAttempt::Unknown {
                try_revoke_access_token(&state, tenant_id, token).await
            } else {
                first
            }
        }
        _ => {
            let first = try_revoke_access_token(&state, tenant_id, token).await;
            if first == RevokeAttempt::Unknown {
                try_revoke_refresh_token(&state, tenant_id, token).await
            } else {
                first
            }
        }
    };

    match attempt {
        RevokeAttempt::Revoked => {
            tracing::info!(
                target: "token_lifecycle",
                event_type = "token_revoked",
                client_id = %client_id,
                tenant_id = %tenant_id,
                token_type_hint = ?hint,
                "Token revoked via RFC 7009"
            );
        }
        RevokeAttempt::Unknown => {
            tracing::debug!(
                target: "token_lifecycle",
                event_type = "revocation_no_match",
                client_id = %client_id,
                "Token not recognized (returning 200 per RFC 7009)"
            );
        }
        RevokeAttempt::Failed => {
            tracing::error!(
                target: "token_lifecycle",
                event_type = "revocation_persist_failed",
                client_id = %client_id,
                "Token revocation was not persisted"
            );
        }
    }

    rfc7009_revoke_status(attempt)
}

/// Try to revoke a token as an access token (JWT).
///
/// Decodes the JWT to extract the JTI, verifies tenant match,
/// then adds the JTI to the blacklist.
/// Unknown/invalid tokens are `Unknown`; persist errors are `Failed`.
async fn try_revoke_access_token(
    state: &OAuthState,
    tenant_id: Uuid,
    token: &str,
) -> RevokeAttempt {
    // Try to decode the JWT (don't validate expiry — we want to revoke expired tokens too)
    let config = xavyo_auth::ValidationConfig::default().skip_exp_validation();

    let claims = match xavyo_auth::decode_token_with_config(token, &state.public_key, &config) {
        Ok(claims) => claims,
        Err(_) => return RevokeAttempt::Unknown, // Not a valid JWT signed by us
    };

    // Verify the token belongs to the requesting client's tenant.
    // Missing tid is unknown — do not revoke into another tenant.
    if !super::client_auth::token_tid_matches_tenant(claims.tid, tenant_id) {
        return RevokeAttempt::Unknown;
    }

    let jti = &claims.jti;
    if jti.is_empty() {
        return RevokeAttempt::Unknown; // No JTI to blacklist
    }

    // Extract user_id from subject. NHI tokens may use a non-UUID subject;
    // derive a stable UUID so we never persist Uuid::nil() as the actor.
    let user_id = revocation_user_id(&claims.sub);

    // SECURITY: Acquire dedicated connection for RLS to prevent pool race condition
    let mut conn = match state.pool.acquire().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                target: "token_lifecycle",
                jti = %jti,
                error = %e,
                "Failed to acquire connection for revocation insert"
            );
            return RevokeAttempt::Failed;
        }
    };

    // Set tenant context for RLS on this connection
    if sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *conn)
        .await
        .is_err()
    {
        tracing::error!(
            target: "token_lifecycle",
            jti = %jti,
            "Failed to set tenant context for revocation insert"
        );
        return RevokeAttempt::Failed;
    }

    // Insert JTI into revoked_tokens table using the same connection
    let input = CreateRevokedToken {
        jti: jti.clone(),
        user_id,
        tenant_id,
        reason: Some("RFC 7009 revocation".to_string()),
        expires_at: chrono::DateTime::from_timestamp(claims.exp, 0)
            .unwrap_or_else(|| Utc::now() + chrono::Duration::hours(1)),
        revoked_by: None,
    };

    let attempt = persist_revocation_insert(RevokedToken::insert(&mut *conn, input).await);

    // Invalidate in cache so subsequent requests are rejected immediately
    if attempt == RevokeAttempt::Revoked {
        if let Some(ref cache) = state.revocation_cache {
            cache.invalidate(jti).await;
        }
    }

    attempt
}

/// Try to revoke a token as a refresh token (opaque).
///
/// Hashes the token and looks it up in `oauth_refresh_tokens`.
/// If found, marks it as revoked and cascades to blacklist access tokens.
/// Unknown tokens are `Unknown`; persist errors are `Failed`.
async fn try_revoke_refresh_token(
    state: &OAuthState,
    tenant_id: Uuid,
    token: &str,
) -> RevokeAttempt {
    let token_hash = hash_token(token);

    // SECURITY: Acquire dedicated connection for RLS to prevent pool race condition
    let mut conn = match state.pool.acquire().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                target: "token_lifecycle",
                error = %e,
                "Failed to acquire connection for refresh-token revocation"
            );
            return RevokeAttempt::Failed;
        }
    };

    // Set tenant context for RLS on this connection
    if sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *conn)
        .await
        .is_err()
    {
        tracing::error!(
            target: "token_lifecycle",
            "Failed to set tenant context for refresh-token revocation"
        );
        return RevokeAttempt::Failed;
    }

    // Look up the refresh token by hash using the same connection.
    // Lookup errors are not "unknown token" — do not pretend revoke succeeded.
    let row: Option<(Uuid, Uuid, bool)> = match sqlx::query_as(
        r"
        SELECT id, user_id, revoked
        FROM oauth_refresh_tokens
        WHERE token_hash = $1 AND tenant_id = $2
        ",
    )
    .bind(&token_hash)
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::error!(
                target: "token_lifecycle",
                error = %e,
                "Failed to look up refresh token for revocation"
            );
            return RevokeAttempt::Failed;
        }
    };

    let (token_id, user_id, already_revoked) = match row {
        Some(r) => r,
        None => return RevokeAttempt::Unknown, // Not a known refresh token
    };

    if already_revoked {
        return RevokeAttempt::Revoked; // Already revoked, nothing to do
    }

    // Mark refresh token as revoked using the same connection
    match sqlx::query(
        r"
        UPDATE oauth_refresh_tokens
        SET revoked = TRUE, revoked_at = now()
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(token_id)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    {
        Ok(result) if result.rows_affected() > 0 => {}
        Ok(_) => {
            tracing::error!(
                target: "token_lifecycle",
                token_id = %token_id,
                "Refresh token revoke update affected 0 rows"
            );
            return RevokeAttempt::Failed;
        }
        Err(e) => {
            tracing::error!(
                target: "token_lifecycle",
                token_id = %token_id,
                error = %e,
                "Failed to mark refresh token revoked"
            );
            return RevokeAttempt::Failed;
        }
    }

    // Cascade: revoke all user's access tokens using sentinel pattern
    cascade_revoke_user_access_tokens(state, tenant_id, user_id).await
}

/// Cascade revocation: blacklist all access tokens for a user.
///
/// Inserts a `revoke-all:{user_id}:{timestamp}` sentinel into `revoked_tokens`.
/// The JWT auth middleware checks for these sentinels and rejects any token
/// issued before the sentinel timestamp.
async fn cascade_revoke_user_access_tokens(
    state: &OAuthState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> RevokeAttempt {
    let sentinel_jti = format!("revoke-all:{}:{}", user_id, Utc::now().timestamp());

    // SECURITY: Acquire dedicated connection for RLS to prevent pool race condition.
    // set_config on a shared pool sets context on a random connection that may not be
    // the same one used for the subsequent insert.
    let mut conn = match state.pool.acquire().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                target: "token_lifecycle",
                user_id = %user_id,
                error = %e,
                "Failed to acquire connection for cascade revocation"
            );
            return RevokeAttempt::Failed;
        }
    };

    // Set tenant context for RLS on this connection
    if sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *conn)
        .await
        .is_err()
    {
        tracing::error!(
            target: "token_lifecycle",
            user_id = %user_id,
            "Failed to set tenant context for cascade revocation"
        );
        return RevokeAttempt::Failed;
    }

    let input = CreateRevokedToken {
        jti: sentinel_jti.clone(),
        user_id,
        tenant_id,
        reason: Some("Cascade from refresh token revocation".to_string()),
        // Sentinel expires after access token max lifetime (15 min + buffer)
        expires_at: Utc::now() + chrono::Duration::hours(1),
        revoked_by: None,
    };

    // Use the same connection for the insert so RLS context applies
    let attempt = persist_revocation_insert(RevokedToken::insert(&mut *conn, input).await);

    // Invalidate sentinel in cache only after a successful persist
    if attempt == RevokeAttempt::Revoked {
        if let Some(ref cache) = state.revocation_cache {
            cache.invalidate(&sentinel_jti).await;
        }
    }

    attempt
}

/// Map a JWT `sub` to a UUID for the revocation record.
///
/// Human users have UUID subjects. NHI tokens may use a name; hash it so we
/// never persist `Uuid::nil()` as the actor.
fn revocation_user_id(sub: &str) -> Uuid {
    Uuid::parse_str(sub).unwrap_or_else(|_| {
        let mut hasher = Sha256::new();
        hasher.update(sub.as_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        Uuid::from_bytes(bytes)
    })
}

/// Outcome of a revocation attempt.
///
/// RFC 7009 §2.2 returns 200 for success *or* unknown/invalid tokens.
/// Persist and lookup errors are not unknown tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RevokeAttempt {
    Revoked,
    Unknown,
    Failed,
}

/// RFC 7009 status. Persist failures must not look like a successful revoke.
pub(crate) fn rfc7009_revoke_status(attempt: RevokeAttempt) -> Result<StatusCode, OAuthError> {
    match attempt {
        RevokeAttempt::Revoked | RevokeAttempt::Unknown => Ok(StatusCode::OK),
        RevokeAttempt::Failed => Err(OAuthError::Internal(
            "Failed to persist token revocation".to_string(),
        )),
    }
}

/// Map a revoked-token insert to a revoke attempt. Insert errors are `Failed`.
pub(crate) fn persist_revocation_insert<T, E: std::fmt::Display>(
    result: Result<T, E>,
) -> RevokeAttempt {
    match result {
        Ok(_) => RevokeAttempt::Revoked,
        Err(e) => {
            tracing::error!(
                target: "token_lifecycle",
                error = %e,
                "Failed to persist revoked token record"
            );
            RevokeAttempt::Failed
        }
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

    #[test]
    fn revocation_does_not_skip_missing_tid() {
        let src = include_str!("revocation.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("token_tid_matches_tenant("),
            "revocation must reject tokens missing tid"
        );
        assert!(
            !production.contains("if let Some(token_tid) = claims.tid"),
            "must not skip tenant match when tid is absent"
        );
        assert!(
            production.contains("revocation_user_id("),
            "revocation must not use Uuid::nil() as the actor"
        );
        assert!(
            !production.contains("unwrap_or(Uuid::nil())"),
            "must not persist a nil UUID as the revoked-token user"
        );
        assert!(
            !production.contains(".ok()\n    .flatten()"),
            "refresh-token lookup errors must not look like an unknown token"
        );
        assert!(
            !production.contains("let _ = sqlx::query("),
            "must not swallow refresh-token revoke updates"
        );
        assert!(
            production.contains("rfc7009_revoke_status("),
            "RFC 7009 persist failures must not return 200"
        );
        assert!(
            production.contains("persist_revocation_insert("),
            "revoked-token inserts must fail closed"
        );
        assert!(
            !production
                .contains("cascade_revoke_user_access_tokens(state, tenant_id, user_id).await;"),
            "must not swallow cascade sentinel persist after refresh-token revoke"
        );
    }

    #[test]
    fn rfc7009_persist_failure_is_not_success() {
        assert_eq!(
            rfc7009_revoke_status(RevokeAttempt::Revoked).unwrap(),
            StatusCode::OK
        );
        assert_eq!(
            rfc7009_revoke_status(RevokeAttempt::Unknown).unwrap(),
            StatusCode::OK
        );
        assert!(rfc7009_revoke_status(RevokeAttempt::Failed).is_err());
        assert_eq!(
            persist_revocation_insert(Ok::<(), &str>(())),
            RevokeAttempt::Revoked
        );
        assert_eq!(
            persist_revocation_insert(Err::<(), _>("db down")),
            RevokeAttempt::Failed
        );
    }

    #[test]
    fn revocation_user_id_is_stable_and_not_nil() {
        let human = Uuid::new_v4();
        assert_eq!(revocation_user_id(&human.to_string()), human);
        let nhi = revocation_user_id("agent-alpha");
        assert_ne!(nhi, Uuid::nil());
        assert_eq!(nhi, revocation_user_id("agent-alpha"));
        assert_ne!(nhi, revocation_user_id("agent-beta"));
    }
}
