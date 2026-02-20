//! Admin token management handlers (F084).
//!
//! - POST /admin/oauth/revoke-user — revoke all tokens for a user
//! - GET /admin/oauth/active-sessions — list active sessions for a user
//! - DELETE /`admin/oauth/sessions/:token_id` — revoke a specific session

use crate::error::OAuthError;
use crate::models::{
    ActiveSessionsResponse, AdminRevokeUserRequest, AdminRevokeUserResponse, SessionInfo,
    SessionRevokedResponse,
};
use crate::router::OAuthState;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::{CreateRevokedToken, RevokedToken};

/// Database row for an active session query result.
#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Uuid,
    client_id: Uuid,
    client_name: String,
    scope: String,
    created_at: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
}

/// Query parameters for listing active sessions.
#[derive(Debug, Deserialize)]
pub struct ActiveSessionsQuery {
    /// User ID to list sessions for.
    pub user_id: Uuid,
}

/// POST /admin/oauth/revoke-user — revoke all tokens for a user.
///
/// Revokes all refresh tokens and blacklists all access tokens
/// for the specified user. Requires admin JWT authentication
/// (enforced by the admin router middleware).
#[utoipa::path(
    post,
    path = "/admin/oauth/revoke-user",
    request_body = AdminRevokeUserRequest,
    responses(
        (status = 200, description = "All tokens revoked for user", body = AdminRevokeUserResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "OAuth2 Admin"
)]
pub async fn admin_revoke_user_handler(
    State(state): State<OAuthState>,
    axum::Extension(claims): axum::Extension<JwtClaims>,
    Json(request): Json<AdminRevokeUserRequest>,
) -> Result<Json<AdminRevokeUserResponse>, OAuthError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let admin_id = claims.sub.parse::<Uuid>().ok();

    // R9-F1: Acquire a dedicated connection so set_config and queries share RLS context.
    let mut conn = state.pool.acquire().await.map_err(|e| {
        tracing::error!(error = %e, "Failed to acquire connection");
        OAuthError::Internal("Database connection failed".to_string())
    })?;

    sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to set tenant context");
            OAuthError::Internal("Failed to set tenant context".to_string())
        })?;

    // 1. Revoke all refresh tokens for the user
    let revoke_result = sqlx::query(
        r"
        UPDATE oauth_refresh_tokens
        SET revoked = TRUE, revoked_at = now()
        WHERE user_id = $1 AND tenant_id = $2 AND revoked = FALSE
        ",
    )
    .bind(request.user_id)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to revoke user refresh tokens");
        OAuthError::Internal("Failed to revoke refresh tokens".to_string())
    })?;

    let refresh_tokens_revoked = revoke_result.rows_affected() as i64;

    // 2. Blacklist all access tokens via sentinel pattern
    let sentinel_jti = format!("revoke-all:{}:{}", request.user_id, Utc::now().timestamp());
    let reason = request
        .reason
        .as_deref()
        .unwrap_or("Admin revocation")
        .to_string();

    let input = CreateRevokedToken {
        jti: sentinel_jti.clone(),
        user_id: request.user_id,
        tenant_id,
        reason: Some(reason.clone()),
        // Sentinel expires after access token max lifetime (15 min + 45 min buffer)
        expires_at: Utc::now() + chrono::Duration::hours(1),
        revoked_by: admin_id,
    };

    if let Err(e) = RevokedToken::insert(&mut *conn, input).await {
        tracing::error!(
            user_id = %request.user_id,
            error = %e,
            "Failed to insert revoke-all sentinel"
        );
    }

    // Invalidate sentinel in cache
    if let Some(ref cache) = state.revocation_cache {
        cache.invalidate(&sentinel_jti).await;
    }

    tracing::info!(
        target: "token_lifecycle",
        event_type = "admin_revoke_user",
        user_id = %request.user_id,
        tenant_id = %tenant_id,
        admin_id = ?admin_id,
        refresh_tokens_revoked = refresh_tokens_revoked,
        reason = %reason,
        "Admin revoked all tokens for user"
    );

    Ok(Json(AdminRevokeUserResponse {
        user_id: request.user_id,
        refresh_tokens_revoked,
        access_tokens_blacklisted: true,
        revoked_at: Utc::now(),
    }))
}

/// GET /admin/oauth/active-sessions — list active sessions for a user.
///
/// Returns all non-revoked, non-expired refresh tokens for a user,
/// joined with client names for display.
#[utoipa::path(
    get,
    path = "/admin/oauth/active-sessions",
    params(
        ("user_id" = Uuid, Query, description = "User ID to list sessions for")
    ),
    responses(
        (status = 200, description = "List of active sessions", body = ActiveSessionsResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "OAuth2 Admin"
)]
pub async fn list_active_sessions_handler(
    State(state): State<OAuthState>,
    axum::Extension(claims): axum::Extension<JwtClaims>,
    Query(query): Query<ActiveSessionsQuery>,
) -> Result<Json<ActiveSessionsResponse>, OAuthError> {
    let tenant_id = extract_tenant_id(&claims)?;

    // R9-F1: Acquire a dedicated connection so set_config and queries share RLS context.
    let mut conn = state.pool.acquire().await.map_err(|e| {
        tracing::error!(error = %e, "Failed to acquire connection");
        OAuthError::Internal("Database connection failed".to_string())
    })?;

    sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to set tenant context");
            OAuthError::Internal("Failed to set tenant context".to_string())
        })?;

    // Query active (non-revoked, non-expired) refresh tokens with client info
    let rows: Vec<SessionRow> = sqlx::query_as(
        r"
        SELECT
            rt.id,
            rt.client_id,
            COALESCE(oc.name, oc.client_id::text) AS client_name,
            rt.scope,
            rt.created_at,
            rt.expires_at
        FROM oauth_refresh_tokens rt
        LEFT JOIN oauth_clients oc ON rt.client_id = oc.id AND oc.tenant_id = $2
        WHERE rt.user_id = $1
          AND rt.tenant_id = $2
          AND rt.revoked = FALSE
          AND rt.expires_at > now()
        ORDER BY rt.created_at DESC
        ",
    )
    .bind(query.user_id)
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to list active sessions");
        OAuthError::Internal("Failed to list active sessions".to_string())
    })?;

    let sessions: Vec<SessionInfo> = rows
        .into_iter()
        .map(|r| SessionInfo {
            id: r.id,
            client_id: r.client_id,
            client_name: r.client_name,
            scope: r.scope,
            created_at: r.created_at,
            expires_at: r.expires_at,
        })
        .collect();

    let total = sessions.len();

    tracing::debug!(
        target: "token_lifecycle",
        event_type = "list_active_sessions",
        user_id = %query.user_id,
        tenant_id = %tenant_id,
        session_count = total,
        "Listed active sessions"
    );

    Ok(Json(ActiveSessionsResponse { sessions, total }))
}

/// DELETE /`admin/oauth/sessions/:token_id` — revoke a specific session.
///
/// Revokes a single refresh token by its ID.
#[utoipa::path(
    delete,
    path = "/admin/oauth/sessions/{token_id}",
    params(
        ("token_id" = Uuid, Path, description = "Token ID of the session to revoke")
    ),
    responses(
        (status = 200, description = "Session revoked", body = SessionRevokedResponse),
        (status = 400, description = "Invalid request or session already revoked"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "OAuth2 Admin"
)]
pub async fn delete_session_handler(
    State(state): State<OAuthState>,
    axum::Extension(claims): axum::Extension<JwtClaims>,
    Path(token_id): Path<Uuid>,
) -> Result<Json<SessionRevokedResponse>, OAuthError> {
    let tenant_id = extract_tenant_id(&claims)?;

    // R9-F1: Acquire a dedicated connection so set_config and queries share RLS context.
    let mut conn = state.pool.acquire().await.map_err(|e| {
        tracing::error!(error = %e, "Failed to acquire connection");
        OAuthError::Internal("Database connection failed".to_string())
    })?;

    sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to set tenant context");
            OAuthError::Internal("Failed to set tenant context".to_string())
        })?;

    // Verify the session exists and belongs to this tenant
    let exists: Option<(bool,)> = sqlx::query_as(
        r"
        SELECT revoked FROM oauth_refresh_tokens
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(token_id)
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to look up session");
        OAuthError::Internal("Failed to look up session".to_string())
    })?;

    match exists {
        None => {
            return Err(OAuthError::InvalidRequest(format!(
                "Session {token_id} not found"
            )));
        }
        Some((true,)) => {
            return Err(OAuthError::InvalidRequest(format!(
                "Session {token_id} is already revoked"
            )));
        }
        Some((false,)) => {} // Valid, proceed with revocation
    }

    // Revoke the specific session
    sqlx::query(
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
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to revoke session");
        OAuthError::Internal("Failed to revoke session".to_string())
    })?;

    tracing::info!(
        target: "token_lifecycle",
        event_type = "delete_session",
        token_id = %token_id,
        tenant_id = %tenant_id,
        "Admin revoked specific session"
    );

    Ok(Json(SessionRevokedResponse {
        token_id,
        revoked_at: Utc::now(),
        message: format!("Session {token_id} has been revoked"),
    }))
}

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, OAuthError> {
    claims
        .tid
        .ok_or_else(|| OAuthError::InvalidRequest("Missing tenant_id in JWT claims".to_string()))
}
