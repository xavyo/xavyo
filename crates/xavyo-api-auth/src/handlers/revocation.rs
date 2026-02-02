//! Token revocation handlers (F069-S4).
//!
//! Provides endpoints for revoking JWT access tokens:
//! - POST /auth/tokens/revoke — Revoke a specific token by JTI
//! - POST /auth/tokens/revoke-user — Revoke all tokens for a user

use axum::{http::StatusCode, response::IntoResponse, Extension, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::{CreateRevokedToken, RevokedToken};

use crate::services::revocation_cache::RevocationCache;
use crate::services::security_audit::{SecurityAudit, SecurityEventType};

// ── Request/Response models ───────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeTokenRequest {
    /// The JWT ID (jti) of the token to revoke.
    pub jti: String,
    /// Optional reason for revocation.
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeUserTokensRequest {
    /// The user ID whose tokens should be revoked.
    pub user_id: Uuid,
    /// Optional reason for revocation.
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RevocationResponse {
    /// The JTI of the revoked token.
    pub jti: String,
    /// ISO 8601 timestamp of when the token was revoked.
    pub revoked_at: String,
    /// Human-readable status message.
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserRevocationResponse {
    /// The user whose tokens were revoked.
    pub user_id: Uuid,
    /// Number of tokens revoked.
    pub tokens_revoked: i64,
    /// ISO 8601 timestamp of when the tokens were revoked.
    pub revoked_at: String,
    /// Human-readable status message.
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RevocationErrorResponse {
    /// Machine-readable error code.
    pub error: String,
    /// Human-readable error message.
    pub message: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────

/// POST /auth/tokens/revoke
///
/// Revoke a specific JWT access token by its JTI claim.
/// Admins can revoke any token. Users can only revoke their own.
#[utoipa::path(
    post,
    path = "/auth/tokens/revoke",
    request_body = RevokeTokenRequest,
    responses(
        (status = 200, description = "Token revoked successfully", body = RevocationResponse),
        (status = 400, description = "Invalid request (empty JTI or reason too long)", body = RevocationErrorResponse),
        (status = 401, description = "Unauthorized (missing or invalid token)", body = RevocationErrorResponse),
        (status = 403, description = "Non-admin cannot revoke another user's token", body = RevocationErrorResponse),
        (status = 500, description = "Internal server error", body = RevocationErrorResponse),
    ),
    tag = "Token Revocation",
    security(("bearerAuth" = []))
)]
pub async fn revoke_token_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    revocation_cache: Option<Extension<RevocationCache>>,
    Json(body): Json<RevokeTokenRequest>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let tenant_id = claims.tid.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(RevocationErrorResponse {
                error: "missing_tenant".to_string(),
                message: "Missing tenant ID in token".to_string(),
            }),
        )
    })?;

    let caller_user_id = claims.sub.parse::<Uuid>().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(RevocationErrorResponse {
                error: "invalid_token".to_string(),
                message: "Invalid user ID in token".to_string(),
            }),
        )
    })?;

    let is_admin = claims.has_role("admin");

    // Validate JTI is not empty
    if body.jti.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(RevocationErrorResponse {
                error: "invalid_request".to_string(),
                message: "JTI must not be empty".to_string(),
            }),
        ));
    }

    // Validate reason length
    if let Some(ref reason) = body.reason {
        if reason.len() > 255 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(RevocationErrorResponse {
                    error: "invalid_request".to_string(),
                    message: "Reason must be at most 255 characters".to_string(),
                }),
            ));
        }
    }

    // For non-admin users, we can only verify they are revoking their own token
    // by checking if the JTI matches their current token's JTI.
    // Since we can't look up who owns an arbitrary JTI without a separate index,
    // we allow self-revocation by matching the caller's own JTI.
    if !is_admin {
        // Non-admin can only revoke their own current token
        if claims.jti != body.jti {
            return Err((
                StatusCode::FORBIDDEN,
                Json(RevocationErrorResponse {
                    error: "forbidden".to_string(),
                    message: "Non-admin users can only revoke their own token".to_string(),
                }),
            ));
        }
    }

    // Calculate a reasonable expires_at: 15 minutes from now (max access token lifetime).
    // This ensures cleanup even if we don't know the exact expiry.
    let expires_at = Utc::now() + chrono::Duration::minutes(15);

    let input = CreateRevokedToken {
        jti: body.jti.clone(),
        user_id: caller_user_id,
        tenant_id,
        reason: body.reason,
        expires_at,
        revoked_by: Some(caller_user_id),
    };

    let _ = RevokedToken::insert(&pool, input).await.map_err(|e| {
        tracing::error!("Failed to revoke token: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RevocationErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to revoke token".to_string(),
            }),
        )
    })?;

    // F082-US4: Invalidate cache entry so next check immediately rejects
    if let Some(Extension(cache)) = revocation_cache {
        cache.invalidate(&body.jti).await;
    }

    // F082-US8: Emit structured security audit event for token revocation
    SecurityAudit::emit(
        SecurityEventType::TokenRevoked,
        Some(tenant_id),
        Some(caller_user_id),
        None,
        None,
        "success",
        &format!("Token revoked: jti={}", body.jti),
    );

    Ok((
        StatusCode::OK,
        Json(RevocationResponse {
            jti: body.jti,
            revoked_at: Utc::now().to_rfc3339(),
            message: "Token revoked successfully".to_string(),
        }),
    ))
}

/// POST /auth/tokens/revoke-user
///
/// Revoke all active tokens for a user ("sign out everywhere").
/// Admins can revoke any user's tokens. Users can only revoke their own.
#[utoipa::path(
    post,
    path = "/auth/tokens/revoke-user",
    request_body = RevokeUserTokensRequest,
    responses(
        (status = 200, description = "All user tokens revoked successfully", body = UserRevocationResponse),
        (status = 401, description = "Unauthorized (missing or invalid token)", body = RevocationErrorResponse),
        (status = 403, description = "Non-admin cannot revoke another user's tokens", body = RevocationErrorResponse),
        (status = 500, description = "Internal server error", body = RevocationErrorResponse),
    ),
    tag = "Token Revocation",
    security(("bearerAuth" = []))
)]
pub async fn revoke_user_tokens_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    revocation_cache: Option<Extension<RevocationCache>>,
    Json(body): Json<RevokeUserTokensRequest>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let tenant_id = claims.tid.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(RevocationErrorResponse {
                error: "missing_tenant".to_string(),
                message: "Missing tenant ID in token".to_string(),
            }),
        )
    })?;

    let caller_user_id = claims.sub.parse::<Uuid>().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(RevocationErrorResponse {
                error: "invalid_token".to_string(),
                message: "Invalid user ID in token".to_string(),
            }),
        )
    })?;

    let is_admin = claims.has_role("admin");

    // Non-admin can only revoke their own tokens
    if !is_admin && body.user_id != caller_user_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(RevocationErrorResponse {
                error: "forbidden".to_string(),
                message: "Non-admin users can only revoke their own tokens".to_string(),
            }),
        ));
    }

    // We mark the user's existing tokens as revoked by inserting a special
    // "all-user-tokens" marker. The JWT auth middleware will check for this.
    // For revoke-all, we insert a single record with a sentinel JTI.
    let all_jti = format!("revoke-all:{}:{}", body.user_id, Utc::now().timestamp());
    let all_jti_clone = all_jti.clone();
    let expires_at = Utc::now() + chrono::Duration::minutes(15);

    let input = CreateRevokedToken {
        jti: all_jti,
        user_id: body.user_id,
        tenant_id,
        reason: body
            .reason
            .clone()
            .or_else(|| Some("logout_all".to_string())),
        expires_at,
        revoked_by: Some(caller_user_id),
    };

    let _ = RevokedToken::insert(&pool, input).await.map_err(|e| {
        tracing::error!("Failed to revoke user tokens: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RevocationErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to revoke tokens".to_string(),
            }),
        )
    })?;

    // F082-US4: Invalidate cache entry for the revoke-all sentinel
    if let Some(Extension(ref cache)) = revocation_cache {
        cache.invalidate(&all_jti_clone).await;
    }

    // Also revoke all refresh tokens for the user
    let refresh_revoked = sqlx::query(
        r#"
        UPDATE refresh_tokens
        SET revoked_at = NOW()
        WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL
        "#,
    )
    .bind(tenant_id)
    .bind(body.user_id)
    .execute(&pool)
    .await
    .map(|r| r.rows_affected() as i64)
    .unwrap_or(0);

    let tokens_revoked = refresh_revoked + 1; // +1 for the access token marker

    Ok((
        StatusCode::OK,
        Json(UserRevocationResponse {
            user_id: body.user_id,
            tokens_revoked,
            revoked_at: Utc::now().to_rfc3339(),
            message: "All user tokens revoked successfully".to_string(),
        }),
    ))
}

/// Create the revocation router.
pub fn revocation_router() -> axum::Router {
    use axum::routing::post;
    axum::Router::new()
        .route("/revoke", post(revoke_token_handler))
        .route("/revoke-user", post(revoke_user_tokens_handler))
}
