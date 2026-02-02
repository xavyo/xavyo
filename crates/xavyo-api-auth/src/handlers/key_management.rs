//! Key management admin handlers (F082-US5).
//!
//! Provides endpoints for JWT signing key lifecycle management:
//! - POST /admin/keys/rotate — Generate a new key, retire the current one
//! - DELETE /admin/keys/:kid — Revoke a retiring key
//! - GET /admin/keys — List all keys for the tenant

use axum::{extract::Path, http::StatusCode, response::IntoResponse, Extension, Json};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::services::key_service::{KeyService, KeyServiceError};
use crate::services::security_audit::{SecurityAudit, SecurityEventType};

// ── Response models ──────────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct KeyInfo {
    pub kid: String,
    pub algorithm: String,
    pub state: String,
    pub created_at: String,
    pub rotated_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RotateKeyResponse {
    pub new_key: KeyInfo,
    pub retired_key: Option<KeyInfo>,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListKeysResponse {
    pub keys: Vec<KeyInfo>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct KeyErrorResponse {
    pub error: String,
    pub message: String,
}

// ── Handlers ─────────────────────────────────────────────────────────────

/// POST /admin/keys/rotate
///
/// Generate a new signing key and retire the current active key.
/// Requires admin role.
#[utoipa::path(
    post,
    path = "/admin/keys/rotate",
    responses(
        (status = 200, description = "Key rotated successfully", body = RotateKeyResponse),
        (status = 401, description = "Unauthorized", body = KeyErrorResponse),
        (status = 403, description = "Forbidden (admin only)", body = KeyErrorResponse),
        (status = 500, description = "Internal server error", body = KeyErrorResponse),
    ),
    tag = "Key Management",
    security(("bearerAuth" = []))
)]
pub async fn rotate_key_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(key_service): Extension<KeyService>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = extract_user_id(&claims)?;
    require_admin(&claims)?;

    match key_service.rotate_key(tenant_id, Some(user_id)).await {
        Ok((new_key, old_key)) => {
            // F082-US8: Emit security audit event
            SecurityAudit::emit(
                SecurityEventType::KeyRotated,
                Some(tenant_id),
                Some(user_id),
                None,
                None,
                "success",
                &format!(
                    "New key: {}, retired: {:?}",
                    new_key.kid,
                    old_key.as_ref().map(|k| &k.kid)
                ),
            );

            Ok((
                StatusCode::OK,
                Json(RotateKeyResponse {
                    new_key: key_to_info(&new_key),
                    retired_key: old_key.as_ref().map(key_to_info),
                    message: "Key rotated successfully".to_string(),
                }),
            ))
        }
        Err(e) => {
            tracing::error!(error = %e, "Key rotation failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(KeyErrorResponse {
                    error: "rotation_failed".to_string(),
                    message: format!("Key rotation failed: {e}"),
                }),
            ))
        }
    }
}

/// DELETE /admin/keys/:kid
///
/// Revoke a retiring key (remove from JWKS).
/// Only retiring keys can be revoked; active keys must be rotated first.
#[utoipa::path(
    delete,
    path = "/admin/keys/{kid}",
    params(("kid" = String, Path, description = "Key ID to revoke")),
    responses(
        (status = 200, description = "Key revoked successfully"),
        (status = 400, description = "Cannot revoke active key", body = KeyErrorResponse),
        (status = 404, description = "Key not found", body = KeyErrorResponse),
        (status = 500, description = "Internal server error", body = KeyErrorResponse),
    ),
    tag = "Key Management",
    security(("bearerAuth" = []))
)]
pub async fn revoke_key_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(key_service): Extension<KeyService>,
    Path(kid): Path<String>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = extract_user_id(&claims)?;
    require_admin(&claims)?;

    match key_service.revoke_key(tenant_id, &kid).await {
        Ok(()) => {
            // F082-US8: Emit security audit event
            SecurityAudit::emit(
                SecurityEventType::KeyRevoked,
                Some(tenant_id),
                Some(user_id),
                None,
                None,
                "success",
                &format!("Revoked key: {kid}"),
            );

            Ok((
                StatusCode::OK,
                Json(serde_json::json!({
                    "message": "Key revoked successfully",
                    "kid": kid,
                })),
            ))
        }
        Err(KeyServiceError::NotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(KeyErrorResponse {
                error: "not_found".to_string(),
                message: "Key not found".to_string(),
            }),
        )),
        Err(KeyServiceError::CannotRevokeActive) => Err((
            StatusCode::BAD_REQUEST,
            Json(KeyErrorResponse {
                error: "cannot_revoke_active".to_string(),
                message: "Cannot revoke active key — rotate first".to_string(),
            }),
        )),
        Err(KeyServiceError::AlreadyRevoked) => Err((
            StatusCode::BAD_REQUEST,
            Json(KeyErrorResponse {
                error: "already_revoked".to_string(),
                message: "Key is already revoked".to_string(),
            }),
        )),
        Err(e) => {
            tracing::error!(error = %e, kid = %kid, "Key revocation failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(KeyErrorResponse {
                    error: "revocation_failed".to_string(),
                    message: format!("Key revocation failed: {e}"),
                }),
            ))
        }
    }
}

/// GET /admin/keys
///
/// List all signing keys for the tenant.
#[utoipa::path(
    get,
    path = "/admin/keys",
    responses(
        (status = 200, description = "List of signing keys", body = ListKeysResponse),
        (status = 401, description = "Unauthorized", body = KeyErrorResponse),
        (status = 500, description = "Internal server error", body = KeyErrorResponse),
    ),
    tag = "Key Management",
    security(("bearerAuth" = []))
)]
pub async fn list_keys_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(key_service): Extension<KeyService>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let tenant_id = extract_tenant_id(&claims)?;
    require_admin(&claims)?;

    match key_service.list_keys(tenant_id).await {
        Ok(keys) => {
            let key_infos: Vec<KeyInfo> = keys.iter().map(key_to_info).collect();
            Ok((StatusCode::OK, Json(ListKeysResponse { keys: key_infos })))
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list keys");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(KeyErrorResponse {
                    error: "list_failed".to_string(),
                    message: "Failed to list keys".to_string(),
                }),
            ))
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn key_to_info(key: &xavyo_db::models::SigningKey) -> KeyInfo {
    KeyInfo {
        kid: key.kid.clone(),
        algorithm: key.algorithm.clone(),
        state: key.state.clone(),
        created_at: key.created_at.to_rfc3339(),
        rotated_at: key.rotated_at.map(|t| t.to_rfc3339()),
        revoked_at: key.revoked_at.map(|t| t.to_rfc3339()),
    }
}

fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, (StatusCode, Json<KeyErrorResponse>)> {
    claims.tid.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(KeyErrorResponse {
                error: "missing_tenant".to_string(),
                message: "Missing tenant ID in token".to_string(),
            }),
        )
    })
}

fn extract_user_id(claims: &JwtClaims) -> Result<Uuid, (StatusCode, Json<KeyErrorResponse>)> {
    claims.sub.parse::<Uuid>().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(KeyErrorResponse {
                error: "invalid_token".to_string(),
                message: "Invalid user ID in token".to_string(),
            }),
        )
    })
}

fn require_admin(claims: &JwtClaims) -> Result<(), (StatusCode, Json<KeyErrorResponse>)> {
    if !claims.has_role("admin") {
        return Err((
            StatusCode::FORBIDDEN,
            Json(KeyErrorResponse {
                error: "forbidden".to_string(),
                message: "Admin role required".to_string(),
            }),
        ));
    }
    Ok(())
}
