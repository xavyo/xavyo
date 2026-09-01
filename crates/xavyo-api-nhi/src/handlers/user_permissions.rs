//! User-to-NHI permission management handlers.
//!
//! Provides endpoints for user-to-NHI permission grants:
//! - `POST /{id}/users/{user_id}/grant` — Grant user permission
//! - `POST /{id}/users/{user_id}/revoke` — Revoke user permission
//! - `GET /{id}/users` — List users with access to an NHI
//! - `GET /users/{user_id}/accessible` — List NHIs accessible by a user

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_db::models::nhi_user_permission::NhiUserPermission;

use crate::error::NhiApiError;
use crate::services::nhi_user_permission_service::NhiUserPermissionService;
use crate::state::NhiState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GrantUserPermissionRequest {
    pub permission_type: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeUserPermissionRequest {
    pub permission_type: String,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct PaginationQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Filter by permission type (`use`, `manage`, or `admin`).
    pub permission_type: Option<String>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PaginatedUserPermissionResponse {
    pub data: Vec<NhiUserPermission>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeResponse {
    pub revoked: bool,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /{id}/users/{user_id}/grant — Grant a user permission to access an NHI.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/{id}/users/{user_id}/grant",
    params(
        ("id" = Uuid, Path, description = "NHI identity ID"),
        ("user_id" = Uuid, Path, description = "User ID"),
    ),
    request_body = GrantUserPermissionRequest,
    responses(
        (status = 201, description = "Permission granted", body = NhiUserPermission),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "NHI not found"),
    ),
    tag = "NHI User Permissions"
))]
pub async fn grant_user_permission(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path((nhi_id, user_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<GrantUserPermissionRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") && !claims.has_role("super_admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let granted_by = Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?;

    let perm = NhiUserPermissionService::grant(
        &state.pool,
        tenant_uuid,
        user_id,
        nhi_id,
        &request.permission_type,
        granted_by,
        request.expires_at,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(perm)))
}

/// POST /{id}/users/{user_id}/revoke — Revoke a user's permission on an NHI.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/{id}/users/{user_id}/revoke",
    params(
        ("id" = Uuid, Path, description = "NHI identity ID"),
        ("user_id" = Uuid, Path, description = "User ID"),
    ),
    request_body = RevokeUserPermissionRequest,
    responses(
        (status = 200, description = "Permission revoked", body = RevokeResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "NHI not found"),
    ),
    tag = "NHI User Permissions"
))]
pub async fn revoke_user_permission(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path((nhi_id, user_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<RevokeUserPermissionRequest>,
) -> Result<Json<RevokeResponse>, NhiApiError> {
    if !claims.has_role("admin") && !claims.has_role("super_admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();

    let revoked = NhiUserPermissionService::revoke(
        &state.pool,
        tenant_uuid,
        user_id,
        nhi_id,
        &request.permission_type,
    )
    .await?;

    Ok(Json(RevokeResponse { revoked }))
}

/// GET /{id}/users — List users with permissions on a specific NHI.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/{id}/users",
    params(
        ("id" = Uuid, Path, description = "NHI identity ID"),
        PaginationQuery,
    ),
    responses(
        (status = 200, description = "Paginated list of user permissions", body = PaginatedUserPermissionResponse),
        (status = 403, description = "Forbidden"),
    ),
    tag = "NHI User Permissions"
))]
pub async fn list_nhi_users(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(nhi_id): Path<Uuid>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedUserPermissionResponse>, NhiApiError> {
    if !claims.has_role("admin") && !claims.has_role("super_admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);
    let permission_type = parse_optional_user_permission_type(query.permission_type.as_deref())?;

    let data = NhiUserPermissionService::list_by_nhi(
        &state.pool,
        tenant_uuid,
        nhi_id,
        permission_type,
        limit,
        offset,
    )
    .await?;

    Ok(Json(PaginatedUserPermissionResponse {
        data,
        limit,
        offset,
    }))
}

/// GET /users/{user_id}/accessible — List NHIs accessible by a specific user.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/users/{user_id}/accessible",
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
        PaginationQuery,
    ),
    responses(
        (status = 200, description = "Paginated list of accessible NHIs", body = PaginatedUserPermissionResponse),
        (status = 403, description = "Forbidden"),
    ),
    tag = "NHI User Permissions"
))]
pub async fn list_user_nhis(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedUserPermissionResponse>, NhiApiError> {
    // Allow admin/super_admin or the user themselves
    let caller_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?;

    if !claims.has_role("admin") && !claims.has_role("super_admin") && caller_id != user_id {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);
    let permission_type = parse_optional_user_permission_type(query.permission_type.as_deref())?;

    let data = NhiUserPermissionService::list_by_user(
        &state.pool,
        tenant_uuid,
        user_id,
        permission_type,
        limit,
        offset,
    )
    .await?;

    Ok(Json(PaginatedUserPermissionResponse {
        data,
        limit,
        offset,
    }))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Invalid permission-type filters must not silently list every grant.
fn parse_optional_user_permission_type(value: Option<&str>) -> Result<Option<&str>, NhiApiError> {
    match value {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) if matches!(s, "use" | "manage" | "admin") => Ok(Some(s)),
        Some(s) => Err(NhiApiError::BadRequest(format!(
            "Invalid permission_type '{s}'. Must be one of: use, manage, admin"
        ))),
    }
}

pub fn user_permission_routes(state: NhiState) -> Router {
    Router::new()
        // Grant/revoke: admin-only mutation endpoints
        // NOTE: Must use /:id (not /:nhi_id) to match the param name used by other
        // merged NHI routers (unified, lifecycle, risk, etc.). Axum requires all
        // routes sharing the same trie position to use the same parameter name.
        .route("/:id/users/:user_id/grant", post(grant_user_permission))
        .route("/:id/users/:user_id/revoke", post(revoke_user_permission))
        // List: admin-only or self
        .route("/:id/users", get(list_nhi_users))
        .route("/users/:user_id/accessible", get(list_user_nhis))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_permission_lists_honor_permission_type() {
        let src = include_str!("user_permissions.rs");
        let production = src.split("mod tests").next().expect("production source");
        for fn_name in ["list_nhi_users", "list_user_nhis"] {
            let body = production
                .split(&format!("pub async fn {fn_name}"))
                .nth(1)
                .and_then(|s| s.split("pub async fn ").next())
                .unwrap_or_else(|| panic!("{fn_name}"));
            assert!(
                body.contains("permission_type")
                    && body.contains("parse_optional_user_permission_type("),
                "{fn_name} must honor advertised permission_type"
            );
        }
    }

    #[test]
    fn invalid_permission_type_does_not_list_all_grants() {
        assert_eq!(parse_optional_user_permission_type(None).unwrap(), None);
        assert_eq!(
            parse_optional_user_permission_type(Some("use")).unwrap(),
            Some("use")
        );
        assert!(parse_optional_user_permission_type(Some("bogus")).is_err());
    }
}
