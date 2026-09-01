//! NHI-to-NHI permission management handlers.
//!
//! Provides endpoints for NHI-to-NHI calling/delegation permission grants:
//! - `POST /{id}/call/{target_id}/grant` — Grant calling permission
//! - `POST /{id}/call/{target_id}/revoke` — Revoke calling permission
//! - `GET /{id}/callers` — List NHIs with calling permission TO this NHI
//! - `GET /{id}/callees` — List NHIs this NHI has calling permission FOR

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
use xavyo_db::models::nhi_nhi_permission::NhiNhiPermission;

use crate::error::NhiApiError;
use crate::services::nhi_nhi_permission_service::NhiNhiPermissionService;
use crate::state::NhiState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GrantNhiPermissionRequest {
    pub permission_type: String,
    pub allowed_actions: Option<serde_json::Value>,
    pub max_calls_per_hour: Option<i32>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeNhiPermissionRequest {
    pub permission_type: String,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct PaginationQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Filter by permission type (`call` or `delegate`).
    pub permission_type: Option<String>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PaginatedNhiPermissionResponse {
    pub data: Vec<NhiNhiPermission>,
    pub total: i64,
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

/// POST /{id}/call/{target_id}/grant — Grant NHI calling permission.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/{id}/call/{target_id}/grant",
    params(
        ("id" = Uuid, Path, description = "Source NHI identity ID"),
        ("target_id" = Uuid, Path, description = "Target NHI identity ID"),
    ),
    request_body = GrantNhiPermissionRequest,
    responses(
        (status = 201, description = "NHI calling permission granted", body = NhiNhiPermission),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "NHI not found"),
    ),
    tag = "NHI Permissions"
))]
pub async fn grant_nhi_permission(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path((source_id, target_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<GrantNhiPermissionRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") && !claims.has_role("super_admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let granted_by = Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?;

    let perm = NhiNhiPermissionService::grant(
        &state.pool,
        tenant_uuid,
        source_id,
        target_id,
        &request.permission_type,
        request.allowed_actions,
        request.max_calls_per_hour,
        granted_by,
        request.expires_at,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(perm)))
}

/// POST /{id}/call/{target_id}/revoke — Revoke NHI calling permission.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/{id}/call/{target_id}/revoke",
    params(
        ("id" = Uuid, Path, description = "Source NHI identity ID"),
        ("target_id" = Uuid, Path, description = "Target NHI identity ID"),
    ),
    request_body = RevokeNhiPermissionRequest,
    responses(
        (status = 200, description = "NHI calling permission revoked", body = RevokeResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "NHI not found"),
    ),
    tag = "NHI Permissions"
))]
pub async fn revoke_nhi_permission(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path((source_id, target_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<RevokeNhiPermissionRequest>,
) -> Result<Json<RevokeResponse>, NhiApiError> {
    if !claims.has_role("admin") && !claims.has_role("super_admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();

    let revoked = NhiNhiPermissionService::revoke(
        &state.pool,
        tenant_uuid,
        source_id,
        target_id,
        &request.permission_type,
    )
    .await?;

    Ok(Json(RevokeResponse { revoked }))
}

/// GET /{id}/callers — List NHIs with calling permission TO this NHI.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/{id}/callers",
    params(
        ("id" = Uuid, Path, description = "NHI identity ID"),
        PaginationQuery,
    ),
    responses(
        (status = 200, description = "Paginated list of caller NHIs", body = PaginatedNhiPermissionResponse),
        (status = 403, description = "Forbidden"),
    ),
    tag = "NHI Permissions"
))]
pub async fn list_callers(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(nhi_id): Path<Uuid>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedNhiPermissionResponse>, NhiApiError> {
    if !claims.has_role("admin") && !claims.has_role("super_admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);
    let permission_type = parse_optional_nhi_nhi_permission_type(query.permission_type.as_deref())?;

    let data = NhiNhiPermissionService::list_callers(
        &state.pool,
        tenant_uuid,
        nhi_id,
        permission_type,
        limit,
        offset,
    )
    .await?;
    let total =
        NhiNhiPermissionService::count_callers(&state.pool, tenant_uuid, nhi_id, permission_type)
            .await?;

    Ok(Json(PaginatedNhiPermissionResponse {
        data,
        total,
        limit,
        offset,
    }))
}

/// GET /{id}/callees — List NHIs this NHI has calling permission FOR.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/{id}/callees",
    params(
        ("id" = Uuid, Path, description = "NHI identity ID"),
        PaginationQuery,
    ),
    responses(
        (status = 200, description = "Paginated list of callee NHIs", body = PaginatedNhiPermissionResponse),
        (status = 403, description = "Forbidden"),
    ),
    tag = "NHI Permissions"
))]
pub async fn list_callees(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(nhi_id): Path<Uuid>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedNhiPermissionResponse>, NhiApiError> {
    if !claims.has_role("admin") && !claims.has_role("super_admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);
    let permission_type = parse_optional_nhi_nhi_permission_type(query.permission_type.as_deref())?;

    let data = NhiNhiPermissionService::list_callees(
        &state.pool,
        tenant_uuid,
        nhi_id,
        permission_type,
        limit,
        offset,
    )
    .await?;
    let total =
        NhiNhiPermissionService::count_callees(&state.pool, tenant_uuid, nhi_id, permission_type)
            .await?;

    Ok(Json(PaginatedNhiPermissionResponse {
        data,
        total,
        limit,
        offset,
    }))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Invalid permission-type filters must not silently list every grant.
fn parse_optional_nhi_nhi_permission_type(
    value: Option<&str>,
) -> Result<Option<&str>, NhiApiError> {
    match value {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) if matches!(s, "call" | "delegate") => Ok(Some(s)),
        Some(s) => Err(NhiApiError::BadRequest(format!(
            "Invalid permission_type '{s}'. Must be one of: call, delegate"
        ))),
    }
}

pub fn nhi_nhi_permission_routes(state: NhiState) -> Router {
    Router::new()
        // Grant/revoke: admin-only mutation endpoints
        // NOTE: Must use /:id (not /:source_id) to match the param name used by other
        // merged NHI routers (unified, lifecycle, risk, etc.). Axum requires all
        // routes sharing the same trie position to use the same parameter name.
        .route("/:id/call/:target_id/grant", post(grant_nhi_permission))
        .route("/:id/call/:target_id/revoke", post(revoke_nhi_permission))
        // List: admin-only
        .route("/:id/callers", get(list_callers))
        .route("/:id/callees", get(list_callees))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_and_callee_lists_honor_permission_type() {
        let src = include_str!("nhi_permissions.rs");
        let production = src.split("mod tests").next().expect("production source");
        for (fn_name, count_fn) in [
            ("list_callers", "count_callers"),
            ("list_callees", "count_callees"),
        ] {
            let body = production
                .split(&format!("pub async fn {fn_name}"))
                .nth(1)
                .and_then(|s| s.split("pub async fn ").next())
                .unwrap_or_else(|| panic!("{fn_name}"));
            assert!(
                body.contains(&format!("{count_fn}("))
                    && body.contains("total,")
                    && body.contains("permission_type")
                    && body.contains("parse_optional_nhi_nhi_permission_type("),
                "{fn_name} must honor advertised permission_type and report a COUNT total"
            );
        }
    }

    #[test]
    fn invalid_permission_type_does_not_list_all_grants() {
        assert_eq!(parse_optional_nhi_nhi_permission_type(None).unwrap(), None);
        assert_eq!(
            parse_optional_nhi_nhi_permission_type(Some("call")).unwrap(),
            Some("call")
        );
        assert!(parse_optional_nhi_nhi_permission_type(Some("bogus")).is_err());
    }
}
