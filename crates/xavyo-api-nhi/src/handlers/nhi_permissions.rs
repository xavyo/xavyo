//! NHI-to-NHI permission management handlers.
//!
//! Provides endpoints for NHI-to-NHI calling/delegation permission grants:
//! - `POST /{source_id}/call/{target_id}/grant` — Grant calling permission
//! - `POST /{source_id}/call/{target_id}/revoke` — Revoke calling permission
//! - `GET /{nhi_id}/callers` — List NHIs with calling permission TO this NHI
//! - `GET /{nhi_id}/callees` — List NHIs this NHI has calling permission FOR

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
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PaginatedNhiPermissionResponse {
    pub data: Vec<NhiNhiPermission>,
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

/// POST /{source_id}/call/{target_id}/grant — Grant NHI calling permission.
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

/// POST /{source_id}/call/{target_id}/revoke — Revoke NHI calling permission.
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

/// GET /{nhi_id}/callers — List NHIs with calling permission TO this NHI.
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

    let data =
        NhiNhiPermissionService::list_callers(&state.pool, tenant_uuid, nhi_id, limit, offset)
            .await?;

    Ok(Json(PaginatedNhiPermissionResponse {
        data,
        limit,
        offset,
    }))
}

/// GET /{nhi_id}/callees — List NHIs this NHI has calling permission FOR.
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

    let data =
        NhiNhiPermissionService::list_callees(&state.pool, tenant_uuid, nhi_id, limit, offset)
            .await?;

    Ok(Json(PaginatedNhiPermissionResponse {
        data,
        limit,
        offset,
    }))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn nhi_nhi_permission_routes(state: NhiState) -> Router {
    Router::new()
        // Grant/revoke: admin-only mutation endpoints
        .route(
            "/:source_id/call/:target_id/grant",
            post(grant_nhi_permission),
        )
        .route(
            "/:source_id/call/:target_id/revoke",
            post(revoke_nhi_permission),
        )
        // List: admin-only
        .route("/:nhi_id/callers", get(list_callers))
        .route("/:nhi_id/callees", get(list_callees))
        .with_state(state)
}
