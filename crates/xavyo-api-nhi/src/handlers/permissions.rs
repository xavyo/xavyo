//! Tool permission management handlers.
//!
//! Provides endpoints for agent-to-tool permission grants:
//! - `POST /agents/{agent_id}/tools/{tool_id}/grant` — Grant tool permission
//! - `POST /agents/{agent_id}/tools/{tool_id}/revoke` — Revoke tool permission
//! - `GET /agents/{agent_id}/tools` — List tools agent has permission to use
//! - `GET /tools/{tool_id}/agents` — List agents with permission to a tool

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
use xavyo_db::models::nhi_tool_permission::NhiToolPermission;

use crate::error::NhiApiError;
use crate::services::nhi_permission_service::NhiPermissionService;
use crate::state::NhiState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct GrantPermissionRequest {
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub data: Vec<T>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Serialize)]
pub struct RevokeResponse {
    pub revoked: bool,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /agents/{agent_id}/tools/{tool_id}/grant — Grant an agent permission to use a tool.
async fn grant_permission(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path((agent_id, tool_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<GrantPermissionRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?;

    let perm = NhiPermissionService::grant(
        &state.pool,
        tenant_uuid,
        agent_id,
        tool_id,
        user_id,
        request.expires_at,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(perm)))
}

/// POST /agents/{agent_id}/tools/{tool_id}/revoke — Revoke an agent's permission to use a tool.
async fn revoke_permission(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path((agent_id, tool_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RevokeResponse>, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();

    let revoked = NhiPermissionService::revoke(&state.pool, tenant_uuid, agent_id, tool_id).await?;

    Ok(Json(RevokeResponse { revoked }))
}

/// GET /agents/{agent_id}/tools — List tools an agent has permission to use.
async fn list_agent_tools(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Path(agent_id): Path<Uuid>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<NhiToolPermission>>, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);

    let data =
        NhiPermissionService::list_agent_tools(&state.pool, tenant_uuid, agent_id, limit, offset)
            .await?;

    Ok(Json(PaginatedResponse {
        data,
        limit,
        offset,
    }))
}

/// GET /tools/{tool_id}/agents — List agents with permission to use a tool.
async fn list_tool_agents(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Path(tool_id): Path<Uuid>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<NhiToolPermission>>, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);

    let data =
        NhiPermissionService::list_tool_agents(&state.pool, tenant_uuid, tool_id, limit, offset)
            .await?;

    Ok(Json(PaginatedResponse {
        data,
        limit,
        offset,
    }))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn permission_routes(state: NhiState) -> Router {
    Router::new()
        // Grant/revoke: admin-only mutation endpoints
        .route(
            "/agents/:agent_id/tools/:tool_id/grant",
            post(grant_permission),
        )
        .route(
            "/agents/:agent_id/tools/:tool_id/revoke",
            post(revoke_permission),
        )
        // List: read-only, tenant-scoped
        .route("/agents/:agent_id/tools", get(list_agent_tools))
        .route("/tools/:tool_id/agents", get(list_tool_agents))
        .with_state(state)
}
