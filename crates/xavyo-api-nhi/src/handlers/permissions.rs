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

use sqlx;

use crate::error::NhiApiError;
use crate::services::nhi_permission_service::NhiPermissionService;
use crate::state::NhiState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GrantPermissionRequest {
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct PaginationQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", aliases(
    PaginatedNhiToolPermissionResponse = PaginatedResponse<NhiToolPermission>,
))]
pub struct PaginatedResponse<T: Serialize> {
    pub data: Vec<T>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeResponse {
    pub revoked: bool,
}

/// Request to grant tool permissions in bulk.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BulkGrantRequest {
    /// Up to 100 tool NHI IDs to grant.
    pub tool_ids: Vec<Uuid>,
    /// Optional expiration for all grants.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Result of a single grant within a bulk operation.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BulkGrantResult {
    pub tool_id: Uuid,
    pub tool_name: Option<String>,
    pub permission_id: Option<Uuid>,
    pub error: Option<String>,
}

/// Response from bulk grant operation.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BulkGrantResponse {
    pub granted: Vec<BulkGrantResult>,
}

/// Request to grant all tools from an MCP server.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GrantByServerRequest {
    /// MCP server name (matches `nhi_tools.provider` field).
    pub server_name: String,
    /// Optional expiration for all grants.
    pub expires_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /agents/{agent_id}/tools/{tool_id}/grant — Grant an agent permission to use a tool.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/agents/{agent_id}/tools/{tool_id}/grant",
    tag = "NHI Permissions",
    operation_id = "grantNhiToolPermission",
    params(
        ("agent_id" = Uuid, Path, description = "Agent NHI ID"),
        ("tool_id" = Uuid, Path, description = "Tool NHI ID")
    ),
    request_body = GrantPermissionRequest,
    responses(
        (status = 201, description = "Permission granted", body = NhiToolPermission),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Agent or tool not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn grant_permission(
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
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/agents/{agent_id}/tools/{tool_id}/revoke",
    tag = "NHI Permissions",
    operation_id = "revokeNhiToolPermission",
    params(
        ("agent_id" = Uuid, Path, description = "Agent NHI ID"),
        ("tool_id" = Uuid, Path, description = "Tool NHI ID")
    ),
    responses(
        (status = 200, description = "Permission revoked", body = RevokeResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden")
    ),
    security(("bearerAuth" = []))
))]
pub async fn revoke_permission(
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
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/agents/{agent_id}/tools",
    tag = "NHI Permissions",
    operation_id = "listNhiAgentTools",
    params(
        ("agent_id" = Uuid, Path, description = "Agent NHI ID"),
        PaginationQuery
    ),
    responses(
        (status = 200, description = "List of tool permissions", body = PaginatedNhiToolPermissionResponse),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_agent_tools(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<NhiToolPermission>>, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
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
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/tools/{tool_id}/agents",
    tag = "NHI Permissions",
    operation_id = "listNhiToolAgents",
    params(
        ("tool_id" = Uuid, Path, description = "Tool NHI ID"),
        PaginationQuery
    ),
    responses(
        (status = 200, description = "List of agent permissions", body = PaginatedNhiToolPermissionResponse),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_tool_agents(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(tool_id): Path<Uuid>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<NhiToolPermission>>, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
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

/// POST /agents/{agent_id}/tools/bulk-grant — Grant permissions for multiple tools at once.
///
/// Individual failures don't block the batch — each result reports success or error.
pub async fn bulk_grant_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
    Json(request): Json<BulkGrantRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    if request.tool_ids.is_empty() {
        return Err(NhiApiError::BadRequest("tool_ids must not be empty".into()));
    }
    if request.tool_ids.len() > 100 {
        return Err(NhiApiError::BadRequest(
            "Maximum 100 tools per bulk-grant request".into(),
        ));
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?;

    let mut results = Vec::with_capacity(request.tool_ids.len());

    for tool_id in &request.tool_ids {
        match NhiPermissionService::grant(
            &state.pool,
            tenant_uuid,
            agent_id,
            *tool_id,
            user_id,
            request.expires_at,
        )
        .await
        {
            Ok(perm) => results.push(BulkGrantResult {
                tool_id: *tool_id,
                tool_name: None,
                permission_id: Some(perm.id),
                error: None,
            }),
            Err(e) => results.push(BulkGrantResult {
                tool_id: *tool_id,
                tool_name: None,
                permission_id: None,
                error: Some(e.to_string()),
            }),
        }
    }

    Ok((StatusCode::OK, Json(BulkGrantResponse { granted: results })))
}

/// POST /agents/{agent_id}/tools/grant-by-server — Grant all MCP tools from a server.
///
/// Looks up tools where `nhi_tools.provider = server_name AND category = 'mcp'`
/// for the tenant, then bulk-grants them to the agent.
pub async fn grant_by_server_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
    Json(request): Json<GrantByServerRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    if request.server_name.trim().is_empty() {
        return Err(NhiApiError::BadRequest(
            "server_name must not be empty".into(),
        ));
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?;

    // Look up all MCP tools from this server
    let tools: Vec<(Uuid, String)> = sqlx::query_as(
        r"
        SELECT i.id, i.name
        FROM nhi_identities i
        INNER JOIN nhi_tools t ON t.nhi_id = i.id
        WHERE i.tenant_id = $1
          AND t.provider = $2
          AND t.category = 'mcp'
          AND i.lifecycle_state = 'active'
        ",
    )
    .bind(tenant_uuid)
    .bind(&request.server_name)
    .fetch_all(&state.pool)
    .await
    .map_err(NhiApiError::Database)?;

    let mut results = Vec::with_capacity(tools.len());

    for (tool_id, tool_name) in &tools {
        match NhiPermissionService::grant(
            &state.pool,
            tenant_uuid,
            agent_id,
            *tool_id,
            user_id,
            request.expires_at,
        )
        .await
        {
            Ok(perm) => results.push(BulkGrantResult {
                tool_id: *tool_id,
                tool_name: Some(tool_name.clone()),
                permission_id: Some(perm.id),
                error: None,
            }),
            Err(e) => results.push(BulkGrantResult {
                tool_id: *tool_id,
                tool_name: Some(tool_name.clone()),
                permission_id: None,
                error: Some(e.to_string()),
            }),
        }
    }

    Ok((StatusCode::OK, Json(BulkGrantResponse { granted: results })))
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
        // Bulk grant endpoints
        .route(
            "/agents/:agent_id/tools/bulk-grant",
            post(bulk_grant_handler),
        )
        .route(
            "/agents/:agent_id/tools/grant-by-server",
            post(grant_by_server_handler),
        )
        // List: read-only, tenant-scoped
        .route("/agents/:agent_id/tools", get(list_agent_tools))
        .route("/tools/:tool_id/agents", get(list_tool_agents))
        .with_state(state)
}
