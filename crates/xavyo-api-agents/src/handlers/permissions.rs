//! Permission management handlers.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::{GrantPermissionRequest, ListPermissionsQuery, PermissionListResponse};
use crate::router::AgentsState;
use xavyo_auth::JwtClaims;

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenant)
}

/// Extract `user_id` from JWT claims.
fn extract_user_id(claims: &JwtClaims) -> Option<Uuid> {
    claims.sub.parse().ok()
}

/// POST /agents/{id}/permissions - Grant permission to agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/agents/{id}/permissions",
    tag = "AI Agent Permissions",
    operation_id = "grantPermission",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    request_body = GrantPermissionRequest,
    responses(
        (status = 201, description = "Permission granted", body = PermissionResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent or tool not found"),
        (status = 409, description = "Permission already exists")
    ),
    security(("bearerAuth" = []))
))]
pub async fn grant_permission(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
    Json(request): Json<GrantPermissionRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let granted_by = extract_user_id(&claims);

    let permission = state
        .permission_service
        .grant(tenant_id, agent_id, request, granted_by)
        .await?;

    Ok((StatusCode::CREATED, Json(permission)))
}

/// GET /agents/{id}/permissions - List agent permissions.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/agents/{id}/permissions",
    tag = "AI Agent Permissions",
    operation_id = "listAgentPermissions",
    params(
        ("id" = Uuid, Path, description = "Agent ID"),
        ListPermissionsQuery
    ),
    responses(
        (status = 200, description = "List of permissions", body = PermissionListResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_permissions(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
    Query(query): Query<ListPermissionsQuery>,
) -> Result<Json<PermissionListResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state
        .permission_service
        .list_by_agent(tenant_id, agent_id, query.limit, query.offset)
        .await?;

    Ok(Json(response))
}

/// DELETE /`agents/{id}/permissions/{tool_id`} - Revoke permission.
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/agents/{id}/permissions/{tool_id}",
    tag = "AI Agent Permissions",
    operation_id = "revokePermission",
    params(
        ("id" = Uuid, Path, description = "Agent ID"),
        ("tool_id" = Uuid, Path, description = "Tool ID")
    ),
    responses(
        (status = 204, description = "Permission revoked"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Permission not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn revoke_permission(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path((agent_id, tool_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    state
        .permission_service
        .revoke(tenant_id, agent_id, tool_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
