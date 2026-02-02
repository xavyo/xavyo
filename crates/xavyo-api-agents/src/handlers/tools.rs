//! Tool management handlers.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::{
    CreateToolRequest, ListToolsQuery, ToolListResponse, ToolResponse, UpdateToolRequest,
};
use crate::router::AgentsState;
use xavyo_auth::JwtClaims;

/// Extract tenant_id from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenant)
}

/// POST /tools - Create a new tool.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/tools",
    tag = "AI Agent Tools",
    operation_id = "createTool",
    request_body = CreateToolRequest,
    responses(
        (status = 201, description = "Tool created", body = ToolResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 409, description = "Tool name already exists")
    ),
    security(("bearerAuth" = []))
))]
pub async fn create_tool(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateToolRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let tool = state.tool_service.create(tenant_id, request).await?;

    Ok((StatusCode::CREATED, Json(tool)))
}

/// GET /tools - List tools.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/tools",
    tag = "AI Agent Tools",
    operation_id = "listTools",
    params(ListToolsQuery),
    responses(
        (status = 200, description = "List of tools", body = ToolListResponse),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_tools(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListToolsQuery>,
) -> Result<Json<ToolListResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state.tool_service.list(tenant_id, query).await?;

    Ok(Json(response))
}

/// GET /tools/{id} - Get tool by ID.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/tools/{id}",
    tag = "AI Agent Tools",
    operation_id = "getTool",
    params(
        ("id" = Uuid, Path, description = "Tool ID")
    ),
    responses(
        (status = 200, description = "Tool details", body = ToolResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Tool not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_tool(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<ToolResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let tool = state.tool_service.get(tenant_id, id).await?;

    Ok(Json(tool))
}

/// PATCH /tools/{id} - Update tool.
#[cfg_attr(feature = "openapi", utoipa::path(
    patch,
    path = "/tools/{id}",
    tag = "AI Agent Tools",
    operation_id = "updateTool",
    params(
        ("id" = Uuid, Path, description = "Tool ID")
    ),
    request_body = UpdateToolRequest,
    responses(
        (status = 200, description = "Tool updated", body = ToolResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Tool not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn update_tool(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateToolRequest>,
) -> Result<Json<ToolResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let tool = state.tool_service.update(tenant_id, id, request).await?;

    Ok(Json(tool))
}

/// DELETE /tools/{id} - Delete tool.
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/tools/{id}",
    tag = "AI Agent Tools",
    operation_id = "deleteTool",
    params(
        ("id" = Uuid, Path, description = "Tool ID")
    ),
    responses(
        (status = 204, description = "Tool deleted"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Tool not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn delete_tool(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    state.tool_service.delete(tenant_id, id).await?;

    Ok(StatusCode::NO_CONTENT)
}
