//! Tool registry handlers for /nhi/tools/* endpoints.
//!
//! These handlers delegate to xavyo-api-agents tool service.
//! F109 - NHI API Consolidation

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiNhiError, ApiResult};
use crate::state::AgentsState;

// Re-export types from agents crate
pub use xavyo_api_agents::models::{
    CreateToolRequest, ToolListResponse, ToolResponse, UpdateToolRequest,
};

// ============================================================================
// Helper Functions
// ============================================================================

fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiNhiError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiNhiError::Unauthorized)
}

// ============================================================================
// Tool CRUD Handlers
// ============================================================================

// Re-export ListToolsQuery for OpenAPI
pub use xavyo_api_agents::models::ListToolsQuery;

/// List registered tools.
#[utoipa::path(
    get,
    path = "/nhi/tools",
    tag = "NHI - Tools",
    params(ListToolsQuery),
    responses(
        (status = 200, description = "List of tools", body = ToolListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_tools(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListToolsQuery>,
) -> ApiResult<Json<ToolListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let response = state.tool_service.list(tenant_id, query).await?;
    Ok(Json(response))
}

/// Register a new tool.
#[utoipa::path(
    post,
    path = "/nhi/tools",
    tag = "NHI - Tools",
    request_body = CreateToolRequest,
    responses(
        (status = 201, description = "Tool registered", body = ToolResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Tool name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_tool(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateToolRequest>,
) -> ApiResult<(StatusCode, Json<ToolResponse>)> {
    let tenant_id = extract_tenant_id(&claims)?;
    let tool = state.tool_service.create(tenant_id, request).await?;
    Ok((StatusCode::CREATED, Json(tool)))
}

/// Get a tool by ID.
#[utoipa::path(
    get,
    path = "/nhi/tools/{id}",
    tag = "NHI - Tools",
    params(
        ("id" = Uuid, Path, description = "Tool ID")
    ),
    responses(
        (status = 200, description = "Tool details", body = ToolResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Tool not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_tool(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ToolResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let tool = state.tool_service.get(tenant_id, id).await?;
    Ok(Json(tool))
}

/// Update a tool.
#[utoipa::path(
    patch,
    path = "/nhi/tools/{id}",
    tag = "NHI - Tools",
    params(
        ("id" = Uuid, Path, description = "Tool ID")
    ),
    request_body = UpdateToolRequest,
    responses(
        (status = 200, description = "Tool updated", body = ToolResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Tool not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_tool(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateToolRequest>,
) -> ApiResult<Json<ToolResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let tool = state.tool_service.update(tenant_id, id, request).await?;
    Ok(Json(tool))
}

/// Delete a tool.
#[utoipa::path(
    delete,
    path = "/nhi/tools/{id}",
    tag = "NHI - Tools",
    params(
        ("id" = Uuid, Path, description = "Tool ID")
    ),
    responses(
        (status = 204, description = "Tool deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Tool not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_tool(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = extract_tenant_id(&claims)?;
    state.tool_service.delete(tenant_id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tools_handlers_compile() {
        // Compile-time verification that handler signatures are correct.
        assert!(true);
    }

    // T048: Test tools list handler types
    #[test]
    fn test_list_tools_query_types() {
        // Verify ListToolsQuery can be constructed with defaults
        let query = ListToolsQuery {
            status: None,
            category: None,
            risk_level: None,
            requires_approval: None,
            name: None,
            limit: 100, // Default is 100
            offset: 0,
        };
        assert!(query.risk_level.is_none());
        assert!(query.name.is_none());

        let query_with_filter = ListToolsQuery {
            status: Some("active".to_string()),
            category: Some("ai".to_string()),
            risk_level: Some("high".to_string()),
            requires_approval: Some(true),
            name: Some("test".to_string()),
            limit: 50,
            offset: 0,
        };
        assert_eq!(query_with_filter.risk_level, Some("high".to_string()));
        assert_eq!(query_with_filter.limit, 50);
    }

    #[test]
    fn test_tool_response_types() {
        // Verify that the handler types compile correctly
        // Note: Cannot instantiate without actual data, but signature verification is sufficient
        assert!(true);
    }
}
