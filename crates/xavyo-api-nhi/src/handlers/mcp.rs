//! MCP (Model Context Protocol) HTTP handlers.
//!
//! Implements endpoints for tool discovery and invocation:
//! - GET /mcp/tools - List available tools
//! - POST /mcp/tools/{name}/call - Invoke a tool
//!
//! Migrated from xavyo-api-agents (Feature 205).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use tracing::{debug, warn};
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::error::NhiApiError;
use crate::models::{
    McpCallRequest, McpCallResponse, McpErrorCode, McpErrorResponse, McpToolsResponse,
};
use crate::services::mcp_service;
use crate::state::NhiState;

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, NhiApiError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or_else(|| NhiApiError::BadRequest("Missing tenant ID in claims".to_string()))
}

/// Extract `agent_id` from JWT claims (subject claim).
fn extract_agent_id(claims: &JwtClaims) -> Result<Uuid, NhiApiError> {
    Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("Invalid agent ID in JWT subject".to_string()))
}

/// Convert MCP error to HTTP response.
fn mcp_error_response(error: McpErrorResponse) -> Response {
    let status = match error.error_code {
        McpErrorCode::InvalidParameters => StatusCode::BAD_REQUEST,
        McpErrorCode::Unauthorized => StatusCode::FORBIDDEN,
        McpErrorCode::NotFound => StatusCode::NOT_FOUND,
        McpErrorCode::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
        McpErrorCode::ExecutionFailed | McpErrorCode::InternalError => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        McpErrorCode::Timeout => StatusCode::GATEWAY_TIMEOUT,
    };

    let mut response = (status, Json(error)).into_response();

    if status == StatusCode::TOO_MANY_REQUESTS {
        response
            .headers_mut()
            .insert("Retry-After", "1800".parse().unwrap());
    }

    response
}

/// GET /mcp/tools - List available tools for the authenticated agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/mcp/tools",
    responses(
        (status = 200, description = "List of available MCP tools", body = McpToolsResponse),
        (status = 400, description = "Invalid request"),
    ),
    tag = "MCP Tools"
))]
pub async fn list_tools(
    State(state): State<NhiState>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<Json<McpToolsResponse>, NhiApiError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let agent_id = extract_agent_id(&claims)?;

    debug!(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        "Listing MCP tools for agent"
    );

    let tools = mcp_service::list_permitted_tools(&state.pool, tenant_id, agent_id).await?;

    Ok(Json(McpToolsResponse { tools }))
}

/// POST /mcp/tools/{name}/call - Invoke a tool.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/mcp/tools/{name}/call",
    params(
        ("name" = String, Path, description = "Tool name"),
    ),
    request_body = McpCallRequest,
    responses(
        (status = 200, description = "Tool invocation result", body = McpCallResponse),
        (status = 400, description = "Invalid parameters"),
        (status = 403, description = "Agent not authorized"),
        (status = 404, description = "Tool not found"),
        (status = 429, description = "Rate limit exceeded"),
    ),
    tag = "MCP Tools"
))]
pub async fn call_tool(
    State(state): State<NhiState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tool_name): Path<String>,
    Json(request): Json<McpCallRequest>,
) -> Result<Json<McpCallResponse>, Response> {
    let tenant_id = extract_tenant_id(&claims).map_err(IntoResponse::into_response)?;
    let agent_id = extract_agent_id(&claims).map_err(IntoResponse::into_response)?;

    debug!(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        tool_name = %tool_name,
        "MCP tool invocation request"
    );

    // Get the tool by name
    let tool = mcp_service::get_tool_by_name(&state.pool, tenant_id, &tool_name)
        .await
        .map_err(IntoResponse::into_response)?
        .ok_or_else(|| {
            mcp_error_response(McpErrorResponse::new(
                McpErrorCode::NotFound,
                format!("Tool '{tool_name}' not found"),
            ))
        })?;

    // Check if agent has permission to use this tool
    let has_permission = mcp_service::check_permission(&state.pool, tenant_id, agent_id, tool.id)
        .await
        .map_err(IntoResponse::into_response)?;

    if !has_permission {
        warn!(
            agent_id = %agent_id,
            tool_name = %tool_name,
            "MCP tool authorization denied"
        );
        return Err(mcp_error_response(McpErrorResponse::new(
            McpErrorCode::Unauthorized,
            format!("Agent not authorized to use tool '{tool_name}'"),
        )));
    }

    // Validate parameters against schema
    mcp_service::validate_parameters(&tool.input_schema, &request.parameters)
        .map_err(mcp_error_response)?;

    // Invoke the tool
    let result = mcp_service::invoke_tool(
        &state.pool,
        tenant_id,
        agent_id,
        &tool_name,
        request.parameters,
        request.context,
    )
    .await
    .map_err(IntoResponse::into_response)?;

    Ok(Json(result))
}
