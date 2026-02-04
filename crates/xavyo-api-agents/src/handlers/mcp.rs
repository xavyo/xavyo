//! MCP (Model Context Protocol) HTTP handlers.
//!
//! Implements endpoints for tool discovery and invocation:
//! - GET /mcp/tools - List available tools
//! - POST /mcp/tools/{name}/call - Invoke a tool

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use tracing::{debug, warn};
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::error::ApiAgentsError;
use crate::models::{
    McpCallRequest, McpCallResponse, McpErrorCode, McpErrorResponse, McpToolsResponse,
};
use crate::router::AgentsState;

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenantId)
}

/// Extract `agent_id` from JWT claims.
/// For MCP endpoints, the `agent_id` should be in the subject claim.
fn extract_agent_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    Uuid::parse_str(&claims.sub).map_err(|_| ApiAgentsError::MissingAgentId)
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

    // Add Retry-After header for rate limit errors
    if status == StatusCode::TOO_MANY_REQUESTS {
        response.headers_mut().insert(
            "Retry-After",
            "1800".parse().unwrap(), // 30 minutes
        );
    }

    response
}

/// GET /mcp/tools - List available tools for the authenticated agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/mcp/tools",
    tag = "MCP Tools",
    operation_id = "listMcpTools",
    responses(
        (status = 200, description = "List of available tools", body = McpToolsResponse),
        (status = 401, description = "Authentication required"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_tools(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<Json<McpToolsResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let agent_id = extract_agent_id(&claims)?;

    debug!(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        "Listing MCP tools for agent"
    );

    let tools = state
        .mcp_service
        .list_permitted_tools(tenant_id, agent_id)
        .await?;

    // If agent has no permissions, return empty list (not an error)
    Ok(Json(McpToolsResponse { tools }))
}

/// POST /mcp/tools/{name}/call - Invoke a tool.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/mcp/tools/{name}/call",
    tag = "MCP Tools",
    operation_id = "callMcpTool",
    params(
        ("name" = String, Path, description = "Tool name")
    ),
    request_body = McpCallRequest,
    responses(
        (status = 200, description = "Tool executed successfully", body = McpCallResponse),
        (status = 400, description = "Invalid parameters", body = McpErrorResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Agent not authorized to use this tool", body = McpErrorResponse),
        (status = 404, description = "Tool not found", body = McpErrorResponse),
        (status = 429, description = "Rate limit exceeded", body = McpErrorResponse,
            headers(("Retry-After" = i32, description = "Seconds until rate limit resets"))),
        (status = 500, description = "Internal server error")
    ),
    security(("bearerAuth" = []))
))]
pub async fn call_tool(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tool_name): Path<String>,
    Json(request): Json<McpCallRequest>,
) -> Result<Json<McpCallResponse>, Response> {
    let tenant_id = extract_tenant_id(&claims).map_err(axum::response::IntoResponse::into_response)?;
    let agent_id = extract_agent_id(&claims).map_err(axum::response::IntoResponse::into_response)?;

    debug!(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        tool_name = %tool_name,
        "MCP tool invocation request"
    );

    // Get the tool
    let tool = state
        .mcp_service
        .get_tool_by_name(tenant_id, &tool_name)
        .await
        .map_err(axum::response::IntoResponse::into_response)?
        .ok_or_else(|| {
            mcp_error_response(McpErrorResponse::new(
                McpErrorCode::NotFound,
                format!("Tool '{tool_name}' not found"),
            ))
        })?;

    // Check authorization via existing authorization service
    let auth_result = state
        .authorization_service
        .authorize(
            tenant_id,
            agent_id,
            &tool_name,
            Some(request.parameters.clone()),
            request
                .context
                .as_ref()
                .and_then(|c| c.conversation_id.clone()),
            request.context.as_ref().and_then(|c| c.session_id.clone()),
        )
        .await
        .map_err(axum::response::IntoResponse::into_response)?;

    if auth_result.decision != "allow" {
        warn!(
            agent_id = %agent_id,
            tool_name = %tool_name,
            decision = %auth_result.decision,
            reason = %auth_result.reason,
            "MCP tool authorization denied"
        );

        // Check if it's a rate limit error
        if auth_result.reason.contains("rate limit") {
            return Err(mcp_error_response(McpErrorResponse::new(
                McpErrorCode::RateLimitExceeded,
                auth_result.reason,
            )));
        }

        return Err(mcp_error_response(McpErrorResponse::new(
            McpErrorCode::Unauthorized,
            auth_result.reason,
        )));
    }

    // Validate parameters against schema
    state
        .mcp_service
        .validate_parameters(&tool, &request.parameters)
        .map_err(mcp_error_response)?;

    // Invoke the tool
    let result = state
        .mcp_service
        .invoke_tool(
            tenant_id,
            agent_id,
            &tool,
            request.parameters,
            request.context,
        )
        .await
        .map_err(axum::response::IntoResponse::into_response)?;

    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_error_status_codes() {
        let error = McpErrorResponse::new(McpErrorCode::InvalidParameters, "test");
        let response = mcp_error_response(error);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let error = McpErrorResponse::new(McpErrorCode::Unauthorized, "test");
        let response = mcp_error_response(error);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let error = McpErrorResponse::new(McpErrorCode::NotFound, "test");
        let response = mcp_error_response(error);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let error = McpErrorResponse::new(McpErrorCode::RateLimitExceeded, "test");
        let response = mcp_error_response(error);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
