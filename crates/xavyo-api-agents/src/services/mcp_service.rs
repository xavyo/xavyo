//! MCP (Model Context Protocol) service for tool discovery and invocation.
//!
//! This service implements the MCP protocol for AI agents to discover and
//! invoke registered tools with proper authorization and validation.

use crate::error::ApiAgentsError;
use crate::models::{McpCallResponse, McpErrorCode, McpErrorResponse, McpTool};
use crate::services::{AuditService, PermissionService};
use jsonschema::JSONSchema;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, warn};
use uuid::Uuid;
use xavyo_db::models::{AiAgentToolPermission, AiTool, AiToolFilter};

/// MCP service for tool operations.
#[derive(Clone)]
pub struct McpService {
    pool: PgPool,
    permission_service: Arc<PermissionService>,
    audit_service: Arc<AuditService>,
}

impl McpService {
    /// Create a new MCP service.
    pub fn new(
        pool: PgPool,
        permission_service: Arc<PermissionService>,
        audit_service: Arc<AuditService>,
    ) -> Self {
        Self {
            pool,
            permission_service,
            audit_service,
        }
    }

    /// List tools the agent has permission to access.
    pub async fn list_permitted_tools(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Vec<McpTool>, ApiAgentsError> {
        // Get all active tools for the tenant
        let filter = AiToolFilter {
            status: Some("active".to_string()),
            ..Default::default()
        };
        let tools: Vec<AiTool> =
            AiTool::list_by_tenant(&self.pool, tenant_id, &filter, 1000, 0).await?;

        // Get agent's permissions directly from DB
        let permissions: Vec<AiAgentToolPermission> =
            AiAgentToolPermission::list_by_agent(&self.pool, tenant_id, agent_id).await?;
        let permitted_tool_ids: std::collections::HashSet<Uuid> =
            permissions.iter().map(|p| p.tool_id).collect();

        // Filter to only permitted tools and convert to MCP format
        let mcp_tools: Vec<McpTool> = tools
            .into_iter()
            .filter(|t| permitted_tool_ids.contains(&t.id))
            .map(|t| {
                let deprecated = t.status == "deprecated";
                McpTool {
                    name: t.name,
                    description: t.description,
                    input_schema: t.input_schema,
                    status: t.status,
                    deprecated: if deprecated { Some(true) } else { None },
                }
            })
            .collect();

        debug!(
            tenant_id = %tenant_id,
            agent_id = %agent_id,
            tool_count = mcp_tools.len(),
            "Listed permitted tools for agent"
        );

        Ok(mcp_tools)
    }

    /// Get a tool by name.
    pub async fn get_tool_by_name(
        &self,
        tenant_id: Uuid,
        tool_name: &str,
    ) -> Result<Option<AiTool>, ApiAgentsError> {
        let tool = AiTool::find_by_name(&self.pool, tenant_id, tool_name).await?;
        Ok(tool)
    }

    /// Validate parameters against a tool's JSON Schema.
    pub fn validate_parameters(
        &self,
        tool: &AiTool,
        parameters: &serde_json::Value,
    ) -> Result<(), McpErrorResponse> {
        let schema = match JSONSchema::compile(&tool.input_schema) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    tool_name = %tool.name,
                    error = %e,
                    "Failed to compile tool JSON schema"
                );
                return Err(McpErrorResponse::new(
                    McpErrorCode::InternalError,
                    "Tool schema is invalid",
                ));
            }
        };

        // Clone parameters to avoid lifetime issues
        let params_owned = parameters.clone();
        if let Err(errors) = schema.validate(&params_owned) {
            let error_details = Self::format_validation_errors_owned(errors);
            return Err(McpErrorResponse::new(
                McpErrorCode::InvalidParameters,
                "Parameter validation failed",
            )
            .with_details(error_details));
        }

        Ok(())
    }

    /// Format JSON Schema validation errors into a details object.
    fn format_validation_errors_owned<'a>(
        errors: impl Iterator<Item = jsonschema::ValidationError<'a>>,
    ) -> serde_json::Value {
        let error_map: std::collections::HashMap<String, String> = errors
            .map(|e| {
                let path = e.instance_path.to_string();
                let path = if path.is_empty() {
                    "root".to_string()
                } else {
                    path
                };
                (path, e.to_string())
            })
            .collect();

        serde_json::to_value(error_map).unwrap_or_else(|_| serde_json::json!({}))
    }

    /// Invoke a tool with the given parameters.
    ///
    /// Note: Actual tool execution is external. This method simulates the invocation
    /// and returns a placeholder result. In production, this would dispatch to
    /// the tool's registered execution endpoint.
    pub async fn invoke_tool(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        tool: &AiTool,
        parameters: serde_json::Value,
        context: Option<crate::models::McpContext>,
    ) -> Result<McpCallResponse, ApiAgentsError> {
        let start = Instant::now();
        let call_id = Uuid::new_v4();

        // Log the invocation to audit trail
        let context_json = context.as_ref().and_then(|c| serde_json::to_value(c).ok());

        self.audit_service
            .log_tool_invocation(
                tenant_id,
                agent_id,
                tool.id,
                &tool.name,
                &parameters,
                context_json.as_ref(),
            )
            .await?;

        // Simulate tool execution
        // In production, this would call the tool's endpoint
        let result = serde_json::json!({
            "status": "executed",
            "message": format!("Tool '{}' executed successfully", tool.name)
        });

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        debug!(
            call_id = %call_id,
            tool_name = %tool.name,
            agent_id = %agent_id,
            latency_ms = latency_ms,
            "Tool invocation completed"
        );

        Ok(McpCallResponse {
            call_id,
            result,
            latency_ms,
        })
    }

    /// Check if an agent has permission to use a tool.
    pub async fn check_permission(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        tool_id: Uuid,
    ) -> Result<bool, ApiAgentsError> {
        let permission: Option<AiAgentToolPermission> = self
            .permission_service
            .check_permission(tenant_id, agent_id, tool_id)
            .await?;
        Ok(permission.is_some())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_validation_error_formatting() {
        // Test that validation errors can be formatted
        // (Integration tests would use actual JSON Schema validation)
    }
}
