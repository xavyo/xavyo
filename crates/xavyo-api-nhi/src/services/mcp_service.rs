//! MCP (Model Context Protocol) service using NHI tables.
//!
//! Provides MCP tool discovery, parameter validation, and tool invocation
//! backed by the unified NHI data model. Migrated from xavyo-api-agents
//! as part of Feature 205 protocol migration.
//!
//! All functions are stateless and take `&PgPool` as their first argument.

use sqlx::PgPool;
use std::time::Instant;
use tracing::{debug, warn};
use uuid::Uuid;

use jsonschema::JSONSchema;
use xavyo_db::models::{NhiToolPermission, NhiToolWithIdentity};
use xavyo_nhi::NhiLifecycleState;

use crate::error::NhiApiError;
use crate::models::{McpCallResponse, McpContext, McpErrorCode, McpErrorResponse, McpTool};

/// List NHI tools the agent has permission to use.
///
/// Queries `nhi_tool_permissions` for the given agent, then for each
/// permitted tool fetches the joined `nhi_identities + nhi_tools` row,
/// filtering to tools whose lifecycle state is `Active`.
pub async fn list_permitted_tools(
    pool: &PgPool,
    tenant_id: Uuid,
    agent_nhi_id: Uuid,
) -> Result<Vec<McpTool>, NhiApiError> {
    // Fetch all non-expired permissions for this agent (up to 100)
    let permissions =
        NhiToolPermission::list_by_agent(pool, tenant_id, agent_nhi_id, 100, 0).await?;

    debug!(
        agent_nhi_id = %agent_nhi_id,
        permission_count = permissions.len(),
        "Fetched tool permissions for agent"
    );

    let mut tools = Vec::with_capacity(permissions.len());

    for perm in &permissions {
        // Skip expired permissions (belt-and-suspenders; list_by_agent filters too)
        if perm.is_expired() {
            continue;
        }

        // Fetch the joined tool + identity data
        let tool_opt =
            xavyo_db::models::nhi_tool::NhiTool::find_by_nhi_id(pool, tenant_id, perm.tool_nhi_id)
                .await?;

        let Some(tool) = tool_opt else {
            warn!(
                tool_nhi_id = %perm.tool_nhi_id,
                "Permission references non-existent tool; skipping"
            );
            continue;
        };

        // Only include active tools
        if tool.lifecycle_state != NhiLifecycleState::Active {
            debug!(
                tool_name = %tool.name,
                state = %tool.lifecycle_state,
                "Skipping non-active tool"
            );
            continue;
        }

        tools.push(McpTool {
            name: tool.name.clone(),
            description: tool.description.clone(),
            input_schema: tool.input_schema.clone(),
            status: tool.lifecycle_state.as_str().to_string(),
            deprecated: if tool.lifecycle_state == NhiLifecycleState::Deprecated {
                Some(true)
            } else {
                None
            },
        });
    }

    debug!(
        agent_nhi_id = %agent_nhi_id,
        active_tool_count = tools.len(),
        "Returning permitted active tools"
    );

    Ok(tools)
}

/// Find a tool by name within a tenant.
///
/// Queries `nhi_identities JOIN nhi_tools` where `nhi_type = 'tool'`
/// and `name` matches.
pub async fn get_tool_by_name(
    pool: &PgPool,
    tenant_id: Uuid,
    name: &str,
) -> Result<Option<NhiToolWithIdentity>, NhiApiError> {
    let tool = sqlx::query_as::<_, NhiToolWithIdentity>(
        r"
        SELECT i.id, i.tenant_id, i.name, i.description, i.owner_id, i.backup_owner_id,
               i.lifecycle_state, i.suspension_reason, i.expires_at, i.last_activity_at,
               i.inactivity_threshold_days, i.grace_period_ends_at, i.risk_score,
               i.last_certified_at, i.next_certification_at, i.last_certified_by,
               i.rotation_interval_days, i.last_rotation_at, i.created_at, i.updated_at, i.created_by,
               t.category, t.input_schema, t.output_schema, t.requires_approval,
               t.max_calls_per_hour, t.provider, t.provider_verified, t.checksum
        FROM nhi_identities i
        INNER JOIN nhi_tools t ON t.nhi_id = i.id
        WHERE i.nhi_type = 'tool' AND i.name = $1 AND i.tenant_id = $2
        ",
    )
    .bind(name)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    Ok(tool)
}

/// Validate tool parameters against a JSON Schema.
///
/// Uses `jsonschema::JSONSchema::compile()` to validate the input
/// parameters against the tool's declared input schema.
pub fn validate_parameters(
    input_schema: &serde_json::Value,
    parameters: &serde_json::Value,
) -> Result<(), McpErrorResponse> {
    let compiled = JSONSchema::compile(input_schema).map_err(|e| {
        warn!(error = %e, "Failed to compile tool input schema");
        McpErrorResponse::new(
            McpErrorCode::InternalError,
            format!("Invalid tool schema: {e}"),
        )
    })?;

    if let Err(errors) = compiled.validate(parameters) {
        let error_details: Vec<String> = errors.map(|e| e.to_string()).collect();
        let details = serde_json::json!({ "validation_errors": error_details });

        return Err(McpErrorResponse::new(
            McpErrorCode::InvalidParameters,
            "Parameter validation failed",
        )
        .with_details(details));
    }

    Ok(())
}

/// Invoke a tool by name on behalf of an agent.
///
/// This is a placeholder implementation that:
/// 1. Resolves the tool by name
/// 2. Verifies the agent has permission to use it
/// 3. Validates parameters against the tool's input schema
/// 4. Returns a simulated result (real execution will be added later)
pub async fn invoke_tool(
    pool: &PgPool,
    tenant_id: Uuid,
    agent_nhi_id: Uuid,
    tool_name: &str,
    parameters: serde_json::Value,
    context: Option<McpContext>,
) -> Result<McpCallResponse, NhiApiError> {
    let start = Instant::now();

    // 1. Resolve the tool by name
    let tool = get_tool_by_name(pool, tenant_id, tool_name)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    // 2. Verify the tool is active
    if tool.lifecycle_state != NhiLifecycleState::Active {
        return Err(NhiApiError::BadRequest(format!(
            "Tool '{}' is in {} state; must be active for invocation",
            tool_name, tool.lifecycle_state
        )));
    }

    // 3. Check permission
    let has_permission = check_permission(pool, tenant_id, agent_nhi_id, tool.id).await?;
    if !has_permission {
        return Err(NhiApiError::Forbidden);
    }

    // 4. Validate parameters against input schema
    validate_parameters(&tool.input_schema, &parameters)
        .map_err(|e| NhiApiError::BadRequest(e.message))?;

    let call_id = Uuid::new_v4();
    let elapsed = start.elapsed();

    debug!(
        call_id = %call_id,
        tool_name = %tool_name,
        agent_nhi_id = %agent_nhi_id,
        latency_ms = elapsed.as_secs_f64() * 1000.0,
        conversation_id = context.as_ref().and_then(|c| c.conversation_id.as_deref()),
        "Tool invocation (simulated)"
    );

    // 5. Return simulated result (placeholder)
    Ok(McpCallResponse {
        call_id,
        result: serde_json::json!({
            "status": "simulated",
            "tool": tool_name,
            "message": "Tool execution is not yet implemented; this is a placeholder result."
        }),
        latency_ms: elapsed.as_secs_f64() * 1000.0,
    })
}

/// Check if an agent has permission to use a tool.
///
/// Looks up the `nhi_tool_permissions` table for a non-expired grant
/// matching the agent-tool pair.
pub async fn check_permission(
    pool: &PgPool,
    tenant_id: Uuid,
    agent_nhi_id: Uuid,
    tool_nhi_id: Uuid,
) -> Result<bool, NhiApiError> {
    let perm = NhiToolPermission::find_by_pair(pool, tenant_id, agent_nhi_id, tool_nhi_id).await?;

    match perm {
        Some(p) => Ok(p.is_valid()),
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_parameters_valid() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "to": { "type": "string" },
                "subject": { "type": "string" }
            },
            "required": ["to"]
        });

        let params = serde_json::json!({
            "to": "user@example.com",
            "subject": "Hello"
        });

        assert!(validate_parameters(&schema, &params).is_ok());
    }

    #[test]
    fn test_validate_parameters_missing_required() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "to": { "type": "string" }
            },
            "required": ["to"]
        });

        let params = serde_json::json!({
            "subject": "Hello"
        });

        let err = validate_parameters(&schema, &params).unwrap_err();
        assert_eq!(err.error_code, McpErrorCode::InvalidParameters);
        assert!(err.details.is_some());
    }

    #[test]
    fn test_validate_parameters_wrong_type() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer" }
            },
            "required": ["count"]
        });

        let params = serde_json::json!({
            "count": "not_a_number"
        });

        let err = validate_parameters(&schema, &params).unwrap_err();
        assert_eq!(err.error_code, McpErrorCode::InvalidParameters);
    }

    #[test]
    fn test_validate_parameters_empty_schema() {
        let schema = serde_json::json!({});
        let params = serde_json::json!({ "anything": "goes" });
        assert!(validate_parameters(&schema, &params).is_ok());
    }
}
