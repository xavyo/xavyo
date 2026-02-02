//! Request DTOs for the AI Agent Security API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Agent Requests
// ============================================================================

/// Request to create a new AI agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateAgentRequest {
    /// Agent display name (unique per tenant).
    pub name: String,

    /// Agent description.
    #[serde(default)]
    pub description: Option<String>,

    /// Agent type: autonomous, copilot, workflow, orchestrator.
    pub agent_type: String,

    /// User ID of the agent owner.
    #[serde(default)]
    pub owner_id: Option<Uuid>,

    /// Team/group ID associated with this agent.
    #[serde(default)]
    pub team_id: Option<Uuid>,

    /// Backup owner ID for governance continuity (F108).
    #[serde(default)]
    pub backup_owner_id: Option<Uuid>,

    /// Model provider (e.g., anthropic, openai, google).
    #[serde(default)]
    pub model_provider: Option<String>,

    /// Model name (e.g., claude-sonnet-4, gpt-4).
    #[serde(default)]
    pub model_name: Option<String>,

    /// Model version.
    #[serde(default)]
    pub model_version: Option<String>,

    /// Risk level: low, medium, high, critical. Default: medium.
    #[serde(default = "default_risk_level")]
    pub risk_level: String,

    /// Maximum OAuth token lifetime in seconds. Default: 900 (15 min).
    #[serde(default = "default_token_lifetime")]
    pub max_token_lifetime_secs: i32,

    /// Require human approval for sensitive operations.
    #[serde(default)]
    pub requires_human_approval: bool,

    /// Optional expiration date.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,

    /// Days of inactivity before agent enters grace period (F108).
    #[serde(default = "default_inactivity_threshold")]
    pub inactivity_threshold_days: Option<i32>,

    /// Days between required credential rotations (F108).
    #[serde(default)]
    pub rotation_interval_days: Option<i32>,
}

fn default_inactivity_threshold() -> Option<i32> {
    Some(90)
}

fn default_risk_level() -> String {
    "medium".to_string()
}

fn default_token_lifetime() -> i32 {
    900
}

/// Request to update an AI agent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateAgentRequest {
    /// Updated description.
    #[serde(default)]
    pub description: Option<String>,

    /// Updated risk level.
    #[serde(default)]
    pub risk_level: Option<String>,

    /// Updated max token lifetime.
    #[serde(default)]
    pub max_token_lifetime_secs: Option<i32>,

    /// Updated human approval requirement.
    #[serde(default)]
    pub requires_human_approval: Option<bool>,

    /// Updated expiration date.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,

    /// Updated model provider.
    #[serde(default)]
    pub model_provider: Option<String>,

    /// Updated model name.
    #[serde(default)]
    pub model_name: Option<String>,

    /// Updated model version.
    #[serde(default)]
    pub model_version: Option<String>,

    /// Updated backup owner ID (F108).
    #[serde(default)]
    pub backup_owner_id: Option<Uuid>,

    /// Updated inactivity threshold in days (F108).
    #[serde(default)]
    pub inactivity_threshold_days: Option<i32>,

    /// Updated rotation interval in days (F108).
    #[serde(default)]
    pub rotation_interval_days: Option<i32>,
}

/// Query parameters for listing agents.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct ListAgentsQuery {
    /// Filter by status.
    #[serde(default)]
    pub status: Option<String>,

    /// Filter by agent type.
    #[serde(default)]
    pub agent_type: Option<String>,

    /// Filter by owner ID.
    #[serde(default)]
    pub owner_id: Option<Uuid>,

    /// Filter by risk level.
    #[serde(default)]
    pub risk_level: Option<String>,

    /// Search by name prefix.
    #[serde(default)]
    pub name: Option<String>,

    /// Maximum number of results. Default: 100.
    #[serde(default = "default_limit")]
    pub limit: i32,

    /// Offset for pagination. Default: 0.
    #[serde(default)]
    pub offset: i32,
}

fn default_limit() -> i32 {
    100
}

// ============================================================================
// Tool Requests
// ============================================================================

/// Request to create a new tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateToolRequest {
    /// Tool name (unique per tenant).
    pub name: String,

    /// Tool description.
    #[serde(default)]
    pub description: Option<String>,

    /// Tool category (e.g., communication, data, system).
    #[serde(default)]
    pub category: Option<String>,

    /// JSON Schema for tool input parameters.
    pub input_schema: serde_json::Value,

    /// JSON Schema for expected output (optional).
    #[serde(default)]
    pub output_schema: Option<serde_json::Value>,

    /// Risk level: low, medium, high, critical.
    pub risk_level: String,

    /// Whether tool invocation requires approval.
    #[serde(default)]
    pub requires_approval: bool,

    /// Maximum calls per hour (rate limiting).
    #[serde(default)]
    pub max_calls_per_hour: Option<i32>,

    /// Tool provider (e.g., internal, mcp:service).
    #[serde(default)]
    pub provider: Option<String>,
}

/// Request to update an existing tool.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateToolRequest {
    /// Updated description.
    #[serde(default)]
    pub description: Option<String>,

    /// Updated category.
    #[serde(default)]
    pub category: Option<String>,

    /// Updated input schema.
    #[serde(default)]
    pub input_schema: Option<serde_json::Value>,

    /// Updated output schema.
    #[serde(default)]
    pub output_schema: Option<serde_json::Value>,

    /// Updated risk level.
    #[serde(default)]
    pub risk_level: Option<String>,

    /// Updated approval requirement.
    #[serde(default)]
    pub requires_approval: Option<bool>,

    /// Updated max calls per hour.
    #[serde(default)]
    pub max_calls_per_hour: Option<i32>,

    /// Updated provider.
    #[serde(default)]
    pub provider: Option<String>,

    /// Updated status.
    #[serde(default)]
    pub status: Option<String>,
}

/// Query parameters for listing tools.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct ListToolsQuery {
    /// Filter by status.
    #[serde(default)]
    pub status: Option<String>,

    /// Filter by category.
    #[serde(default)]
    pub category: Option<String>,

    /// Filter by risk level.
    #[serde(default)]
    pub risk_level: Option<String>,

    /// Filter by approval requirement.
    #[serde(default)]
    pub requires_approval: Option<bool>,

    /// Search by name (partial match).
    #[serde(default)]
    pub name: Option<String>,

    /// Maximum number of results. Default: 100.
    #[serde(default = "default_limit")]
    pub limit: i32,

    /// Offset for pagination. Default: 0.
    #[serde(default)]
    pub offset: i32,
}

// ============================================================================
// Permission Requests
// ============================================================================

/// Request to grant a tool permission to an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GrantPermissionRequest {
    /// Tool ID to grant permission for.
    pub tool_id: Uuid,

    /// Parameter restrictions (JSON object).
    #[serde(default)]
    pub allowed_parameters: Option<serde_json::Value>,

    /// Override tool's max calls per hour.
    #[serde(default)]
    pub max_calls_per_hour: Option<i32>,

    /// Override tool's approval requirement.
    #[serde(default)]
    pub requires_approval: Option<bool>,

    /// Permission expiration date.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Query parameters for listing permissions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct ListPermissionsQuery {
    /// Maximum number of results. Default: 100.
    #[serde(default = "default_limit")]
    pub limit: i32,

    /// Offset for pagination. Default: 0.
    #[serde(default)]
    pub offset: i32,
}

// ============================================================================
// Authorization Requests
// ============================================================================

/// Request for real-time authorization decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuthorizeRequest {
    /// Agent ID requesting authorization.
    pub agent_id: Uuid,

    /// Tool name to authorize.
    pub tool: String,

    /// Tool invocation parameters.
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,

    /// Authorization context.
    #[serde(default)]
    pub context: Option<AuthorizationContext>,
}

/// User context for three-layer authorization (F123).
/// Identifies the human user running the workflow.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserContext {
    /// Xavyo user ID.
    pub user_id: Uuid,

    /// User email for audit trail.
    #[serde(default)]
    pub email: Option<String>,

    /// User roles in Xavyo.
    #[serde(default)]
    pub roles: Option<Vec<String>>,
}

/// Context for authorization decisions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuthorizationContext {
    /// Conversation/session ID for audit trail.
    #[serde(default)]
    pub conversation_id: Option<String>,

    /// Session ID for correlation.
    #[serde(default)]
    pub session_id: Option<String>,

    /// User instruction that triggered the tool call.
    #[serde(default)]
    pub user_instruction: Option<String>,

    /// User context for three-layer authorization (F123).
    #[serde(default)]
    pub user_context: Option<UserContext>,
}

/// Request to check if a user can operate an agent (F123).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CanOperateRequest {
    /// User ID to check.
    pub user_id: Uuid,
}

// ============================================================================
// Audit Requests
// ============================================================================

/// Query parameters for audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct AuditFilter {
    /// Start time filter.
    #[serde(default)]
    pub start_time: Option<DateTime<Utc>>,

    /// End time filter.
    #[serde(default)]
    pub end_time: Option<DateTime<Utc>>,

    /// Filter by event type.
    #[serde(default)]
    pub event_type: Option<String>,

    /// Filter by decision.
    #[serde(default)]
    pub decision: Option<String>,

    /// Filter by tool name.
    #[serde(default)]
    pub tool_name: Option<String>,

    /// Maximum number of results. Default: 100.
    #[serde(default = "default_limit")]
    pub limit: i32,

    /// Offset for pagination. Default: 0.
    #[serde(default)]
    pub offset: i32,
}

impl Default for AuditFilter {
    fn default() -> Self {
        Self {
            start_time: None,
            end_time: None,
            event_type: None,
            decision: None,
            tool_name: None,
            limit: default_limit(),
            offset: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_agent_request_defaults() {
        let json = r#"{"name": "test-agent", "agent_type": "copilot"}"#;
        let request: CreateAgentRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.name, "test-agent");
        assert_eq!(request.agent_type, "copilot");
        assert_eq!(request.risk_level, "medium");
        assert_eq!(request.max_token_lifetime_secs, 900);
        assert!(!request.requires_human_approval);
    }

    #[test]
    fn test_create_tool_request_serialization() {
        let request = CreateToolRequest {
            name: "send_email".to_string(),
            description: Some("Send email".to_string()),
            category: Some("communication".to_string()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "to": { "type": "string" }
                }
            }),
            output_schema: None,
            risk_level: "medium".to_string(),
            requires_approval: false,
            max_calls_per_hour: Some(100),
            provider: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("send_email"));
        assert!(json.contains("communication"));
    }

    #[test]
    fn test_authorize_request_serialization() {
        let request = AuthorizeRequest {
            agent_id: Uuid::new_v4(),
            tool: "send_email".to_string(),
            parameters: Some(serde_json::json!({"to": "test@example.com"})),
            context: Some(AuthorizationContext {
                conversation_id: Some("conv-123".to_string()),
                session_id: Some("sess-456".to_string()),
                user_instruction: Some("Send follow-up email".to_string()),
                user_context: None,
            }),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("send_email"));
        assert!(json.contains("conv-123"));
    }

    #[test]
    fn test_audit_filter_defaults() {
        let filter = AuditFilter::default();

        assert!(filter.start_time.is_none());
        assert!(filter.end_time.is_none());
        assert_eq!(filter.limit, 100);
        assert_eq!(filter.offset, 0);
    }

    #[test]
    fn test_grant_permission_request() {
        let request = GrantPermissionRequest {
            tool_id: Uuid::new_v4(),
            allowed_parameters: Some(serde_json::json!({"max_recipients": 10})),
            max_calls_per_hour: Some(50),
            requires_approval: None,
            expires_at: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: GrantPermissionRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.tool_id, deserialized.tool_id);
        assert_eq!(request.max_calls_per_hour, deserialized.max_calls_per_hour);
    }
}
