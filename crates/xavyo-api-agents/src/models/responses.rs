//! Response DTOs for the AI Agent Security API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Agent Responses
// ============================================================================

/// Agent response DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentResponse {
    /// Agent unique identifier.
    pub id: Uuid,

    /// Agent display name.
    pub name: String,

    /// Agent description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Agent type: autonomous, copilot, workflow, orchestrator.
    pub agent_type: String,

    /// Owner user ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<Uuid>,

    /// Team/group ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<Uuid>,

    /// Backup owner ID for governance continuity (F108).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_owner_id: Option<Uuid>,

    /// Model provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_provider: Option<String>,

    /// Model name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,

    /// Agent status: active, suspended, expired.
    pub status: String,

    /// Risk level: low, medium, high, critical.
    pub risk_level: String,

    /// Maximum token lifetime in seconds.
    pub max_token_lifetime_secs: i32,

    /// Requires human approval for sensitive operations.
    pub requires_human_approval: bool,

    /// Agent creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Agent last update timestamp.
    pub updated_at: DateTime<Utc>,

    /// Last activity timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity_at: Option<DateTime<Utc>>,

    /// Expiration timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    // F108: Inactivity detection fields
    /// Days of inactivity before agent enters grace period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inactivity_threshold_days: Option<i32>,

    /// When grace period expires and agent will be suspended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_period_ends_at: Option<DateTime<Utc>>,

    /// Reason for suspension (if suspended).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspension_reason: Option<String>,

    // F108: Credential rotation tracking
    /// Days between required credential rotations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_interval_days: Option<i32>,

    /// Timestamp of last credential rotation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_rotation_at: Option<DateTime<Utc>>,
}

/// List response for agents with pagination.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentListResponse {
    /// List of agents.
    pub agents: Vec<AgentResponse>,

    /// Total count (for pagination).
    pub total: i64,

    /// Current limit.
    pub limit: i32,

    /// Current offset.
    pub offset: i32,
}

/// Response for an orphaned agent (owner no longer exists).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OrphanedAgentResponse {
    /// Agent unique identifier.
    pub id: Uuid,

    /// Agent display name.
    pub name: String,

    /// Agent type.
    pub agent_type: String,

    /// Original owner ID (no longer exists).
    pub owner_id: Option<Uuid>,

    /// Backup owner ID (if available for promotion).
    pub backup_owner_id: Option<Uuid>,

    /// Agent status.
    pub status: String,

    /// Risk level.
    pub risk_level: String,

    /// Last activity timestamp.
    pub last_activity_at: Option<DateTime<Utc>>,

    /// Whether this agent can be auto-promoted (has valid `backup_owner`).
    pub can_auto_promote: bool,
}

/// List response for orphaned agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OrphanedAgentListResponse {
    /// List of orphaned agents.
    pub agents: Vec<OrphanedAgentResponse>,

    /// Total count.
    pub total: i64,
}

/// Response for backup owner promotion.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PromotionResponse {
    /// Agent that was updated.
    pub agent: AgentResponse,

    /// Previous owner ID.
    pub previous_owner_id: Option<Uuid>,

    /// New owner ID (promoted from backup).
    pub new_owner_id: Uuid,
}

// ============================================================================
// Tool Responses
// ============================================================================

/// Tool response DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ToolResponse {
    /// Tool unique identifier.
    pub id: Uuid,

    /// Tool name.
    pub name: String,

    /// Tool description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Tool category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,

    /// JSON Schema for tool input parameters.
    pub input_schema: serde_json::Value,

    /// JSON Schema for expected output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,

    /// Risk level: low, medium, high, critical.
    pub risk_level: String,

    /// Whether tool invocation requires approval.
    pub requires_approval: bool,

    /// Maximum calls per hour.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_calls_per_hour: Option<i32>,

    /// Tool provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// Whether provider is verified.
    pub provider_verified: bool,

    /// Tool status: active, inactive, deprecated.
    pub status: String,

    /// Tool creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Tool last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// List response for tools with pagination.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ToolListResponse {
    /// List of tools.
    pub tools: Vec<ToolResponse>,

    /// Total count (for pagination).
    pub total: i64,

    /// Current limit.
    pub limit: i32,

    /// Current offset.
    pub offset: i32,
}

// ============================================================================
// Permission Responses
// ============================================================================

/// Permission response DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PermissionResponse {
    /// Permission unique identifier.
    pub id: Uuid,

    /// Agent ID.
    pub agent_id: Uuid,

    /// Tool ID.
    pub tool_id: Uuid,

    /// Tool name (for convenience).
    pub tool_name: String,

    /// Parameter restrictions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_parameters: Option<serde_json::Value>,

    /// Override max calls per hour.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_calls_per_hour: Option<i32>,

    /// Override approval requirement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<bool>,

    /// When permission was granted.
    pub granted_at: DateTime<Utc>,

    /// Who granted the permission.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted_by: Option<Uuid>,

    /// Permission expiration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// List response for permissions with pagination.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PermissionListResponse {
    /// List of permissions.
    pub permissions: Vec<PermissionResponse>,

    /// Total count (for pagination).
    pub total: i64,

    /// Current limit.
    pub limit: i32,

    /// Current offset.
    pub offset: i32,
}

// ============================================================================
// Authorization Responses
// ============================================================================

/// Authorization decision response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuthorizeResponse {
    /// Authorization decision: allow, deny, `require_approval`.
    pub decision: String,

    /// Decision ID for audit trail correlation.
    pub decision_id: Uuid,

    /// Reason for the decision.
    pub reason: String,

    /// Decision latency in milliseconds.
    pub latency_ms: f64,

    /// Approval request ID (if decision is `require_approval`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<Uuid>,

    /// Behavioral anomaly warnings detected during authorization.
    /// Non-blocking: request is still processed but anomalies are flagged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anomaly_warnings: Option<Vec<AnomalyWarning>>,
}

/// Anomaly warning included in authorization response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AnomalyWarning {
    /// Type of anomaly detected.
    pub anomaly_type: String,

    /// Severity level (low, medium, high, critical).
    pub severity: String,

    /// Human-readable description.
    pub description: String,

    /// Anomaly score (0-100).
    pub score: i32,
}

// ============================================================================
// Audit Responses
// ============================================================================

/// Audit event response DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuditEventResponse {
    /// Event unique identifier.
    pub id: Uuid,

    /// Agent ID.
    pub agent_id: Uuid,

    /// Event type: `tool_invocation`, authorization, `status_change`.
    pub event_type: String,

    /// Conversation ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,

    /// Session ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Tool name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,

    /// Authorization decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,

    /// Decision reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,

    /// Outcome: success, failure, error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,

    /// Event timestamp.
    pub timestamp: DateTime<Utc>,
}

/// List response for audit events with pagination.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuditListResponse {
    /// List of audit events.
    pub events: Vec<AuditEventResponse>,

    /// Total count (for pagination).
    pub total: i64,

    /// Current limit.
    pub limit: i32,

    /// Current offset.
    pub offset: i32,
}

// ============================================================================
// AgentCard (A2A Protocol)
// ============================================================================

/// A2A Protocol `AgentCard` for agent discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentCard {
    /// Agent name.
    pub name: String,

    /// Agent description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Agent API URL.
    pub url: String,

    /// Agent version.
    pub version: String,

    /// A2A protocol version.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,

    /// Agent capabilities.
    pub capabilities: AgentCapabilities,

    /// Authentication configuration.
    pub authentication: AgentAuthentication,

    /// Agent skills (tools it can use).
    pub skills: Vec<AgentSkill>,
}

/// Agent capabilities (A2A Protocol).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentCapabilities {
    /// Whether agent supports streaming.
    pub streaming: bool,

    /// Whether agent supports push notifications.
    #[serde(rename = "pushNotifications")]
    pub push_notifications: bool,
}

/// Agent authentication configuration (A2A Protocol).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentAuthentication {
    /// Supported authentication schemes.
    pub schemes: Vec<String>,
}

/// Agent skill (tool capability) for A2A Protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentSkill {
    /// Skill/tool ID.
    pub id: String,

    /// Skill display name.
    pub name: String,

    /// Skill description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ============================================================================
// Can-Operate Response (F123 - Three-Layer Authorization)
// ============================================================================

/// Response from can-operate check (F123).
/// Determines if a user has permission to operate (run workflows with) an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CanOperateResponse {
    /// Whether the user can operate the agent.
    pub can_operate: bool,

    /// Reason for the decision.
    pub reason: String,

    /// Permissions the user has on the agent.
    pub permissions: Vec<String>,
}

// ============================================================================
// Common Responses
// ============================================================================

/// Simple success message response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MessageResponse {
    /// Success message.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_response_serialization() {
        let response = AgentResponse {
            id: Uuid::new_v4(),
            name: "test-agent".to_string(),
            description: Some("Test agent".to_string()),
            agent_type: "copilot".to_string(),
            owner_id: Some(Uuid::new_v4()),
            team_id: None,
            backup_owner_id: None,
            model_provider: Some("anthropic".to_string()),
            model_name: Some("claude-sonnet-4".to_string()),
            status: "active".to_string(),
            risk_level: "medium".to_string(),
            max_token_lifetime_secs: 900,
            requires_human_approval: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_activity_at: None,
            expires_at: None,
            // F108 governance fields
            inactivity_threshold_days: Some(90),
            grace_period_ends_at: None,
            suspension_reason: None,
            rotation_interval_days: None,
            last_rotation_at: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("test-agent"));
        assert!(json.contains("copilot"));
        assert!(json.contains("active"));
        // team_id should be omitted (skip_serializing_if)
        assert!(!json.contains("team_id"));
    }

    #[test]
    fn test_authorize_response_serialization() {
        let response = AuthorizeResponse {
            decision: "allow".to_string(),
            decision_id: Uuid::new_v4(),
            reason: "Agent has permission for tool".to_string(),
            latency_ms: 12.5,
            approval_request_id: None,
            anomaly_warnings: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("allow"));
        assert!(json.contains("12.5"));
        // approval_request_id and anomaly_warnings should be omitted (skip_serializing_if)
        assert!(!json.contains("approval_request_id"));
        assert!(!json.contains("anomaly_warnings"));
    }

    #[test]
    fn test_authorize_response_with_anomaly_warnings() {
        let response = AuthorizeResponse {
            decision: "allow".to_string(),
            decision_id: Uuid::new_v4(),
            reason: "Agent has permission for tool".to_string(),
            latency_ms: 15.0,
            approval_request_id: None,
            anomaly_warnings: Some(vec![AnomalyWarning {
                anomaly_type: "unusual_tool".to_string(),
                severity: "medium".to_string(),
                description: "Tool rarely used by this agent".to_string(),
                score: 65,
            }]),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("unusual_tool"));
        assert!(json.contains("medium"));
        assert!(json.contains("anomaly_warnings"));
    }

    #[test]
    fn test_agent_card_serialization() {
        let card = AgentCard {
            name: "sales-assistant".to_string(),
            description: Some("AI assistant for sales team".to_string()),
            url: "https://api.example.com/agents/sales-assistant".to_string(),
            version: "1.0.0".to_string(),
            protocol_version: "0.3".to_string(),
            capabilities: AgentCapabilities {
                streaming: false,
                push_notifications: false,
            },
            authentication: AgentAuthentication {
                schemes: vec!["bearer".to_string()],
            },
            skills: vec![AgentSkill {
                id: "send_email".to_string(),
                name: "Send Email".to_string(),
                description: Some("Send emails on behalf of users".to_string()),
            }],
        };

        let json = serde_json::to_string(&card).unwrap();
        assert!(json.contains("sales-assistant"));
        assert!(json.contains("protocolVersion"));
        assert!(json.contains("pushNotifications"));
        assert!(json.contains("send_email"));
    }

    #[test]
    fn test_tool_list_response() {
        let response = ToolListResponse {
            tools: vec![],
            total: 0,
            limit: 100,
            offset: 0,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: ToolListResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(response.total, deserialized.total);
        assert_eq!(response.limit, deserialized.limit);
    }

    #[test]
    fn test_permission_response_serialization() {
        let response = PermissionResponse {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            tool_id: Uuid::new_v4(),
            tool_name: "send_email".to_string(),
            allowed_parameters: Some(serde_json::json!({"max_recipients": 10})),
            max_calls_per_hour: Some(50),
            requires_approval: None,
            granted_at: Utc::now(),
            granted_by: Some(Uuid::new_v4()),
            expires_at: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("send_email"));
        assert!(json.contains("max_recipients"));
    }

    #[test]
    fn test_audit_event_response() {
        let response = AuditEventResponse {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            event_type: "authorization".to_string(),
            conversation_id: Some("conv-123".to_string()),
            session_id: Some("sess-456".to_string()),
            tool_name: Some("send_email".to_string()),
            decision: Some("allowed".to_string()),
            decision_reason: Some("Agent has permission".to_string()),
            outcome: Some("success".to_string()),
            timestamp: Utc::now(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("authorization"));
        assert!(json.contains("conv-123"));
    }
}
