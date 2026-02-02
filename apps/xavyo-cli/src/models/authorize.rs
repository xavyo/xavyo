//! Authorization data models for xavyo CLI

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request to authorize an agent action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    /// Agent ID requesting authorization
    pub agent_id: Uuid,
    /// Tool name to authorize
    pub tool: String,
    /// Tool invocation parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
    /// Authorization context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<AuthorizationContext>,
}

/// Context for authorization requests
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthorizationContext {
    /// Conversation/session ID for audit trail
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    /// Session ID for correlation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// User instruction that triggered the action
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_instruction: Option<String>,
}

/// Response from authorization service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    /// Authorization decision: allow, deny, require_approval
    pub decision: String,
    /// Decision ID for audit trail correlation
    pub decision_id: Uuid,
    /// Reason for the decision
    pub reason: String,
    /// Decision latency in milliseconds
    pub latency_ms: f64,
    /// Approval request ID (if decision is require_approval)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<Uuid>,
}

impl AuthorizeRequest {
    pub fn new(agent_id: Uuid, tool: String) -> Self {
        Self {
            agent_id,
            tool,
            parameters: None,
            context: None,
        }
    }

    pub fn with_parameters(mut self, parameters: Option<serde_json::Value>) -> Self {
        self.parameters = parameters;
        self
    }

    pub fn with_context(mut self, context: Option<AuthorizationContext>) -> Self {
        self.context = context;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorize_request_serialization() {
        let request = AuthorizeRequest::new(
            Uuid::parse_str("a1b2c3d4-e5f6-7890-abcd-ef1234567890").unwrap(),
            "send_email".to_string(),
        );

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["tool"], "send_email");
        assert!(json.get("parameters").is_none());
        assert!(json.get("context").is_none());
    }

    #[test]
    fn test_authorize_request_with_context() {
        let context = AuthorizationContext {
            conversation_id: Some("conv-123".to_string()),
            session_id: Some("sess-456".to_string()),
            user_instruction: None,
        };

        let request = AuthorizeRequest::new(
            Uuid::parse_str("a1b2c3d4-e5f6-7890-abcd-ef1234567890").unwrap(),
            "send_email".to_string(),
        )
        .with_context(Some(context))
        .with_parameters(Some(serde_json::json!({"to": "test@example.com"})));

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["tool"], "send_email");
        assert_eq!(json["context"]["conversation_id"], "conv-123");
        assert_eq!(json["parameters"]["to"], "test@example.com");
    }

    #[test]
    fn test_authorize_response_deserialization() {
        let json = r#"{
            "decision": "allow",
            "decision_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "reason": "Agent has permission for tool",
            "latency_ms": 12.5
        }"#;

        let response: AuthorizeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.decision, "allow");
        assert_eq!(response.reason, "Agent has permission for tool");
        assert_eq!(response.latency_ms, 12.5);
        assert!(response.approval_request_id.is_none());
    }

    #[test]
    fn test_authorize_response_with_approval_id() {
        let json = r#"{
            "decision": "require_approval",
            "decision_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "reason": "Tool requires human approval",
            "latency_ms": 15.3,
            "approval_request_id": "b2c3d4e5-f607-8901-bcde-f12345678901"
        }"#;

        let response: AuthorizeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.decision, "require_approval");
        assert!(response.approval_request_id.is_some());
    }

    #[test]
    fn test_authorization_context_serialization() {
        let context = AuthorizationContext {
            conversation_id: Some("conv-123".to_string()),
            session_id: None,
            user_instruction: Some("Send email".to_string()),
        };

        let json = serde_json::to_value(&context).unwrap();
        assert_eq!(json["conversation_id"], "conv-123");
        assert!(json.get("session_id").is_none());
        assert_eq!(json["user_instruction"], "Send email");
    }
}
