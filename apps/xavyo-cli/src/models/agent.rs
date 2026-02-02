//! Agent data models for xavyo CLI

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Response for a single agent from the API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub agent_type: String,
    #[serde(default)]
    pub model_provider: Option<String>,
    #[serde(default)]
    pub model_name: Option<String>,
    pub status: String,
    pub risk_level: String,
    #[serde(default)]
    pub requires_human_approval: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Paginated list response for agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentListResponse {
    pub agents: Vec<AgentResponse>,
    pub total: i64,
    pub limit: i32,
    pub offset: i32,
}

/// Request to create a new agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAgentRequest {
    pub name: String,
    pub agent_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
}

impl CreateAgentRequest {
    pub fn new(name: String, agent_type: String) -> Self {
        Self {
            name,
            agent_type,
            description: None,
            model_provider: None,
            model_name: None,
            risk_level: None,
        }
    }

    pub fn with_model(mut self, provider: Option<String>, name: Option<String>) -> Self {
        self.model_provider = provider;
        self.model_name = name;
        self
    }

    pub fn with_risk_level(mut self, risk_level: String) -> Self {
        self.risk_level = Some(risk_level);
        self
    }

    pub fn with_description(mut self, description: Option<String>) -> Self {
        self.description = description;
        self
    }
}

// =============================================================================
// NHI Credential Models (F110)
// =============================================================================

/// Response for a single NHI credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiCredentialResponse {
    pub id: Uuid,
    pub nhi_id: Uuid,
    pub credential_type: String,
    pub is_active: bool,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub days_until_expiry: i64,
    pub created_at: DateTime<Utc>,
}

/// Response for listing NHI credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiCredentialListResponse {
    pub items: Vec<NhiCredentialResponse>,
    pub total: i64,
}

/// Response when rotating credentials - includes the secret value (shown once)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiCredentialCreatedResponse {
    pub credential: NhiCredentialResponse,
    pub secret_value: String,
    pub warning: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_period_ends_at: Option<DateTime<Utc>>,
}

/// Request to rotate credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateCredentialsRequest {
    pub credential_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_period_hours: Option<i32>,
}

impl RotateCredentialsRequest {
    pub fn new(credential_type: &str) -> Self {
        Self {
            credential_type: credential_type.to_string(),
            name: None,
            expires_at: None,
            grace_period_hours: None,
        }
    }

    pub fn with_grace_period(mut self, hours: i32) -> Self {
        self.grace_period_hours = Some(hours);
        self
    }
}

/// Request to revoke a credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeCredentialRequest {
    pub reason: String,
    #[serde(default = "default_immediate")]
    pub immediate: bool,
}

fn default_immediate() -> bool {
    true
}

impl RevokeCredentialRequest {
    pub fn new(reason: &str) -> Self {
        Self {
            reason: reason.to_string(),
            immediate: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_response_deserialization() {
        let json = r#"{
            "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "name": "my-bot",
            "agent_type": "copilot",
            "status": "active",
            "risk_level": "low",
            "requires_human_approval": false,
            "created_at": "2026-01-29T10:30:00Z",
            "updated_at": "2026-01-29T10:30:00Z"
        }"#;

        let agent: AgentResponse = serde_json::from_str(json).unwrap();
        assert_eq!(agent.name, "my-bot");
        assert_eq!(agent.agent_type, "copilot");
        assert_eq!(agent.status, "active");
        assert_eq!(agent.risk_level, "low");
        assert!(!agent.requires_human_approval);
        assert!(agent.description.is_none());
        assert!(agent.model_provider.is_none());
    }

    #[test]
    fn test_agent_response_with_optional_fields() {
        let json = r#"{
            "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "name": "security-bot",
            "description": "Security scanning agent",
            "agent_type": "autonomous",
            "model_provider": "anthropic",
            "model_name": "claude-sonnet-4",
            "status": "active",
            "risk_level": "high",
            "requires_human_approval": true,
            "created_at": "2026-01-29T10:30:00Z",
            "updated_at": "2026-01-29T10:30:00Z"
        }"#;

        let agent: AgentResponse = serde_json::from_str(json).unwrap();
        assert_eq!(agent.name, "security-bot");
        assert_eq!(
            agent.description.as_deref(),
            Some("Security scanning agent")
        );
        assert_eq!(agent.model_provider.as_deref(), Some("anthropic"));
        assert_eq!(agent.model_name.as_deref(), Some("claude-sonnet-4"));
        assert!(agent.requires_human_approval);
    }

    #[test]
    fn test_agent_list_response_deserialization() {
        let json = r#"{
            "agents": [
                {
                    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "name": "bot-1",
                    "agent_type": "copilot",
                    "status": "active",
                    "risk_level": "low",
                    "created_at": "2026-01-29T10:30:00Z",
                    "updated_at": "2026-01-29T10:30:00Z"
                }
            ],
            "total": 1,
            "limit": 50,
            "offset": 0
        }"#;

        let list: AgentListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(list.agents.len(), 1);
        assert_eq!(list.total, 1);
        assert_eq!(list.limit, 50);
        assert_eq!(list.offset, 0);
    }

    #[test]
    fn test_create_agent_request_serialization() {
        let request = CreateAgentRequest::new("my-bot".to_string(), "copilot".to_string())
            .with_model(
                Some("anthropic".to_string()),
                Some("claude-sonnet-4".to_string()),
            )
            .with_risk_level("medium".to_string());

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["name"], "my-bot");
        assert_eq!(json["agent_type"], "copilot");
        assert_eq!(json["model_provider"], "anthropic");
        assert_eq!(json["model_name"], "claude-sonnet-4");
        assert_eq!(json["risk_level"], "medium");
        assert!(json.get("description").is_none());
    }

    #[test]
    fn test_create_agent_request_minimal() {
        let request = CreateAgentRequest::new("simple-bot".to_string(), "workflow".to_string());

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["name"], "simple-bot");
        assert_eq!(json["agent_type"], "workflow");
        // Optional fields should not be present when None
        assert!(json.get("model_provider").is_none());
        assert!(json.get("risk_level").is_none());
    }
}
