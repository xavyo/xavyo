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
    pub lifecycle_state: String,
    #[serde(default)]
    pub risk_score: Option<i32>,
    #[serde(default)]
    pub requires_human_approval: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Paginated list response for agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentListResponse {
    pub data: Vec<AgentResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
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
}

impl CreateAgentRequest {
    pub fn new(name: String, agent_type: String) -> Self {
        Self {
            name,
            agent_type,
            description: None,
            model_provider: None,
            model_name: None,
        }
    }

    pub fn with_model(mut self, provider: Option<String>, name: Option<String>) -> Self {
        self.model_provider = provider;
        self.model_name = name;
        self
    }

    pub fn with_description(mut self, description: Option<String>) -> Self {
        self.description = description;
        self
    }
}

// =============================================================================
// Update Agent Models (F-051)
// =============================================================================

/// Request to update an existing agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAgentRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

impl UpdateAgentRequest {
    pub fn new() -> Self {
        Self {
            name: None,
            description: None,
            status: None,
        }
    }

    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    pub fn with_status(mut self, status: String) -> Self {
        self.status = Some(status);
        self
    }

    /// Check if at least one field is set
    pub fn has_changes(&self) -> bool {
        self.name.is_some() || self.description.is_some() || self.status.is_some()
    }
}

impl Default for UpdateAgentRequest {
    fn default() -> Self {
        Self::new()
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
            "lifecycle_state": "active",
            "requires_human_approval": false,
            "created_at": "2026-01-29T10:30:00Z",
            "updated_at": "2026-01-29T10:30:00Z"
        }"#;

        let agent: AgentResponse = serde_json::from_str(json).unwrap();
        assert_eq!(agent.name, "my-bot");
        assert_eq!(agent.agent_type, "copilot");
        assert_eq!(agent.lifecycle_state, "active");
        assert!(agent.risk_score.is_none());
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
            "lifecycle_state": "active",
            "risk_score": 85,
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
        assert_eq!(agent.risk_score, Some(85));
        assert!(agent.requires_human_approval);
    }

    #[test]
    fn test_agent_list_response_deserialization() {
        let json = r#"{
            "data": [
                {
                    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "name": "bot-1",
                    "agent_type": "copilot",
                    "lifecycle_state": "active",
                    "created_at": "2026-01-29T10:30:00Z",
                    "updated_at": "2026-01-29T10:30:00Z"
                }
            ],
            "total": 1,
            "limit": 50,
            "offset": 0
        }"#;

        let list: AgentListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(list.data.len(), 1);
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
            );

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["name"], "my-bot");
        assert_eq!(json["agent_type"], "copilot");
        assert_eq!(json["model_provider"], "anthropic");
        assert_eq!(json["model_name"], "claude-sonnet-4");
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
    }

    // F-051: Update agent request tests

    #[test]
    fn test_update_agent_request_serialization() {
        let request = UpdateAgentRequest::new()
            .with_name("new-name".to_string())
            .with_status("inactive".to_string());

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["name"], "new-name");
        assert_eq!(json["status"], "inactive");
        // Description not set, should not be present
        assert!(json.get("description").is_none());
    }

    #[test]
    fn test_update_agent_request_has_changes() {
        let empty = UpdateAgentRequest::new();
        assert!(!empty.has_changes());

        let with_name = UpdateAgentRequest::new().with_name("test".to_string());
        assert!(with_name.has_changes());

        let with_desc = UpdateAgentRequest::new().with_description("desc".to_string());
        assert!(with_desc.has_changes());

        let with_status = UpdateAgentRequest::new().with_status("active".to_string());
        assert!(with_status.has_changes());
    }

    #[test]
    fn test_update_agent_request_minimal_serialization() {
        let request = UpdateAgentRequest::new();
        let json = serde_json::to_value(&request).unwrap();
        // All fields are None, so JSON should be empty object
        assert!(json.get("name").is_none());
        assert!(json.get("description").is_none());
        assert!(json.get("status").is_none());
    }
}
