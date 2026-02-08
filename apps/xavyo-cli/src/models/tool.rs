//! Tool data models for xavyo CLI

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Response for a single tool from the API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    pub input_schema: serde_json::Value,
    #[serde(default)]
    pub output_schema: Option<serde_json::Value>,
    #[serde(default)]
    pub risk_score: Option<i32>,
    pub requires_approval: bool,
    #[serde(default)]
    pub max_calls_per_hour: Option<i32>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub provider_verified: bool,
    pub lifecycle_state: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Paginated list response for tools
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolListResponse {
    pub data: Vec<ToolResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Request to create a new tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateToolRequest {
    pub name: String,
    pub input_schema: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_calls_per_hour: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

impl CreateToolRequest {
    pub fn new(name: String, input_schema: serde_json::Value) -> Self {
        Self {
            name,
            input_schema,
            description: None,
            category: None,
            output_schema: None,
            requires_approval: None,
            max_calls_per_hour: None,
            provider: None,
        }
    }

    pub fn with_description(mut self, description: Option<String>) -> Self {
        self.description = description;
        self
    }

    pub fn with_category(mut self, category: Option<String>) -> Self {
        self.category = category;
        self
    }

    pub fn with_requires_approval(mut self, requires_approval: bool) -> Self {
        self.requires_approval = Some(requires_approval);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_response_deserialization() {
        let json = r#"{
            "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "name": "send_email",
            "input_schema": {"type": "object"},
            "requires_approval": false,
            "provider_verified": false,
            "lifecycle_state": "active",
            "created_at": "2026-01-29T10:30:00Z",
            "updated_at": "2026-01-29T10:30:00Z"
        }"#;

        let tool: ToolResponse = serde_json::from_str(json).unwrap();
        assert_eq!(tool.name, "send_email");
        assert!(tool.risk_score.is_none());
        assert_eq!(tool.lifecycle_state, "active");
        assert!(!tool.requires_approval);
        assert!(tool.description.is_none());
        assert!(tool.category.is_none());
    }

    #[test]
    fn test_tool_response_with_optional_fields() {
        let json = r#"{
            "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "name": "query_database",
            "description": "Execute database queries",
            "category": "data",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"}
                },
                "required": ["query"]
            },
            "output_schema": {"type": "array"},
            "risk_score": 75,
            "requires_approval": true,
            "max_calls_per_hour": 100,
            "provider": "internal",
            "provider_verified": true,
            "lifecycle_state": "active",
            "created_at": "2026-01-29T10:30:00Z",
            "updated_at": "2026-01-29T10:30:00Z"
        }"#;

        let tool: ToolResponse = serde_json::from_str(json).unwrap();
        assert_eq!(tool.name, "query_database");
        assert_eq!(
            tool.description.as_deref(),
            Some("Execute database queries")
        );
        assert_eq!(tool.category.as_deref(), Some("data"));
        assert_eq!(tool.risk_score, Some(75));
        assert!(tool.requires_approval);
        assert_eq!(tool.max_calls_per_hour, Some(100));
        assert!(tool.provider_verified);
    }

    #[test]
    fn test_tool_list_response_deserialization() {
        let json = r#"{
            "data": [
                {
                    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "name": "tool-1",
                    "input_schema": {"type": "object"},
                    "requires_approval": false,
                    "provider_verified": false,
                    "lifecycle_state": "active",
                    "created_at": "2026-01-29T10:30:00Z",
                    "updated_at": "2026-01-29T10:30:00Z"
                }
            ],
            "total": 1,
            "limit": 50,
            "offset": 0
        }"#;

        let list: ToolListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(list.data.len(), 1);
        assert_eq!(list.total, 1);
        assert_eq!(list.limit, 50);
        assert_eq!(list.offset, 0);
    }

    #[test]
    fn test_create_tool_request_serialization() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "to": {"type": "string", "format": "email"}
            }
        });

        let request = CreateToolRequest::new("send_email".to_string(), schema)
            .with_description(Some("Send emails".to_string()))
            .with_category(Some("communication".to_string()))
            .with_requires_approval(true);

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["name"], "send_email");
        assert_eq!(json["description"], "Send emails");
        assert_eq!(json["category"], "communication");
        assert_eq!(json["requires_approval"], true);
        // risk_level should NOT be present (removed from model)
        assert!(json.get("risk_level").is_none());
    }

    #[test]
    fn test_create_tool_request_minimal() {
        let request = CreateToolRequest::new(
            "simple_tool".to_string(),
            serde_json::json!({"type": "object"}),
        );

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["name"], "simple_tool");
        // Optional fields should not be present when None
        assert!(json.get("description").is_none());
        assert!(json.get("category").is_none());
        assert!(json.get("risk_level").is_none());
    }
}
