//! A2A Protocol AgentCard discovery models.
//!
//! Response types for the A2A AgentCard discovery endpoint.
//! Migrated from xavyo-api-agents (Feature 205).

use serde::{Deserialize, Serialize};

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

/// A2A Protocol `AgentCard` for agent discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct AgentCapabilities {
    /// Whether agent supports streaming.
    pub streaming: bool,

    /// Whether agent supports push notifications.
    #[serde(rename = "pushNotifications")]
    pub push_notifications: bool,
}

/// Agent authentication configuration (A2A Protocol).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct AgentAuthentication {
    /// Supported authentication schemes.
    pub schemes: Vec<String>,
}

/// Agent skill (tool capability) for A2A Protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct AgentSkill {
    /// Skill/tool ID.
    pub id: String,

    /// Skill display name.
    pub name: String,

    /// Skill description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
