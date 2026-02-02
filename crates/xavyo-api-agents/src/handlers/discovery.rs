//! A2A Protocol AgentCard discovery handler.

use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::{AgentAuthentication, AgentCapabilities, AgentCard, AgentSkill};
use crate::router::AgentsState;
use xavyo_db::models::ai_agent::AiAgent;
use xavyo_db::models::ai_agent_tool_permission::AiAgentToolPermission;
use xavyo_db::models::ai_tool::AiTool;

/// GET /.well-known/agents/{id} - A2A AgentCard discovery.
///
/// Returns the AgentCard for the specified agent in A2A Protocol v0.3 format.
/// This endpoint is publicly accessible for agent discovery.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/.well-known/agents/{id}",
    tag = "AI Agent Discovery",
    operation_id = "getAgentCard",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "AgentCard", body = AgentCard),
        (status = 404, description = "Agent not found"),
        (status = 410, description = "Agent not active")
    )
))]
pub async fn get_agent_card(
    State(state): State<AgentsState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgentCard>, ApiAgentsError> {
    // Find the agent - we need to find by ID without tenant context
    // For discovery, we search across all tenants (agent IDs are globally unique)
    let agent = find_agent_by_id(&state.pool, id)
        .await?
        .ok_or(ApiAgentsError::AgentNotFound)?;

    // Check if agent is active
    if !agent.is_active() {
        return Err(ApiAgentsError::AgentNotActive);
    }

    // Get the agent's tool permissions to populate skills
    let permissions =
        AiAgentToolPermission::list_by_agent(&state.pool, agent.tenant_id, agent.id).await?;

    // Get tool details for each permission
    let mut skills = Vec::new();
    for permission in permissions {
        if let Some(tool) =
            AiTool::find_by_id(&state.pool, agent.tenant_id, permission.tool_id).await?
        {
            if tool.status == "active" {
                skills.push(AgentSkill {
                    id: tool.name.clone(),
                    name: tool.name.replace('_', " ").to_uppercase(),
                    description: tool.description,
                });
            }
        }
    }

    // Build the AgentCard
    let card = AgentCard {
        name: agent.name.clone(),
        description: agent.description,
        url: agent
            .agent_card_url
            .clone()
            .unwrap_or_else(|| format!("https://api.xavyo.net/agents/{}", agent.name)),
        version: "1.0.0".to_string(),
        protocol_version: "0.3".to_string(),
        capabilities: AgentCapabilities {
            streaming: false,
            push_notifications: false,
        },
        authentication: AgentAuthentication {
            schemes: vec!["bearer".to_string()],
        },
        skills,
    };

    Ok(Json(card))
}

/// Find agent by ID across all tenants.
///
/// Note: Agent IDs are globally unique UUIDs, so this is safe.
/// For public discovery, we don't require tenant context.
async fn find_agent_by_id(pool: &sqlx::PgPool, id: Uuid) -> Result<Option<AiAgent>, sqlx::Error> {
    sqlx::query_as::<_, AiAgent>(
        r#"
        SELECT * FROM ai_agents
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_card_structure() {
        let card = AgentCard {
            name: "test-agent".to_string(),
            description: Some("Test description".to_string()),
            url: "https://example.com/agent".to_string(),
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
                id: "test_skill".to_string(),
                name: "Test Skill".to_string(),
                description: Some("A test skill".to_string()),
            }],
        };

        let json = serde_json::to_string(&card).unwrap();
        assert!(json.contains("protocolVersion"));
        assert!(json.contains("0.3"));
        assert!(json.contains("pushNotifications"));
    }
}
