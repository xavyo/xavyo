//! A2A Protocol AgentCard discovery handler.
//! Migrated from xavyo-api-agents (Feature 205).
//!
//! Uses SECURITY DEFINER functions (`public_find_agent_for_discovery`,
//! `public_list_agent_tools_for_discovery`) to bypass RLS for public
//! discovery endpoints. See migration 1205.

use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;

use crate::error::NhiApiError;
use crate::models::{AgentAuthentication, AgentCapabilities, AgentCard, AgentSkill};
use crate::state::NhiState;

/// Minimal agent info returned by the discovery function.
#[derive(Debug, sqlx::FromRow)]
struct DiscoveryAgent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub lifecycle_state: String,
    #[allow(dead_code)]
    pub agent_type: Option<String>,
    pub agent_card_url: Option<String>,
}

/// Minimal tool info returned by the discovery function.
#[derive(Debug, sqlx::FromRow)]
struct DiscoveryTool {
    pub tool_name: String,
    pub tool_description: Option<String>,
}

/// GET /.well-known/agents/{id} - A2A AgentCard discovery.
///
/// Returns the AgentCard for the specified agent in A2A Protocol v0.3 format.
/// This endpoint is publicly accessible for agent discovery.
///
/// Uses SECURITY DEFINER functions to bypass RLS (since this endpoint has no
/// authentication and no tenant context).
pub async fn get_agent_card(
    State(state): State<NhiState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgentCard>, NhiApiError> {
    // Find the agent using SECURITY DEFINER function (bypasses RLS)
    let agent = sqlx::query_as::<_, DiscoveryAgent>(
        r"SELECT id, tenant_id, name, description, lifecycle_state, agent_type, agent_card_url
          FROM public_find_agent_for_discovery($1)",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(NhiApiError::Database)?
    .ok_or(NhiApiError::NotFound)?;

    // Check if agent is active
    if agent.lifecycle_state != "active" {
        return Err(NhiApiError::NotFound);
    }

    // Get agent's tools using SECURITY DEFINER function (bypasses RLS)
    let tools = sqlx::query_as::<_, DiscoveryTool>(
        r"SELECT tool_name, tool_description
          FROM public_list_agent_tools_for_discovery($1, $2)",
    )
    .bind(agent.tenant_id)
    .bind(agent.id)
    .fetch_all(&state.pool)
    .await
    .map_err(NhiApiError::Database)?;

    let skills = tools
        .into_iter()
        .map(|t| AgentSkill {
            id: t.tool_name.clone(),
            name: t.tool_name.replace('_', " ").to_uppercase(),
            description: t.tool_description,
        })
        .collect();

    // Build the AgentCard
    let card = AgentCard {
        name: agent.name.clone(),
        description: agent.description,
        url: agent
            .agent_card_url
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
