//! A2A Protocol AgentCard discovery handler.
//! Migrated from xavyo-api-agents (Feature 205).

use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;

use crate::error::NhiApiError;
use crate::models::{AgentAuthentication, AgentCapabilities, AgentCard, AgentSkill};
use crate::state::NhiState;
use xavyo_db::models::nhi_tool::NhiTool;
use xavyo_db::models::{NhiAgentWithIdentity, NhiToolPermission};
use xavyo_nhi::NhiLifecycleState;

/// GET /.well-known/agents/{id} - A2A AgentCard discovery.
///
/// Returns the AgentCard for the specified agent in A2A Protocol v0.3 format.
/// This endpoint is publicly accessible for agent discovery.
pub async fn get_agent_card(
    State(state): State<NhiState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgentCard>, NhiApiError> {
    // Find the agent across all tenants (public discovery, IDs are globally unique)
    let agent = find_agent_by_id(&state.pool, id)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    // Check if agent is active
    if agent.lifecycle_state != NhiLifecycleState::Active {
        return Err(NhiApiError::NotFound);
    }

    // Get the agent's tool permissions to populate skills
    let permissions =
        NhiToolPermission::list_by_agent(&state.pool, agent.tenant_id, agent.id, 100, 0)
            .await
            .map_err(NhiApiError::Database)?;

    // Get tool details for each permission
    let mut skills = Vec::new();
    for permission in permissions {
        if let Some(tool) =
            NhiTool::find_by_nhi_id(&state.pool, agent.tenant_id, permission.tool_nhi_id)
                .await
                .map_err(NhiApiError::Database)?
        {
            if tool.lifecycle_state == NhiLifecycleState::Active {
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

/// Find agent by ID across all tenants (for public discovery).
async fn find_agent_by_id(
    pool: &sqlx::PgPool,
    id: Uuid,
) -> Result<Option<NhiAgentWithIdentity>, NhiApiError> {
    let result = sqlx::query_as::<_, NhiAgentWithIdentity>(
        r"
        SELECT i.id, i.tenant_id, i.name, i.description, i.owner_id, i.backup_owner_id,
               i.lifecycle_state, i.suspension_reason, i.expires_at, i.last_activity_at,
               i.inactivity_threshold_days, i.grace_period_ends_at, i.risk_score,
               i.last_certified_at, i.next_certification_at, i.last_certified_by,
               i.rotation_interval_days, i.last_rotation_at, i.created_at, i.updated_at, i.created_by,
               a.agent_type, a.model_provider, a.model_name, a.model_version,
               a.agent_card_url, a.agent_card_signature,
               a.max_token_lifetime_secs, a.requires_human_approval, a.team_id
        FROM nhi_identities i
        INNER JOIN nhi_agents a ON a.nhi_id = i.id
        WHERE i.id = $1 AND i.nhi_type = 'agent'
        ",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(NhiApiError::Database)?;

    Ok(result)
}
