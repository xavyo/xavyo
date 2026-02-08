//! NHI Agent extension model (201-tool-nhi-promotion).
//!
//! Type-specific fields for AI agents. 1:1 relationship with `nhi_identities`
//! where `nhi_type = 'agent'`. Always queried via JOIN with `nhi_identities`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use xavyo_nhi::NhiLifecycleState;

/// Agent extension row (the `nhi_agents` table only).
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct NhiAgent {
    pub nhi_id: Uuid,
    pub agent_type: String,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub agent_card_url: Option<String>,
    pub agent_card_signature: Option<String>,
    pub max_token_lifetime_secs: i32,
    pub requires_human_approval: bool,
    pub team_id: Option<Uuid>,
}

/// Combined NHI identity + agent extension fields.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiAgentWithIdentity {
    // Base identity fields
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: Option<Uuid>,
    pub backup_owner_id: Option<Uuid>,
    pub lifecycle_state: NhiLifecycleState,
    pub suspension_reason: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub inactivity_threshold_days: Option<i32>,
    pub grace_period_ends_at: Option<DateTime<Utc>>,
    pub risk_score: Option<i32>,
    pub last_certified_at: Option<DateTime<Utc>>,
    pub next_certification_at: Option<DateTime<Utc>>,
    pub last_certified_by: Option<Uuid>,
    pub rotation_interval_days: Option<i32>,
    pub last_rotation_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
    // Agent-specific fields
    pub agent_type: String,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub agent_card_url: Option<String>,
    pub agent_card_signature: Option<String>,
    pub max_token_lifetime_secs: i32,
    pub requires_human_approval: bool,
    pub team_id: Option<Uuid>,
}

/// Request to create an agent extension row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNhiAgent {
    pub nhi_id: Uuid,
    pub agent_type: String,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub agent_card_url: Option<String>,
    pub agent_card_signature: Option<String>,
    pub max_token_lifetime_secs: i32,
    pub requires_human_approval: bool,
    pub team_id: Option<Uuid>,
}

/// Request to update an agent extension row.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateNhiAgent {
    pub agent_type: Option<String>,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub agent_card_url: Option<String>,
    pub agent_card_signature: Option<String>,
    pub max_token_lifetime_secs: Option<i32>,
    pub requires_human_approval: Option<bool>,
    pub team_id: Option<Uuid>,
}

/// Filter options for listing NHI agents.
#[derive(Debug, Clone, Default)]
pub struct NhiAgentFilter {
    pub agent_type: Option<String>,
    pub lifecycle_state: Option<NhiLifecycleState>,
    pub owner_id: Option<Uuid>,
    pub requires_human_approval: Option<bool>,
    pub team_id: Option<Uuid>,
}

const AGENT_JOIN_SELECT: &str = r"
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
";

impl NhiAgent {
    /// Insert an agent extension row. The base `nhi_identities` row must exist already.
    pub async fn create(pool: &PgPool, input: CreateNhiAgent) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO nhi_agents (
                nhi_id, agent_type, model_provider, model_name, model_version,
                agent_card_url, agent_card_signature,
                max_token_lifetime_secs, requires_human_approval, team_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            ",
        )
        .bind(input.nhi_id)
        .bind(&input.agent_type)
        .bind(&input.model_provider)
        .bind(&input.model_name)
        .bind(&input.model_version)
        .bind(&input.agent_card_url)
        .bind(&input.agent_card_signature)
        .bind(input.max_token_lifetime_secs)
        .bind(input.requires_human_approval)
        .bind(input.team_id)
        .fetch_one(pool)
        .await
    }

    /// Find an agent by NHI ID (returns joined identity + agent data).
    pub async fn find_by_nhi_id(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<Option<NhiAgentWithIdentity>, sqlx::Error> {
        let query = format!("{AGENT_JOIN_SELECT} WHERE i.tenant_id = $1 AND i.id = $2");
        sqlx::query_as::<_, NhiAgentWithIdentity>(&query)
            .bind(tenant_id)
            .bind(nhi_id)
            .fetch_optional(pool)
            .await
    }

    /// Update an agent extension row.
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        input: UpdateNhiAgent,
    ) -> Result<Option<NhiAgent>, sqlx::Error> {
        sqlx::query_as::<_, NhiAgent>(
            r"
            UPDATE nhi_agents
            SET agent_type = COALESCE($3, agent_type),
                model_provider = COALESCE($4, model_provider),
                model_name = COALESCE($5, model_name),
                model_version = COALESCE($6, model_version),
                agent_card_url = COALESCE($7, agent_card_url),
                agent_card_signature = COALESCE($8, agent_card_signature),
                max_token_lifetime_secs = COALESCE($9, max_token_lifetime_secs),
                requires_human_approval = COALESCE($10, requires_human_approval),
                team_id = COALESCE($11, team_id)
            WHERE nhi_id = $2
              AND EXISTS (SELECT 1 FROM nhi_identities WHERE id = $2 AND tenant_id = $1)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .bind(&input.agent_type)
        .bind(&input.model_provider)
        .bind(&input.model_name)
        .bind(&input.model_version)
        .bind(&input.agent_card_url)
        .bind(&input.agent_card_signature)
        .bind(input.max_token_lifetime_secs)
        .bind(input.requires_human_approval)
        .bind(input.team_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete an agent extension row (tenant-scoped).
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, nhi_id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM nhi_agents WHERE nhi_id = $1 AND EXISTS (SELECT 1 FROM nhi_identities WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(nhi_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// List agents for a tenant with optional filtering and pagination.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &NhiAgentFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NhiAgentWithIdentity>, sqlx::Error> {
        let limit = limit.min(100);
        let offset = offset.max(0);

        let mut query = format!("{AGENT_JOIN_SELECT} WHERE i.tenant_id = $1");
        let mut param_idx = 2;

        if filter.agent_type.is_some() {
            query.push_str(&format!(" AND a.agent_type = ${param_idx}"));
            param_idx += 1;
        }
        if filter.lifecycle_state.is_some() {
            query.push_str(&format!(" AND i.lifecycle_state = ${param_idx}"));
            param_idx += 1;
        }
        if filter.owner_id.is_some() {
            query.push_str(&format!(" AND i.owner_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.requires_human_approval.is_some() {
            query.push_str(&format!(" AND a.requires_human_approval = ${param_idx}"));
            param_idx += 1;
        }
        if filter.team_id.is_some() {
            query.push_str(&format!(" AND a.team_id = ${param_idx}"));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY i.name ASC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, NhiAgentWithIdentity>(&query).bind(tenant_id);

        if let Some(ref agent_type) = filter.agent_type {
            q = q.bind(agent_type);
        }
        if let Some(lifecycle_state) = filter.lifecycle_state {
            q = q.bind(lifecycle_state);
        }
        if let Some(owner_id) = filter.owner_id {
            q = q.bind(owner_id);
        }
        if let Some(requires_human_approval) = filter.requires_human_approval {
            q = q.bind(requires_human_approval);
        }
        if let Some(team_id) = filter.team_id {
            q = q.bind(team_id);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nhi_agent_serialization() {
        let agent = NhiAgent {
            nhi_id: Uuid::new_v4(),
            agent_type: "autonomous".to_string(),
            model_provider: Some("anthropic".to_string()),
            model_name: Some("claude-4".to_string()),
            model_version: Some("20260101".to_string()),
            agent_card_url: None,
            agent_card_signature: None,
            max_token_lifetime_secs: 900,
            requires_human_approval: false,
            team_id: None,
        };

        let json = serde_json::to_string(&agent).unwrap();
        let deserialized: NhiAgent = serde_json::from_str(&json).unwrap();
        assert_eq!(agent.agent_type, deserialized.agent_type);
        assert_eq!(
            agent.max_token_lifetime_secs,
            deserialized.max_token_lifetime_secs
        );
    }

    #[test]
    fn test_create_nhi_agent() {
        let input = CreateNhiAgent {
            nhi_id: Uuid::new_v4(),
            agent_type: "copilot".to_string(),
            model_provider: None,
            model_name: None,
            model_version: None,
            agent_card_url: None,
            agent_card_signature: None,
            max_token_lifetime_secs: 900,
            requires_human_approval: true,
            team_id: None,
        };

        assert_eq!(input.agent_type, "copilot");
        assert!(input.requires_human_approval);
    }

    #[test]
    fn test_update_nhi_agent_default() {
        let update = UpdateNhiAgent::default();
        assert!(update.agent_type.is_none());
        assert!(update.model_provider.is_none());
        assert!(update.max_token_lifetime_secs.is_none());
    }

    #[test]
    fn test_nhi_agent_filter_default() {
        let filter = NhiAgentFilter::default();
        assert!(filter.agent_type.is_none());
        assert!(filter.lifecycle_state.is_none());
        assert!(filter.owner_id.is_none());
    }
}
