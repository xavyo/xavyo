use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// A reusable template for agent provisioning.
///
/// Blueprints capture agent configuration (model, permissions, delegation)
/// so organisations can provision agents consistently.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiAgentBlueprint {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub agent_type: String,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub max_token_lifetime_secs: i32,
    pub requires_human_approval: bool,
    pub default_entitlements: Vec<String>,
    pub default_delegation: Option<serde_json::Value>,
    pub tags: Vec<String>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Input for creating a new agent blueprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNhiAgentBlueprint {
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub agent_type: String,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub max_token_lifetime_secs: i32,
    pub requires_human_approval: bool,
    pub default_entitlements: Vec<String>,
    pub default_delegation: Option<serde_json::Value>,
    pub tags: Vec<String>,
    pub created_by: Option<Uuid>,
}

/// Input for updating an existing agent blueprint.
/// All fields are optional — `None` means "don't change".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateNhiAgentBlueprint {
    pub name: Option<String>,
    pub description: Option<String>,
    pub agent_type: Option<String>,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub max_token_lifetime_secs: Option<i32>,
    pub requires_human_approval: Option<bool>,
    pub default_entitlements: Option<Vec<String>>,
    pub default_delegation: Option<serde_json::Value>,
    pub tags: Option<Vec<String>>,
}

/// Filter criteria for listing blueprints.
#[derive(Debug, Clone, Default)]
pub struct NhiAgentBlueprintFilter {
    pub agent_type: Option<String>,
    pub created_by: Option<Uuid>,
    pub tag: Option<String>,
}

impl NhiAgentBlueprint {
    pub async fn create(
        pool: &PgPool,
        input: CreateNhiAgentBlueprint,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO nhi_agent_blueprints (
                tenant_id, name, description, agent_type,
                model_provider, model_name, model_version,
                max_token_lifetime_secs, requires_human_approval,
                default_entitlements, default_delegation, tags, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
            ",
        )
        .bind(input.tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&input.agent_type)
        .bind(&input.model_provider)
        .bind(&input.model_name)
        .bind(&input.model_version)
        .bind(input.max_token_lifetime_secs)
        .bind(input.requires_human_approval)
        .bind(&input.default_entitlements)
        .bind(&input.default_delegation)
        .bind(&input.tags)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM nhi_agent_blueprints
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    pub async fn find_by_name(
        pool: &PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM nhi_agent_blueprints
            WHERE tenant_id = $1 AND name = $2
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateNhiAgentBlueprint,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            UPDATE nhi_agent_blueprints
            SET name = COALESCE($3, name),
                description = COALESCE($4, description),
                agent_type = COALESCE($5, agent_type),
                model_provider = COALESCE($6, model_provider),
                model_name = COALESCE($7, model_name),
                model_version = COALESCE($8, model_version),
                max_token_lifetime_secs = COALESCE($9, max_token_lifetime_secs),
                requires_human_approval = COALESCE($10, requires_human_approval),
                default_entitlements = COALESCE($11, default_entitlements),
                default_delegation = COALESCE($12, default_delegation),
                tags = COALESCE($13, tags),
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&input.agent_type)
        .bind(&input.model_provider)
        .bind(&input.model_name)
        .bind(&input.model_version)
        .bind(input.max_token_lifetime_secs)
        .bind(input.requires_human_approval)
        .bind(&input.default_entitlements)
        .bind(&input.default_delegation)
        .bind(&input.tags)
        .fetch_optional(pool)
        .await
    }

    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM nhi_agent_blueprints
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &NhiAgentBlueprintFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let limit = limit.min(100);
        let offset = offset.max(0);

        let mut query = "SELECT * FROM nhi_agent_blueprints WHERE tenant_id = $1".to_string();
        let mut param_idx: u32 = 2;

        if filter.agent_type.is_some() {
            query.push_str(&format!(" AND agent_type = ${param_idx}"));
            param_idx += 1;
        }
        if filter.created_by.is_some() {
            query.push_str(&format!(" AND created_by = ${param_idx}"));
            param_idx += 1;
        }
        if filter.tag.is_some() {
            query.push_str(&format!(" AND ${param_idx} = ANY(tags)"));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY name ASC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(ref agent_type) = filter.agent_type {
            q = q.bind(agent_type);
        }
        if let Some(created_by) = filter.created_by {
            q = q.bind(created_by);
        }
        if let Some(ref tag) = filter.tag {
            q = q.bind(tag);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    pub async fn count(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &NhiAgentBlueprintFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            "SELECT COUNT(*) as count FROM nhi_agent_blueprints WHERE tenant_id = $1".to_string();
        let mut param_idx: u32 = 2;

        if filter.agent_type.is_some() {
            query.push_str(&format!(" AND agent_type = ${param_idx}"));
            param_idx += 1;
        }
        if filter.created_by.is_some() {
            query.push_str(&format!(" AND created_by = ${param_idx}"));
            param_idx += 1;
        }
        if filter.tag.is_some() {
            query.push_str(&format!(" AND ${param_idx} = ANY(tags)"));
            #[allow(unused_assignments)]
            {
                param_idx += 1;
            }
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(ref agent_type) = filter.agent_type {
            q = q.bind(agent_type);
        }
        if let Some(created_by) = filter.created_by {
            q = q.bind(created_by);
        }
        if let Some(ref tag) = filter.tag {
            q = q.bind(tag);
        }

        q.fetch_one(pool).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_input_serializes() {
        let input = CreateNhiAgentBlueprint {
            tenant_id: Uuid::new_v4(),
            name: "crm-agent".into(),
            description: Some("CRM digital twin blueprint".into()),
            agent_type: "autonomous".into(),
            model_provider: Some("anthropic".into()),
            model_name: Some("claude-sonnet-4-6".into()),
            model_version: None,
            max_token_lifetime_secs: 3600,
            requires_human_approval: false,
            default_entitlements: vec!["crm:read".into(), "crm:write".into()],
            default_delegation: Some(serde_json::json!({
                "enabled": true,
                "max_delegation_depth": 1,
                "allowed_scopes": ["crm:read", "crm:write"]
            })),
            tags: vec!["crm".into(), "sales".into()],
            created_by: Some(Uuid::new_v4()),
        };

        let json = serde_json::to_string(&input).unwrap();
        let parsed: CreateNhiAgentBlueprint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "crm-agent");
        assert_eq!(parsed.agent_type, "autonomous");
        assert_eq!(parsed.default_entitlements.len(), 2);
        assert_eq!(parsed.tags.len(), 2);
    }

    #[test]
    fn update_input_defaults_to_none() {
        let update = UpdateNhiAgentBlueprint::default();
        assert!(update.name.is_none());
        assert!(update.agent_type.is_none());
        assert!(update.default_entitlements.is_none());
    }

    #[test]
    fn filter_defaults_to_none() {
        let filter = NhiAgentBlueprintFilter::default();
        assert!(filter.agent_type.is_none());
        assert!(filter.created_by.is_none());
        assert!(filter.tag.is_none());
    }
}
