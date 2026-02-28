//! Cedar policy storage model.
//!
//! CRUD operations for Cedar policy records in PostgreSQL.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// A stored Cedar policy.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CedarPolicy {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub policy_text: String,
    pub schema_text: Option<String>,
    pub resource_type: Option<String>,
    pub agent_type: Option<String>,
    pub priority: i32,
    pub status: String,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Input for creating a new Cedar policy.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateCedarPolicy {
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub policy_text: String,
    pub schema_text: Option<String>,
    pub resource_type: Option<String>,
    pub agent_type: Option<String>,
    pub priority: Option<i32>,
    pub created_by: Option<Uuid>,
}

/// Input for updating an existing Cedar policy.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateCedarPolicy {
    pub name: Option<String>,
    pub description: Option<String>,
    pub policy_text: Option<String>,
    pub schema_text: Option<String>,
    pub resource_type: Option<String>,
    pub agent_type: Option<String>,
    pub priority: Option<i32>,
    pub status: Option<String>,
}

impl CedarPolicy {
    /// Create a new Cedar policy.
    pub async fn create(pool: &PgPool, input: CreateCedarPolicy) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            INSERT INTO cedar_policies (
                tenant_id, name, description, policy_text, schema_text,
                resource_type, agent_type, priority, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(input.tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&input.policy_text)
        .bind(&input.schema_text)
        .bind(&input.resource_type)
        .bind(&input.agent_type)
        .bind(input.priority.unwrap_or(100))
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Find a Cedar policy by ID and tenant.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>("SELECT * FROM cedar_policies WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .fetch_optional(pool)
            .await
    }

    /// List all active Cedar policies for a tenant.
    pub async fn list_active(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT * FROM cedar_policies
            WHERE tenant_id = $1 AND status = 'active'
            ORDER BY priority ASC, created_at ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List active Cedar policies filtered by resource type and/or agent type.
    ///
    /// Returns policies that either have no scope filter or match the given filters.
    pub async fn list_for_scope(
        pool: &PgPool,
        tenant_id: Uuid,
        resource_type: Option<&str>,
        agent_type: Option<&str>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT * FROM cedar_policies
            WHERE tenant_id = $1
              AND status = 'active'
              AND (resource_type IS NULL OR resource_type = $2)
              AND (agent_type IS NULL OR agent_type = $3)
            ORDER BY priority ASC, created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(resource_type)
        .bind(agent_type)
        .fetch_all(pool)
        .await
    }

    /// Update a Cedar policy using COALESCE pattern.
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateCedarPolicy,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            UPDATE cedar_policies SET
                name = COALESCE($3, name),
                description = COALESCE($4, description),
                policy_text = COALESCE($5, policy_text),
                schema_text = COALESCE($6, schema_text),
                resource_type = COALESCE($7, resource_type),
                agent_type = COALESCE($8, agent_type),
                priority = COALESCE($9, priority),
                status = COALESCE($10, status),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&input.policy_text)
        .bind(&input.schema_text)
        .bind(&input.resource_type)
        .bind(&input.agent_type)
        .bind(input.priority)
        .bind(&input.status)
        .fetch_optional(pool)
        .await
    }

    /// Delete a Cedar policy.
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM cedar_policies WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_cedar_policy_input() {
        let input = CreateCedarPolicy {
            tenant_id: Uuid::new_v4(),
            name: "agent-tool-access".to_string(),
            description: Some("Controls which tools agents can use".to_string()),
            policy_text:
                r#"permit(principal, action, resource) when { context.resource_type == "tool" };"#
                    .to_string(),
            schema_text: None,
            resource_type: Some("tool".to_string()),
            agent_type: None,
            priority: Some(50),
            created_by: Some(Uuid::new_v4()),
        };

        assert_eq!(input.name, "agent-tool-access");
        assert_eq!(input.priority, Some(50));
        assert!(input.description.is_some());
    }

    #[test]
    fn test_update_cedar_policy_default() {
        let update = UpdateCedarPolicy::default();
        assert!(update.name.is_none());
        assert!(update.policy_text.is_none());
        assert!(update.status.is_none());
    }

    #[test]
    fn test_cedar_policy_serialization() {
        let policy = CedarPolicy {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "test-policy".to_string(),
            description: None,
            policy_text: "permit(principal, action, resource);".to_string(),
            schema_text: None,
            resource_type: None,
            agent_type: None,
            priority: 100,
            status: "active".to_string(),
            created_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("test-policy"));
        assert!(json.contains("permit"));
        assert!(json.contains("active"));

        let deserialized: CedarPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "test-policy");
        assert_eq!(deserialized.priority, 100);
    }
}
