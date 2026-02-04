//! Authorization Policy model (F083).
//!
//! Represents tenant-scoped authorization policies with allow/deny effects.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// An authorization policy.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AuthorizationPolicy {
    /// Unique identifier for the policy.
    pub id: Uuid,

    /// The tenant this policy belongs to.
    pub tenant_id: Uuid,

    /// Human-readable policy name.
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// Effect: "allow" or "deny".
    pub effect: String,

    /// Priority (lower = evaluated first).
    pub priority: i32,

    /// Status: "active" or "inactive".
    pub status: String,

    /// Optional resource type filter (None = wildcard).
    pub resource_type: Option<String>,

    /// Optional action filter (None = wildcard).
    pub action: Option<String>,

    /// Who created this policy.
    pub created_by: Option<Uuid>,

    /// When the policy was created.
    pub created_at: DateTime<Utc>,

    /// When the policy was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new authorization policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAuthorizationPolicy {
    pub name: String,
    pub description: Option<String>,
    pub effect: String,
    pub priority: i32,
    pub resource_type: Option<String>,
    pub action: Option<String>,
    pub created_by: Option<Uuid>,
}

/// Request to update an authorization policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAuthorizationPolicy {
    pub name: Option<String>,
    pub description: Option<String>,
    pub effect: Option<String>,
    pub priority: Option<i32>,
    pub status: Option<String>,
    pub resource_type: Option<String>,
    pub action: Option<String>,
}

impl AuthorizationPolicy {
    /// Find a policy by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM authorization_policies
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find all active policies for a tenant, ordered by priority (deny first, then by priority asc).
    pub async fn find_active_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM authorization_policies
            WHERE tenant_id = $1 AND status = 'active'
            ORDER BY
                CASE effect WHEN 'deny' THEN 0 ELSE 1 END,
                priority ASC,
                created_at ASC
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List all policies for a tenant with pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM authorization_policies
            WHERE tenant_id = $1
            ORDER BY priority ASC, created_at DESC
            LIMIT $2 OFFSET $3
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Count policies for a tenant.
    pub async fn count_by_tenant(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
        let result: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM authorization_policies
            WHERE tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(result.0)
    }

    /// Create a new authorization policy.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateAuthorizationPolicy,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO authorization_policies (
                tenant_id, name, description, effect, priority,
                resource_type, action, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&input.effect)
        .bind(input.priority)
        .bind(&input.resource_type)
        .bind(&input.action)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Update an authorization policy.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateAuthorizationPolicy,
    ) -> Result<Option<Self>, sqlx::Error> {
        let existing = Self::find_by_id(pool, tenant_id, id).await?;
        let existing = match existing {
            Some(e) => e,
            None => return Ok(None),
        };

        let name = input.name.unwrap_or(existing.name);
        let description = input.description.or(existing.description);
        let effect = input.effect.unwrap_or(existing.effect);
        let priority = input.priority.unwrap_or(existing.priority);
        let status = input.status.unwrap_or(existing.status);
        let resource_type = input.resource_type.or(existing.resource_type);
        let action = input.action.or(existing.action);

        sqlx::query_as(
            r"
            UPDATE authorization_policies
            SET name = $3, description = $4, effect = $5, priority = $6,
                status = $7, resource_type = $8, action = $9, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&name)
        .bind(&description)
        .bind(&effect)
        .bind(priority)
        .bind(&status)
        .bind(&resource_type)
        .bind(&action)
        .fetch_optional(pool)
        .await
    }

    /// Delete an authorization policy.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM authorization_policies
            WHERE id = $1 AND tenant_id = $2
            ",
        )
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
    fn test_create_policy_request() {
        let request = CreateAuthorizationPolicy {
            name: "deny-after-hours".to_string(),
            description: Some("Deny access outside business hours".to_string()),
            effect: "deny".to_string(),
            priority: 10,
            resource_type: None,
            action: None,
            created_by: Some(Uuid::new_v4()),
        };

        assert_eq!(request.effect, "deny");
        assert_eq!(request.priority, 10);
    }

    #[test]
    fn test_policy_serialization() {
        let policy = AuthorizationPolicy {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "test-policy".to_string(),
            description: None,
            effect: "allow".to_string(),
            priority: 100,
            status: "active".to_string(),
            resource_type: Some("document".to_string()),
            action: Some("read".to_string()),
            created_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("test-policy"));
        assert!(json.contains("allow"));
    }
}
