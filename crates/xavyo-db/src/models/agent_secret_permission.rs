//! Agent Secret Permission model for dynamic secrets provisioning.
//!
//! Links AI agents to secret types they are permitted to access,
//! with optional overrides for TTL and rate limits.
//! Part of the SecretlessAI feature (F120).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Permission for an agent to access a secret type.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentSecretPermission {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant that owns this permission.
    pub tenant_id: Uuid,

    /// Agent this permission applies to.
    pub agent_id: Uuid,

    /// Secret type this permission grants access to.
    pub secret_type: String,

    /// Override for max TTL (optional, uses type default if not set).
    pub max_ttl_seconds: Option<i32>,

    /// Override for rate limit (optional, uses type default if not set).
    pub max_requests_per_hour: Option<i32>,

    /// When this permission expires (optional).
    pub expires_at: Option<DateTime<Utc>>,

    /// User who granted this permission.
    pub granted_by: Uuid,

    /// When permission was granted.
    pub granted_at: DateTime<Utc>,
}

impl AgentSecretPermission {
    /// Check if this permission is currently valid.
    pub fn is_valid(&self) -> bool {
        match self.expires_at {
            Some(expires) => expires > Utc::now(),
            None => true,
        }
    }

    /// Get the effective max TTL for this permission.
    pub fn effective_max_ttl(&self, type_max_ttl: i32) -> i32 {
        self.max_ttl_seconds
            .map(|ttl| ttl.min(type_max_ttl))
            .unwrap_or(type_max_ttl)
    }

    /// Get the effective rate limit for this permission.
    pub fn effective_rate_limit(&self, type_rate_limit: i32) -> i32 {
        self.max_requests_per_hour
            .map(|rate| rate.min(type_rate_limit))
            .unwrap_or(type_rate_limit)
    }
}

/// Request to grant a secret permission to an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GrantSecretPermission {
    /// Secret type to grant access to.
    pub secret_type: String,

    /// Override for max TTL (optional).
    pub max_ttl_seconds: Option<i32>,

    /// Override for rate limit (optional).
    pub max_requests_per_hour: Option<i32>,

    /// When this permission expires (optional).
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to update a secret permission.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateSecretPermission {
    /// Updated max TTL override.
    pub max_ttl_seconds: Option<Option<i32>>,

    /// Updated rate limit override.
    pub max_requests_per_hour: Option<Option<i32>>,

    /// Updated expiration time.
    pub expires_at: Option<Option<DateTime<Utc>>>,
}

/// Filter options for listing agent permissions.
#[derive(Debug, Clone, Default)]
pub struct AgentSecretPermissionFilter {
    /// Filter by agent ID.
    pub agent_id: Option<Uuid>,

    /// Filter by secret type.
    pub secret_type: Option<String>,

    /// Filter by granting user.
    pub granted_by: Option<Uuid>,

    /// Only include valid (non-expired) permissions.
    pub valid_only: bool,
}

impl AgentSecretPermission {
    /// Find a permission by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM agent_secret_permissions
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a specific permission for an agent and secret type.
    pub async fn find_by_agent_and_type(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        secret_type: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM agent_secret_permissions
            WHERE tenant_id = $1 AND agent_id = $2 AND secret_type = $3
            "#,
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(secret_type)
        .fetch_optional(pool)
        .await
    }

    /// Check if an agent has a valid permission for a secret type.
    pub async fn has_permission(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        secret_type: &str,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM agent_secret_permissions
            WHERE tenant_id = $1 AND agent_id = $2 AND secret_type = $3
            AND (expires_at IS NULL OR expires_at > NOW())
            "#,
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(secret_type)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// List permissions for a tenant with filtering.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &AgentSecretPermissionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM agent_secret_permissions
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.agent_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND agent_id = ${}", param_count));
        }

        if filter.secret_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND secret_type = ${}", param_count));
        }

        if filter.granted_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND granted_by = ${}", param_count));
        }

        if filter.valid_only {
            query.push_str(" AND (expires_at IS NULL OR expires_at > NOW())");
        }

        query.push_str(&format!(
            " ORDER BY granted_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, AgentSecretPermission>(&query).bind(tenant_id);

        if let Some(agent_id) = filter.agent_id {
            q = q.bind(agent_id);
        }
        if let Some(ref secret_type) = filter.secret_type {
            q = q.bind(secret_type);
        }
        if let Some(granted_by) = filter.granted_by {
            q = q.bind(granted_by);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// List all permissions for an agent.
    pub async fn list_by_agent(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM agent_secret_permissions
            WHERE tenant_id = $1 AND agent_id = $2
            AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY secret_type
            "#,
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_all(pool)
        .await
    }

    /// Grant a permission to an agent.
    pub async fn grant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        granted_by: Uuid,
        input: GrantSecretPermission,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO agent_secret_permissions (
                tenant_id, agent_id, secret_type, max_ttl_seconds,
                max_requests_per_hour, expires_at, granted_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (tenant_id, agent_id, secret_type)
            DO UPDATE SET
                max_ttl_seconds = EXCLUDED.max_ttl_seconds,
                max_requests_per_hour = EXCLUDED.max_requests_per_hour,
                expires_at = EXCLUDED.expires_at,
                granted_by = EXCLUDED.granted_by,
                granted_at = NOW()
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(&input.secret_type)
        .bind(input.max_ttl_seconds)
        .bind(input.max_requests_per_hour)
        .bind(input.expires_at)
        .bind(granted_by)
        .fetch_one(pool)
        .await
    }

    /// Update a permission.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateSecretPermission,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = Vec::new();
        let mut param_idx = 3;

        if input.max_ttl_seconds.is_some() {
            updates.push(format!("max_ttl_seconds = ${}", param_idx));
            param_idx += 1;
        }
        if input.max_requests_per_hour.is_some() {
            updates.push(format!("max_requests_per_hour = ${}", param_idx));
            param_idx += 1;
        }
        if input.expires_at.is_some() {
            updates.push(format!("expires_at = ${}", param_idx));
            // param_idx += 1;
        }

        if updates.is_empty() {
            return Self::find_by_id(pool, tenant_id, id).await;
        }

        let query = format!(
            "UPDATE agent_secret_permissions SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, AgentSecretPermission>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref max_ttl_opt) = input.max_ttl_seconds {
            q = q.bind(*max_ttl_opt);
        }
        if let Some(ref rate_opt) = input.max_requests_per_hour {
            q = q.bind(*rate_opt);
        }
        if let Some(ref expires_opt) = input.expires_at {
            q = q.bind(*expires_opt);
        }

        q.fetch_optional(pool).await
    }

    /// Revoke a permission (delete).
    pub async fn revoke(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        secret_type: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM agent_secret_permissions
            WHERE tenant_id = $1 AND agent_id = $2 AND secret_type = $3
            "#,
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(secret_type)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Revoke all permissions for an agent.
    pub async fn revoke_all_for_agent(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM agent_secret_permissions
            WHERE tenant_id = $1 AND agent_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(agent_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Delete expired permissions.
    pub async fn delete_expired(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM agent_secret_permissions
            WHERE tenant_id = $1 AND expires_at IS NOT NULL AND expires_at <= NOW()
            "#,
        )
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_is_valid() {
        use chrono::Duration;

        // No expiration - always valid
        let perm_no_expiry = AgentSecretPermission {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            secret_type: "test-type".to_string(),
            max_ttl_seconds: None,
            max_requests_per_hour: None,
            expires_at: None,
            granted_by: Uuid::new_v4(),
            granted_at: Utc::now(),
        };
        assert!(perm_no_expiry.is_valid());

        // Future expiration - valid
        let perm_future = AgentSecretPermission {
            expires_at: Some(Utc::now() + Duration::hours(1)),
            ..perm_no_expiry.clone()
        };
        assert!(perm_future.is_valid());

        // Past expiration - invalid
        let perm_past = AgentSecretPermission {
            expires_at: Some(Utc::now() - Duration::hours(1)),
            ..perm_no_expiry
        };
        assert!(!perm_past.is_valid());
    }

    #[test]
    fn test_effective_max_ttl() {
        let perm = AgentSecretPermission {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            secret_type: "test-type".to_string(),
            max_ttl_seconds: Some(300),
            max_requests_per_hour: None,
            expires_at: None,
            granted_by: Uuid::new_v4(),
            granted_at: Utc::now(),
        };

        // Use permission override (capped at type max)
        assert_eq!(perm.effective_max_ttl(600), 300);

        // Use type max when permission override exceeds it
        let perm_high = AgentSecretPermission {
            max_ttl_seconds: Some(900),
            ..perm.clone()
        };
        assert_eq!(perm_high.effective_max_ttl(600), 600);

        // Use type max when no override
        let perm_none = AgentSecretPermission {
            max_ttl_seconds: None,
            ..perm
        };
        assert_eq!(perm_none.effective_max_ttl(600), 600);
    }

    #[test]
    fn test_effective_rate_limit() {
        let perm = AgentSecretPermission {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            secret_type: "test-type".to_string(),
            max_ttl_seconds: None,
            max_requests_per_hour: Some(10),
            expires_at: None,
            granted_by: Uuid::new_v4(),
            granted_at: Utc::now(),
        };

        // Use permission override (capped at type rate)
        assert_eq!(perm.effective_rate_limit(100), 10);

        // Use type rate when permission override exceeds it
        let perm_high = AgentSecretPermission {
            max_requests_per_hour: Some(200),
            ..perm.clone()
        };
        assert_eq!(perm_high.effective_rate_limit(100), 100);

        // Use type rate when no override
        let perm_none = AgentSecretPermission {
            max_requests_per_hour: None,
            ..perm
        };
        assert_eq!(perm_none.effective_rate_limit(100), 100);
    }
}
