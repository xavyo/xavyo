//! NHI Tool Permission model (201-tool-nhi-promotion).
//!
//! Agent-to-tool permission grants. Both `agent_nhi_id` and `tool_nhi_id`
//! reference `nhi_identities`. Replaces `ai_agent_tool_permissions`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// An NHI tool permission record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiToolPermission {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub agent_nhi_id: Uuid,
    pub tool_nhi_id: Uuid,
    pub allowed_parameters: Option<serde_json::Value>,
    pub max_calls_per_hour: Option<i32>,
    pub requires_approval: Option<bool>,
    pub granted_at: DateTime<Utc>,
    pub granted_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to grant a tool permission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNhiToolPermission {
    pub agent_nhi_id: Uuid,
    pub tool_nhi_id: Uuid,
    pub allowed_parameters: Option<serde_json::Value>,
    pub max_calls_per_hour: Option<i32>,
    pub requires_approval: Option<bool>,
    pub granted_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl NhiToolPermission {
    /// Check if the permission has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            expires_at < Utc::now()
        } else {
            false
        }
    }

    /// Check if the permission is currently valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }

    /// Grant a permission (upsert on unique constraint).
    pub async fn grant(
        pool: &PgPool,
        tenant_id: Uuid,
        input: CreateNhiToolPermission,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            INSERT INTO nhi_tool_permissions (
                tenant_id, agent_nhi_id, tool_nhi_id, allowed_parameters,
                max_calls_per_hour, requires_approval, granted_by, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (tenant_id, agent_nhi_id, tool_nhi_id)
            DO UPDATE SET
                allowed_parameters = EXCLUDED.allowed_parameters,
                max_calls_per_hour = EXCLUDED.max_calls_per_hour,
                requires_approval = EXCLUDED.requires_approval,
                granted_at = NOW(),
                granted_by = EXCLUDED.granted_by,
                expires_at = EXCLUDED.expires_at
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.agent_nhi_id)
        .bind(input.tool_nhi_id)
        .bind(&input.allowed_parameters)
        .bind(input.max_calls_per_hour)
        .bind(input.requires_approval)
        .bind(input.granted_by)
        .bind(input.expires_at)
        .fetch_one(pool)
        .await
    }

    /// Find a permission by ID within a tenant.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM nhi_tool_permissions
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Find a permission by agent-tool pair.
    pub async fn find_by_pair(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_nhi_id: Uuid,
        tool_nhi_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM nhi_tool_permissions
            WHERE tenant_id = $1 AND agent_nhi_id = $2 AND tool_nhi_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(agent_nhi_id)
        .bind(tool_nhi_id)
        .fetch_optional(pool)
        .await
    }

    /// List all non-expired permissions for a specific agent (paginated).
    pub async fn list_by_agent(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_nhi_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let limit = limit.min(100);
        let offset = offset.max(0);
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM nhi_tool_permissions
            WHERE tenant_id = $1 AND agent_nhi_id = $2
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY granted_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(agent_nhi_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List all non-expired permissions for a specific tool (paginated).
    pub async fn list_by_tool(
        pool: &PgPool,
        tenant_id: Uuid,
        tool_nhi_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let limit = limit.min(100);
        let offset = offset.max(0);
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM nhi_tool_permissions
            WHERE tenant_id = $1 AND tool_nhi_id = $2
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY granted_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(tool_nhi_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Revoke a specific permission by ID.
    pub async fn revoke(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM nhi_tool_permissions
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Revoke all permissions where the given NHI is either agent or tool.
    pub async fn revoke_all_for_nhi(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM nhi_tool_permissions
            WHERE tenant_id = $1 AND (agent_nhi_id = $2 OR tool_nhi_id = $2)
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Resolve tool names for an agent's non-expired permissions via a single JOIN.
    ///
    /// Returns tool identity names (not UUIDs), suitable for populating
    /// `allowed_tools` in ext_authz dynamic_metadata.
    pub async fn tool_names_by_agent(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_nhi_id: Uuid,
    ) -> Result<Vec<String>, sqlx::Error> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r"
            SELECT ni.name
            FROM nhi_tool_permissions tp
            JOIN nhi_identities ni ON ni.id = tp.tool_nhi_id AND ni.tenant_id = tp.tenant_id
            WHERE tp.tenant_id = $1 AND tp.agent_nhi_id = $2
              AND (tp.expires_at IS NULL OR tp.expires_at > NOW())
            ORDER BY ni.name
            ",
        )
        .bind(tenant_id)
        .bind(agent_nhi_id)
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|(name,)| name).collect())
    }

    /// Clean up expired permissions for a tenant.
    pub async fn cleanup_expired(pool: &PgPool, tenant_id: Uuid) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM nhi_tool_permissions
            WHERE tenant_id = $1 AND expires_at IS NOT NULL AND expires_at < NOW()
            ",
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
    use chrono::Duration;
    use serde_json::json;

    #[test]
    fn test_nhi_tool_permission_is_expired() {
        let perm = NhiToolPermission {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_nhi_id: Uuid::new_v4(),
            tool_nhi_id: Uuid::new_v4(),
            allowed_parameters: None,
            max_calls_per_hour: None,
            requires_approval: None,
            granted_at: Utc::now(),
            granted_by: None,
            expires_at: None,
        };

        // No expiration -> not expired
        assert!(!perm.is_expired());
        assert!(perm.is_valid());

        // Future expiration -> not expired
        let future_perm = NhiToolPermission {
            expires_at: Some(Utc::now() + Duration::days(30)),
            ..perm.clone()
        };
        assert!(!future_perm.is_expired());

        // Past expiration -> expired
        let past_perm = NhiToolPermission {
            expires_at: Some(Utc::now() - Duration::days(1)),
            ..perm
        };
        assert!(past_perm.is_expired());
        assert!(!past_perm.is_valid());
    }

    #[test]
    fn test_nhi_tool_permission_serialization() {
        let perm = NhiToolPermission {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_nhi_id: Uuid::new_v4(),
            tool_nhi_id: Uuid::new_v4(),
            allowed_parameters: Some(json!({"max_rows": 1000})),
            max_calls_per_hour: Some(100),
            requires_approval: Some(false),
            granted_at: Utc::now(),
            granted_by: Some(Uuid::new_v4()),
            expires_at: Some(Utc::now() + Duration::days(90)),
        };

        let json_str = serde_json::to_string(&perm).unwrap();
        let deserialized: NhiToolPermission = serde_json::from_str(&json_str).unwrap();
        assert_eq!(perm.id, deserialized.id);
        assert_eq!(perm.max_calls_per_hour, deserialized.max_calls_per_hour);
    }

    #[test]
    fn test_create_nhi_tool_permission() {
        let input = CreateNhiToolPermission {
            agent_nhi_id: Uuid::new_v4(),
            tool_nhi_id: Uuid::new_v4(),
            allowed_parameters: None,
            max_calls_per_hour: Some(50),
            requires_approval: Some(true),
            granted_by: None,
            expires_at: None,
        };

        assert_eq!(input.max_calls_per_hour, Some(50));
        assert_eq!(input.requires_approval, Some(true));
    }
}
