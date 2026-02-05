//! AI Agent Tool Permission model (F089 - AI Agent Security Platform).
//!
//! Represents permissions that grant agents access to specific tools.
//! Implements least-privilege access control with parameter-level restrictions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// AI Agent Tool Permission model representing a permission grant.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AiAgentToolPermission {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub tool_id: Uuid,
    pub allowed_parameters: Option<serde_json::Value>,
    pub max_calls_per_hour: Option<i32>,
    pub requires_approval: Option<bool>,
    pub granted_at: DateTime<Utc>,
    pub granted_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl AiAgentToolPermission {
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
}

/// Request struct for granting a tool permission to an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantToolPermission {
    pub agent_id: Uuid,
    pub tool_id: Uuid,
    pub allowed_parameters: Option<serde_json::Value>,
    pub max_calls_per_hour: Option<i32>,
    pub requires_approval: Option<bool>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request struct for updating an existing permission.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateToolPermission {
    pub allowed_parameters: Option<serde_json::Value>,
    pub max_calls_per_hour: Option<i32>,
    pub requires_approval: Option<bool>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Permission with expanded agent and tool information.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AiAgentToolPermissionDetails {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub agent_name: String,
    pub tool_id: Uuid,
    pub tool_name: String,
    pub allowed_parameters: Option<serde_json::Value>,
    pub max_calls_per_hour: Option<i32>,
    pub requires_approval: Option<bool>,
    pub granted_at: DateTime<Utc>,
    pub granted_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl AiAgentToolPermission {
    /// Find a permission by ID within a tenant.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, agent_id, tool_id, allowed_parameters, max_calls_per_hour,
                   requires_approval, granted_at, granted_by, expires_at
            FROM ai_agent_tool_permissions
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Check if an agent has permission to use a specific tool.
    /// Returns the permission if it exists and is not expired, None otherwise.
    pub async fn check_permission(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        tool_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, agent_id, tool_id, allowed_parameters, max_calls_per_hour,
                   requires_approval, granted_at, granted_by, expires_at
            FROM ai_agent_tool_permissions
            WHERE tenant_id = $1 AND agent_id = $2 AND tool_id = $3
              AND (expires_at IS NULL OR expires_at > NOW())
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(tool_id)
        .fetch_optional(pool)
        .await
    }

    /// List all permissions for a specific agent.
    pub async fn list_by_agent(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, agent_id, tool_id, allowed_parameters, max_calls_per_hour,
                   requires_approval, granted_at, granted_by, expires_at
            FROM ai_agent_tool_permissions
            WHERE tenant_id = $1 AND agent_id = $2
            ORDER BY granted_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_all(pool)
        .await
    }

    /// List all permissions for a specific agent with tool details.
    pub async fn list_by_agent_with_details(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Vec<AiAgentToolPermissionDetails>, sqlx::Error> {
        sqlx::query_as::<_, AiAgentToolPermissionDetails>(
            r"
            SELECT p.id, p.tenant_id, p.agent_id, a.name as agent_name, p.tool_id, t.name as tool_name,
                   p.allowed_parameters, p.max_calls_per_hour, p.requires_approval, p.granted_at,
                   p.granted_by, p.expires_at
            FROM ai_agent_tool_permissions p
            JOIN ai_agents a ON p.agent_id = a.id AND a.tenant_id = $1
            JOIN ai_tools t ON p.tool_id = t.id AND t.tenant_id = $1
            WHERE p.tenant_id = $1 AND p.agent_id = $2
            ORDER BY p.granted_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_all(pool)
        .await
    }

    /// List all permissions for a specific tool.
    pub async fn list_by_tool(
        pool: &PgPool,
        tenant_id: Uuid,
        tool_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, agent_id, tool_id, allowed_parameters, max_calls_per_hour,
                   requires_approval, granted_at, granted_by, expires_at
            FROM ai_agent_tool_permissions
            WHERE tenant_id = $1 AND tool_id = $2
            ORDER BY granted_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(tool_id)
        .fetch_all(pool)
        .await
    }

    /// List all permissions for a specific tool with agent details.
    pub async fn list_by_tool_with_details(
        pool: &PgPool,
        tenant_id: Uuid,
        tool_id: Uuid,
    ) -> Result<Vec<AiAgentToolPermissionDetails>, sqlx::Error> {
        sqlx::query_as::<_, AiAgentToolPermissionDetails>(
            r"
            SELECT p.id, p.tenant_id, p.agent_id, a.name as agent_name, p.tool_id, t.name as tool_name,
                   p.allowed_parameters, p.max_calls_per_hour, p.requires_approval, p.granted_at,
                   p.granted_by, p.expires_at
            FROM ai_agent_tool_permissions p
            JOIN ai_agents a ON p.agent_id = a.id AND a.tenant_id = $1
            JOIN ai_tools t ON p.tool_id = t.id AND t.tenant_id = $1
            WHERE p.tenant_id = $1 AND p.tool_id = $2
            ORDER BY p.granted_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(tool_id)
        .fetch_all(pool)
        .await
    }

    /// Grant a permission to an agent for a specific tool.
    /// Uses ON CONFLICT to handle duplicate grants (upsert behavior).
    pub async fn grant(
        pool: &PgPool,
        tenant_id: Uuid,
        input: GrantToolPermission,
        granted_by: Option<Uuid>,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            INSERT INTO ai_agent_tool_permissions (
                tenant_id, agent_id, tool_id, allowed_parameters, max_calls_per_hour,
                requires_approval, granted_by, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (tenant_id, agent_id, tool_id)
            DO UPDATE SET
                allowed_parameters = EXCLUDED.allowed_parameters,
                max_calls_per_hour = EXCLUDED.max_calls_per_hour,
                requires_approval = EXCLUDED.requires_approval,
                granted_at = NOW(),
                granted_by = EXCLUDED.granted_by,
                expires_at = EXCLUDED.expires_at
            RETURNING id, tenant_id, agent_id, tool_id, allowed_parameters, max_calls_per_hour,
                      requires_approval, granted_at, granted_by, expires_at
            ",
        )
        .bind(tenant_id)
        .bind(input.agent_id)
        .bind(input.tool_id)
        .bind(&input.allowed_parameters)
        .bind(input.max_calls_per_hour)
        .bind(input.requires_approval)
        .bind(granted_by)
        .bind(input.expires_at)
        .fetch_one(pool)
        .await
    }

    /// Update an existing permission.
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateToolPermission,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            UPDATE ai_agent_tool_permissions
            SET allowed_parameters = COALESCE($3, allowed_parameters),
                max_calls_per_hour = COALESCE($4, max_calls_per_hour),
                requires_approval = COALESCE($5, requires_approval),
                expires_at = COALESCE($6, expires_at)
            WHERE tenant_id = $1 AND id = $2
            RETURNING id, tenant_id, agent_id, tool_id, allowed_parameters, max_calls_per_hour,
                      requires_approval, granted_at, granted_by, expires_at
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&input.allowed_parameters)
        .bind(input.max_calls_per_hour)
        .bind(input.requires_approval)
        .bind(input.expires_at)
        .fetch_optional(pool)
        .await
    }

    /// Revoke a specific permission (by `agent_id` and `tool_id`).
    pub async fn revoke(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        tool_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM ai_agent_tool_permissions
            WHERE tenant_id = $1 AND agent_id = $2 AND tool_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(tool_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Revoke all permissions for a specific agent.
    pub async fn revoke_all_for_agent(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM ai_agent_tool_permissions
            WHERE tenant_id = $1 AND agent_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Revoke all permissions for a specific tool.
    pub async fn revoke_all_for_tool(
        pool: &PgPool,
        tenant_id: Uuid,
        tool_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM ai_agent_tool_permissions
            WHERE tenant_id = $1 AND tool_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(tool_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count active (non-expired) permissions for an agent.
    pub async fn count_active_by_agent(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar::<_, i64>(
            r"
            SELECT COUNT(*) as count
            FROM ai_agent_tool_permissions
            WHERE tenant_id = $1 AND agent_id = $2
              AND (expires_at IS NULL OR expires_at > NOW())
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_one(pool)
        .await
    }

    /// Count active (non-expired) permissions for a tool.
    pub async fn count_active_by_tool(
        pool: &PgPool,
        tenant_id: Uuid,
        tool_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar::<_, i64>(
            r"
            SELECT COUNT(*) as count
            FROM ai_agent_tool_permissions
            WHERE tenant_id = $1 AND tool_id = $2
              AND (expires_at IS NULL OR expires_at > NOW())
            ",
        )
        .bind(tenant_id)
        .bind(tool_id)
        .fetch_one(pool)
        .await
    }

    /// Clean up expired permissions for a tenant.
    pub async fn cleanup_expired(pool: &PgPool, tenant_id: Uuid) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM ai_agent_tool_permissions
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
    fn test_ai_agent_tool_permission_serialization() {
        let permission = AiAgentToolPermission {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            tool_id: Uuid::new_v4(),
            allowed_parameters: Some(json!({
                "to": ["*@company.com"],
                "max_recipients": 10
            })),
            max_calls_per_hour: Some(100),
            requires_approval: Some(false),
            granted_at: Utc::now(),
            granted_by: Some(Uuid::new_v4()),
            expires_at: Some(Utc::now() + Duration::days(30)),
        };

        let json = serde_json::to_string(&permission).unwrap();
        let deserialized: AiAgentToolPermission = serde_json::from_str(&json).unwrap();

        assert_eq!(permission.id, deserialized.id);
        assert_eq!(permission.agent_id, deserialized.agent_id);
        assert_eq!(permission.tool_id, deserialized.tool_id);
        assert_eq!(
            permission.max_calls_per_hour,
            deserialized.max_calls_per_hour
        );
        assert_eq!(permission.requires_approval, deserialized.requires_approval);
    }

    #[test]
    fn test_ai_agent_tool_permission_is_expired() {
        // Permission without expiration - never expires
        let perm_no_expire = AiAgentToolPermission {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            tool_id: Uuid::new_v4(),
            allowed_parameters: None,
            max_calls_per_hour: None,
            requires_approval: None,
            granted_at: Utc::now(),
            granted_by: None,
            expires_at: None,
        };
        assert!(!perm_no_expire.is_expired());
        assert!(perm_no_expire.is_valid());

        // Permission with future expiration - not expired
        let perm_future = AiAgentToolPermission {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            tool_id: Uuid::new_v4(),
            allowed_parameters: None,
            max_calls_per_hour: None,
            requires_approval: None,
            granted_at: Utc::now(),
            granted_by: None,
            expires_at: Some(Utc::now() + Duration::days(1)),
        };
        assert!(!perm_future.is_expired());
        assert!(perm_future.is_valid());

        // Permission with past expiration - expired
        let perm_past = AiAgentToolPermission {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            tool_id: Uuid::new_v4(),
            allowed_parameters: None,
            max_calls_per_hour: None,
            requires_approval: None,
            granted_at: Utc::now() - Duration::days(2),
            granted_by: None,
            expires_at: Some(Utc::now() - Duration::days(1)),
        };
        assert!(perm_past.is_expired());
        assert!(!perm_past.is_valid());
    }

    #[test]
    fn test_grant_tool_permission_serialization() {
        let input = GrantToolPermission {
            agent_id: Uuid::new_v4(),
            tool_id: Uuid::new_v4(),
            allowed_parameters: Some(json!({
                "database": ["readonly_db", "analytics_db"],
                "max_rows": 1000
            })),
            max_calls_per_hour: Some(50),
            requires_approval: Some(true),
            expires_at: Some(Utc::now() + Duration::days(90)),
        };

        let json = serde_json::to_string(&input).unwrap();
        let deserialized: GrantToolPermission = serde_json::from_str(&json).unwrap();

        assert_eq!(input.agent_id, deserialized.agent_id);
        assert_eq!(input.tool_id, deserialized.tool_id);
        assert_eq!(input.max_calls_per_hour, deserialized.max_calls_per_hour);
        assert_eq!(input.requires_approval, deserialized.requires_approval);
    }

    #[test]
    fn test_grant_tool_permission_minimal() {
        let input = GrantToolPermission {
            agent_id: Uuid::new_v4(),
            tool_id: Uuid::new_v4(),
            allowed_parameters: None,
            max_calls_per_hour: None,
            requires_approval: None,
            expires_at: None,
        };

        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"agent_id\""));
        assert!(json.contains("\"tool_id\""));
    }

    #[test]
    fn test_update_tool_permission_serialization() {
        let input = UpdateToolPermission {
            allowed_parameters: Some(json!({"max_rows": 500})),
            max_calls_per_hour: Some(200),
            requires_approval: Some(false),
            expires_at: Some(Utc::now() + Duration::days(180)),
        };

        let json = serde_json::to_string(&input).unwrap();
        let deserialized: UpdateToolPermission = serde_json::from_str(&json).unwrap();

        assert_eq!(input.max_calls_per_hour, deserialized.max_calls_per_hour);
        assert_eq!(input.requires_approval, deserialized.requires_approval);
    }

    #[test]
    fn test_update_tool_permission_default() {
        let input = UpdateToolPermission::default();

        assert!(input.allowed_parameters.is_none());
        assert!(input.max_calls_per_hour.is_none());
        assert!(input.requires_approval.is_none());
        assert!(input.expires_at.is_none());
    }

    #[test]
    fn test_permission_details_serialization() {
        let details = AiAgentToolPermissionDetails {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            agent_name: "sales-assistant".to_string(),
            tool_id: Uuid::new_v4(),
            tool_name: "send_email".to_string(),
            allowed_parameters: Some(json!({"domain": "company.com"})),
            max_calls_per_hour: Some(100),
            requires_approval: Some(false),
            granted_at: Utc::now(),
            granted_by: Some(Uuid::new_v4()),
            expires_at: None,
        };

        let json = serde_json::to_string(&details).unwrap();
        let deserialized: AiAgentToolPermissionDetails = serde_json::from_str(&json).unwrap();

        assert_eq!(details.agent_name, deserialized.agent_name);
        assert_eq!(details.tool_name, deserialized.tool_name);
    }

    #[test]
    fn test_allowed_parameters_complex() {
        // Test complex parameter restrictions
        let allowed_params = json!({
            "recipients": {
                "pattern": "^[a-z]+@company\\.com$",
                "max_count": 5
            },
            "attachments": {
                "allowed_types": ["pdf", "docx", "xlsx"],
                "max_size_mb": 10
            },
            "templates": {
                "allowed_ids": ["tmpl_001", "tmpl_002", "tmpl_003"]
            }
        });

        let input = GrantToolPermission {
            agent_id: Uuid::new_v4(),
            tool_id: Uuid::new_v4(),
            allowed_parameters: Some(allowed_params.clone()),
            max_calls_per_hour: None,
            requires_approval: None,
            expires_at: None,
        };

        let json = serde_json::to_string(&input).unwrap();
        let deserialized: GrantToolPermission = serde_json::from_str(&json).unwrap();

        assert_eq!(input.allowed_parameters, deserialized.allowed_parameters);
        assert_eq!(
            deserialized.allowed_parameters.as_ref().unwrap()["recipients"]["max_count"],
            5
        );
    }
}
