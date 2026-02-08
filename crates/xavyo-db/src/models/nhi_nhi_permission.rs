//! NHI-to-NHI Permission model (204-nhi-permission-model).
//!
//! NHI-to-NHI calling/delegation permission grants. Allows one NHI identity
//! to call or delegate to another. Separate from nhi_tool_permissions which
//! handles the specific agent→tool grant with allowed_parameters.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// An NHI-to-NHI permission record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiNhiPermission {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub source_nhi_id: Uuid,
    pub target_nhi_id: Uuid,
    pub permission_type: String,
    pub allowed_actions: Option<serde_json::Value>,
    pub max_calls_per_hour: Option<i32>,
    pub granted_at: DateTime<Utc>,
    pub granted_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to grant an NHI-to-NHI permission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNhiNhiPermission {
    pub source_nhi_id: Uuid,
    pub target_nhi_id: Uuid,
    pub permission_type: String,
    pub allowed_actions: Option<serde_json::Value>,
    pub max_calls_per_hour: Option<i32>,
    pub granted_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl NhiNhiPermission {
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
        input: CreateNhiNhiPermission,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            INSERT INTO nhi_nhi_permissions (
                tenant_id, source_nhi_id, target_nhi_id, permission_type,
                allowed_actions, max_calls_per_hour, granted_by, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (tenant_id, source_nhi_id, target_nhi_id, permission_type)
            DO UPDATE SET
                allowed_actions = EXCLUDED.allowed_actions,
                max_calls_per_hour = EXCLUDED.max_calls_per_hour,
                granted_at = NOW(),
                granted_by = EXCLUDED.granted_by,
                expires_at = EXCLUDED.expires_at
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.source_nhi_id)
        .bind(input.target_nhi_id)
        .bind(&input.permission_type)
        .bind(&input.allowed_actions)
        .bind(input.max_calls_per_hour)
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
            SELECT * FROM nhi_nhi_permissions
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Find a permission by source-target-type triple.
    pub async fn find_by_triple(
        pool: &PgPool,
        tenant_id: Uuid,
        source_nhi_id: Uuid,
        target_nhi_id: Uuid,
        permission_type: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM nhi_nhi_permissions
            WHERE tenant_id = $1 AND source_nhi_id = $2 AND target_nhi_id = $3
              AND permission_type = $4
            ",
        )
        .bind(tenant_id)
        .bind(source_nhi_id)
        .bind(target_nhi_id)
        .bind(permission_type)
        .fetch_optional(pool)
        .await
    }

    /// List all non-expired permissions where this NHI is the source (callees).
    pub async fn list_by_source(
        pool: &PgPool,
        tenant_id: Uuid,
        source_nhi_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let limit = limit.min(100);
        let offset = offset.max(0);
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM nhi_nhi_permissions
            WHERE tenant_id = $1 AND source_nhi_id = $2
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY granted_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(source_nhi_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List all non-expired permissions where this NHI is the target (callers).
    pub async fn list_by_target(
        pool: &PgPool,
        tenant_id: Uuid,
        target_nhi_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let limit = limit.min(100);
        let offset = offset.max(0);
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM nhi_nhi_permissions
            WHERE tenant_id = $1 AND target_nhi_id = $2
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY granted_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(target_nhi_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Revoke a permission by source-target-type triple.
    pub async fn revoke(
        pool: &PgPool,
        tenant_id: Uuid,
        source_nhi_id: Uuid,
        target_nhi_id: Uuid,
        permission_type: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM nhi_nhi_permissions
            WHERE tenant_id = $1 AND source_nhi_id = $2 AND target_nhi_id = $3
              AND permission_type = $4
            ",
        )
        .bind(tenant_id)
        .bind(source_nhi_id)
        .bind(target_nhi_id)
        .bind(permission_type)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Revoke all permissions where the given NHI is either source or target.
    pub async fn revoke_all_for_nhi(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM nhi_nhi_permissions
            WHERE tenant_id = $1 AND (source_nhi_id = $2 OR target_nhi_id = $2)
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Check if source NHI has calling permission to target NHI.
    pub async fn check_permission(
        pool: &PgPool,
        tenant_id: Uuid,
        source_nhi_id: Uuid,
        target_nhi_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query_scalar::<_, bool>(
            r"
            SELECT EXISTS(
                SELECT 1 FROM nhi_nhi_permissions
                WHERE tenant_id = $1 AND source_nhi_id = $2 AND target_nhi_id = $3
                  AND (expires_at IS NULL OR expires_at > NOW())
            )
            ",
        )
        .bind(tenant_id)
        .bind(source_nhi_id)
        .bind(target_nhi_id)
        .fetch_one(pool)
        .await?;

        Ok(result)
    }

    /// Clean up expired permissions for a tenant.
    pub async fn cleanup_expired(pool: &PgPool, tenant_id: Uuid) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM nhi_nhi_permissions
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
    fn test_nhi_nhi_permission_is_expired() {
        let perm = NhiNhiPermission {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            source_nhi_id: Uuid::new_v4(),
            target_nhi_id: Uuid::new_v4(),
            permission_type: "call".to_string(),
            allowed_actions: None,
            max_calls_per_hour: None,
            granted_at: Utc::now(),
            granted_by: None,
            expires_at: None,
        };

        // No expiration -> not expired
        assert!(!perm.is_expired());
        assert!(perm.is_valid());

        // Future expiration -> not expired
        let future_perm = NhiNhiPermission {
            expires_at: Some(Utc::now() + Duration::days(30)),
            ..perm.clone()
        };
        assert!(!future_perm.is_expired());

        // Past expiration -> expired
        let past_perm = NhiNhiPermission {
            expires_at: Some(Utc::now() - Duration::days(1)),
            ..perm
        };
        assert!(past_perm.is_expired());
        assert!(!past_perm.is_valid());
    }

    #[test]
    fn test_nhi_nhi_permission_serialization() {
        let perm = NhiNhiPermission {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            source_nhi_id: Uuid::new_v4(),
            target_nhi_id: Uuid::new_v4(),
            permission_type: "call".to_string(),
            allowed_actions: Some(json!({"methods": ["invoke"]})),
            max_calls_per_hour: Some(100),
            granted_at: Utc::now(),
            granted_by: Some(Uuid::new_v4()),
            expires_at: Some(Utc::now() + Duration::days(90)),
        };

        let json_str = serde_json::to_string(&perm).unwrap();
        let deserialized: NhiNhiPermission = serde_json::from_str(&json_str).unwrap();
        assert_eq!(perm.id, deserialized.id);
        assert_eq!(perm.max_calls_per_hour, deserialized.max_calls_per_hour);
    }

    #[test]
    fn test_create_nhi_nhi_permission() {
        let input = CreateNhiNhiPermission {
            source_nhi_id: Uuid::new_v4(),
            target_nhi_id: Uuid::new_v4(),
            permission_type: "delegate".to_string(),
            allowed_actions: Some(json!({"scopes": ["read", "write"]})),
            max_calls_per_hour: Some(500),
            granted_by: None,
            expires_at: None,
        };

        assert_eq!(input.permission_type, "delegate");
        assert_eq!(input.max_calls_per_hour, Some(500));
    }
}
