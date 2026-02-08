//! NHI User Permission model (204-nhi-permission-model).
//!
//! User-to-NHI permission grants. Allows non-admin users explicit access
//! to specific NHI identities with permission levels: use, manage, admin.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// An NHI user permission record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiUserPermission {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub nhi_id: Uuid,
    pub permission_type: String,
    pub granted_at: DateTime<Utc>,
    pub granted_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to grant a user permission on an NHI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNhiUserPermission {
    pub user_id: Uuid,
    pub nhi_id: Uuid,
    pub permission_type: String,
    pub granted_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl NhiUserPermission {
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
        input: CreateNhiUserPermission,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            INSERT INTO nhi_user_permissions (
                tenant_id, user_id, nhi_id, permission_type, granted_by, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (tenant_id, user_id, nhi_id, permission_type)
            DO UPDATE SET
                granted_at = NOW(),
                granted_by = EXCLUDED.granted_by,
                expires_at = EXCLUDED.expires_at
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.user_id)
        .bind(input.nhi_id)
        .bind(&input.permission_type)
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
            SELECT * FROM nhi_user_permissions
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Find a permission by user-NHI-type triple.
    pub async fn find_by_triple(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        nhi_id: Uuid,
        permission_type: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM nhi_user_permissions
            WHERE tenant_id = $1 AND user_id = $2 AND nhi_id = $3 AND permission_type = $4
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(nhi_id)
        .bind(permission_type)
        .fetch_optional(pool)
        .await
    }

    /// List all non-expired permissions for a specific user (paginated).
    pub async fn list_by_user(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let limit = limit.min(100);
        let offset = offset.max(0);
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM nhi_user_permissions
            WHERE tenant_id = $1 AND user_id = $2
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY granted_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List all non-expired permissions for a specific NHI (paginated).
    pub async fn list_by_nhi(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let limit = limit.min(100);
        let offset = offset.max(0);
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM nhi_user_permissions
            WHERE tenant_id = $1 AND nhi_id = $2
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY granted_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Revoke a permission by user-NHI-type triple.
    pub async fn revoke(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        nhi_id: Uuid,
        permission_type: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM nhi_user_permissions
            WHERE tenant_id = $1 AND user_id = $2 AND nhi_id = $3 AND permission_type = $4
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(nhi_id)
        .bind(permission_type)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Revoke all permissions for a specific NHI (cascade on archive).
    pub async fn revoke_all_for_nhi(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM nhi_user_permissions
            WHERE tenant_id = $1 AND nhi_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Revoke all permissions for a specific user.
    pub async fn revoke_all_for_user(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM nhi_user_permissions
            WHERE tenant_id = $1 AND user_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Check if a user has a specific permission (or higher) on an NHI.
    ///
    /// Permission hierarchy: admin > manage > use.
    /// Having `admin` implies `manage` and `use`.
    /// Having `manage` implies `use`.
    pub async fn check_permission(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        nhi_id: Uuid,
        required_type: &str,
    ) -> Result<bool, sqlx::Error> {
        let types = match required_type {
            "use" => vec!["use", "manage", "admin"],
            "manage" => vec!["manage", "admin"],
            "admin" => vec!["admin"],
            _ => return Ok(false),
        };

        let result = sqlx::query_scalar::<_, bool>(
            r"
            SELECT EXISTS(
                SELECT 1 FROM nhi_user_permissions
                WHERE tenant_id = $1 AND user_id = $2 AND nhi_id = $3
                  AND permission_type = ANY($4)
                  AND (expires_at IS NULL OR expires_at > NOW())
            )
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(nhi_id)
        .bind(&types)
        .fetch_one(pool)
        .await?;

        Ok(result)
    }

    /// Clean up expired permissions for a tenant.
    pub async fn cleanup_expired(pool: &PgPool, tenant_id: Uuid) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM nhi_user_permissions
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

    #[test]
    fn test_nhi_user_permission_is_expired() {
        let perm = NhiUserPermission {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            nhi_id: Uuid::new_v4(),
            permission_type: "use".to_string(),
            granted_at: Utc::now(),
            granted_by: None,
            expires_at: None,
        };

        // No expiration -> not expired
        assert!(!perm.is_expired());
        assert!(perm.is_valid());

        // Future expiration -> not expired
        let future_perm = NhiUserPermission {
            expires_at: Some(Utc::now() + Duration::days(30)),
            ..perm.clone()
        };
        assert!(!future_perm.is_expired());

        // Past expiration -> expired
        let past_perm = NhiUserPermission {
            expires_at: Some(Utc::now() - Duration::days(1)),
            ..perm
        };
        assert!(past_perm.is_expired());
        assert!(!past_perm.is_valid());
    }

    #[test]
    fn test_nhi_user_permission_serialization() {
        let perm = NhiUserPermission {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            nhi_id: Uuid::new_v4(),
            permission_type: "manage".to_string(),
            granted_at: Utc::now(),
            granted_by: Some(Uuid::new_v4()),
            expires_at: Some(Utc::now() + Duration::days(90)),
        };

        let json_str = serde_json::to_string(&perm).unwrap();
        let deserialized: NhiUserPermission = serde_json::from_str(&json_str).unwrap();
        assert_eq!(perm.id, deserialized.id);
        assert_eq!(perm.permission_type, deserialized.permission_type);
    }

    #[test]
    fn test_create_nhi_user_permission() {
        let input = CreateNhiUserPermission {
            user_id: Uuid::new_v4(),
            nhi_id: Uuid::new_v4(),
            permission_type: "admin".to_string(),
            granted_by: Some(Uuid::new_v4()),
            expires_at: None,
        };

        assert_eq!(input.permission_type, "admin");
        assert!(input.granted_by.is_some());
    }
}
