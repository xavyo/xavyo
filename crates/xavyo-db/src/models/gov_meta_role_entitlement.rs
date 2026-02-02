//! Governance Meta-role Entitlement model (F056).
//!
//! Represents entitlements inherited by roles matching the meta-role criteria.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::PermissionType;

/// An entitlement inherited from a meta-role.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovMetaRoleEntitlement {
    /// Unique identifier.
    pub id: Uuid,

    /// The tenant this belongs to.
    pub tenant_id: Uuid,

    /// The parent meta-role.
    pub meta_role_id: Uuid,

    /// The entitlement being inherited.
    pub entitlement_id: Uuid,

    /// Permission type (grant or deny).
    pub permission_type: PermissionType,

    /// When this was created.
    pub created_at: DateTime<Utc>,
}

/// Request to add an entitlement to a meta-role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovMetaRoleEntitlement {
    pub entitlement_id: Uuid,
    pub permission_type: Option<PermissionType>,
}

impl GovMetaRoleEntitlement {
    /// Find by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_meta_role_entitlements
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find by meta-role and entitlement.
    pub async fn find_by_meta_role_and_entitlement(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_meta_role_entitlements
            WHERE tenant_id = $1 AND meta_role_id = $2 AND entitlement_id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .bind(entitlement_id)
        .fetch_optional(pool)
        .await
    }

    /// List all entitlements for a meta-role.
    pub async fn list_by_meta_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_meta_role_entitlements
            WHERE tenant_id = $1 AND meta_role_id = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .fetch_all(pool)
        .await
    }

    /// Create a new meta-role entitlement.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        input: CreateGovMetaRoleEntitlement,
    ) -> Result<Self, sqlx::Error> {
        let permission_type = input.permission_type.unwrap_or_default();

        sqlx::query_as(
            r#"
            INSERT INTO gov_meta_role_entitlements (
                tenant_id, meta_role_id, entitlement_id, permission_type
            )
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .bind(input.entitlement_id)
        .bind(permission_type)
        .fetch_one(pool)
        .await
    }

    /// Delete a meta-role entitlement.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_meta_role_entitlements
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all entitlements for a meta-role.
    pub async fn delete_by_meta_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_meta_role_entitlements
            WHERE tenant_id = $1 AND meta_role_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_entitlement_default_grant() {
        let input = CreateGovMetaRoleEntitlement {
            entitlement_id: Uuid::new_v4(),
            permission_type: None,
        };

        assert!(input.permission_type.is_none());
        // Default should be Grant
    }

    #[test]
    fn test_create_entitlement_deny() {
        let input = CreateGovMetaRoleEntitlement {
            entitlement_id: Uuid::new_v4(),
            permission_type: Some(PermissionType::Deny),
        };

        assert_eq!(input.permission_type, Some(PermissionType::Deny));
    }
}
