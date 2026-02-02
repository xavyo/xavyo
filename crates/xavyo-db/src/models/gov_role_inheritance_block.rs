//! Governance Role Inheritance Block model.
//!
//! Represents an explicit block preventing a specific entitlement from being
//! inherited by a role from its ancestors.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// An inheritance block for a role.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GovRoleInheritanceBlock {
    /// Unique identifier.
    pub id: Uuid,

    /// The tenant this block belongs to.
    pub tenant_id: Uuid,

    /// The role that blocks the inheritance.
    pub role_id: Uuid,

    /// The entitlement that is blocked from inheritance.
    pub entitlement_id: Uuid,

    /// User who created this block.
    pub created_by: Uuid,

    /// When the block was created.
    pub created_at: DateTime<Utc>,
}

/// Inheritance block with entitlement details for display.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct InheritanceBlockDetails {
    /// Block ID.
    pub id: Uuid,

    /// Entitlement ID.
    pub entitlement_id: Uuid,

    /// Entitlement name.
    pub entitlement_name: String,

    /// Application name.
    pub application_name: Option<String>,

    /// User who created this block.
    pub created_by: Uuid,

    /// When the block was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create an inheritance block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateGovRoleInheritanceBlock {
    /// The entitlement to block from inheritance.
    pub entitlement_id: Uuid,
}

impl GovRoleInheritanceBlock {
    /// Find a block by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_role_inheritance_blocks
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a block by role and entitlement.
    pub async fn find_by_role_and_entitlement(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_role_inheritance_blocks
            WHERE role_id = $1 AND tenant_id = $2 AND entitlement_id = $3
            "#,
        )
        .bind(role_id)
        .bind(tenant_id)
        .bind(entitlement_id)
        .fetch_optional(pool)
        .await
    }

    /// List all inheritance blocks for a role.
    pub async fn list_for_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_role_inheritance_blocks
            WHERE role_id = $1 AND tenant_id = $2
            ORDER BY created_at DESC
            "#,
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List inheritance blocks with details for a role.
    pub async fn list_for_role_with_details(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<InheritanceBlockDetails>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT
                b.id,
                b.entitlement_id,
                e.name AS entitlement_name,
                a.name AS application_name,
                b.created_by,
                b.created_at
            FROM gov_role_inheritance_blocks b
            JOIN gov_entitlements e ON b.entitlement_id = e.id
            LEFT JOIN gov_applications a ON e.application_id = a.id
            WHERE b.role_id = $1 AND b.tenant_id = $2
            ORDER BY e.name
            "#,
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Get blocked entitlement IDs for a role.
    pub async fn get_blocked_entitlement_ids(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT entitlement_id FROM gov_role_inheritance_blocks
            WHERE role_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Create a new inheritance block.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        entitlement_id: Uuid,
        created_by: Uuid,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_role_inheritance_blocks (tenant_id, role_id, entitlement_id, created_by)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(role_id)
        .bind(entitlement_id)
        .bind(created_by)
        .fetch_one(pool)
        .await
    }

    /// Delete an inheritance block by ID.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_role_inheritance_blocks
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete an inheritance block by role and entitlement.
    pub async fn delete_by_role_and_entitlement(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_role_inheritance_blocks
            WHERE role_id = $1 AND tenant_id = $2 AND entitlement_id = $3
            "#,
        )
        .bind(role_id)
        .bind(tenant_id)
        .bind(entitlement_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all inheritance blocks for a role.
    pub async fn delete_all_for_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_role_inheritance_blocks
            WHERE role_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(role_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count inheritance blocks for a role.
    pub async fn count_for_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_role_inheritance_blocks
            WHERE role_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Check if a specific entitlement is blocked for a role.
    pub async fn is_blocked(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM gov_role_inheritance_blocks
                WHERE role_id = $1 AND tenant_id = $2 AND entitlement_id = $3
            )
            "#,
        )
        .bind(role_id)
        .bind(tenant_id)
        .bind(entitlement_id)
        .fetch_one(pool)
        .await?;

        Ok(exists)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inheritance_block_serialization() {
        let block = GovRoleInheritanceBlock {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            role_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&block).unwrap();
        assert!(json.contains("entitlement_id"));
    }

    #[test]
    fn test_create_inheritance_block_request() {
        let request = CreateGovRoleInheritanceBlock {
            entitlement_id: Uuid::new_v4(),
        };

        assert!(!request.entitlement_id.is_nil());
    }

    #[test]
    fn test_inheritance_block_details() {
        let details = InheritanceBlockDetails {
            id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            entitlement_name: "deploy-to-production".to_string(),
            application_name: Some("CI/CD".to_string()),
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
        };

        assert_eq!(details.entitlement_name, "deploy-to-production");
    }
}
