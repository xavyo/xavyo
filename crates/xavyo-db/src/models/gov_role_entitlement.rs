//! Governance Role Entitlement model.
//!
//! Represents mappings between roles and entitlements for RBAC integration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A governance role-to-entitlement mapping.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovRoleEntitlement {
    /// Unique identifier for the mapping.
    pub id: Uuid,

    /// The tenant this mapping belongs to.
    pub tenant_id: Uuid,

    /// The entitlement being mapped.
    pub entitlement_id: Uuid,

    /// The role name being mapped (e.g., "admin", "viewer").
    pub role_name: String,

    /// When the mapping was created.
    pub created_at: DateTime<Utc>,

    /// Who created this mapping.
    pub created_by: Uuid,

    /// Optional FK to `gov_roles` entity for structured role hierarchy support (F088).
    /// When set, this mapping links to a formal `GovRole` rather than just a string `role_name`.
    pub role_id: Option<Uuid>,
}

/// Request to create a new role-entitlement mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovRoleEntitlement {
    pub entitlement_id: Uuid,
    pub role_name: String,
    pub created_by: Uuid,
}

/// Filter options for listing role entitlements.
#[derive(Debug, Clone, Default)]
pub struct RoleEntitlementFilter {
    pub entitlement_id: Option<Uuid>,
    pub role_name: Option<String>,
}

impl GovRoleEntitlement {
    /// Find a mapping by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_role_entitlements
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find an existing mapping.
    pub async fn find_by_role_and_entitlement(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_name: &str,
        entitlement_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_role_entitlements
            WHERE tenant_id = $1 AND role_name = $2 AND entitlement_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(role_name)
        .bind(entitlement_id)
        .fetch_optional(pool)
        .await
    }

    /// List role entitlements for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &RoleEntitlementFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_role_entitlements
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.entitlement_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND entitlement_id = ${param_count}"));
        }
        if filter.role_name.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND role_name = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY role_name, created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovRoleEntitlement>(&query).bind(tenant_id);

        if let Some(entitlement_id) = filter.entitlement_id {
            q = q.bind(entitlement_id);
        }
        if let Some(ref role_name) = filter.role_name {
            q = q.bind(role_name);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count role entitlements in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &RoleEntitlementFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_role_entitlements
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.entitlement_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND entitlement_id = ${param_count}"));
        }
        if filter.role_name.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND role_name = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(entitlement_id) = filter.entitlement_id {
            q = q.bind(entitlement_id);
        }
        if let Some(ref role_name) = filter.role_name {
            q = q.bind(role_name);
        }

        q.fetch_one(pool).await
    }

    /// Create a new role-entitlement mapping.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovRoleEntitlement,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_role_entitlements (tenant_id, entitlement_id, role_name, created_by)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.entitlement_id)
        .bind(&input.role_name)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Delete a role-entitlement mapping.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_role_entitlements
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// List all entitlement IDs for a role.
    pub async fn list_entitlement_ids_by_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_name: &str,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT entitlement_id FROM gov_role_entitlements
            WHERE tenant_id = $1 AND role_name = $2
            ",
        )
        .bind(tenant_id)
        .bind(role_name)
        .fetch_all(pool)
        .await
    }

    /// List all role names for an entitlement.
    pub async fn list_roles_by_entitlement(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Vec<String>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT role_name FROM gov_role_entitlements
            WHERE tenant_id = $1 AND entitlement_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(entitlement_id)
        .fetch_all(pool)
        .await
    }

    /// Get all distinct role names in a tenant.
    pub async fn list_distinct_roles(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<String>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT DISTINCT role_name FROM gov_role_entitlements
            WHERE tenant_id = $1
            ORDER BY role_name
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    // ====== F088: Role Hierarchy Support ======

    /// List all entitlement IDs for a `GovRole` (by `role_id` UUID).
    pub async fn list_entitlement_ids_by_role_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT entitlement_id FROM gov_role_entitlements
            WHERE tenant_id = $1 AND role_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_all(pool)
        .await
    }

    /// List all role-entitlement mappings for a `GovRole`.
    pub async fn list_by_role_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_role_entitlements
            WHERE tenant_id = $1 AND role_id = $2
            ORDER BY created_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_all(pool)
        .await
    }

    /// Create a new role-entitlement mapping with `role_id` (for `GovRole` hierarchy).
    pub async fn create_with_role_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        entitlement_id: Uuid,
        created_by: Uuid,
    ) -> Result<Self, sqlx::Error> {
        // Use the role name from the GovRole for backward compatibility
        let role_name: String = sqlx::query_scalar(
            r"
            SELECT name FROM gov_roles WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        sqlx::query_as(
            r"
            INSERT INTO gov_role_entitlements (tenant_id, entitlement_id, role_name, created_by, role_id)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(entitlement_id)
        .bind(&role_name)
        .bind(created_by)
        .bind(role_id)
        .fetch_one(pool)
        .await
    }

    /// Find an existing mapping by `role_id` and `entitlement_id`.
    pub async fn find_by_role_id_and_entitlement(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_role_entitlements
            WHERE tenant_id = $1 AND role_id = $2 AND entitlement_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .bind(entitlement_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a role-entitlement mapping by `role_id` and `entitlement_id`.
    pub async fn delete_by_role_id_and_entitlement(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_role_entitlements
            WHERE tenant_id = $1 AND role_id = $2 AND entitlement_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .bind(entitlement_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Count direct entitlements for a `GovRole`.
    pub async fn count_by_role_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_role_entitlements
            WHERE tenant_id = $1 AND role_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_one(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_role_entitlement_request() {
        let request = CreateGovRoleEntitlement {
            entitlement_id: Uuid::new_v4(),
            role_name: "admin".to_string(),
            created_by: Uuid::new_v4(),
        };

        assert_eq!(request.role_name, "admin");
    }

    #[test]
    fn test_role_entitlement_serialization() {
        let mapping = GovRoleEntitlement {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            role_name: "viewer".to_string(),
            created_at: Utc::now(),
            created_by: Uuid::new_v4(),
            role_id: Some(Uuid::new_v4()),
        };

        let json = serde_json::to_string(&mapping).unwrap();
        assert!(json.contains("viewer"));
    }
}
