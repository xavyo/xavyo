//! Entitlement Action Mapping model (F083).
//!
//! Links entitlements to actions and resource types for authorization decisions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// An entitlement-to-action mapping.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct EntitlementActionMapping {
    /// Unique identifier for the mapping.
    pub id: Uuid,

    /// The tenant this mapping belongs to.
    pub tenant_id: Uuid,

    /// The entitlement being mapped.
    pub entitlement_id: Uuid,

    /// The action this entitlement grants (e.g., "read", "write", "*").
    pub action: String,

    /// The resource type this mapping applies to (e.g., "document", "*").
    pub resource_type: String,

    /// Who created this mapping.
    pub created_by: Option<Uuid>,

    /// When the mapping was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create an entitlement action mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEntitlementActionMapping {
    pub entitlement_id: Uuid,
    pub action: String,
    pub resource_type: String,
    pub created_by: Option<Uuid>,
}

impl EntitlementActionMapping {
    /// Find a mapping by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM entitlement_action_mappings
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find all mappings for a tenant.
    pub async fn find_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM entitlement_action_mappings
            WHERE tenant_id = $1
            ORDER BY resource_type, action
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Find mappings for a specific entitlement.
    pub async fn find_by_entitlement(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM entitlement_action_mappings
            WHERE tenant_id = $1 AND entitlement_id = $2
            ORDER BY resource_type, action
            "#,
        )
        .bind(tenant_id)
        .bind(entitlement_id)
        .fetch_all(pool)
        .await
    }

    /// List all mappings with pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM entitlement_action_mappings
            WHERE tenant_id = $1
            ORDER BY resource_type, action
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Count mappings for a tenant.
    pub async fn count_by_tenant(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
        let result: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM entitlement_action_mappings
            WHERE tenant_id = $1
            "#,
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(result.0)
    }

    /// Create a new entitlement action mapping.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateEntitlementActionMapping,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO entitlement_action_mappings (
                tenant_id, entitlement_id, action, resource_type, created_by
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.entitlement_id)
        .bind(&input.action)
        .bind(&input.resource_type)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Delete an entitlement action mapping.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM entitlement_action_mappings
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Find all mappings for a list of entitlement IDs within a tenant.
    /// Used by the Policy Decision Point (PDP) to resolve entitlement-based access.
    pub async fn find_by_entitlement_ids(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        entitlement_ids: &[Uuid],
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM entitlement_action_mappings
            WHERE tenant_id = $1 AND entitlement_id = ANY($2)
            ORDER BY resource_type, action
            "#,
        )
        .bind(tenant_id)
        .bind(entitlement_ids)
        .fetch_all(pool)
        .await
    }

    /// Delete all mappings for an entitlement.
    pub async fn delete_by_entitlement(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM entitlement_action_mappings
            WHERE tenant_id = $1 AND entitlement_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(entitlement_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_mapping_request() {
        let request = CreateEntitlementActionMapping {
            entitlement_id: Uuid::new_v4(),
            action: "read".to_string(),
            resource_type: "document".to_string(),
            created_by: Some(Uuid::new_v4()),
        };

        assert_eq!(request.action, "read");
        assert_eq!(request.resource_type, "document");
    }

    #[test]
    fn test_mapping_serialization() {
        let mapping = EntitlementActionMapping {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            action: "write".to_string(),
            resource_type: "project".to_string(),
            created_by: None,
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&mapping).unwrap();
        assert!(json.contains("write"));
        assert!(json.contains("project"));
    }
}
