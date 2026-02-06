//! Governance Role Effective Entitlement model.
//!
//! Cached/denormalized record of all effective entitlements for a role (direct + inherited).
//! This cache enables O(1) lookups for effective access checks.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A cached effective entitlement for a role.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GovRoleEffectiveEntitlement {
    /// Unique identifier.
    pub id: Uuid,

    /// The tenant this record belongs to.
    pub tenant_id: Uuid,

    /// The role this effective entitlement applies to.
    pub role_id: Uuid,

    /// The entitlement.
    pub entitlement_id: Uuid,

    /// The role that originally grants this entitlement.
    pub source_role_id: Uuid,

    /// True if inherited from an ancestor, false if directly assigned.
    pub is_inherited: bool,

    /// When the cache entry was created.
    pub created_at: DateTime<Utc>,
}

/// Effective entitlement with details for display.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EffectiveEntitlementDetails {
    /// Entitlement ID.
    pub entitlement_id: Uuid,

    /// Entitlement name.
    pub entitlement_name: String,

    /// Application name.
    pub application_name: Option<String>,

    /// Source role ID.
    pub source_role_id: Uuid,

    /// Source role name.
    pub source_role_name: String,

    /// Whether this is inherited.
    pub is_inherited: bool,
}

impl GovRoleEffectiveEntitlement {
    /// Get all effective entitlements for a role.
    pub async fn get_for_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_role_effective_entitlements
            WHERE role_id = $1 AND tenant_id = $2
            ORDER BY is_inherited, entitlement_id
            ",
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Get effective entitlements with full details for a role.
    pub async fn get_for_role_with_details(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<EffectiveEntitlementDetails>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT
                ee.entitlement_id,
                e.name AS entitlement_name,
                a.name AS application_name,
                ee.source_role_id,
                sr.name AS source_role_name,
                ee.is_inherited
            FROM gov_role_effective_entitlements ee
            JOIN gov_entitlements e ON ee.entitlement_id = e.id AND e.tenant_id = ee.tenant_id
            LEFT JOIN gov_applications a ON e.application_id = a.id AND a.tenant_id = ee.tenant_id
            JOIN gov_roles sr ON ee.source_role_id = sr.id AND sr.tenant_id = ee.tenant_id
            WHERE ee.role_id = $1 AND ee.tenant_id = $2
            ORDER BY ee.is_inherited, e.name
            ",
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Get entitlement IDs for a role (for `SoD` checks etc.)
    pub async fn get_entitlement_ids_for_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT entitlement_id FROM gov_role_effective_entitlements
            WHERE role_id = $1 AND tenant_id = $2
            ",
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Compute and cache effective entitlements for a role.
    /// This aggregates direct entitlements + inherited entitlements from ancestors,
    /// minus any blocked entitlements.
    pub async fn compute_for_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        // Clear existing cache for this role
        sqlx::query(
            r"
            DELETE FROM gov_role_effective_entitlements
            WHERE role_id = $1 AND tenant_id = $2
            ",
        )
        .bind(role_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        // Get blocked entitlements for this role
        let blocked: Vec<Uuid> = sqlx::query_scalar(
            r"
            SELECT entitlement_id FROM gov_role_inheritance_blocks
            WHERE role_id = $1 AND tenant_id = $2
            ",
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;

        // Insert direct entitlements (from gov_role_entitlements where role_id matches)
        sqlx::query(
            r"
            INSERT INTO gov_role_effective_entitlements (tenant_id, role_id, entitlement_id, source_role_id, is_inherited)
            SELECT $2, $1, entitlement_id, $1, false
            FROM gov_role_entitlements
            WHERE role_id = $1 AND tenant_id = $2
            ON CONFLICT (role_id, entitlement_id) DO NOTHING
            ",
        )
        .bind(role_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        // Get ancestors and their direct entitlements (inherited)
        // Using recursive CTE to walk up the hierarchy
        if blocked.is_empty() {
            sqlx::query(
                r"
                WITH RECURSIVE ancestors AS (
                    -- Base case: direct parent
                    SELECT r.id, r.parent_role_id
                    FROM gov_roles r
                    WHERE r.id = (SELECT parent_role_id FROM gov_roles WHERE id = $1 AND tenant_id = $2)
                      AND r.tenant_id = $2

                    UNION ALL

                    -- Recursive case
                    SELECT r.id, r.parent_role_id
                    FROM gov_roles r
                    INNER JOIN ancestors a ON r.id = a.parent_role_id
                    WHERE r.tenant_id = $2
                )
                INSERT INTO gov_role_effective_entitlements (tenant_id, role_id, entitlement_id, source_role_id, is_inherited)
                SELECT $2, $1, re.entitlement_id, re.role_id, true
                FROM ancestors a
                JOIN gov_role_entitlements re ON re.role_id = a.id AND re.tenant_id = $2
                ON CONFLICT (role_id, entitlement_id) DO NOTHING
                ",
            )
            .bind(role_id)
            .bind(tenant_id)
            .execute(pool)
            .await?;
        } else {
            // Exclude blocked entitlements
            sqlx::query(
                r"
                WITH RECURSIVE ancestors AS (
                    SELECT r.id, r.parent_role_id
                    FROM gov_roles r
                    WHERE r.id = (SELECT parent_role_id FROM gov_roles WHERE id = $1 AND tenant_id = $2)
                      AND r.tenant_id = $2

                    UNION ALL

                    SELECT r.id, r.parent_role_id
                    FROM gov_roles r
                    INNER JOIN ancestors a ON r.id = a.parent_role_id
                    WHERE r.tenant_id = $2
                )
                INSERT INTO gov_role_effective_entitlements (tenant_id, role_id, entitlement_id, source_role_id, is_inherited)
                SELECT $2, $1, re.entitlement_id, re.role_id, true
                FROM ancestors a
                JOIN gov_role_entitlements re ON re.role_id = a.id AND re.tenant_id = $2
                WHERE re.entitlement_id != ALL($3)
                ON CONFLICT (role_id, entitlement_id) DO NOTHING
                ",
            )
            .bind(role_id)
            .bind(tenant_id)
            .bind(&blocked)
            .execute(pool)
            .await?;
        }

        // Return the computed effective entitlements
        Self::get_for_role(pool, tenant_id, role_id).await
    }

    /// Recompute effective entitlements for a role and all its descendants.
    pub async fn recompute_for_descendants(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        // First recompute for the role itself
        Self::compute_for_role(pool, tenant_id, role_id).await?;

        // Get all descendants
        let descendants: Vec<Uuid> = sqlx::query_scalar(
            r"
            WITH RECURSIVE descendants AS (
                SELECT id FROM gov_roles WHERE parent_role_id = $1 AND tenant_id = $2

                UNION ALL

                SELECT r.id FROM gov_roles r
                INNER JOIN descendants d ON r.parent_role_id = d.id
                WHERE r.tenant_id = $2
            )
            SELECT id FROM descendants
            ORDER BY (SELECT hierarchy_depth FROM gov_roles WHERE id = descendants.id)
            ",
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;

        // Recompute for each descendant in order (parents before children)
        for desc_id in &descendants {
            Self::compute_for_role(pool, tenant_id, *desc_id).await?;
        }

        Ok((descendants.len() + 1) as i64)
    }

    /// Count effective entitlements for a role.
    pub async fn count_for_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_role_effective_entitlements
            WHERE role_id = $1 AND tenant_id = $2
            ",
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Count direct (non-inherited) entitlements for a role.
    pub async fn count_direct_for_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_role_effective_entitlements
            WHERE role_id = $1 AND tenant_id = $2 AND is_inherited = false
            ",
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Delete all effective entitlements for a role.
    pub async fn delete_for_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_role_effective_entitlements
            WHERE role_id = $1 AND tenant_id = $2
            ",
        )
        .bind(role_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Check if a role has a specific entitlement (direct or inherited).
    pub async fn has_entitlement(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let exists: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS(
                SELECT 1 FROM gov_role_effective_entitlements
                WHERE role_id = $1 AND tenant_id = $2 AND entitlement_id = $3
            )
            ",
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
    fn test_effective_entitlement_serialization() {
        let ee = GovRoleEffectiveEntitlement {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            role_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            source_role_id: Uuid::new_v4(),
            is_inherited: true,
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&ee).unwrap();
        assert!(json.contains("is_inherited"));
    }

    #[test]
    fn test_effective_entitlement_details() {
        let details = EffectiveEntitlementDetails {
            entitlement_id: Uuid::new_v4(),
            entitlement_name: "deploy-to-production".to_string(),
            application_name: Some("CI/CD Pipeline".to_string()),
            source_role_id: Uuid::new_v4(),
            source_role_name: "Developer".to_string(),
            is_inherited: true,
        };

        assert_eq!(details.entitlement_name, "deploy-to-production");
        assert!(details.is_inherited);
    }
}
