//! License-Entitlement Link model (F065).
//!
//! Links license pools to entitlements for automatic license allocation
//! when entitlements are granted.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use super::gov_license_types::LicenseEntitlementLinkId;

/// A link between a license pool and an entitlement.
///
/// When a user is granted an entitlement with a linked license pool,
/// a license can be automatically allocated from the pool.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovLicenseEntitlementLink {
    /// Unique identifier for the link.
    pub id: Uuid,

    /// The tenant this link belongs to.
    pub tenant_id: Uuid,

    /// The license pool to allocate from.
    pub license_pool_id: Uuid,

    /// The entitlement that triggers allocation.
    pub entitlement_id: Uuid,

    /// Priority when multiple pools could satisfy the entitlement (lower = higher priority).
    pub priority: i32,

    /// Whether this link is active.
    pub enabled: bool,

    /// When the link was created.
    pub created_at: DateTime<Utc>,

    /// Who created this link.
    pub created_by: Uuid,
}

/// Request to create a new license-entitlement link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovLicenseEntitlementLink {
    /// The license pool to link.
    pub license_pool_id: Uuid,

    /// The entitlement to link.
    pub entitlement_id: Uuid,

    /// Priority (default: 0).
    pub priority: Option<i32>,

    /// Whether this link is enabled (default: true).
    pub enabled: Option<bool>,

    /// Who is creating this link.
    pub created_by: Uuid,
}

/// Filter options for querying entitlement links.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LicenseEntitlementLinkFilter {
    /// Filter by license pool.
    pub license_pool_id: Option<Uuid>,

    /// Filter by entitlement.
    pub entitlement_id: Option<Uuid>,

    /// Filter by enabled status.
    pub enabled: Option<bool>,
}

/// Link with pool and entitlement details for display.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct LicenseEntitlementLinkWithDetails {
    /// The link itself.
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub license_pool_id: Uuid,
    pub entitlement_id: Uuid,
    pub priority: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,

    /// Pool name.
    pub pool_name: Option<String>,

    /// Pool vendor.
    pub pool_vendor: Option<String>,

    /// Entitlement name.
    pub entitlement_name: Option<String>,
}

impl GovLicenseEntitlementLink {
    // ========================================================================
    // QUERIES
    // ========================================================================

    /// Find a link by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: LicenseEntitlementLinkId,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id,
                tenant_id,
                license_pool_id,
                entitlement_id,
                priority,
                enabled,
                created_at,
                created_by
            FROM gov_license_entitlement_links
            WHERE tenant_id = $1 AND id = $2
            "#,
            tenant_id,
            id.inner()
        )
        .fetch_optional(pool)
        .await
    }

    /// Find links by license pool.
    pub async fn find_by_pool(
        pool: &PgPool,
        tenant_id: Uuid,
        license_pool_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id,
                tenant_id,
                license_pool_id,
                entitlement_id,
                priority,
                enabled,
                created_at,
                created_by
            FROM gov_license_entitlement_links
            WHERE tenant_id = $1 AND license_pool_id = $2
            ORDER BY priority ASC, created_at ASC
            "#,
            tenant_id,
            license_pool_id
        )
        .fetch_all(pool)
        .await
    }

    /// Find links by entitlement (ordered by priority for pool selection).
    pub async fn find_by_entitlement(
        pool: &PgPool,
        tenant_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id,
                tenant_id,
                license_pool_id,
                entitlement_id,
                priority,
                enabled,
                created_at,
                created_by
            FROM gov_license_entitlement_links
            WHERE tenant_id = $1 AND entitlement_id = $2
            ORDER BY priority ASC, created_at ASC
            "#,
            tenant_id,
            entitlement_id
        )
        .fetch_all(pool)
        .await
    }

    /// Find enabled links for an entitlement with available pool capacity.
    pub async fn find_available_for_entitlement(
        pool: &PgPool,
        tenant_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                l.id,
                l.tenant_id,
                l.license_pool_id,
                l.entitlement_id,
                l.priority,
                l.enabled,
                l.created_at,
                l.created_by
            FROM gov_license_entitlement_links l
            JOIN gov_license_pools p ON p.id = l.license_pool_id
            WHERE l.tenant_id = $1
              AND l.entitlement_id = $2
              AND l.enabled = true
              AND p.status = 'active'
              AND p.allocated_count < p.total_capacity
            ORDER BY l.priority ASC, l.created_at ASC
            "#,
            tenant_id,
            entitlement_id
        )
        .fetch_all(pool)
        .await
    }

    /// List links with optional filtering.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &LicenseEntitlementLinkFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id,
                tenant_id,
                license_pool_id,
                entitlement_id,
                priority,
                enabled,
                created_at,
                created_by
            FROM gov_license_entitlement_links
            WHERE tenant_id = $1
              AND ($2::uuid IS NULL OR license_pool_id = $2)
              AND ($3::uuid IS NULL OR entitlement_id = $3)
              AND ($4::boolean IS NULL OR enabled = $4)
            ORDER BY priority ASC, created_at DESC
            LIMIT $5 OFFSET $6
            "#,
            tenant_id,
            filter.license_pool_id,
            filter.entitlement_id,
            filter.enabled,
            limit,
            offset
        )
        .fetch_all(pool)
        .await
    }

    /// List links with pool and entitlement details.
    pub async fn list_with_details(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &LicenseEntitlementLinkFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<LicenseEntitlementLinkWithDetails>, sqlx::Error> {
        sqlx::query_as!(
            LicenseEntitlementLinkWithDetails,
            r#"
            SELECT
                l.id,
                l.tenant_id,
                l.license_pool_id,
                l.entitlement_id,
                l.priority,
                l.enabled,
                l.created_at,
                l.created_by,
                p.name as pool_name,
                p.vendor as pool_vendor,
                e.name as entitlement_name
            FROM gov_license_entitlement_links l
            LEFT JOIN gov_license_pools p ON p.id = l.license_pool_id
            LEFT JOIN gov_entitlements e ON e.id = l.entitlement_id
            WHERE l.tenant_id = $1
              AND ($2::uuid IS NULL OR l.license_pool_id = $2)
              AND ($3::uuid IS NULL OR l.entitlement_id = $3)
              AND ($4::boolean IS NULL OR l.enabled = $4)
            ORDER BY l.priority ASC, l.created_at DESC
            LIMIT $5 OFFSET $6
            "#,
            tenant_id,
            filter.license_pool_id,
            filter.entitlement_id,
            filter.enabled,
            limit,
            offset
        )
        .fetch_all(pool)
        .await
    }

    /// Count links matching filter.
    pub async fn count(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &LicenseEntitlementLinkFilter,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM gov_license_entitlement_links
            WHERE tenant_id = $1
              AND ($2::uuid IS NULL OR license_pool_id = $2)
              AND ($3::uuid IS NULL OR entitlement_id = $3)
              AND ($4::boolean IS NULL OR enabled = $4)
            "#,
            tenant_id,
            filter.license_pool_id,
            filter.entitlement_id,
            filter.enabled
        )
        .fetch_one(pool)
        .await?;

        Ok(result)
    }

    // ========================================================================
    // MUTATIONS
    // ========================================================================

    /// Create a new license-entitlement link.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        req: &CreateGovLicenseEntitlementLink,
    ) -> Result<Self, sqlx::Error> {
        let id = LicenseEntitlementLinkId::new();

        sqlx::query_as!(
            Self,
            r#"
            INSERT INTO gov_license_entitlement_links (
                id, tenant_id, license_pool_id, entitlement_id,
                priority, enabled, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING
                id,
                tenant_id,
                license_pool_id,
                entitlement_id,
                priority,
                enabled,
                created_at,
                created_by
            "#,
            id.inner(),
            tenant_id,
            req.license_pool_id,
            req.entitlement_id,
            req.priority.unwrap_or(0),
            req.enabled.unwrap_or(true),
            req.created_by
        )
        .fetch_one(pool)
        .await
    }

    /// Update a link's priority.
    pub async fn update_priority(
        pool: &PgPool,
        tenant_id: Uuid,
        id: LicenseEntitlementLinkId,
        priority: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            UPDATE gov_license_entitlement_links
            SET priority = $3
            WHERE tenant_id = $1 AND id = $2
            RETURNING
                id,
                tenant_id,
                license_pool_id,
                entitlement_id,
                priority,
                enabled,
                created_at,
                created_by
            "#,
            tenant_id,
            id.inner(),
            priority
        )
        .fetch_optional(pool)
        .await
    }

    /// Enable or disable a link.
    pub async fn set_enabled(
        pool: &PgPool,
        tenant_id: Uuid,
        id: LicenseEntitlementLinkId,
        enabled: bool,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            UPDATE gov_license_entitlement_links
            SET enabled = $3
            WHERE tenant_id = $1 AND id = $2
            RETURNING
                id,
                tenant_id,
                license_pool_id,
                entitlement_id,
                priority,
                enabled,
                created_at,
                created_by
            "#,
            tenant_id,
            id.inner(),
            enabled
        )
        .fetch_optional(pool)
        .await
    }

    /// Delete a link.
    pub async fn delete(
        pool: &PgPool,
        tenant_id: Uuid,
        id: LicenseEntitlementLinkId,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM gov_license_entitlement_links
            WHERE tenant_id = $1 AND id = $2
            "#,
            tenant_id,
            id.inner()
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all links for a pool.
    pub async fn delete_by_pool(
        pool: &PgPool,
        tenant_id: Uuid,
        license_pool_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM gov_license_entitlement_links
            WHERE tenant_id = $1 AND license_pool_id = $2
            "#,
            tenant_id,
            license_pool_id
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Delete all links for an entitlement.
    pub async fn delete_by_entitlement(
        pool: &PgPool,
        tenant_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM gov_license_entitlement_links
            WHERE tenant_id = $1 AND entitlement_id = $2
            "#,
            tenant_id,
            entitlement_id
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_request_defaults() {
        let req = CreateGovLicenseEntitlementLink {
            license_pool_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            priority: None,
            enabled: None,
            created_by: Uuid::new_v4(),
        };

        assert!(req.priority.is_none());
        assert!(req.enabled.is_none());
    }

    #[test]
    fn test_filter_default() {
        let filter = LicenseEntitlementLinkFilter::default();
        assert!(filter.license_pool_id.is_none());
        assert!(filter.entitlement_id.is_none());
        assert!(filter.enabled.is_none());
    }
}
