//! License Assignment model (F065).
//!
//! Links users to license pools with allocation tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_license_types::{
    LicenseAssignmentSource, LicenseAssignmentStatus, LicenseReclaimReason,
};

/// A license assignment linking a user to a license pool.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovLicenseAssignment {
    /// Unique identifier for the assignment.
    pub id: Uuid,

    /// The tenant this assignment belongs to.
    pub tenant_id: Uuid,

    /// The license pool this assignment is from.
    pub license_pool_id: Uuid,

    /// The user who has this license.
    pub user_id: Uuid,

    /// When the license was assigned.
    pub assigned_at: DateTime<Utc>,

    /// Who assigned the license (user ID or system).
    pub assigned_by: Uuid,

    /// How the license was assigned.
    pub source: LicenseAssignmentSource,

    /// If source=entitlement, the link that triggered this.
    pub entitlement_link_id: Option<Uuid>,

    /// For concurrent licenses, the active session ID.
    pub session_id: Option<Uuid>,

    /// Assignment status.
    pub status: LicenseAssignmentStatus,

    /// When the license was reclaimed (if applicable).
    pub reclaimed_at: Option<DateTime<Utc>>,

    /// Why the license was reclaimed.
    pub reclaim_reason: Option<LicenseReclaimReason>,

    /// Optional notes.
    pub notes: Option<String>,

    /// When the record was created.
    pub created_at: DateTime<Utc>,

    /// When the record was last updated.
    pub updated_at: DateTime<Utc>,
}

impl GovLicenseAssignment {
    /// Check if the assignment is active.
    pub fn is_active(&self) -> bool {
        matches!(self.status, LicenseAssignmentStatus::Active)
    }

    /// Find an assignment by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_license_assignments
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find an active assignment for a user in a specific pool.
    pub async fn find_active_by_user_and_pool(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        license_pool_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_license_assignments
            WHERE tenant_id = $1 AND user_id = $2 AND license_pool_id = $3 AND status = 'active'
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(license_pool_id)
        .fetch_optional(pool)
        .await
    }

    /// Get all active assignments for a user.
    pub async fn list_active_by_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_license_assignments
            WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'
            ORDER BY assigned_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(pool)
        .await
    }

    /// Get all active assignments for a pool.
    pub async fn list_active_by_pool(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        license_pool_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_license_assignments
            WHERE tenant_id = $1 AND license_pool_id = $2 AND status = 'active'
            ORDER BY assigned_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(license_pool_id)
        .fetch_all(pool)
        .await
    }

    /// List assignments for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &LicenseAssignmentFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_license_assignments
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.license_pool_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND license_pool_id = ${}", param_count));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${}", param_count));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.source.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND source = ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY assigned_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovLicenseAssignment>(&query).bind(tenant_id);

        if let Some(pool_id) = filter.license_pool_id {
            q = q.bind(pool_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(source) = filter.source {
            q = q.bind(source);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count assignments in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &LicenseAssignmentFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_license_assignments
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.license_pool_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND license_pool_id = ${}", param_count));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${}", param_count));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.source.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND source = ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(pool_id) = filter.license_pool_id {
            q = q.bind(pool_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(source) = filter.source {
            q = q.bind(source);
        }

        q.fetch_one(pool).await
    }

    /// Create a new assignment.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovLicenseAssignment,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_license_assignments (
                tenant_id, license_pool_id, user_id, assigned_by, source,
                entitlement_link_id, session_id, notes
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.license_pool_id)
        .bind(input.user_id)
        .bind(input.assigned_by)
        .bind(input.source)
        .bind(input.entitlement_link_id)
        .bind(input.session_id)
        .bind(&input.notes)
        .fetch_one(pool)
        .await
    }

    /// Release (deallocate) an assignment.
    pub async fn release(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_license_assignments
            SET status = 'released', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Reclaim an assignment with reason.
    pub async fn reclaim(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        reason: LicenseReclaimReason,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_license_assignments
            SET status = 'reclaimed', reclaimed_at = NOW(), reclaim_reason = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(reason)
        .fetch_optional(pool)
        .await
    }

    /// Set assignment to expired status.
    pub async fn set_expired(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_license_assignments
            SET status = 'expired', reclaim_reason = 'expiration', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Expire all active assignments for a pool.
    pub async fn expire_all_for_pool(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        license_pool_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE gov_license_assignments
            SET status = 'expired', reclaim_reason = 'expiration', updated_at = NOW()
            WHERE tenant_id = $1 AND license_pool_id = $2 AND status = 'active'
            "#,
        )
        .bind(tenant_id)
        .bind(license_pool_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Find assignments by entitlement link.
    pub async fn find_by_entitlement_link(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        entitlement_link_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_license_assignments
            WHERE tenant_id = $1 AND entitlement_link_id = $2
            ORDER BY assigned_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(entitlement_link_id)
        .fetch_all(pool)
        .await
    }

    /// Find active assignments for a user that were assigned via entitlement.
    pub async fn find_active_entitlement_assignments(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_license_assignments
            WHERE tenant_id = $1 AND user_id = $2
              AND source = 'entitlement' AND status = 'active'
            ORDER BY assigned_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(pool)
        .await
    }

    /// Get pools assigned to a user (for incompatibility checking).
    pub async fn get_user_pool_ids(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT DISTINCT license_pool_id FROM gov_license_assignments
            WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(pool)
        .await
    }

    /// Count active assignments for a pool.
    pub async fn count_active_for_pool(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        license_pool_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_license_assignments
            WHERE tenant_id = $1 AND license_pool_id = $2 AND status = 'active'
            "#,
        )
        .bind(tenant_id)
        .bind(license_pool_id)
        .fetch_one(pool)
        .await
    }
}

/// Request to create a new license assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovLicenseAssignment {
    pub license_pool_id: Uuid,
    pub user_id: Uuid,
    pub assigned_by: Uuid,
    pub source: LicenseAssignmentSource,
    pub entitlement_link_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub notes: Option<String>,
}

/// Filter options for listing license assignments.
#[derive(Debug, Clone, Default)]
pub struct LicenseAssignmentFilter {
    pub license_pool_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub status: Option<LicenseAssignmentStatus>,
    pub source: Option<LicenseAssignmentSource>,
}

/// Extended assignment info with pool name and user display name.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct LicenseAssignmentWithDetails {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub license_pool_id: Uuid,
    pub license_pool_name: String,
    pub user_id: Uuid,
    pub user_display_name: Option<String>,
    pub user_email: String,
    pub assigned_at: DateTime<Utc>,
    pub assigned_by: Uuid,
    pub source: LicenseAssignmentSource,
    pub status: LicenseAssignmentStatus,
    pub reclaimed_at: Option<DateTime<Utc>>,
    pub reclaim_reason: Option<LicenseReclaimReason>,
    pub notes: Option<String>,
}

impl LicenseAssignmentWithDetails {
    /// Get assignments with pool and user details.
    pub async fn list_with_details(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &LicenseAssignmentFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT
                a.id, a.tenant_id, a.license_pool_id, p.name as license_pool_name,
                a.user_id, u.display_name as user_display_name, u.email as user_email,
                a.assigned_at, a.assigned_by, a.source, a.status,
                a.reclaimed_at, a.reclaim_reason, a.notes
            FROM gov_license_assignments a
            JOIN gov_license_pools p ON a.license_pool_id = p.id
            JOIN users u ON a.user_id = u.id
            WHERE a.tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.license_pool_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND a.license_pool_id = ${}", param_count));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND a.user_id = ${}", param_count));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND a.status = ${}", param_count));
        }
        if filter.source.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND a.source = ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY a.assigned_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(pool_id) = filter.license_pool_id {
            q = q.bind(pool_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(source) = filter.source {
            q = q.bind(source);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_active() {
        let assignment = GovLicenseAssignment {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            license_pool_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            assigned_at: Utc::now(),
            assigned_by: Uuid::new_v4(),
            source: LicenseAssignmentSource::Manual,
            entitlement_link_id: None,
            session_id: None,
            status: LicenseAssignmentStatus::Active,
            reclaimed_at: None,
            reclaim_reason: None,
            notes: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(assignment.is_active());
    }

    #[test]
    fn test_filter_default() {
        let filter = LicenseAssignmentFilter::default();
        assert!(filter.license_pool_id.is_none());
        assert!(filter.user_id.is_none());
        assert!(filter.status.is_none());
        assert!(filter.source.is_none());
    }
}
