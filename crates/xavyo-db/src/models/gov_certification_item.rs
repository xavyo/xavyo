//! Governance Certification Item model.
//!
//! Represents an individual review item linking a user to an entitlement within a campaign.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status for certification items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "cert_item_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CertItemStatus {
    /// Awaiting reviewer decision.
    Pending,
    /// Reviewer approved the access.
    Approved,
    /// Reviewer revoked the access.
    Revoked,
    /// Item skipped (assignment was deleted).
    Skipped,
}

impl CertItemStatus {
    /// Check if the item is pending decision.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Check if the item has been decided.
    #[must_use]
    pub fn is_decided(&self) -> bool {
        matches!(self, Self::Approved | Self::Revoked)
    }

    /// Check if the item is in a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        !self.is_pending()
    }
}

/// A certification item in a campaign.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovCertificationItem {
    /// Unique identifier for the item.
    pub id: Uuid,

    /// The tenant this item belongs to.
    pub tenant_id: Uuid,

    /// The parent campaign.
    pub campaign_id: Uuid,

    /// The source entitlement assignment (NULL if deleted).
    pub assignment_id: Option<Uuid>,

    /// The user whose access is being reviewed.
    pub user_id: Uuid,

    /// The entitlement being reviewed.
    pub entitlement_id: Uuid,

    /// The assigned reviewer.
    pub reviewer_id: Uuid,

    /// Item status.
    pub status: CertItemStatus,

    /// Snapshot of assignment at generation time.
    pub assignment_snapshot: serde_json::Value,

    /// When the decision was made.
    pub decided_at: Option<DateTime<Utc>>,

    /// When the item was created.
    pub created_at: DateTime<Utc>,

    /// When the item was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new certification item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCertificationItem {
    pub campaign_id: Uuid,
    pub assignment_id: Option<Uuid>,
    pub user_id: Uuid,
    pub entitlement_id: Uuid,
    pub reviewer_id: Uuid,
    pub assignment_snapshot: serde_json::Value,
}

/// Filter options for listing certification items.
#[derive(Debug, Clone, Default)]
pub struct CertItemFilter {
    pub campaign_id: Option<Uuid>,
    pub reviewer_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub entitlement_id: Option<Uuid>,
    pub status: Option<CertItemStatus>,
    pub statuses: Option<Vec<CertItemStatus>>,
}

/// Summary of items by status for a campaign or reviewer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertItemSummary {
    pub total: i64,
    pub pending: i64,
    pub approved: i64,
    pub revoked: i64,
    pub skipped: i64,
}

impl GovCertificationItem {
    /// Find an item by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_certification_items
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find an item by ID without tenant check (for internal use with FK lookups).
    pub async fn find_by_id_internal(
        pool: &sqlx::PgPool,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_certification_items
            WHERE id = $1
            ",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Check if a pending item exists for this user-entitlement in the given campaign.
    ///
    /// Scoped to a single campaign so that the same user+entitlement pair can be
    /// reviewed in multiple concurrent campaigns.
    pub async fn exists_pending_for_user_entitlement(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        campaign_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_certification_items
            WHERE tenant_id = $1 AND campaign_id = $2 AND user_id = $3 AND entitlement_id = $4 AND status = 'pending'
            ",
        )
        .bind(tenant_id)
        .bind(campaign_id)
        .bind(user_id)
        .bind(entitlement_id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// List items for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CertItemFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_certification_items
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.campaign_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND campaign_id = ${param_count}"));
        }
        if filter.reviewer_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND reviewer_id = ${param_count}"));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.entitlement_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND entitlement_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovCertificationItem>(&query).bind(tenant_id);

        if let Some(campaign_id) = filter.campaign_id {
            q = q.bind(campaign_id);
        }
        if let Some(reviewer_id) = filter.reviewer_id {
            q = q.bind(reviewer_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(entitlement_id) = filter.entitlement_id {
            q = q.bind(entitlement_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count items in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CertItemFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_certification_items
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.campaign_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND campaign_id = ${param_count}"));
        }
        if filter.reviewer_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND reviewer_id = ${param_count}"));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.entitlement_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND entitlement_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(campaign_id) = filter.campaign_id {
            q = q.bind(campaign_id);
        }
        if let Some(reviewer_id) = filter.reviewer_id {
            q = q.bind(reviewer_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(entitlement_id) = filter.entitlement_id {
            q = q.bind(entitlement_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }

        q.fetch_one(pool).await
    }

    /// Get summary of items for a campaign.
    pub async fn get_campaign_summary(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<CertItemSummary, sqlx::Error> {
        let row: (i64, i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'approved') as approved,
                COUNT(*) FILTER (WHERE status = 'revoked') as revoked,
                COUNT(*) FILTER (WHERE status = 'skipped') as skipped
            FROM gov_certification_items
            WHERE tenant_id = $1 AND campaign_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(campaign_id)
        .fetch_one(pool)
        .await?;

        Ok(CertItemSummary {
            total: row.0,
            pending: row.1,
            approved: row.2,
            revoked: row.3,
            skipped: row.4,
        })
    }

    /// Get summary of pending items for a reviewer.
    pub async fn get_reviewer_pending_count(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        reviewer_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_certification_items
            WHERE tenant_id = $1 AND reviewer_id = $2 AND status = 'pending'
            ",
        )
        .bind(tenant_id)
        .bind(reviewer_id)
        .fetch_one(pool)
        .await
    }

    /// Create a new certification item.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateCertificationItem,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_certification_items (
                tenant_id, campaign_id, assignment_id, user_id,
                entitlement_id, reviewer_id, assignment_snapshot
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.campaign_id)
        .bind(input.assignment_id)
        .bind(input.user_id)
        .bind(input.entitlement_id)
        .bind(input.reviewer_id)
        .bind(&input.assignment_snapshot)
        .fetch_one(pool)
        .await
    }

    /// Bulk create certification items.
    pub async fn bulk_create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        items: Vec<CreateCertificationItem>,
    ) -> Result<u64, sqlx::Error> {
        if items.is_empty() {
            return Ok(0);
        }

        // Build bulk insert query
        let mut query = String::from(
            r"
            INSERT INTO gov_certification_items (
                tenant_id, campaign_id, assignment_id, user_id,
                entitlement_id, reviewer_id, assignment_snapshot
            ) VALUES
            ",
        );

        let mut params: Vec<String> = Vec::with_capacity(items.len());
        let mut param_idx = 1;

        for _ in &items {
            params.push(format!(
                "(${}, ${}, ${}, ${}, ${}, ${}, ${})",
                param_idx,
                param_idx + 1,
                param_idx + 2,
                param_idx + 3,
                param_idx + 4,
                param_idx + 5,
                param_idx + 6
            ));
            param_idx += 7;
        }

        query.push_str(&params.join(", "));
        query.push_str(" ON CONFLICT DO NOTHING");

        let mut q = sqlx::query(&query);

        for item in items {
            q = q
                .bind(tenant_id)
                .bind(item.campaign_id)
                .bind(item.assignment_id)
                .bind(item.user_id)
                .bind(item.entitlement_id)
                .bind(item.reviewer_id)
                .bind(item.assignment_snapshot);
        }

        let result = q.execute(pool).await?;
        Ok(result.rows_affected())
    }

    /// Update item status to approved.
    pub async fn approve(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_certification_items
            SET status = 'approved',
                decided_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Update item status to revoked.
    pub async fn revoke(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_certification_items
            SET status = 'revoked',
                decided_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Update item status to skipped.
    pub async fn skip(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_certification_items
            SET status = 'skipped',
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Reassign item to a different reviewer.
    pub async fn reassign(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        new_reviewer_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_certification_items
            SET reviewer_id = $3,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_reviewer_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark items as skipped when assignment is deleted.
    pub async fn skip_by_assignment(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_certification_items
            SET status = 'skipped', updated_at = NOW()
            WHERE tenant_id = $1 AND assignment_id = $2 AND status = 'pending'
            ",
        )
        .bind(tenant_id)
        .bind(assignment_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Check if the item is pending.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.status.is_pending()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_item_status_is_pending() {
        assert!(CertItemStatus::Pending.is_pending());
        assert!(!CertItemStatus::Approved.is_pending());
        assert!(!CertItemStatus::Revoked.is_pending());
        assert!(!CertItemStatus::Skipped.is_pending());
    }

    #[test]
    fn test_item_status_is_decided() {
        assert!(CertItemStatus::Approved.is_decided());
        assert!(CertItemStatus::Revoked.is_decided());
        assert!(!CertItemStatus::Pending.is_decided());
        assert!(!CertItemStatus::Skipped.is_decided());
    }

    #[test]
    fn test_item_status_is_terminal() {
        assert!(CertItemStatus::Approved.is_terminal());
        assert!(CertItemStatus::Revoked.is_terminal());
        assert!(CertItemStatus::Skipped.is_terminal());
        assert!(!CertItemStatus::Pending.is_terminal());
    }

    #[test]
    fn test_status_serialization() {
        let pending = CertItemStatus::Pending;
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(json, "\"pending\"");

        let approved = CertItemStatus::Approved;
        let json = serde_json::to_string(&approved).unwrap();
        assert_eq!(json, "\"approved\"");
    }

    #[test]
    fn test_create_item_request() {
        let request = CreateCertificationItem {
            campaign_id: Uuid::new_v4(),
            assignment_id: Some(Uuid::new_v4()),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
            assignment_snapshot: serde_json::json!({"assigned_at": "2026-01-24T00:00:00Z"}),
        };

        assert!(request.assignment_id.is_some());
    }

    #[test]
    fn test_item_summary_default() {
        let summary = CertItemSummary::default();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.pending, 0);
        assert_eq!(summary.approved, 0);
        assert_eq!(summary.revoked, 0);
        assert_eq!(summary.skipped, 0);
    }
}
