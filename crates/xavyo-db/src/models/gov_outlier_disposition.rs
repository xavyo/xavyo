//! Outlier disposition model for analyst assessments.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_outlier_types::OutlierDispositionStatus;

/// Analyst's assessment of an outlier result.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovOutlierDisposition {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this disposition belongs to.
    pub tenant_id: Uuid,

    /// Related outlier result.
    pub result_id: Uuid,

    /// User who is the subject of the outlier.
    pub user_id: Uuid,

    /// Current disposition status.
    pub status: OutlierDispositionStatus,

    /// Analyst justification for the disposition.
    pub justification: Option<String>,

    /// Analyst who reviewed.
    pub reviewed_by: Option<Uuid>,

    /// When reviewed.
    pub reviewed_at: Option<DateTime<Utc>>,

    /// When this disposition expires (for temporary exceptions).
    pub expires_at: Option<DateTime<Utc>>,

    /// When created.
    pub created_at: DateTime<Utc>,

    /// When last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new disposition.
#[derive(Debug, Clone)]
pub struct CreateDisposition {
    pub result_id: Uuid,
    pub user_id: Uuid,
}

/// Request to update a disposition.
#[derive(Debug, Clone)]
pub struct UpdateDisposition {
    pub status: OutlierDispositionStatus,
    pub justification: Option<String>,
    pub reviewed_by: Uuid,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Filter options for listing dispositions.
#[derive(Debug, Clone, Default)]
pub struct DispositionFilter {
    pub user_id: Option<Uuid>,
    pub status: Option<OutlierDispositionStatus>,
    pub reviewed_by: Option<Uuid>,
    pub include_expired: bool,
}

/// Summary of dispositions by status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispositionSummary {
    pub new_count: i64,
    pub legitimate_count: i64,
    pub requires_remediation_count: i64,
    pub under_investigation_count: i64,
    pub remediated_count: i64,
}

impl GovOutlierDisposition {
    /// Find disposition by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_outlier_dispositions
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find disposition by result ID.
    pub async fn find_by_result(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        result_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_outlier_dispositions
            WHERE result_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(result_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find the most recent disposition for a user.
    pub async fn find_latest_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_outlier_dispositions
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
    }

    /// List dispositions with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &DispositionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_outlier_dispositions WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${}", param_count));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.reviewed_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND reviewed_by = ${}", param_count));
        }
        if !filter.include_expired {
            query.push_str(" AND (expires_at IS NULL OR expires_at > NOW())");
        }

        query.push_str(&format!(
            " ORDER BY updated_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(reviewed_by) = filter.reviewed_by {
            q = q.bind(reviewed_by);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count dispositions with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &DispositionFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from("SELECT COUNT(*) FROM gov_outlier_dispositions WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${}", param_count));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.reviewed_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND reviewed_by = ${}", param_count));
        }
        if !filter.include_expired {
            query.push_str(" AND (expires_at IS NULL OR expires_at > NOW())");
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(reviewed_by) = filter.reviewed_by {
            q = q.bind(reviewed_by);
        }

        q.fetch_one(pool).await
    }

    /// Get summary of dispositions by status.
    pub async fn get_summary(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<DispositionSummary, sqlx::Error> {
        let row: (i64, i64, i64, i64, i64) = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE status = 'new') as new_count,
                COUNT(*) FILTER (WHERE status = 'legitimate') as legitimate_count,
                COUNT(*) FILTER (WHERE status = 'requires_remediation') as requires_remediation_count,
                COUNT(*) FILTER (WHERE status = 'under_investigation') as under_investigation_count,
                COUNT(*) FILTER (WHERE status = 'remediated') as remediated_count
            FROM gov_outlier_dispositions
            WHERE tenant_id = $1 AND (expires_at IS NULL OR expires_at > NOW())
            "#,
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(DispositionSummary {
            new_count: row.0,
            legitimate_count: row.1,
            requires_remediation_count: row.2,
            under_investigation_count: row.3,
            remediated_count: row.4,
        })
    }

    /// Create a new disposition (default status: New).
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateDisposition,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_outlier_dispositions (tenant_id, result_id, user_id)
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.result_id)
        .bind(input.user_id)
        .fetch_one(pool)
        .await
    }

    /// Update a disposition with state machine validation.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        current_status: OutlierDispositionStatus,
        input: UpdateDisposition,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Validate state transition
        if !current_status.can_transition_to(&input.status) {
            return Ok(None);
        }

        sqlx::query_as(
            r#"
            UPDATE gov_outlier_dispositions
            SET status = $3, justification = $4, reviewed_by = $5,
                reviewed_at = NOW(), expires_at = $6, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.status)
        .bind(input.justification)
        .bind(input.reviewed_by)
        .bind(input.expires_at)
        .fetch_optional(pool)
        .await
    }

    /// Re-flag a legitimate disposition back to New (for score increases).
    pub async fn reflag(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE gov_outlier_dispositions
            SET status = 'new', updated_at = NOW()
            WHERE tenant_id = $1 AND user_id = $2 AND status = 'legitimate'
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Find dispositions pending review (New or RequiresRemediation).
    pub async fn find_pending_review(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_outlier_dispositions
            WHERE tenant_id = $1 AND status IN ('new', 'requires_remediation')
                AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at ASC
            LIMIT $2
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Find expired legitimate dispositions (need re-review).
    pub async fn find_expired(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_outlier_dispositions
            WHERE tenant_id = $1 AND status = 'legitimate'
                AND expires_at IS NOT NULL AND expires_at <= NOW()
            ORDER BY expires_at ASC
            LIMIT $2
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Delete disposition.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_outlier_dispositions
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if this disposition requires attention.
    pub fn requires_attention(&self) -> bool {
        self.status.requires_attention()
    }

    /// Check if this disposition has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            expires_at <= Utc::now()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disposition_requires_attention() {
        let disposition = GovOutlierDisposition {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            result_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            status: OutlierDispositionStatus::New,
            justification: None,
            reviewed_by: None,
            reviewed_at: None,
            expires_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(disposition.requires_attention());
    }

    #[test]
    fn test_disposition_does_not_require_attention() {
        let disposition = GovOutlierDisposition {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            result_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            status: OutlierDispositionStatus::Legitimate,
            justification: Some("Approved".to_string()),
            reviewed_by: Some(Uuid::new_v4()),
            reviewed_at: Some(Utc::now()),
            expires_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(!disposition.requires_attention());
    }

    #[test]
    fn test_disposition_is_expired() {
        let disposition = GovOutlierDisposition {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            result_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            status: OutlierDispositionStatus::Legitimate,
            justification: None,
            reviewed_by: None,
            reviewed_at: None,
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(disposition.is_expired());
    }

    #[test]
    fn test_disposition_not_expired() {
        let disposition = GovOutlierDisposition {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            result_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            status: OutlierDispositionStatus::Legitimate,
            justification: None,
            reviewed_by: None,
            reviewed_at: None,
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(!disposition.is_expired());
    }

    #[test]
    fn test_filter_default() {
        let filter = DispositionFilter::default();
        assert!(filter.user_id.is_none());
        assert!(filter.status.is_none());
        assert!(filter.reviewed_by.is_none());
        assert!(!filter.include_expired);
    }
}
