//! Governance Orphan Detection model.
//!
//! Represents a detected orphan account with status and remediation tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Reason why an account was detected as orphan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_detection_reason", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum DetectionReason {
    /// User has no manager assigned.
    NoManager,
    /// User marked as terminated in HR system.
    TerminatedEmployee,
    /// User has been inactive for configured threshold.
    Inactive,
    /// HR data mismatch with system data.
    HrMismatch,
}

/// Status of an orphan detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_orphan_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum OrphanStatus {
    /// Newly detected, awaiting review.
    Pending,
    /// Under active review.
    UnderReview,
    /// Remediation action completed.
    Remediated,
    /// Dismissed as false positive.
    Dismissed,
}

/// Type of remediation action taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_remediation_action", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum RemediationAction {
    /// Account reassigned to new owner.
    Reassign,
    /// Account disabled.
    Disable,
    /// Account deletion requested/completed.
    Delete,
    /// Detection dismissed as false positive.
    Dismiss,
    /// Detection reopened for review.
    Reopen,
}

impl OrphanStatus {
    /// Check if this status allows remediation actions.
    #[must_use]
    pub fn can_remediate(&self) -> bool {
        matches!(self, Self::Pending | Self::UnderReview)
    }
}

/// An orphan detection record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovOrphanDetection {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this detection belongs to.
    pub tenant_id: Uuid,

    /// The user identified as orphan.
    pub user_id: Uuid,

    /// The reconciliation run that detected this.
    pub run_id: Uuid,

    /// Why this user was flagged.
    pub detection_reason: DetectionReason,

    /// Current status.
    pub status: OrphanStatus,

    /// When this orphan was detected.
    pub detected_at: DateTime<Utc>,

    /// Last activity time for the user (if available).
    pub last_activity_at: Option<DateTime<Utc>>,

    /// Days since last activity (for inactive detection).
    pub days_inactive: Option<i32>,

    /// Remediation action taken (if any).
    pub remediation_action: Option<RemediationAction>,

    /// Who performed the remediation.
    pub remediation_by: Option<Uuid>,

    /// When remediation was performed.
    pub remediation_at: Option<DateTime<Utc>>,

    /// Notes or justification for remediation.
    pub remediation_notes: Option<String>,

    /// New owner for reassignment.
    pub new_owner_id: Option<Uuid>,

    /// When the record was created.
    pub created_at: DateTime<Utc>,

    /// When the record was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new orphan detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovOrphanDetection {
    pub user_id: Uuid,
    pub run_id: Uuid,
    pub detection_reason: DetectionReason,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub days_inactive: Option<i32>,
}

/// Request to remediate an orphan detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediateGovOrphanDetection {
    pub action: RemediationAction,
    pub remediation_by: Uuid,
    pub remediation_notes: Option<String>,
    pub new_owner_id: Option<Uuid>,
}

/// Filter options for listing orphan detections.
#[derive(Debug, Clone, Default)]
pub struct OrphanDetectionFilter {
    pub status: Option<OrphanStatus>,
    pub detection_reason: Option<DetectionReason>,
    pub run_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

impl GovOrphanDetection {
    /// Find a detection by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_orphan_detections
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find detection for a specific user that is still active (`pending/under_review`).
    pub async fn find_active_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_orphan_detections
            WHERE tenant_id = $1 AND user_id = $2 AND status IN ('pending', 'under_review')
            ORDER BY detected_at DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
    }

    /// List all detections for a tenant with optional filtering.
    pub async fn list(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &OrphanDetectionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_orphan_detections
            WHERE tenant_id = $1
            ",
        );

        let mut param_idx = 2;

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${param_idx}"));
            param_idx += 1;
        }

        if filter.detection_reason.is_some() {
            query.push_str(&format!(" AND detection_reason = ${param_idx}"));
            param_idx += 1;
        }

        if filter.run_id.is_some() {
            query.push_str(&format!(" AND run_id = ${param_idx}"));
            param_idx += 1;
        }

        if filter.user_id.is_some() {
            query.push_str(&format!(" AND user_id = ${param_idx}"));
            param_idx += 1;
        }

        if filter.since.is_some() {
            query.push_str(&format!(" AND detected_at >= ${param_idx}"));
            param_idx += 1;
        }

        if filter.until.is_some() {
            query.push_str(&format!(" AND detected_at <= ${param_idx}"));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY detected_at DESC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(status) = &filter.status {
            q = q.bind(status);
        }

        if let Some(reason) = &filter.detection_reason {
            q = q.bind(reason);
        }

        if let Some(run_id) = filter.run_id {
            q = q.bind(run_id);
        }

        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }

        if let Some(since) = filter.since {
            q = q.bind(since);
        }

        if let Some(until) = filter.until {
            q = q.bind(until);
        }

        q = q.bind(limit).bind(offset);

        q.fetch_all(pool).await
    }

    /// Count detections for a tenant with optional filtering.
    pub async fn count(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &OrphanDetectionFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_orphan_detections
            WHERE tenant_id = $1
            ",
        );

        let mut param_idx = 2;

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${param_idx}"));
            param_idx += 1;
        }

        if filter.detection_reason.is_some() {
            query.push_str(&format!(" AND detection_reason = ${param_idx}"));
            param_idx += 1;
        }

        if filter.run_id.is_some() {
            query.push_str(&format!(" AND run_id = ${param_idx}"));
            param_idx += 1;
        }

        if filter.user_id.is_some() {
            query.push_str(&format!(" AND user_id = ${param_idx}"));
            param_idx += 1;
        }

        if filter.since.is_some() {
            query.push_str(&format!(" AND detected_at >= ${param_idx}"));
            param_idx += 1;
        }

        if filter.until.is_some() {
            query.push_str(&format!(" AND detected_at <= ${param_idx}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = &filter.status {
            q = q.bind(status);
        }

        if let Some(reason) = &filter.detection_reason {
            q = q.bind(reason);
        }

        if let Some(run_id) = filter.run_id {
            q = q.bind(run_id);
        }

        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }

        if let Some(since) = filter.since {
            q = q.bind(since);
        }

        if let Some(until) = filter.until {
            q = q.bind(until);
        }

        q.fetch_one(pool).await
    }

    /// Get summary counts by status.
    pub async fn get_summary_by_status(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<(OrphanStatus, i64)>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT status, COUNT(*) as count
            FROM gov_orphan_detections
            WHERE tenant_id = $1
            GROUP BY status
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Get summary counts by reason.
    pub async fn get_summary_by_reason(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<(DetectionReason, i64)>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT detection_reason, COUNT(*) as count
            FROM gov_orphan_detections
            WHERE tenant_id = $1 AND status IN ('pending', 'under_review')
            GROUP BY detection_reason
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Create a new orphan detection.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        data: CreateGovOrphanDetection,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_orphan_detections (
                tenant_id, user_id, run_id, detection_reason, last_activity_at, days_inactive
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(data.user_id)
        .bind(data.run_id)
        .bind(data.detection_reason)
        .bind(data.last_activity_at)
        .bind(data.days_inactive)
        .fetch_one(pool)
        .await
    }

    /// Update status only.
    pub async fn update_status(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: OrphanStatus,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_orphan_detections
            SET status = $3
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(status)
        .fetch_optional(pool)
        .await
    }

    /// Apply remediation to a detection.
    pub async fn remediate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        data: RemediateGovOrphanDetection,
    ) -> Result<Option<Self>, sqlx::Error> {
        let new_status = match data.action {
            RemediationAction::Dismiss
            | RemediationAction::Reassign
            | RemediationAction::Disable
            | RemediationAction::Delete => OrphanStatus::Remediated,
            RemediationAction::Reopen => OrphanStatus::Pending,
        };

        // For dismiss action, mark as dismissed instead of remediated
        let new_status = if data.action == RemediationAction::Dismiss {
            OrphanStatus::Dismissed
        } else {
            new_status
        };

        sqlx::query_as(
            r"
            UPDATE gov_orphan_detections
            SET
                status = $3,
                remediation_action = $4,
                remediation_by = $5,
                remediation_at = NOW(),
                remediation_notes = $6,
                new_owner_id = $7
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_status)
        .bind(data.action)
        .bind(data.remediation_by)
        .bind(data.remediation_notes)
        .bind(data.new_owner_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark previous active detections for a user as resolved.
    pub async fn mark_resolved_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        current_run_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_orphan_detections
            SET
                status = 'remediated',
                remediation_action = 'reopen',
                remediation_at = NOW(),
                remediation_notes = 'Auto-resolved: user no longer orphaned'
            WHERE tenant_id = $1 AND user_id = $2
                AND run_id != $3
                AND status IN ('pending', 'under_review')
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(current_run_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Delete a detection.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_orphan_detections
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get average age in days of pending orphans.
    pub async fn get_average_age_days(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Option<f64>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT AVG(EXTRACT(EPOCH FROM (NOW() - detected_at)) / 86400)::float8
            FROM gov_orphan_detections
            WHERE tenant_id = $1 AND status IN ('pending', 'under_review')
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orphan_status_can_remediate() {
        assert!(OrphanStatus::Pending.can_remediate());
        assert!(OrphanStatus::UnderReview.can_remediate());
        assert!(!OrphanStatus::Remediated.can_remediate());
        assert!(!OrphanStatus::Dismissed.can_remediate());
    }
}
