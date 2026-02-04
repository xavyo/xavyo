//! Governance Remediation Log model.
//!
//! Represents audit trail entries for remediation actions on orphan detections.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_orphan_detection::RemediationAction;

/// A governance remediation log entry.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovRemediationLog {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this log belongs to.
    pub tenant_id: Uuid,

    /// The orphan detection this action relates to.
    pub orphan_detection_id: Uuid,

    /// The action that was performed.
    pub action: RemediationAction,

    /// Who performed the action.
    pub performed_by: Uuid,

    /// When the action was performed.
    pub performed_at: DateTime<Utc>,

    /// Additional details about the action.
    pub details: serde_json::Value,

    /// When the record was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new remediation log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovRemediationLog {
    pub orphan_detection_id: Uuid,
    pub action: RemediationAction,
    pub performed_by: Uuid,
    pub details: Option<serde_json::Value>,
}

/// Filter options for listing remediation logs.
#[derive(Debug, Clone, Default)]
pub struct RemediationLogFilter {
    pub orphan_detection_id: Option<Uuid>,
    pub action: Option<RemediationAction>,
    pub performed_by: Option<Uuid>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

impl GovRemediationLog {
    /// Find a log entry by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_remediation_logs
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List logs for a specific orphan detection.
    pub async fn list_by_detection(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        orphan_detection_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_remediation_logs
            WHERE tenant_id = $1 AND orphan_detection_id = $2
            ORDER BY performed_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(orphan_detection_id)
        .fetch_all(pool)
        .await
    }

    /// List logs by performer.
    pub async fn list_by_performer(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        performed_by: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_remediation_logs
            WHERE tenant_id = $1 AND performed_by = $2
            ORDER BY performed_at DESC
            LIMIT $3
            ",
        )
        .bind(tenant_id)
        .bind(performed_by)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// List all logs for a tenant with optional filtering.
    pub async fn list(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &RemediationLogFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_remediation_logs
            WHERE tenant_id = $1
            ",
        );

        let mut param_idx = 2;

        if filter.orphan_detection_id.is_some() {
            query.push_str(&format!(" AND orphan_detection_id = ${param_idx}"));
            param_idx += 1;
        }

        if filter.action.is_some() {
            query.push_str(&format!(" AND action = ${param_idx}"));
            param_idx += 1;
        }

        if filter.performed_by.is_some() {
            query.push_str(&format!(" AND performed_by = ${param_idx}"));
            param_idx += 1;
        }

        if filter.since.is_some() {
            query.push_str(&format!(" AND performed_at >= ${param_idx}"));
            param_idx += 1;
        }

        if filter.until.is_some() {
            query.push_str(&format!(" AND performed_at <= ${param_idx}"));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY performed_at DESC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(detection_id) = filter.orphan_detection_id {
            q = q.bind(detection_id);
        }

        if let Some(action) = filter.action {
            q = q.bind(action);
        }

        if let Some(performed_by) = filter.performed_by {
            q = q.bind(performed_by);
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

    /// Count logs for a tenant with optional filtering.
    pub async fn count(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &RemediationLogFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_remediation_logs
            WHERE tenant_id = $1
            ",
        );

        let mut param_idx = 2;

        if filter.orphan_detection_id.is_some() {
            query.push_str(&format!(" AND orphan_detection_id = ${param_idx}"));
            param_idx += 1;
        }

        if filter.action.is_some() {
            query.push_str(&format!(" AND action = ${param_idx}"));
            param_idx += 1;
        }

        if filter.performed_by.is_some() {
            query.push_str(&format!(" AND performed_by = ${param_idx}"));
            param_idx += 1;
        }

        if filter.since.is_some() {
            query.push_str(&format!(" AND performed_at >= ${param_idx}"));
            param_idx += 1;
        }

        if filter.until.is_some() {
            query.push_str(&format!(" AND performed_at <= ${param_idx}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(detection_id) = filter.orphan_detection_id {
            q = q.bind(detection_id);
        }

        if let Some(action) = filter.action {
            q = q.bind(action);
        }

        if let Some(performed_by) = filter.performed_by {
            q = q.bind(performed_by);
        }

        if let Some(since) = filter.since {
            q = q.bind(since);
        }

        if let Some(until) = filter.until {
            q = q.bind(until);
        }

        q.fetch_one(pool).await
    }

    /// Create a new remediation log entry.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        data: CreateGovRemediationLog,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_remediation_logs (
                tenant_id, orphan_detection_id, action, performed_by, details
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(data.orphan_detection_id)
        .bind(data.action)
        .bind(data.performed_by)
        .bind(data.details.unwrap_or_else(|| serde_json::json!({})))
        .fetch_one(pool)
        .await
    }

    /// Get action counts by type for a tenant.
    pub async fn get_action_counts(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<(RemediationAction, i64)>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT action, COUNT(*) as count
            FROM gov_remediation_logs
            WHERE tenant_id = $1
            GROUP BY action
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Get action counts by performer for a tenant.
    pub async fn get_counts_by_performer(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<(Uuid, i64)>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT performed_by, COUNT(*) as count
            FROM gov_remediation_logs
            WHERE tenant_id = $1
            GROUP BY performed_by
            ORDER BY count DESC
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Get recent activity (last N days).
    pub async fn get_recent_activity(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        days: i32,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_remediation_logs
            WHERE tenant_id = $1
                AND performed_at >= NOW() - ($2 || ' days')::interval
            ORDER BY performed_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(days)
        .fetch_all(pool)
        .await
    }

    /// Delete logs older than specified days (for cleanup).
    pub async fn delete_older_than(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        days: i32,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_remediation_logs
            WHERE tenant_id = $1
                AND performed_at < NOW() - ($2 || ' days')::interval
            ",
        )
        .bind(tenant_id)
        .bind(days)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_filter() {
        let filter = RemediationLogFilter::default();
        assert!(filter.orphan_detection_id.is_none());
        assert!(filter.action.is_none());
        assert!(filter.performed_by.is_none());
        assert!(filter.since.is_none());
        assert!(filter.until.is_none());
    }
}
