//! Governance Risk Alert model.
//!
//! Represents generated alerts when users exceed risk thresholds.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_risk_threshold::AlertSeverity;

/// A governance risk alert.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovRiskAlert {
    /// Unique identifier for the alert.
    pub id: Uuid,

    /// The tenant this alert belongs to.
    pub tenant_id: Uuid,

    /// The user who triggered the alert.
    pub user_id: Uuid,

    /// The threshold that was exceeded.
    pub threshold_id: Uuid,

    /// Score at the time the alert was triggered.
    pub score_at_alert: i32,

    /// Alert severity.
    pub severity: AlertSeverity,

    /// Whether the alert has been acknowledged.
    pub acknowledged: bool,

    /// User who acknowledged the alert.
    pub acknowledged_by: Option<Uuid>,

    /// When the alert was acknowledged.
    pub acknowledged_at: Option<DateTime<Utc>>,

    /// When the alert was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new risk alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovRiskAlert {
    pub user_id: Uuid,
    pub threshold_id: Uuid,
    pub score_at_alert: i32,
    pub severity: AlertSeverity,
}

/// Filter options for listing risk alerts.
#[derive(Debug, Clone, Default)]
pub struct RiskAlertFilter {
    pub user_id: Option<Uuid>,
    pub threshold_id: Option<Uuid>,
    pub severity: Option<AlertSeverity>,
    pub acknowledged: Option<bool>,
}

/// Sort options for risk alerts.
#[derive(Debug, Clone, Copy, Default)]
pub enum RiskAlertSortBy {
    #[default]
    CreatedAtDesc,
    CreatedAtAsc,
    SeverityDesc,
    ScoreDesc,
}

impl RiskAlertSortBy {
    fn as_sql(self) -> &'static str {
        match self {
            Self::CreatedAtDesc => "created_at DESC",
            Self::CreatedAtAsc => "created_at ASC",
            Self::SeverityDesc => "severity DESC, created_at DESC",
            Self::ScoreDesc => "score_at_alert DESC, created_at DESC",
        }
    }
}

impl GovRiskAlert {
    /// Find an alert by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_risk_alerts
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List unacknowledged alerts for a tenant.
    pub async fn list_unacknowledged(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_risk_alerts
            WHERE tenant_id = $1 AND acknowledged = false
            ORDER BY severity DESC, created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List alerts for a user.
    pub async fn list_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_risk_alerts
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Check if an alert already exists within cooldown period.
    pub async fn exists_within_cooldown(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        threshold_id: Uuid,
        cooldown_hours: i32,
    ) -> Result<bool, sqlx::Error> {
        let exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM gov_risk_alerts
                WHERE tenant_id = $1 AND user_id = $2 AND threshold_id = $3
                AND created_at > NOW() - INTERVAL '1 hour' * $4
            )
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(threshold_id)
        .bind(cooldown_hours)
        .fetch_one(pool)
        .await?;

        Ok(exists)
    }

    /// List alerts for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &RiskAlertFilter,
        sort_by: RiskAlertSortBy,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_risk_alerts
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${}", param_count));
        }
        if filter.threshold_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND threshold_id = ${}", param_count));
        }
        if filter.severity.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND severity = ${}", param_count));
        }
        if filter.acknowledged.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND acknowledged = ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY {} LIMIT ${} OFFSET ${}",
            sort_by.as_sql(),
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovRiskAlert>(&query).bind(tenant_id);

        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(threshold_id) = filter.threshold_id {
            q = q.bind(threshold_id);
        }
        if let Some(severity) = filter.severity {
            q = q.bind(severity);
        }
        if let Some(acknowledged) = filter.acknowledged {
            q = q.bind(acknowledged);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count alerts in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &RiskAlertFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_risk_alerts
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${}", param_count));
        }
        if filter.threshold_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND threshold_id = ${}", param_count));
        }
        if filter.severity.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND severity = ${}", param_count));
        }
        if filter.acknowledged.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND acknowledged = ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(threshold_id) = filter.threshold_id {
            q = q.bind(threshold_id);
        }
        if let Some(severity) = filter.severity {
            q = q.bind(severity);
        }
        if let Some(acknowledged) = filter.acknowledged {
            q = q.bind(acknowledged);
        }

        q.fetch_one(pool).await
    }

    /// Count unacknowledged alerts per severity.
    pub async fn count_unacknowledged_by_severity(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<(AlertSeverity, i64)>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT severity, COUNT(*) as count
            FROM gov_risk_alerts
            WHERE tenant_id = $1 AND acknowledged = false
            GROUP BY severity
            ORDER BY severity DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Create a new risk alert.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovRiskAlert,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_risk_alerts (
                tenant_id, user_id, threshold_id, score_at_alert, severity
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.user_id)
        .bind(input.threshold_id)
        .bind(input.score_at_alert)
        .bind(input.severity)
        .fetch_one(pool)
        .await
    }

    /// Acknowledge an alert.
    pub async fn acknowledge(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        acknowledged_by: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_risk_alerts
            SET acknowledged = true, acknowledged_by = $3, acknowledged_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND acknowledged = false
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(acknowledged_by)
        .fetch_optional(pool)
        .await
    }

    /// Bulk acknowledge alerts for a user.
    pub async fn acknowledge_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        acknowledged_by: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE gov_risk_alerts
            SET acknowledged = true, acknowledged_by = $3, acknowledged_at = NOW()
            WHERE tenant_id = $1 AND user_id = $2 AND acknowledged = false
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(acknowledged_by)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Delete an alert.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_risk_alerts
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete alerts older than a specific date.
    pub async fn cleanup_older_than(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        before: DateTime<Utc>,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_risk_alerts
            WHERE tenant_id = $1 AND created_at < $2
            "#,
        )
        .bind(tenant_id)
        .bind(before)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get the most recent alert for a user.
    pub async fn get_most_recent_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_risk_alerts
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sort_by_as_sql() {
        assert_eq!(RiskAlertSortBy::CreatedAtDesc.as_sql(), "created_at DESC");
        assert_eq!(RiskAlertSortBy::CreatedAtAsc.as_sql(), "created_at ASC");
        assert_eq!(
            RiskAlertSortBy::SeverityDesc.as_sql(),
            "severity DESC, created_at DESC"
        );
        assert_eq!(
            RiskAlertSortBy::ScoreDesc.as_sql(),
            "score_at_alert DESC, created_at DESC"
        );
    }

    #[test]
    fn test_default_sort_by() {
        let default = RiskAlertSortBy::default();
        assert!(matches!(default, RiskAlertSortBy::CreatedAtDesc));
    }

    #[test]
    fn test_default_filter() {
        let filter = RiskAlertFilter::default();
        assert!(filter.user_id.is_none());
        assert!(filter.threshold_id.is_none());
        assert!(filter.severity.is_none());
        assert!(filter.acknowledged.is_none());
    }
}
