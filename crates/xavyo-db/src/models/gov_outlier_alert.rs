//! Outlier alert model for notifications.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_outlier_types::{OutlierAlertSeverity, OutlierAlertType, OutlierClassification};

/// Alert generated when an outlier is detected.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovOutlierAlert {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this alert belongs to.
    pub tenant_id: Uuid,

    /// Analysis that generated this alert.
    pub analysis_id: Uuid,

    /// User who is the outlier.
    pub user_id: Uuid,

    /// Type of alert.
    pub alert_type: OutlierAlertType,

    /// Severity level.
    pub severity: OutlierAlertSeverity,

    /// Outlier score at alert time.
    pub score: f64,

    /// Classification at alert time.
    pub classification: OutlierClassification,

    /// Whether the alert has been read.
    pub is_read: bool,

    /// Whether the alert has been dismissed.
    pub is_dismissed: bool,

    /// When created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new alert.
#[derive(Debug, Clone)]
pub struct CreateAlert {
    pub analysis_id: Uuid,
    pub user_id: Uuid,
    pub alert_type: OutlierAlertType,
    pub score: f64,
    pub classification: OutlierClassification,
}

/// Filter options for listing alerts.
#[derive(Debug, Clone, Default)]
pub struct AlertFilter {
    pub user_id: Option<Uuid>,
    pub analysis_id: Option<Uuid>,
    pub alert_type: Option<OutlierAlertType>,
    pub severity: Option<OutlierAlertSeverity>,
    pub is_read: Option<bool>,
    pub is_dismissed: Option<bool>,
}

/// Summary of alerts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSummary {
    pub total_count: i64,
    pub unread_count: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
}

impl GovOutlierAlert {
    /// Find alert by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_outlier_alerts
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List alerts with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &AlertFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_outlier_alerts WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.analysis_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND analysis_id = ${param_count}"));
        }
        if filter.alert_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND alert_type = ${param_count}"));
        }
        if filter.severity.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND severity = ${param_count}"));
        }
        if filter.is_read.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_read = ${param_count}"));
        }
        if filter.is_dismissed.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_dismissed = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(analysis_id) = filter.analysis_id {
            q = q.bind(analysis_id);
        }
        if let Some(alert_type) = filter.alert_type {
            q = q.bind(alert_type);
        }
        if let Some(severity) = filter.severity {
            q = q.bind(severity);
        }
        if let Some(is_read) = filter.is_read {
            q = q.bind(is_read);
        }
        if let Some(is_dismissed) = filter.is_dismissed {
            q = q.bind(is_dismissed);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count alerts with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &AlertFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from("SELECT COUNT(*) FROM gov_outlier_alerts WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.analysis_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND analysis_id = ${param_count}"));
        }
        if filter.alert_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND alert_type = ${param_count}"));
        }
        if filter.severity.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND severity = ${param_count}"));
        }
        if filter.is_read.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_read = ${param_count}"));
        }
        if filter.is_dismissed.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_dismissed = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(analysis_id) = filter.analysis_id {
            q = q.bind(analysis_id);
        }
        if let Some(alert_type) = filter.alert_type {
            q = q.bind(alert_type);
        }
        if let Some(severity) = filter.severity {
            q = q.bind(severity);
        }
        if let Some(is_read) = filter.is_read {
            q = q.bind(is_read);
        }
        if let Some(is_dismissed) = filter.is_dismissed {
            q = q.bind(is_dismissed);
        }

        q.fetch_one(pool).await
    }

    /// Get alert summary.
    pub async fn get_summary(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<AlertSummary, sqlx::Error> {
        let row: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                COUNT(*) as total_count,
                COUNT(*) FILTER (WHERE is_read = false AND is_dismissed = false) as unread_count,
                COUNT(*) FILTER (WHERE severity = 'critical' AND is_dismissed = false) as critical_count,
                COUNT(*) FILTER (WHERE severity = 'high' AND is_dismissed = false) as high_count,
                COUNT(*) FILTER (WHERE severity = 'medium' AND is_dismissed = false) as medium_count,
                COUNT(*) FILTER (WHERE severity = 'low' AND is_dismissed = false) as low_count
            FROM gov_outlier_alerts
            WHERE tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(AlertSummary {
            total_count: row.0,
            unread_count: row.1,
            critical_count: row.2,
            high_count: row.3,
            medium_count: row.4,
            low_count: row.5,
        })
    }

    /// Create a new alert.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateAlert,
    ) -> Result<Self, sqlx::Error> {
        let severity = OutlierAlertSeverity::from_score(input.score);

        sqlx::query_as(
            r"
            INSERT INTO gov_outlier_alerts (
                tenant_id, analysis_id, user_id, alert_type, severity, score, classification
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.analysis_id)
        .bind(input.user_id)
        .bind(input.alert_type)
        .bind(severity)
        .bind(input.score)
        .bind(input.classification)
        .fetch_one(pool)
        .await
    }

    /// Bulk create alerts for an analysis.
    pub async fn create_batch(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        alerts: Vec<CreateAlert>,
    ) -> Result<u64, sqlx::Error> {
        if alerts.is_empty() {
            return Ok(0);
        }

        let mut tx = pool.begin().await?;
        let mut count = 0u64;

        for input in alerts {
            let severity = OutlierAlertSeverity::from_score(input.score);

            sqlx::query(
                r"
                INSERT INTO gov_outlier_alerts (
                    tenant_id, analysis_id, user_id, alert_type, severity, score, classification
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ",
            )
            .bind(tenant_id)
            .bind(input.analysis_id)
            .bind(input.user_id)
            .bind(input.alert_type)
            .bind(severity)
            .bind(input.score)
            .bind(input.classification)
            .execute(&mut *tx)
            .await?;
            count += 1;
        }

        tx.commit().await?;
        Ok(count)
    }

    /// Mark alert as read.
    pub async fn mark_read(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_outlier_alerts
            SET is_read = true
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark alert as dismissed.
    pub async fn dismiss(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_outlier_alerts
            SET is_dismissed = true, is_read = true
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark all alerts as read for a tenant.
    pub async fn mark_all_read(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_outlier_alerts
            SET is_read = true
            WHERE tenant_id = $1 AND is_read = false
            ",
        )
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get unread alerts (for notifications).
    pub async fn get_unread(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_outlier_alerts
            WHERE tenant_id = $1 AND is_read = false AND is_dismissed = false
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                END,
                created_at DESC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Delete alerts by analysis.
    pub async fn delete_by_analysis(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        analysis_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_outlier_alerts
            WHERE tenant_id = $1 AND analysis_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(analysis_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Delete old dismissed alerts.
    pub async fn delete_old_dismissed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        days: i32,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_outlier_alerts
            WHERE tenant_id = $1 AND is_dismissed = true
                AND created_at < NOW() - ($2 || ' days')::INTERVAL
            ",
        )
        .bind(tenant_id)
        .bind(days)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Check if user already has an alert from this analysis.
    pub async fn exists_for_user_analysis(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        analysis_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let exists: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS(
                SELECT 1 FROM gov_outlier_alerts
                WHERE tenant_id = $1 AND analysis_id = $2 AND user_id = $3
            )
            ",
        )
        .bind(tenant_id)
        .bind(analysis_id)
        .bind(user_id)
        .fetch_one(pool)
        .await?;

        Ok(exists)
    }

    /// Check if this is a critical alert.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        matches!(self.severity, OutlierAlertSeverity::Critical)
    }

    /// Check if this requires immediate attention.
    #[must_use]
    pub fn requires_attention(&self) -> bool {
        !self.is_read && !self.is_dismissed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_is_critical() {
        let alert = GovOutlierAlert {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            analysis_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            alert_type: OutlierAlertType::NewOutlier,
            severity: OutlierAlertSeverity::Critical,
            score: 85.0,
            classification: OutlierClassification::Outlier,
            is_read: false,
            is_dismissed: false,
            created_at: Utc::now(),
        };

        assert!(alert.is_critical());
    }

    #[test]
    fn test_alert_not_critical() {
        let alert = GovOutlierAlert {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            analysis_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            alert_type: OutlierAlertType::NewOutlier,
            severity: OutlierAlertSeverity::Medium,
            score: 50.0,
            classification: OutlierClassification::Outlier,
            is_read: false,
            is_dismissed: false,
            created_at: Utc::now(),
        };

        assert!(!alert.is_critical());
    }

    #[test]
    fn test_alert_requires_attention() {
        let alert = GovOutlierAlert {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            analysis_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            alert_type: OutlierAlertType::NewOutlier,
            severity: OutlierAlertSeverity::High,
            score: 70.0,
            classification: OutlierClassification::Outlier,
            is_read: false,
            is_dismissed: false,
            created_at: Utc::now(),
        };

        assert!(alert.requires_attention());
    }

    #[test]
    fn test_alert_does_not_require_attention_when_read() {
        let alert = GovOutlierAlert {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            analysis_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            alert_type: OutlierAlertType::NewOutlier,
            severity: OutlierAlertSeverity::High,
            score: 70.0,
            classification: OutlierClassification::Outlier,
            is_read: true,
            is_dismissed: false,
            created_at: Utc::now(),
        };

        assert!(!alert.requires_attention());
    }

    #[test]
    fn test_filter_default() {
        let filter = AlertFilter::default();
        assert!(filter.user_id.is_none());
        assert!(filter.analysis_id.is_none());
        assert!(filter.alert_type.is_none());
        assert!(filter.severity.is_none());
        assert!(filter.is_read.is_none());
        assert!(filter.is_dismissed.is_none());
    }

    #[test]
    fn test_severity_from_score_in_alert() {
        // The alert severity is calculated based on score
        assert_eq!(
            OutlierAlertSeverity::from_score(30.0),
            OutlierAlertSeverity::Low
        );
        assert_eq!(
            OutlierAlertSeverity::from_score(50.0),
            OutlierAlertSeverity::Medium
        );
        assert_eq!(
            OutlierAlertSeverity::from_score(70.0),
            OutlierAlertSeverity::High
        );
        assert_eq!(
            OutlierAlertSeverity::from_score(90.0),
            OutlierAlertSeverity::Critical
        );
    }
}
