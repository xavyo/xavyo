//! Outlier analysis run model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_outlier_types::{OutlierAnalysisStatus, OutlierTriggerType, ScoringWeights};

/// An outlier detection analysis run.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovOutlierAnalysis {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this analysis belongs to.
    pub tenant_id: Uuid,

    /// Snapshot of configuration at analysis time.
    pub config_snapshot: sqlx::types::Json<ConfigSnapshot>,

    /// Current status.
    pub status: OutlierAnalysisStatus,

    /// How the analysis was triggered.
    pub triggered_by: OutlierTriggerType,

    /// When the analysis started.
    pub started_at: DateTime<Utc>,

    /// When the analysis completed (null if still running).
    pub completed_at: Option<DateTime<Utc>>,

    /// Number of users analyzed.
    pub users_analyzed: i32,

    /// Number of outliers detected.
    pub outliers_detected: i32,

    /// Progress percentage (0-100).
    pub progress_percent: i32,

    /// Error message if failed.
    pub error_message: Option<String>,

    /// When created.
    pub created_at: DateTime<Utc>,
}

/// Snapshot of configuration at analysis time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    pub confidence_threshold: f64,
    pub frequency_threshold: f64,
    pub min_peer_group_size: i32,
    pub scoring_weights: ScoringWeights,
}

/// Request to create a new analysis.
#[derive(Debug, Clone)]
pub struct CreateOutlierAnalysis {
    pub triggered_by: OutlierTriggerType,
    pub config_snapshot: ConfigSnapshot,
}

/// Filter options for listing analyses.
#[derive(Debug, Clone, Default)]
pub struct OutlierAnalysisFilter {
    pub status: Option<OutlierAnalysisStatus>,
    pub triggered_by: Option<OutlierTriggerType>,
}

impl GovOutlierAnalysis {
    /// Find analysis by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_outlier_analyses
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Get the most recent completed analysis.
    pub async fn find_latest_completed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_outlier_analyses
            WHERE tenant_id = $1 AND status = 'completed'
            ORDER BY completed_at DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Check if there's a running analysis.
    pub async fn has_running(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<bool, sqlx::Error> {
        let exists: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS(
                SELECT 1 FROM gov_outlier_analyses
                WHERE tenant_id = $1 AND status = 'running'
            )
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(exists)
    }

    /// List analyses with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &OutlierAnalysisFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_outlier_analyses WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.triggered_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND triggered_by = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(triggered_by) = filter.triggered_by {
            q = q.bind(triggered_by);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count analyses with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &OutlierAnalysisFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from("SELECT COUNT(*) FROM gov_outlier_analyses WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.triggered_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND triggered_by = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(triggered_by) = filter.triggered_by {
            q = q.bind(triggered_by);
        }

        q.fetch_one(pool).await
    }

    /// Create a new analysis.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateOutlierAnalysis,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_outlier_analyses (
                tenant_id, config_snapshot, status, triggered_by
            )
            VALUES ($1, $2, 'pending', $3)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(sqlx::types::Json(&input.config_snapshot))
        .bind(input.triggered_by)
        .fetch_one(pool)
        .await
    }

    /// Start an analysis (transition to running).
    pub async fn start(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_outlier_analyses
            SET status = 'running', started_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Update progress.
    pub async fn update_progress(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        progress_percent: i32,
        users_analyzed: i32,
        outliers_detected: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_outlier_analyses
            SET progress_percent = $3, users_analyzed = $4, outliers_detected = $5
            WHERE id = $1 AND tenant_id = $2 AND status = 'running'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(progress_percent)
        .bind(users_analyzed)
        .bind(outliers_detected)
        .fetch_optional(pool)
        .await
    }

    /// Complete an analysis successfully.
    pub async fn complete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        users_analyzed: i32,
        outliers_detected: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_outlier_analyses
            SET status = 'completed', completed_at = NOW(), progress_percent = 100,
                users_analyzed = $3, outliers_detected = $4
            WHERE id = $1 AND tenant_id = $2 AND status = 'running'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(users_analyzed)
        .bind(outliers_detected)
        .fetch_optional(pool)
        .await
    }

    /// Fail an analysis with an error message.
    pub async fn fail(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error_message: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_outlier_analyses
            SET status = 'failed', completed_at = NOW(), error_message = $3
            WHERE id = $1 AND tenant_id = $2 AND status = 'running'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(error_message)
        .fetch_optional(pool)
        .await
    }

    /// Cancel a running analysis.
    pub async fn cancel(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_outlier_analyses
            SET status = 'failed', completed_at = NOW(), error_message = 'Cancelled by user'
            WHERE id = $1 AND tenant_id = $2 AND status = 'running'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete old analyses based on retention period.
    pub async fn delete_old(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        retention_days: i32,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_outlier_analyses
            WHERE tenant_id = $1 AND created_at < NOW() - ($2 || ' days')::INTERVAL
            ",
        )
        .bind(tenant_id)
        .bind(retention_days)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get the config snapshot as a struct.
    #[must_use]
    pub fn get_config(&self) -> &ConfigSnapshot {
        &self.config_snapshot.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_snapshot_serialization() {
        let snapshot = ConfigSnapshot {
            confidence_threshold: 2.0,
            frequency_threshold: 0.1,
            min_peer_group_size: 5,
            scoring_weights: ScoringWeights::default(),
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: ConfigSnapshot = serde_json::from_str(&json).unwrap();

        assert!((parsed.confidence_threshold - 2.0).abs() < 0.001);
        assert!((parsed.frequency_threshold - 0.1).abs() < 0.001);
        assert_eq!(parsed.min_peer_group_size, 5);
    }
}
