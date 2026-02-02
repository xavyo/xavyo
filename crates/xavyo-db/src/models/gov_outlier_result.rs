//! Outlier detection result model for individual users.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_outlier_types::{FactorBreakdown, OutlierClassification, PeerGroupScore};

/// Result of outlier analysis for a single user.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovOutlierResult {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this result belongs to.
    pub tenant_id: Uuid,

    /// Parent analysis that generated this result.
    pub analysis_id: Uuid,

    /// User who was analyzed.
    pub user_id: Uuid,

    /// Composite outlier score (0-100).
    pub overall_score: f64,

    /// Classification based on the score.
    pub classification: OutlierClassification,

    /// Score breakdown per peer group.
    pub peer_scores: sqlx::types::Json<Vec<PeerGroupScore>>,

    /// Score contribution per factor.
    pub factor_breakdown: sqlx::types::Json<FactorBreakdown>,

    /// Score from previous analysis (if any).
    pub previous_score: Option<f64>,

    /// Change from previous score.
    pub score_change: Option<f64>,

    /// When created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new outlier result.
#[derive(Debug, Clone)]
pub struct CreateOutlierResult {
    pub analysis_id: Uuid,
    pub user_id: Uuid,
    pub overall_score: f64,
    pub classification: OutlierClassification,
    pub peer_scores: Vec<PeerGroupScore>,
    pub factor_breakdown: FactorBreakdown,
    pub previous_score: Option<f64>,
    pub score_change: Option<f64>,
}

/// Filter options for listing results.
#[derive(Debug, Clone, Default)]
pub struct OutlierResultFilter {
    pub analysis_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub classification: Option<OutlierClassification>,
    pub min_score: Option<f64>,
    pub max_score: Option<f64>,
}

/// Summary statistics for outlier results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutlierResultSummary {
    pub total_users: i64,
    pub outlier_count: i64,
    pub normal_count: i64,
    pub unclassifiable_count: i64,
    pub avg_score: f64,
    pub max_score: f64,
}

impl GovOutlierResult {
    /// Find result by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_outlier_results
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find the most recent result for a user.
    pub async fn find_latest_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT r.* FROM gov_outlier_results r
            JOIN gov_outlier_analyses a ON r.analysis_id = a.id
            WHERE r.tenant_id = $1 AND r.user_id = $2 AND a.status = 'completed'
            ORDER BY r.created_at DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
    }

    /// List results with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &OutlierResultFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_outlier_results WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.analysis_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND analysis_id = ${}", param_count));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${}", param_count));
        }
        if filter.classification.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND classification = ${}", param_count));
        }
        if filter.min_score.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND overall_score >= ${}", param_count));
        }
        if filter.max_score.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND overall_score <= ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY overall_score DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(analysis_id) = filter.analysis_id {
            q = q.bind(analysis_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(classification) = filter.classification {
            q = q.bind(classification);
        }
        if let Some(min_score) = filter.min_score {
            q = q.bind(min_score);
        }
        if let Some(max_score) = filter.max_score {
            q = q.bind(max_score);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count results with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &OutlierResultFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from("SELECT COUNT(*) FROM gov_outlier_results WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.analysis_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND analysis_id = ${}", param_count));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${}", param_count));
        }
        if filter.classification.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND classification = ${}", param_count));
        }
        if filter.min_score.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND overall_score >= ${}", param_count));
        }
        if filter.max_score.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND overall_score <= ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(analysis_id) = filter.analysis_id {
            q = q.bind(analysis_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(classification) = filter.classification {
            q = q.bind(classification);
        }
        if let Some(min_score) = filter.min_score {
            q = q.bind(min_score);
        }
        if let Some(max_score) = filter.max_score {
            q = q.bind(max_score);
        }

        q.fetch_one(pool).await
    }

    /// Get summary statistics for an analysis.
    pub async fn get_summary(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        analysis_id: Uuid,
    ) -> Result<OutlierResultSummary, sqlx::Error> {
        let row: (i64, i64, i64, i64, Option<f64>, Option<f64>) = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) as total_users,
                COUNT(*) FILTER (WHERE classification = 'outlier') as outlier_count,
                COUNT(*) FILTER (WHERE classification = 'normal') as normal_count,
                COUNT(*) FILTER (WHERE classification = 'unclassifiable') as unclassifiable_count,
                AVG(overall_score) as avg_score,
                MAX(overall_score) as max_score
            FROM gov_outlier_results
            WHERE tenant_id = $1 AND analysis_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(analysis_id)
        .fetch_one(pool)
        .await?;

        Ok(OutlierResultSummary {
            total_users: row.0,
            outlier_count: row.1,
            normal_count: row.2,
            unclassifiable_count: row.3,
            avg_score: row.4.unwrap_or(0.0),
            max_score: row.5.unwrap_or(0.0),
        })
    }

    /// Create a new result.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateOutlierResult,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_outlier_results (
                tenant_id, analysis_id, user_id, overall_score, classification,
                peer_scores, factor_breakdown, previous_score, score_change
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.analysis_id)
        .bind(input.user_id)
        .bind(input.overall_score)
        .bind(input.classification)
        .bind(sqlx::types::Json(&input.peer_scores))
        .bind(sqlx::types::Json(&input.factor_breakdown))
        .bind(input.previous_score)
        .bind(input.score_change)
        .fetch_one(pool)
        .await
    }

    /// Bulk create results for an analysis.
    pub async fn create_batch(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        results: Vec<CreateOutlierResult>,
    ) -> Result<u64, sqlx::Error> {
        if results.is_empty() {
            return Ok(0);
        }

        let mut tx = pool.begin().await?;
        let mut count = 0u64;

        for input in results {
            sqlx::query(
                r#"
                INSERT INTO gov_outlier_results (
                    tenant_id, analysis_id, user_id, overall_score, classification,
                    peer_scores, factor_breakdown, previous_score, score_change
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(tenant_id)
            .bind(input.analysis_id)
            .bind(input.user_id)
            .bind(input.overall_score)
            .bind(input.classification)
            .bind(sqlx::types::Json(&input.peer_scores))
            .bind(sqlx::types::Json(&input.factor_breakdown))
            .bind(input.previous_score)
            .bind(input.score_change)
            .execute(&mut *tx)
            .await?;
            count += 1;
        }

        tx.commit().await?;
        Ok(count)
    }

    /// Delete all results for an analysis.
    pub async fn delete_by_analysis(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        analysis_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_outlier_results
            WHERE tenant_id = $1 AND analysis_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(analysis_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get user history (all results across analyses).
    pub async fn get_user_history(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT r.* FROM gov_outlier_results r
            JOIN gov_outlier_analyses a ON r.analysis_id = a.id
            WHERE r.tenant_id = $1 AND r.user_id = $2 AND a.status = 'completed'
            ORDER BY r.created_at DESC
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Get top outliers from an analysis.
    pub async fn get_top_outliers(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        analysis_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_outlier_results
            WHERE tenant_id = $1 AND analysis_id = $2 AND classification = 'outlier'
            ORDER BY overall_score DESC
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(analysis_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Get peer scores as a vec.
    pub fn get_peer_scores(&self) -> &Vec<PeerGroupScore> {
        &self.peer_scores.0
    }

    /// Get factor breakdown.
    pub fn get_factors(&self) -> &FactorBreakdown {
        &self.factor_breakdown.0
    }

    /// Check if this is an outlier.
    pub fn is_outlier(&self) -> bool {
        matches!(self.classification, OutlierClassification::Outlier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::gov_outlier_types::FactorScore;

    #[test]
    fn test_outlier_result_is_outlier() {
        let result = GovOutlierResult {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            analysis_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            overall_score: 75.0,
            classification: OutlierClassification::Outlier,
            peer_scores: sqlx::types::Json(vec![]),
            factor_breakdown: sqlx::types::Json(FactorBreakdown::default()),
            previous_score: None,
            score_change: None,
            created_at: Utc::now(),
        };

        assert!(result.is_outlier());
    }

    #[test]
    fn test_outlier_result_not_outlier() {
        let result = GovOutlierResult {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            analysis_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            overall_score: 25.0,
            classification: OutlierClassification::Normal,
            peer_scores: sqlx::types::Json(vec![]),
            factor_breakdown: sqlx::types::Json(FactorBreakdown::default()),
            previous_score: None,
            score_change: None,
            created_at: Utc::now(),
        };

        assert!(!result.is_outlier());
    }

    #[test]
    fn test_filter_default() {
        let filter = OutlierResultFilter::default();
        assert!(filter.analysis_id.is_none());
        assert!(filter.user_id.is_none());
        assert!(filter.classification.is_none());
        assert!(filter.min_score.is_none());
        assert!(filter.max_score.is_none());
    }

    #[test]
    fn test_peer_group_score_serialization() {
        let score = PeerGroupScore {
            peer_group_id: Uuid::new_v4(),
            peer_group_name: "Engineering".to_string(),
            z_score: 2.5,
            deviation_factor: 0.75,
            is_outlier: true,
        };

        let json = serde_json::to_string(&score).unwrap();
        let parsed: PeerGroupScore = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.peer_group_name, "Engineering");
        assert!((parsed.z_score - 2.5).abs() < 0.001);
        assert!(parsed.is_outlier);
    }

    #[test]
    fn test_factor_breakdown_serialization() {
        let mut breakdown = FactorBreakdown::default();
        breakdown.role_frequency = Some(FactorScore {
            raw_value: 85.0,
            weight: 0.30,
            contribution: 25.5,
            details: "3 rare roles".to_string(),
        });

        let json = serde_json::to_string(&breakdown).unwrap();
        let parsed: FactorBreakdown = serde_json::from_str(&json).unwrap();

        assert!(parsed.role_frequency.is_some());
        let rf = parsed.role_frequency.unwrap();
        assert!((rf.contribution - 25.5).abs() < 0.001);
    }
}
