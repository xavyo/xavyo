//! Governance Risk Score History model.
//!
//! Represents historical snapshots of risk scores for trend analysis.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_risk_score::RiskLevel;

/// A historical risk score snapshot.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovRiskScoreHistory {
    /// Unique identifier for the history record.
    pub id: Uuid,

    /// The tenant this history belongs to.
    pub tenant_id: Uuid,

    /// The user this history is for.
    pub user_id: Uuid,

    /// Score at the snapshot time.
    pub score: i32,

    /// Risk level at the snapshot time.
    pub risk_level: RiskLevel,

    /// Date of the snapshot.
    pub snapshot_date: NaiveDate,

    /// When the record was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a history snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovRiskScoreHistory {
    pub user_id: Uuid,
    pub score: i32,
    pub snapshot_date: NaiveDate,
}

/// Trend direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum TrendDirection {
    Increasing,
    Stable,
    Decreasing,
}

/// Risk score trend analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoreTrend {
    pub user_id: Uuid,
    pub current_score: i32,
    pub score_30d_ago: Option<i32>,
    pub score_60d_ago: Option<i32>,
    pub score_90d_ago: Option<i32>,
    pub change_30d: Option<i32>,
    pub change_60d: Option<i32>,
    pub change_90d: Option<i32>,
    pub direction: TrendDirection,
}

impl TrendDirection {
    /// Determine trend direction from score change.
    #[must_use]
    pub fn from_change(change: i32, threshold: i32) -> Self {
        if change > threshold {
            Self::Increasing
        } else if change < -threshold {
            Self::Decreasing
        } else {
            Self::Stable
        }
    }
}

impl GovRiskScoreHistory {
    /// Find history by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_risk_score_history
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Get history for a user within a date range.
    pub async fn get_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        start_date: NaiveDate,
        end_date: NaiveDate,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_risk_score_history
            WHERE tenant_id = $1 AND user_id = $2
            AND snapshot_date >= $3 AND snapshot_date <= $4
            ORDER BY snapshot_date ASC
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(start_date)
        .bind(end_date)
        .fetch_all(pool)
        .await
    }

    /// Get the most recent N history entries for a user.
    pub async fn get_recent_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_risk_score_history
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY snapshot_date DESC
            LIMIT $3
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Get score at a specific date for a user.
    pub async fn get_at_date(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        date: NaiveDate,
    ) -> Result<Option<i32>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT score FROM gov_risk_score_history
            WHERE tenant_id = $1 AND user_id = $2 AND snapshot_date = $3
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(date)
        .fetch_optional(pool)
        .await
    }

    /// Get the closest score on or before a date.
    pub async fn get_at_or_before_date(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        date: NaiveDate,
    ) -> Result<Option<i32>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT score FROM gov_risk_score_history
            WHERE tenant_id = $1 AND user_id = $2 AND snapshot_date <= $3
            ORDER BY snapshot_date DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(date)
        .fetch_optional(pool)
        .await
    }

    /// Create a new history snapshot.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovRiskScoreHistory,
    ) -> Result<Self, sqlx::Error> {
        let risk_level = RiskLevel::from_score(input.score);

        sqlx::query_as(
            r"
            INSERT INTO gov_risk_score_history (
                tenant_id, user_id, score, risk_level, snapshot_date
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (tenant_id, user_id, snapshot_date) DO UPDATE SET
                score = EXCLUDED.score,
                risk_level = EXCLUDED.risk_level
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.user_id)
        .bind(input.score)
        .bind(risk_level)
        .bind(input.snapshot_date)
        .fetch_one(pool)
        .await
    }

    /// Delete history older than a specific date.
    pub async fn cleanup_older_than(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        before: NaiveDate,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_risk_score_history
            WHERE tenant_id = $1 AND snapshot_date < $2
            ",
        )
        .bind(tenant_id)
        .bind(before)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Calculate trend for a user.
    pub async fn calculate_trend(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        current_score: i32,
    ) -> Result<RiskScoreTrend, sqlx::Error> {
        let today = Utc::now().date_naive();
        let date_30d = today - chrono::Duration::days(30);
        let date_60d = today - chrono::Duration::days(60);
        let date_90d = today - chrono::Duration::days(90);

        let score_30d = Self::get_at_or_before_date(pool, tenant_id, user_id, date_30d).await?;
        let score_60d = Self::get_at_or_before_date(pool, tenant_id, user_id, date_60d).await?;
        let score_90d = Self::get_at_or_before_date(pool, tenant_id, user_id, date_90d).await?;

        let change_30d = score_30d.map(|s| current_score - s);
        let change_60d = score_60d.map(|s| current_score - s);
        let change_90d = score_90d.map(|s| current_score - s);

        // Determine overall direction based on most recent change
        let direction = match change_30d {
            Some(c) => TrendDirection::from_change(c, 5), // 5-point threshold for stability
            None => TrendDirection::Stable,
        };

        Ok(RiskScoreTrend {
            user_id,
            current_score,
            score_30d_ago: score_30d,
            score_60d_ago: score_60d,
            score_90d_ago: score_90d,
            change_30d,
            change_60d,
            change_90d,
            direction,
        })
    }

    /// Get average score over a period for a user.
    pub async fn get_average_for_period(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        start_date: NaiveDate,
        end_date: NaiveDate,
    ) -> Result<Option<f64>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT AVG(score::float8) FROM gov_risk_score_history
            WHERE tenant_id = $1 AND user_id = $2
            AND snapshot_date >= $3 AND snapshot_date <= $4
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(start_date)
        .bind(end_date)
        .fetch_one(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trend_direction_from_change() {
        assert_eq!(
            TrendDirection::from_change(10, 5),
            TrendDirection::Increasing
        );
        assert_eq!(TrendDirection::from_change(5, 5), TrendDirection::Stable);
        assert_eq!(TrendDirection::from_change(0, 5), TrendDirection::Stable);
        assert_eq!(TrendDirection::from_change(-5, 5), TrendDirection::Stable);
        assert_eq!(
            TrendDirection::from_change(-10, 5),
            TrendDirection::Decreasing
        );
    }

    #[test]
    fn test_trend_direction_serialization() {
        let increasing = TrendDirection::Increasing;
        let json = serde_json::to_string(&increasing).unwrap();
        assert_eq!(json, "\"increasing\"");

        let stable = TrendDirection::Stable;
        let json = serde_json::to_string(&stable).unwrap();
        assert_eq!(json, "\"stable\"");
    }
}
