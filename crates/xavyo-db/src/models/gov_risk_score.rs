//! Governance Risk Score model.
//!
//! Represents current calculated risk score per user.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Risk level classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "risk_level", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Low risk (0-25).
    Low,
    /// Medium risk (26-50).
    Medium,
    /// High risk (51-75).
    High,
    /// Critical risk (76-100).
    Critical,
}

impl RiskLevel {
    /// Determine risk level from a score (0-100).
    #[must_use] 
    pub fn from_score(score: i32) -> Self {
        match score {
            0..=25 => Self::Low,
            26..=50 => Self::Medium,
            51..=75 => Self::High,
            _ => Self::Critical,
        }
    }

    /// Check if this is a high or critical risk level.
    #[must_use] 
    pub fn is_elevated(&self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }

    /// Check if this is critical risk.
    #[must_use] 
    pub fn is_critical(&self) -> bool {
        matches!(self, Self::Critical)
    }

    /// Get the minimum score for this level.
    #[must_use] 
    pub fn min_score(&self) -> i32 {
        match self {
            Self::Low => 0,
            Self::Medium => 26,
            Self::High => 51,
            Self::Critical => 76,
        }
    }

    /// Get the maximum score for this level.
    #[must_use] 
    pub fn max_score(&self) -> i32 {
        match self {
            Self::Low => 25,
            Self::Medium => 50,
            Self::High => 75,
            Self::Critical => 100,
        }
    }
}

/// A governance risk score for a user.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovRiskScore {
    /// Unique identifier for the score record.
    pub id: Uuid,

    /// The tenant this score belongs to.
    pub tenant_id: Uuid,

    /// The user this score is for.
    pub user_id: Uuid,

    /// Total calculated risk score (0-100).
    pub total_score: i32,

    /// Risk level classification.
    pub risk_level: RiskLevel,

    /// Score contribution from static factors.
    pub static_score: i32,

    /// Score contribution from dynamic factors.
    pub dynamic_score: i32,

    /// Per-factor score breakdown (JSON).
    pub factor_breakdown: serde_json::Value,

    /// Peer comparison data (optional JSON).
    pub peer_comparison: Option<serde_json::Value>,

    /// When the score was last calculated.
    pub calculated_at: DateTime<Utc>,

    /// When the record was created.
    pub created_at: DateTime<Utc>,

    /// When the record was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create or update a risk score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertGovRiskScore {
    pub user_id: Uuid,
    pub total_score: i32,
    pub static_score: i32,
    pub dynamic_score: i32,
    pub factor_breakdown: serde_json::Value,
    pub peer_comparison: Option<serde_json::Value>,
}

/// Filter options for listing risk scores.
#[derive(Debug, Clone, Default)]
pub struct RiskScoreFilter {
    pub risk_level: Option<RiskLevel>,
    pub min_score: Option<i32>,
    pub max_score: Option<i32>,
}

/// Sort options for risk scores.
#[derive(Debug, Clone, Copy, Default)]
pub enum RiskScoreSortBy {
    #[default]
    ScoreDesc,
    ScoreAsc,
    CalculatedAtDesc,
    CalculatedAtAsc,
}

impl RiskScoreSortBy {
    fn as_sql(self) -> &'static str {
        match self {
            Self::ScoreDesc => "total_score DESC",
            Self::ScoreAsc => "total_score ASC",
            Self::CalculatedAtDesc => "calculated_at DESC",
            Self::CalculatedAtAsc => "calculated_at ASC",
        }
    }
}

impl GovRiskScore {
    /// Find a score by user ID within a tenant.
    pub async fn find_by_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_risk_scores
            WHERE tenant_id = $1 AND user_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a score by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_risk_scores
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List scores by risk level.
    pub async fn list_by_level(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        level: RiskLevel,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_risk_scores
            WHERE tenant_id = $1 AND risk_level = $2
            ORDER BY total_score DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(level)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List scores for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &RiskScoreFilter,
        sort_by: RiskScoreSortBy,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_risk_scores
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.risk_level.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND risk_level = ${param_count}"));
        }
        if filter.min_score.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND total_score >= ${param_count}"));
        }
        if filter.max_score.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND total_score <= ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY {} LIMIT ${} OFFSET ${}",
            sort_by.as_sql(),
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovRiskScore>(&query).bind(tenant_id);

        if let Some(level) = filter.risk_level {
            q = q.bind(level);
        }
        if let Some(min_score) = filter.min_score {
            q = q.bind(min_score);
        }
        if let Some(max_score) = filter.max_score {
            q = q.bind(max_score);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count scores in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &RiskScoreFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_risk_scores
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.risk_level.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND risk_level = ${param_count}"));
        }
        if filter.min_score.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND total_score >= ${param_count}"));
        }
        if filter.max_score.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND total_score <= ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(level) = filter.risk_level {
            q = q.bind(level);
        }
        if let Some(min_score) = filter.min_score {
            q = q.bind(min_score);
        }
        if let Some(max_score) = filter.max_score {
            q = q.bind(max_score);
        }

        q.fetch_one(pool).await
    }

    /// Get count of users per risk level.
    pub async fn count_by_level(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<(RiskLevel, i64)>, sqlx::Error> {
        let rows: Vec<(RiskLevel, i64)> = sqlx::query_as(
            r"
            SELECT risk_level, COUNT(*) as count
            FROM gov_risk_scores
            WHERE tenant_id = $1
            GROUP BY risk_level
            ORDER BY risk_level
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Create or update a risk score (upsert).
    pub async fn upsert(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: UpsertGovRiskScore,
    ) -> Result<Self, sqlx::Error> {
        let risk_level = RiskLevel::from_score(input.total_score);

        sqlx::query_as(
            r"
            INSERT INTO gov_risk_scores (
                tenant_id, user_id, total_score, risk_level, static_score, dynamic_score,
                factor_breakdown, peer_comparison, calculated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            ON CONFLICT (tenant_id, user_id) DO UPDATE SET
                total_score = EXCLUDED.total_score,
                risk_level = EXCLUDED.risk_level,
                static_score = EXCLUDED.static_score,
                dynamic_score = EXCLUDED.dynamic_score,
                factor_breakdown = EXCLUDED.factor_breakdown,
                peer_comparison = EXCLUDED.peer_comparison,
                calculated_at = NOW(),
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.user_id)
        .bind(input.total_score)
        .bind(risk_level)
        .bind(input.static_score)
        .bind(input.dynamic_score)
        .bind(&input.factor_breakdown)
        .bind(&input.peer_comparison)
        .fetch_one(pool)
        .await
    }

    /// Delete a risk score.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_risk_scores
            WHERE tenant_id = $1 AND user_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get users with stale scores (not calculated recently).
    pub async fn list_stale(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        older_than: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT user_id FROM gov_risk_scores
            WHERE tenant_id = $1 AND calculated_at < $2
            ORDER BY calculated_at ASC
            LIMIT $3
            ",
        )
        .bind(tenant_id)
        .bind(older_than)
        .bind(limit)
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_from_score() {
        assert_eq!(RiskLevel::from_score(0), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(25), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(26), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(50), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(51), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(75), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(76), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(100), RiskLevel::Critical);
    }

    #[test]
    fn test_risk_level_is_elevated() {
        assert!(!RiskLevel::Low.is_elevated());
        assert!(!RiskLevel::Medium.is_elevated());
        assert!(RiskLevel::High.is_elevated());
        assert!(RiskLevel::Critical.is_elevated());
    }

    #[test]
    fn test_risk_level_is_critical() {
        assert!(!RiskLevel::Low.is_critical());
        assert!(!RiskLevel::Medium.is_critical());
        assert!(!RiskLevel::High.is_critical());
        assert!(RiskLevel::Critical.is_critical());
    }

    #[test]
    fn test_risk_level_bounds() {
        assert_eq!(RiskLevel::Low.min_score(), 0);
        assert_eq!(RiskLevel::Low.max_score(), 25);
        assert_eq!(RiskLevel::Medium.min_score(), 26);
        assert_eq!(RiskLevel::Medium.max_score(), 50);
        assert_eq!(RiskLevel::High.min_score(), 51);
        assert_eq!(RiskLevel::High.max_score(), 75);
        assert_eq!(RiskLevel::Critical.min_score(), 76);
        assert_eq!(RiskLevel::Critical.max_score(), 100);
    }

    #[test]
    fn test_risk_level_serialization() {
        let low = RiskLevel::Low;
        let json = serde_json::to_string(&low).unwrap();
        assert_eq!(json, "\"low\"");

        let critical = RiskLevel::Critical;
        let json = serde_json::to_string(&critical).unwrap();
        assert_eq!(json, "\"critical\"");
    }
}
