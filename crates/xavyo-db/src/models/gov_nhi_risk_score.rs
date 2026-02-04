//! NHI Risk Score model.
//!
//! Cached risk scores for NHIs with factor breakdown.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::RiskLevel;

/// An NHI risk score record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovNhiRiskScore {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this score belongs to.
    pub tenant_id: Uuid,

    /// The NHI this score is for.
    pub nhi_id: Uuid,

    /// Combined risk score (0-100).
    pub total_score: i32,

    /// Risk level based on score.
    pub risk_level: RiskLevel,

    /// Contribution from staleness (days since last use).
    pub staleness_factor: i32,

    /// Contribution from credential age.
    pub credential_age_factor: i32,

    /// Contribution from access scope (entitlement sensitivity).
    pub access_scope_factor: i32,

    /// Detailed breakdown of factor calculations.
    pub factor_breakdown: serde_json::Value,

    /// When the score was calculated.
    pub calculated_at: DateTime<Utc>,

    /// When the next calculation should occur.
    pub next_calculation_at: Option<DateTime<Utc>>,
}

/// Request to upsert an NHI risk score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertGovNhiRiskScore {
    pub nhi_id: Uuid,
    pub total_score: i32,
    pub risk_level: RiskLevel,
    pub staleness_factor: i32,
    pub credential_age_factor: i32,
    pub access_scope_factor: i32,
    pub factor_breakdown: serde_json::Value,
    pub next_calculation_at: Option<DateTime<Utc>>,
}

/// Filter options for listing NHI risk scores.
#[derive(Debug, Clone, Default)]
pub struct NhiRiskScoreFilter {
    pub risk_level: Option<RiskLevel>,
    pub min_score: Option<i32>,
    pub max_score: Option<i32>,
    pub needs_recalculation: Option<bool>,
}

impl GovNhiRiskScore {
    /// Determine risk level from score.
    #[must_use] 
    pub fn level_from_score(score: i32) -> RiskLevel {
        match score {
            0..=25 => RiskLevel::Low,
            26..=50 => RiskLevel::Medium,
            51..=75 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    /// Check if recalculation is needed.
    #[must_use] 
    pub fn needs_recalculation(&self) -> bool {
        match self.next_calculation_at {
            Some(next) => next <= Utc::now(),
            None => false,
        }
    }

    /// Find score by NHI ID.
    pub async fn find_by_nhi(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_nhi_risk_scores
            WHERE tenant_id = $1 AND nhi_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .fetch_optional(pool)
        .await
    }

    /// List NHI risk scores with filtering.
    pub async fn list(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &NhiRiskScoreFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_nhi_risk_scores
            WHERE tenant_id = $1
            ",
        );

        let mut param_idx = 2;

        if filter.risk_level.is_some() {
            query.push_str(&format!(" AND risk_level = ${param_idx}"));
            param_idx += 1;
        }

        if filter.min_score.is_some() {
            query.push_str(&format!(" AND total_score >= ${param_idx}"));
            param_idx += 1;
        }

        if filter.max_score.is_some() {
            query.push_str(&format!(" AND total_score <= ${param_idx}"));
            param_idx += 1;
        }

        if filter.needs_recalculation == Some(true) {
            query.push_str(" AND next_calculation_at IS NOT NULL AND next_calculation_at <= NOW()");
        }

        query.push_str(&format!(
            " ORDER BY total_score DESC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(level) = filter.risk_level {
            q = q.bind(level);
        }

        if let Some(min) = filter.min_score {
            q = q.bind(min);
        }

        if let Some(max) = filter.max_score {
            q = q.bind(max);
        }

        q = q.bind(limit).bind(offset);

        q.fetch_all(pool).await
    }

    /// Count NHI risk scores with filtering.
    pub async fn count(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &NhiRiskScoreFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_nhi_risk_scores
            WHERE tenant_id = $1
            ",
        );

        let mut param_idx = 2;

        if filter.risk_level.is_some() {
            query.push_str(&format!(" AND risk_level = ${param_idx}"));
            param_idx += 1;
        }

        if filter.min_score.is_some() {
            query.push_str(&format!(" AND total_score >= ${param_idx}"));
            param_idx += 1;
        }

        if filter.max_score.is_some() {
            query.push_str(&format!(" AND total_score <= ${param_idx}"));
        }

        if filter.needs_recalculation == Some(true) {
            query.push_str(" AND next_calculation_at IS NOT NULL AND next_calculation_at <= NOW()");
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(level) = filter.risk_level {
            q = q.bind(level);
        }

        if let Some(min) = filter.min_score {
            q = q.bind(min);
        }

        if let Some(max) = filter.max_score {
            q = q.bind(max);
        }

        q.fetch_one(pool).await
    }

    /// Upsert a risk score (insert or update).
    pub async fn upsert(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        data: UpsertGovNhiRiskScore,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_nhi_risk_scores (
                tenant_id, nhi_id, total_score, risk_level,
                staleness_factor, credential_age_factor, access_scope_factor,
                factor_breakdown, next_calculation_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (tenant_id, nhi_id)
            DO UPDATE SET
                total_score = EXCLUDED.total_score,
                risk_level = EXCLUDED.risk_level,
                staleness_factor = EXCLUDED.staleness_factor,
                credential_age_factor = EXCLUDED.credential_age_factor,
                access_scope_factor = EXCLUDED.access_scope_factor,
                factor_breakdown = EXCLUDED.factor_breakdown,
                calculated_at = NOW(),
                next_calculation_at = EXCLUDED.next_calculation_at
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(data.nhi_id)
        .bind(data.total_score)
        .bind(data.risk_level)
        .bind(data.staleness_factor)
        .bind(data.credential_age_factor)
        .bind(data.access_scope_factor)
        .bind(&data.factor_breakdown)
        .bind(data.next_calculation_at)
        .fetch_one(pool)
        .await
    }

    /// Delete score for an NHI.
    pub async fn delete_by_nhi(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_nhi_risk_scores
            WHERE tenant_id = $1 AND nhi_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// List NHIs needing recalculation.
    pub async fn list_needing_recalculation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT nhi_id FROM gov_nhi_risk_scores
            WHERE tenant_id = $1
                AND next_calculation_at IS NOT NULL
                AND next_calculation_at <= NOW()
            ORDER BY next_calculation_at ASC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Get count by risk level.
    pub async fn count_by_level(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<(RiskLevel, i64)>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT risk_level, COUNT(*) as count
            FROM gov_nhi_risk_scores
            WHERE tenant_id = $1
            GROUP BY risk_level
            ORDER BY risk_level
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_from_score() {
        assert_eq!(GovNhiRiskScore::level_from_score(0), RiskLevel::Low);
        assert_eq!(GovNhiRiskScore::level_from_score(25), RiskLevel::Low);
        assert_eq!(GovNhiRiskScore::level_from_score(26), RiskLevel::Medium);
        assert_eq!(GovNhiRiskScore::level_from_score(50), RiskLevel::Medium);
        assert_eq!(GovNhiRiskScore::level_from_score(51), RiskLevel::High);
        assert_eq!(GovNhiRiskScore::level_from_score(75), RiskLevel::High);
        assert_eq!(GovNhiRiskScore::level_from_score(76), RiskLevel::Critical);
        assert_eq!(GovNhiRiskScore::level_from_score(100), RiskLevel::Critical);
    }
}
