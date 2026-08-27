//! NHI risk scoring service.
//!
//! Computes risk scores (0-100) for NHI entities based on:
//! - Common factors: staleness, inactivity
//! - Type-specific factors: blast radius (tools), autonomy (agents), access scope (service accounts)

use chrono::Utc;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::models::{NhiIdentity, NhiToolPermission};
use xavyo_nhi::NhiType;

use crate::error::NhiApiError;

/// Never-seen NHIs must score as fully inactive, not 0 days.
pub fn inactivity_days(
    last_activity_at: Option<chrono::DateTime<Utc>>,
    now: chrono::DateTime<Utc>,
    threshold_days: i64,
) -> i64 {
    match last_activity_at {
        Some(at) => (now - at).num_days(),
        None => threshold_days.max(0),
    }
}

/// Individual risk factor with score and weight.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RiskFactor {
    pub name: String,
    pub score: f64,
    pub weight: f64,
    pub description: String,
}

/// Complete risk breakdown for an NHI entity.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RiskBreakdown {
    pub nhi_id: Uuid,
    pub total_score: i32,
    pub risk_level: String,
    pub common_factors: Vec<RiskFactor>,
    pub type_specific_factors: Vec<RiskFactor>,
}

/// Risk summary aggregation.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RiskSummary {
    pub total_entities: i64,
    pub by_type: Vec<TypeRiskSummary>,
    pub by_level: Vec<LevelRiskSummary>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TypeRiskSummary {
    pub nhi_type: String,
    pub count: i64,
    pub avg_score: f64,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LevelRiskSummary {
    pub level: String,
    pub count: i64,
}

pub struct NhiRiskService;

impl NhiRiskService {
    /// Compute risk score for a single NHI entity.
    pub async fn compute(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<RiskBreakdown, NhiApiError> {
        let identity = NhiIdentity::find_by_id(pool, tenant_id, nhi_id)
            .await
            .map_err(NhiApiError::Database)?
            .ok_or(NhiApiError::NotFound)?;

        let mut common_factors = Vec::new();
        let mut type_factors = Vec::new();

        // Common factors (apply to all types)
        common_factors.push(Self::staleness_factor(&identity));
        common_factors.push(Self::inactivity_factor(&identity));

        // Type-specific factors
        match identity.nhi_type {
            NhiType::Tool => {
                type_factors.push(Self::blast_radius_factor(pool, tenant_id, nhi_id).await?);
            }
            NhiType::Agent => {
                type_factors.push(Self::autonomy_factor(pool, tenant_id, nhi_id).await?);
            }
            NhiType::ServiceAccount => {
                type_factors.push(Self::access_scope_factor(pool, tenant_id, nhi_id).await?);
            }
            _ => {}
        }

        // Weighted average
        let all_factors: Vec<&RiskFactor> =
            common_factors.iter().chain(type_factors.iter()).collect();
        let total_weight: f64 = all_factors.iter().map(|f| f.weight).sum();
        let weighted_sum: f64 = all_factors.iter().map(|f| f.score * f.weight).sum();
        let total_score = if total_weight > 0.0 {
            (weighted_sum / total_weight).round() as i32
        } else {
            0
        };
        let total_score = total_score.clamp(0, 100);

        let risk_level = match total_score {
            0..=25 => "low",
            26..=50 => "medium",
            51..=75 => "high",
            _ => "critical",
        }
        .to_string();

        // Persist the computed score on the identity. A missed write is not success.
        let persisted = NhiIdentity::update_risk_score(pool, tenant_id, nhi_id, total_score)
            .await
            .map_err(NhiApiError::Database)?;
        if !persisted {
            return Err(NhiApiError::NotFound);
        }

        Ok(RiskBreakdown {
            nhi_id,
            total_score,
            risk_level,
            common_factors,
            type_specific_factors: type_factors,
        })
    }

    fn staleness_factor(identity: &NhiIdentity) -> RiskFactor {
        let days_since = (Utc::now() - identity.updated_at).num_days();
        let score = ((days_since as f64 / 90.0) * 100.0).min(100.0);
        RiskFactor {
            name: "staleness".into(),
            score,
            weight: 0.35,
            description: format!("{days_since} days since last update"),
        }
    }

    fn inactivity_factor(identity: &NhiIdentity) -> RiskFactor {
        let threshold = i64::from(identity.inactivity_threshold_days.unwrap_or(90));
        let days_inactive = inactivity_days(identity.last_activity_at, Utc::now(), threshold);
        let score = if threshold > 0 {
            ((days_inactive as f64 / threshold as f64) * 100.0).min(100.0)
        } else {
            0.0
        };
        RiskFactor {
            name: "inactivity".into(),
            score,
            weight: 0.30,
            description: format!(
                "{days_inactive} days since last activity (threshold: {threshold})"
            ),
        }
    }

    async fn blast_radius_factor(
        pool: &PgPool,
        tenant_id: Uuid,
        tool_nhi_id: Uuid,
    ) -> Result<RiskFactor, NhiApiError> {
        let permissions = NhiToolPermission::list_by_tool(pool, tenant_id, tool_nhi_id, 100, 0)
            .await
            .map_err(NhiApiError::Database)?;
        let count = permissions.len();
        let score = ((count as f64 / 10.0) * 100.0).min(100.0);
        Ok(RiskFactor {
            name: "blast_radius".into(),
            score,
            weight: 0.35,
            description: format!("{count} agents have permissions"),
        })
    }

    async fn autonomy_factor(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_nhi_id: Uuid,
    ) -> Result<RiskFactor, NhiApiError> {
        let requires_approval: Option<bool> = sqlx::query_scalar(
            r"SELECT a.requires_human_approval
              FROM nhi_agents a
              WHERE a.nhi_id = $2
                AND EXISTS (SELECT 1 FROM nhi_identities WHERE id = $2 AND tenant_id = $1)",
        )
        .bind(tenant_id)
        .bind(agent_nhi_id)
        .fetch_optional(pool)
        .await
        .map_err(NhiApiError::Database)?;

        let requires_approval = requires_approval.ok_or(NhiApiError::NotFound)?;
        let score = if requires_approval { 25.0 } else { 75.0 };
        Ok(RiskFactor {
            name: "autonomy".into(),
            score,
            weight: 0.35,
            description: format!("Requires human approval: {requires_approval}"),
        })
    }

    async fn access_scope_factor(
        pool: &PgPool,
        tenant_id: Uuid,
        sa_nhi_id: Uuid,
    ) -> Result<RiskFactor, NhiApiError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM nhi_user_permissions WHERE tenant_id = $1 AND nhi_id = $2",
        )
        .bind(tenant_id)
        .bind(sa_nhi_id)
        .fetch_one(pool)
        .await
        .map_err(NhiApiError::Database)?;
        let score = ((count as f64 / 5.0) * 100.0).min(100.0);
        Ok(RiskFactor {
            name: "access_scope".into(),
            score,
            weight: 0.35,
            description: format!("{count} user permission grants"),
        })
    }

    /// Aggregate risk summary across all NHIs in a tenant.
    pub async fn summary(pool: &PgPool, tenant_id: Uuid) -> Result<RiskSummary, NhiApiError> {
        let by_type: Vec<TypeRiskSummary> = sqlx::query_as::<_, (String, i64, Option<f64>)>(
            r"SELECT nhi_type, COUNT(*), AVG(risk_score::float8)
              FROM nhi_identities WHERE tenant_id = $1
              GROUP BY nhi_type",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .map_err(NhiApiError::Database)?
        .into_iter()
        .map(|(t, c, a)| TypeRiskSummary {
            nhi_type: t,
            count: c,
            avg_score: a.unwrap_or(0.0),
        })
        .collect();

        let by_level: Vec<LevelRiskSummary> = sqlx::query_as::<_, (String, i64)>(
            r"SELECT
                CASE
                    WHEN COALESCE(risk_score, 0) <= 25 THEN 'low'
                    WHEN COALESCE(risk_score, 0) <= 50 THEN 'medium'
                    WHEN COALESCE(risk_score, 0) <= 75 THEN 'high'
                    ELSE 'critical'
                END AS level,
                COUNT(*)
              FROM nhi_identities WHERE tenant_id = $1
              GROUP BY level
              ORDER BY level",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .map_err(NhiApiError::Database)?
        .into_iter()
        .map(|(l, c)| LevelRiskSummary { level: l, count: c })
        .collect();

        let total_entities: i64 = by_type.iter().map(|t| t.count).sum();

        Ok(RiskSummary {
            total_entities,
            by_type,
            by_level,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_factors_do_not_fail_open_on_query_errors() {
        let src = include_str!("nhi_risk_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        let blast = production
            .split("fn blast_radius_factor")
            .nth(1)
            .expect("blast_radius_factor")
            .split("fn autonomy_factor")
            .next()
            .expect("blast_radius_factor body");
        assert!(
            blast.contains("map_err(NhiApiError::Database)"),
            "blast radius errors must fail closed"
        );
        assert!(
            !blast.contains("unwrap_or_default()"),
            "must not treat permission-list errors as zero blast radius"
        );

        let autonomy = production
            .split("fn autonomy_factor")
            .nth(1)
            .expect("autonomy_factor")
            .split("fn access_scope_factor")
            .next()
            .expect("autonomy_factor body");
        assert!(
            autonomy.contains(
                "AND EXISTS (SELECT 1 FROM nhi_identities WHERE id = $2 AND tenant_id = $1)"
            ),
            "autonomy lookup must include tenant_id"
        );
        assert!(
            autonomy.contains("ok_or(NhiApiError::NotFound)"),
            "missing agent rows must fail closed"
        );
        assert!(
            !autonomy.contains("unwrap_or(None)"),
            "must not treat autonomy query errors as requiring approval"
        );
        assert!(
            !autonomy.contains("FROM nhi_agents WHERE nhi_id = $1"),
            "must not look up agents by nhi_id alone"
        );

        let access = production
            .split("fn access_scope_factor")
            .nth(1)
            .expect("access_scope_factor")
            .split("pub async fn summary")
            .next()
            .expect("access_scope_factor body");
        assert!(
            access.contains("map_err(NhiApiError::Database)"),
            "access scope errors must fail closed"
        );
        assert!(
            !access.contains("unwrap_or(0)"),
            "must not treat permission-count errors as score 0"
        );
    }

    #[test]
    fn compute_does_not_swallow_risk_score_persist() {
        let src = include_str!("nhi_risk_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        let compute = production
            .split("pub async fn compute")
            .nth(1)
            .expect("compute")
            .split("fn staleness_factor")
            .next()
            .expect("compute body");
        assert!(
            compute.contains("map_err(NhiApiError::Database)"),
            "risk score persist errors must fail closed"
        );
        assert!(
            !compute.contains("let _ = NhiIdentity::update_risk_score"),
            "must not swallow risk score persist errors"
        );
    }

    #[test]
    fn never_active_nhi_is_not_scored_as_zero_inactivity() {
        let now = Utc::now();
        assert_eq!(inactivity_days(None, now, 90), 90);
        assert_eq!(inactivity_days(Some(now), now, 90), 0);
        let src = include_str!("nhi_risk_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        let inactivity = production
            .split("fn inactivity_factor")
            .nth(1)
            .expect("inactivity_factor")
            .split("fn blast_radius_factor")
            .next()
            .expect("inactivity_factor body");
        assert!(
            inactivity.contains("inactivity_days(") && !inactivity.contains("unwrap_or(0)"),
            "missing last_activity_at must not score as 0 days inactive"
        );
    }
}
