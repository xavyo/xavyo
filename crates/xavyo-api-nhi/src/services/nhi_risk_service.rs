//! NHI risk scoring service.
//!
//! Computes risk scores (0-100) for NHI entities based on:
//! - Common factors: staleness, credential age, inactivity
//! - Type-specific factors: blast radius (tools), autonomy (agents), access scope (service accounts)

use chrono::Utc;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::models::{NhiCredential, NhiIdentity, NhiToolPermission};
use xavyo_nhi::NhiType;

use crate::error::NhiApiError;

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
        common_factors.push(Self::credential_age_factor(pool, tenant_id, nhi_id).await);
        common_factors.push(Self::inactivity_factor(&identity));

        // Type-specific factors
        match identity.nhi_type {
            NhiType::Tool => {
                type_factors.push(Self::blast_radius_factor(pool, tenant_id, nhi_id).await);
            }
            NhiType::Agent => {
                type_factors.push(Self::autonomy_factor(pool, nhi_id).await);
            }
            NhiType::ServiceAccount => {
                type_factors.push(Self::access_scope_factor(pool, tenant_id, nhi_id).await);
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

        // Persist the computed score on the identity
        let _ = NhiIdentity::update_risk_score(pool, tenant_id, nhi_id, total_score).await;

        Ok(RiskBreakdown {
            nhi_id,
            total_score,
            risk_level,
            common_factors,
            type_specific_factors: type_factors,
        })
    }

    fn staleness_factor(identity: &NhiIdentity) -> RiskFactor {
        let days_since = identity
            .last_rotation_at
            .map(|lr| (Utc::now() - lr).num_days())
            .unwrap_or_else(|| (Utc::now() - identity.created_at).num_days()); // Fall back to age since creation
        let score = ((days_since as f64 / 90.0) * 100.0).min(100.0);
        RiskFactor {
            name: "staleness".into(),
            score,
            weight: 0.3,
            description: format!("{days_since} days since last rotation"),
        }
    }

    async fn credential_age_factor(pool: &PgPool, tenant_id: Uuid, nhi_id: Uuid) -> RiskFactor {
        let creds = NhiCredential::list_active_by_nhi(pool, tenant_id, nhi_id)
            .await
            .unwrap_or_default();
        let oldest_days = creds
            .iter()
            .map(|c| (Utc::now() - c.created_at).num_days())
            .max()
            .unwrap_or(0);
        let score = ((oldest_days as f64 / 180.0) * 100.0).min(100.0);
        RiskFactor {
            name: "credential_age".into(),
            score,
            weight: 0.25,
            description: format!("Oldest active credential: {oldest_days} days"),
        }
    }

    fn inactivity_factor(identity: &NhiIdentity) -> RiskFactor {
        let threshold = i64::from(identity.inactivity_threshold_days.unwrap_or(90));
        let days_inactive = identity
            .last_activity_at
            .map(|la| (Utc::now() - la).num_days())
            .unwrap_or(0);
        let score = if threshold > 0 {
            ((days_inactive as f64 / threshold as f64) * 100.0).min(100.0)
        } else {
            0.0
        };
        RiskFactor {
            name: "inactivity".into(),
            score,
            weight: 0.2,
            description: format!(
                "{days_inactive} days since last activity (threshold: {threshold})"
            ),
        }
    }

    async fn blast_radius_factor(pool: &PgPool, tenant_id: Uuid, tool_nhi_id: Uuid) -> RiskFactor {
        let permissions = NhiToolPermission::list_by_tool(pool, tenant_id, tool_nhi_id, 100, 0)
            .await
            .unwrap_or_default();
        let count = permissions.len();
        let score = ((count as f64 / 10.0) * 100.0).min(100.0);
        RiskFactor {
            name: "blast_radius".into(),
            score,
            weight: 0.25,
            description: format!("{count} agents have permissions"),
        }
    }

    async fn autonomy_factor(pool: &PgPool, agent_nhi_id: Uuid) -> RiskFactor {
        let requires_approval: Option<bool> =
            sqlx::query_scalar("SELECT requires_human_approval FROM nhi_agents WHERE nhi_id = $1")
                .bind(agent_nhi_id)
                .fetch_optional(pool)
                .await
                .unwrap_or(None);

        let score = if requires_approval == Some(false) {
            75.0
        } else {
            25.0
        };
        RiskFactor {
            name: "autonomy".into(),
            score,
            weight: 0.25,
            description: format!(
                "Requires human approval: {}",
                requires_approval.unwrap_or(true)
            ),
        }
    }

    async fn access_scope_factor(pool: &PgPool, tenant_id: Uuid, sa_nhi_id: Uuid) -> RiskFactor {
        let creds = NhiCredential::list_active_by_nhi(pool, tenant_id, sa_nhi_id)
            .await
            .unwrap_or_default();
        let count = creds.len();
        let score = ((count as f64 / 5.0) * 100.0).min(100.0);
        RiskFactor {
            name: "access_scope".into(),
            score,
            weight: 0.25,
            description: format!("{count} active credentials"),
        }
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
