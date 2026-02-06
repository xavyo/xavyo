//! NHI Risk Service for F061.
//!
//! Provides risk scoring for Non-Human Identities:
//! - Staleness factor (0-40 points based on days inactive)
//! - Credential age factor (0-30 points based on rotation interval)
//! - Access scope factor (0-30 points based on entitlement sensitivity)

use chrono::{Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
#[cfg(feature = "kafka")]
use std::sync::Arc;
use uuid::Uuid;

use xavyo_governance::GovernanceError;

use crate::models::{NhiRiskScoreListResponse, NhiRiskScoreResponse, RiskLevelSummary};

#[cfg(feature = "kafka")]
use xavyo_events::{events::nhi::NhiRiskScoreChanged, EventProducer};

use xavyo_db::{
    GovNhiCredential, GovNhiRiskScore, GovServiceAccount, NhiRiskScoreFilter, RiskLevel,
    UpsertGovNhiRiskScore,
};

type Result<T> = std::result::Result<T, GovernanceError>;

/// Configuration for risk factor calculations.
#[derive(Debug, Clone)]
pub struct RiskFactorConfig {
    /// Maximum points for staleness factor.
    pub staleness_max_points: i32,
    /// Days threshold for maximum staleness.
    pub staleness_max_days: i32,
    /// Maximum points for credential age factor.
    pub credential_age_max_points: i32,
    /// Days threshold for maximum credential age.
    pub credential_age_max_days: i32,
    /// Maximum points for access scope factor.
    pub access_scope_max_points: i32,
    /// Threshold for significant score change (emit event).
    pub significant_change_threshold: i32,
    /// Hours until next recalculation.
    pub recalculation_interval_hours: i64,
}

impl Default for RiskFactorConfig {
    fn default() -> Self {
        Self {
            staleness_max_points: 40,
            staleness_max_days: 180,
            credential_age_max_points: 30,
            credential_age_max_days: 365,
            access_scope_max_points: 30,
            significant_change_threshold: 10,
            recalculation_interval_hours: 24,
        }
    }
}

/// Service for managing NHI risk scoring.
pub struct NhiRiskService {
    pool: PgPool,
    config: RiskFactorConfig,
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl NhiRiskService {
    /// Create a new risk service with default configuration.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            config: RiskFactorConfig::default(),
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(pool: PgPool, config: RiskFactorConfig) -> Self {
        Self {
            pool,
            config,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Set the event producer for Kafka integration.
    #[cfg(feature = "kafka")]
    pub fn set_event_producer(&mut self, producer: Arc<EventProducer>) {
        self.event_producer = Some(producer);
    }

    // =========================================================================
    // Calculate Risk Score
    // =========================================================================

    /// Calculate risk score for an NHI.
    ///
    /// Factors:
    /// - Staleness: 0-40 points based on days since last use
    /// - Credential Age: 0-30 points based on oldest credential age
    /// - Access Scope: 0-30 points based on entitlement count and sensitivity
    pub async fn calculate_score(
        &self,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<NhiRiskScoreResponse> {
        // Validate NHI exists
        let nhi = GovServiceAccount::find_by_id(&self.pool, tenant_id, nhi_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(nhi_id))?;

        // Get previous score for comparison (used for trend analysis)
        let _previous_score = GovNhiRiskScore::find_by_nhi(&self.pool, tenant_id, nhi_id)
            .await
            .map_err(GovernanceError::Database)?;

        // Calculate staleness factor (0-40 points)
        let (staleness_factor, staleness_breakdown) = self.calculate_staleness_factor(&nhi);

        // Calculate credential age factor (0-30 points)
        let (credential_age_factor, credential_breakdown) = self
            .calculate_credential_age_factor(tenant_id, nhi_id)
            .await?;

        // Calculate access scope factor (0-30 points)
        let (access_scope_factor, access_breakdown) = self
            .calculate_access_scope_factor(tenant_id, nhi_id)
            .await?;

        // Total score
        let total_score = staleness_factor + credential_age_factor + access_scope_factor;
        let risk_level = GovNhiRiskScore::level_from_score(total_score);

        // Build factor breakdown
        let factor_breakdown = json!({
            "staleness": staleness_breakdown,
            "credential_age": credential_breakdown,
            "access_scope": access_breakdown
        });

        // Next recalculation time
        let next_calculation_at =
            Some(Utc::now() + Duration::hours(self.config.recalculation_interval_hours));

        // Upsert the score
        let upsert_data = UpsertGovNhiRiskScore {
            nhi_id,
            total_score,
            risk_level,
            staleness_factor,
            credential_age_factor,
            access_scope_factor,
            factor_breakdown: factor_breakdown.clone(),
            next_calculation_at,
        };

        let score = GovNhiRiskScore::upsert(&self.pool, tenant_id, upsert_data)
            .await
            .map_err(GovernanceError::Database)?;

        tracing::debug!(
            tenant_id = %tenant_id,
            nhi_id = %nhi_id,
            total_score = total_score,
            risk_level = ?risk_level,
            "NHI risk score calculated"
        );

        // Emit event if score changed significantly
        #[cfg(feature = "kafka")]
        if let Some(prev) = previous_score {
            let change = (total_score - prev.total_score).abs();
            if change >= self.config.significant_change_threshold {
                self.emit_score_change_event(tenant_id, nhi_id, prev.total_score, total_score)
                    .await;
            }
        }

        Ok(NhiRiskScoreResponse::from(score))
    }

    /// Calculate staleness factor (0-40 points).
    fn calculate_staleness_factor(&self, nhi: &GovServiceAccount) -> (i32, serde_json::Value) {
        let now = Utc::now();

        // Calculate days since last use (or since creation if never used)
        let days_inactive = nhi
            .last_used_at
            .map_or((now - nhi.created_at).num_days(), |last| {
                (now - last).num_days()
            }) as i32;

        // Linear scaling: 0 days = 0 points, max_days = max_points
        let factor = if days_inactive >= self.config.staleness_max_days {
            self.config.staleness_max_points
        } else {
            (days_inactive * self.config.staleness_max_points) / self.config.staleness_max_days
        };

        let breakdown = json!({
            "days_inactive": days_inactive,
            "last_used_at": nhi.last_used_at,
            "created_at": nhi.created_at.to_rfc3339(),
            "points": factor,
            "max_points": self.config.staleness_max_points,
            "threshold_days": self.config.staleness_max_days
        });

        (factor, breakdown)
    }

    /// Calculate credential age factor (0-30 points).
    async fn calculate_credential_age_factor(
        &self,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<(i32, serde_json::Value)> {
        let now = Utc::now();

        // Get active credentials for this NHI
        let credentials = GovNhiCredential::list_active_by_nhi(&self.pool, tenant_id, nhi_id)
            .await
            .map_err(GovernanceError::Database)?;

        if credentials.is_empty() {
            // No credentials = moderate risk (could be legitimate or concerning)
            return Ok((
                15,
                json!({
                    "reason": "no_active_credentials",
                    "points": 15,
                    "max_points": self.config.credential_age_max_points
                }),
            ));
        }

        // Find the oldest active credential
        let oldest_credential_days = credentials
            .iter()
            .map(|c| {
                let duration = now.signed_duration_since(c.created_at);
                duration.num_days()
            })
            .max()
            .unwrap_or(0) as i32;

        // Linear scaling: 0 days = 0 points, max_days = max_points
        let factor = if oldest_credential_days >= self.config.credential_age_max_days {
            self.config.credential_age_max_points
        } else {
            (oldest_credential_days * self.config.credential_age_max_points)
                / self.config.credential_age_max_days
        };

        let breakdown = json!({
            "oldest_credential_days": oldest_credential_days,
            "active_credential_count": credentials.len(),
            "points": factor,
            "max_points": self.config.credential_age_max_points,
            "threshold_days": self.config.credential_age_max_days
        });

        Ok((factor, breakdown))
    }

    /// Calculate access scope factor (0-30 points).
    ///
    /// Based on:
    /// - Number of entitlements assigned
    /// - Risk levels of those entitlements (if available)
    async fn calculate_access_scope_factor(
        &self,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<(i32, serde_json::Value)> {
        // Count entitlements assigned to this NHI via service account assignments
        // This queries gov_entitlement_assignments for the user_id that matches the NHI
        let entitlement_count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_entitlement_assignments
            WHERE tenant_id = $1 AND target_id = $2 AND target_type = 'user' AND status = 'active'
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        // Simple heuristic: more entitlements = more risk
        // 0 entitlements = 0 points
        // 1-5 entitlements = 5 points
        // 6-10 entitlements = 10 points
        // 11-20 entitlements = 15 points
        // 21-50 entitlements = 20 points
        // 51+ entitlements = 30 points
        let factor = match entitlement_count {
            0 => 0,
            1..=5 => 5,
            6..=10 => 10,
            11..=20 => 15,
            21..=50 => 20,
            _ => self.config.access_scope_max_points,
        };

        let breakdown = json!({
            "entitlement_count": entitlement_count,
            "points": factor,
            "max_points": self.config.access_scope_max_points,
            "thresholds": {
                "low": "1-5 entitlements",
                "medium": "6-20 entitlements",
                "high": "21-50 entitlements",
                "critical": "51+ entitlements"
            }
        });

        Ok((factor, breakdown))
    }

    // =========================================================================
    // Get Risk Score
    // =========================================================================

    /// Get current risk score for an NHI.
    ///
    /// Returns None if no score has been calculated yet.
    pub async fn get_score(
        &self,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<Option<NhiRiskScoreResponse>> {
        let score = GovNhiRiskScore::find_by_nhi(&self.pool, tenant_id, nhi_id)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(score.map(NhiRiskScoreResponse::from))
    }

    /// Get risk score, calculating if not present or stale.
    pub async fn get_or_calculate_score(
        &self,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<NhiRiskScoreResponse> {
        if let Some(score) = GovNhiRiskScore::find_by_nhi(&self.pool, tenant_id, nhi_id)
            .await
            .map_err(GovernanceError::Database)?
        {
            if !score.needs_recalculation() {
                return Ok(NhiRiskScoreResponse::from(score));
            }
        }

        // Calculate fresh score
        self.calculate_score(tenant_id, nhi_id).await
    }

    // =========================================================================
    // Batch Operations
    // =========================================================================

    /// Calculate risk scores for multiple NHIs.
    pub async fn batch_calculate(
        &self,
        tenant_id: Uuid,
        nhi_ids: Vec<Uuid>,
    ) -> Result<Vec<NhiRiskScoreResponse>> {
        let mut results = Vec::with_capacity(nhi_ids.len());

        for nhi_id in nhi_ids {
            match self.calculate_score(tenant_id, nhi_id).await {
                Ok(score) => results.push(score),
                Err(e) => {
                    tracing::warn!(error = %e, nhi_id = %nhi_id, "Failed to calculate risk score");
                    // Continue with other NHIs
                }
            }
        }

        Ok(results)
    }

    /// Recalculate scores for all NHIs needing recalculation.
    pub async fn recalculate_stale_scores(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<NhiRiskScoreResponse>> {
        let nhi_ids = GovNhiRiskScore::list_needing_recalculation(&self.pool, tenant_id, limit)
            .await
            .map_err(GovernanceError::Database)?;

        if nhi_ids.is_empty() {
            return Ok(vec![]);
        }

        tracing::info!(
            tenant_id = %tenant_id,
            count = nhi_ids.len(),
            "Recalculating stale risk scores"
        );

        self.batch_calculate(tenant_id, nhi_ids).await
    }

    // =========================================================================
    // List and Filter
    // =========================================================================

    /// List risk scores with filtering.
    pub async fn list_scores(
        &self,
        tenant_id: Uuid,
        filter: &NhiRiskScoreFilter,
        limit: i64,
        offset: i64,
    ) -> Result<NhiRiskScoreListResponse> {
        let scores = GovNhiRiskScore::list(&self.pool, tenant_id, filter, limit, offset)
            .await
            .map_err(GovernanceError::Database)?;

        let total = GovNhiRiskScore::count(&self.pool, tenant_id, filter)
            .await
            .map_err(GovernanceError::Database)?;

        let items: Vec<NhiRiskScoreResponse> =
            scores.into_iter().map(NhiRiskScoreResponse::from).collect();

        Ok(NhiRiskScoreListResponse {
            items,
            total,
            limit: limit as i32,
            offset: offset as i32,
        })
    }

    /// Get summary of risk scores by level.
    pub async fn get_risk_summary(&self, tenant_id: Uuid) -> Result<RiskLevelSummary> {
        let counts = GovNhiRiskScore::count_by_level(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        let mut low = 0;
        let mut medium = 0;
        let mut high = 0;
        let mut critical = 0;

        for (level, count) in counts {
            match level {
                RiskLevel::Low => low = count,
                RiskLevel::Medium => medium = count,
                RiskLevel::High => high = count,
                RiskLevel::Critical => critical = count,
            }
        }

        let total = low + medium + high + critical;

        Ok(RiskLevelSummary {
            total,
            low,
            medium,
            high,
            critical,
        })
    }

    // =========================================================================
    // Kafka Event Emission (Private)
    // =========================================================================

    #[cfg(feature = "kafka")]
    async fn emit_score_change_event(
        &self,
        tenant_id: Uuid,
        nhi_id: Uuid,
        previous_score: i32,
        new_score: i32,
    ) {
        if let Some(ref producer) = self.event_producer {
            let event = NhiRiskScoreChanged {
                nhi_id,
                tenant_id,
                previous_score,
                new_score,
                previous_level: format!("{:?}", GovNhiRiskScore::level_from_score(previous_score)),
                new_level: format!("{:?}", GovNhiRiskScore::level_from_score(new_score)),
                changed_at: Utc::now(),
            };

            if let Err(e) = producer.publish(&event).await {
                tracing::warn!(error = %e, "Failed to publish NhiRiskScoreChanged event");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RiskFactorConfig::default();
        assert_eq!(config.staleness_max_points, 40);
        assert_eq!(config.credential_age_max_points, 30);
        assert_eq!(config.access_scope_max_points, 30);
        assert_eq!(
            config.staleness_max_points
                + config.credential_age_max_points
                + config.access_scope_max_points,
            100
        );
    }

    #[test]
    fn test_risk_level_from_score() {
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
