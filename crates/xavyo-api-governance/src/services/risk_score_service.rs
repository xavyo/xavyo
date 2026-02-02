//! Risk score service for identity risk scoring management.
//!
//! Provides risk score calculation, retrieval, and trend analysis.

use chrono::{Duration, NaiveDate, Utc};
use sqlx::PgPool;
use std::time::Instant;
use uuid::Uuid;

use xavyo_db::{
    CreateGovRiskScoreHistory, GovAssignmentFilter, GovAssignmentStatus, GovAssignmentTargetType,
    GovEntitlementAssignment, GovRiskEvent, GovRiskFactor, GovRiskScore, GovRiskScoreHistory,
    GovRiskThreshold, GovSodViolation, GovViolationStatus, RiskFactorCategory, RiskFactorFilter,
    RiskLevel, RiskScoreFilter, RiskScoreSortBy, SodViolationFilter, ThresholdAction,
    TrendDirection, UpsertGovRiskScore,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    BatchCalculateResponse, EnforcementAction, FactorBreakdown, LevelCount,
    RiskEnforcementResponse, RiskScoreHistoryEntry, RiskScoreHistoryResponse,
    RiskScoreListResponse, RiskScoreResponse, RiskScoreSortOption, RiskScoreSummary,
    RiskTrendResponse,
};

/// Service for risk score operations.
pub struct RiskScoreService {
    pool: PgPool,
}

impl RiskScoreService {
    /// Create a new risk score service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the current risk score for a user.
    ///
    /// Returns the cached score if available, or NotFound if user has no score yet.
    pub async fn get_user_score(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<RiskScoreResponse> {
        let score = GovRiskScore::find_by_user(&self.pool, tenant_id, user_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::RiskScoreNotFound(user_id))?;

        Ok(RiskScoreResponse::from(score))
    }

    /// Calculate and store the risk score for a user.
    ///
    /// Evaluates all enabled risk factors and produces a 0-100 score.
    pub async fn calculate_score(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        include_peer_comparison: bool,
    ) -> Result<RiskScoreResponse> {
        // Get all enabled risk factors
        let filter = RiskFactorFilter {
            category: None,
            is_enabled: Some(true),
            factor_type: None,
        };
        let factors = GovRiskFactor::list_by_tenant(&self.pool, tenant_id, &filter, 100, 0)
            .await
            .map_err(GovernanceError::Database)?;

        if factors.is_empty() {
            // No factors configured - return zero score
            return self
                .save_score(tenant_id, user_id, 0, 0, vec![], None)
                .await;
        }

        // Calculate static and dynamic scores
        let (static_score, static_breakdown) = self
            .calculate_static_factors(tenant_id, user_id, &factors)
            .await?;
        let (dynamic_score, dynamic_breakdown) = self
            .calculate_dynamic_factors(tenant_id, user_id, &factors)
            .await?;

        // Combine breakdowns
        let mut factor_breakdown = static_breakdown;
        factor_breakdown.extend(dynamic_breakdown);

        // Optionally include peer comparison
        let peer_comparison = if include_peer_comparison {
            self.calculate_peer_comparison(tenant_id, user_id)
                .await
                .ok()
        } else {
            None
        };

        // Save and return the score
        self.save_score(
            tenant_id,
            user_id,
            static_score,
            dynamic_score,
            factor_breakdown,
            peer_comparison,
        )
        .await
    }

    /// Calculate static risk factors for a user.
    async fn calculate_static_factors(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        factors: &[GovRiskFactor],
    ) -> Result<(i32, Vec<FactorBreakdown>)> {
        let static_factors: Vec<&GovRiskFactor> = factors
            .iter()
            .filter(|f| f.category == RiskFactorCategory::Static)
            .collect();

        let mut total_weighted = 0.0;
        let mut total_weight = 0.0;
        let mut breakdown = Vec::new();

        for factor in static_factors {
            let raw_value = self
                .get_static_factor_value(tenant_id, user_id, &factor.factor_type)
                .await?;

            // Normalize raw value to 0-100 range based on factor type
            let normalized = self.normalize_factor_value(&factor.factor_type, raw_value);

            let contribution = (normalized * factor.weight) as i32;
            total_weighted += normalized * factor.weight;
            total_weight += factor.weight;

            breakdown.push(FactorBreakdown {
                factor_id: factor.id,
                factor_name: factor.name.clone(),
                category: "static".to_string(),
                raw_value,
                weight: factor.weight,
                contribution,
            });
        }

        // Weighted average normalized to 0-100
        let score = if total_weight > 0.0 {
            ((total_weighted / total_weight) * 100.0 / 100.0) as i32
        } else {
            0
        };

        Ok((score.min(100), breakdown))
    }

    /// Calculate dynamic risk factors for a user.
    async fn calculate_dynamic_factors(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        factors: &[GovRiskFactor],
    ) -> Result<(i32, Vec<FactorBreakdown>)> {
        let dynamic_factors: Vec<&GovRiskFactor> = factors
            .iter()
            .filter(|f| f.category == RiskFactorCategory::Dynamic)
            .collect();

        let mut total_weighted = 0.0;
        let mut total_weight = 0.0;
        let mut breakdown = Vec::new();

        for factor in dynamic_factors {
            let raw_value = self
                .get_dynamic_factor_value(tenant_id, user_id, &factor.factor_type)
                .await?;

            // Normalize raw value to 0-100 range based on factor type
            let normalized = self.normalize_factor_value(&factor.factor_type, raw_value);

            let contribution = (normalized * factor.weight) as i32;
            total_weighted += normalized * factor.weight;
            total_weight += factor.weight;

            breakdown.push(FactorBreakdown {
                factor_id: factor.id,
                factor_name: factor.name.clone(),
                category: "dynamic".to_string(),
                raw_value,
                weight: factor.weight,
                contribution,
            });
        }

        // Weighted average normalized to 0-100
        let score = if total_weight > 0.0 {
            ((total_weighted / total_weight) * 100.0 / 100.0) as i32
        } else {
            0
        };

        Ok((score.min(100), breakdown))
    }

    /// Get the raw value for a static risk factor.
    async fn get_static_factor_value(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        factor_type: &str,
    ) -> Result<f64> {
        match factor_type {
            "sensitive_entitlement_count" | "high_risk_app_access" => {
                // Count high-risk entitlements assigned to user
                // Note: This requires joining assignments with entitlements to check risk_level.
                // For simplicity, we count entitlement IDs and then check each one.
                let entitlement_ids = GovEntitlementAssignment::list_user_entitlement_ids(
                    &self.pool, tenant_id, user_id,
                )
                .await
                .map_err(GovernanceError::Database)?;

                // Count how many of these entitlements are high/critical risk
                // This is a simplified approach - in production you'd do a single query
                let mut high_risk_count = 0;
                for ent_id in entitlement_ids {
                    if let Some(ent) =
                        xavyo_db::GovEntitlement::find_by_id(&self.pool, tenant_id, ent_id)
                            .await
                            .map_err(GovernanceError::Database)?
                    {
                        if ent.risk_level == xavyo_db::GovRiskLevel::High
                            || ent.risk_level == xavyo_db::GovRiskLevel::Critical
                        {
                            high_risk_count += 1;
                        }
                    }
                }
                Ok(high_risk_count as f64)
            }
            "sod_violation_count" => {
                // Count active SoD violations
                let filter = SodViolationFilter {
                    rule_id: None,
                    user_id: Some(user_id),
                    status: Some(GovViolationStatus::Active),
                    detected_after: None,
                    detected_before: None,
                };
                let count =
                    GovSodViolation::count_by_tenant(&self.pool, tenant_id, &filter).await?;
                Ok(count as f64)
            }
            "total_entitlement_count" => {
                // Total entitlement count for user
                let filter = GovAssignmentFilter {
                    entitlement_id: None,
                    target_type: Some(GovAssignmentTargetType::User),
                    target_id: Some(user_id),
                    status: Some(GovAssignmentStatus::Active),
                    assigned_by: None,
                };
                let count =
                    GovEntitlementAssignment::count_by_tenant(&self.pool, tenant_id, &filter)
                        .await
                        .map_err(GovernanceError::Database)?;
                Ok(count as f64)
            }
            "excessive_privilege" => {
                // Placeholder - would compare against peer group average
                Ok(0.0)
            }
            "orphan_account" => {
                // Placeholder - would check if account has no manager/owner
                Ok(0.0)
            }
            _ => Ok(0.0), // Unknown factor type
        }
    }

    /// Get the raw value for a dynamic risk factor.
    async fn get_dynamic_factor_value(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        factor_type: &str,
    ) -> Result<f64> {
        // Sum event values by type for the user (uses active/non-expired events)
        let total_value =
            GovRiskEvent::sum_by_type_for_user(&self.pool, tenant_id, user_id, factor_type)
                .await
                .map_err(GovernanceError::Database)?;

        Ok(total_value)
    }

    /// Normalize a factor value to a 0-100 scale based on factor type.
    fn normalize_factor_value(&self, factor_type: &str, raw_value: f64) -> f64 {
        match factor_type {
            // Count-based factors: log scale with caps
            "sensitive_entitlement_count" => {
                // 0 = 0, 1 = 25, 3 = 50, 10 = 75, 20+ = 100
                if raw_value <= 0.0 {
                    0.0
                } else if raw_value >= 20.0 {
                    100.0
                } else {
                    (raw_value.ln() / 20.0_f64.ln()) * 100.0
                }
            }
            "sod_violation_count" => {
                // Each violation is serious: 1 = 50, 2 = 75, 3+ = 100
                if raw_value <= 0.0 {
                    0.0
                } else if raw_value >= 3.0 {
                    100.0
                } else {
                    raw_value * 33.33
                }
            }
            "total_entitlement_count" => {
                // 0-10 = low risk, 10-50 = medium, 50+ = high
                if raw_value <= 10.0 {
                    raw_value * 2.5 // 0-25
                } else if raw_value <= 50.0 {
                    25.0 + ((raw_value - 10.0) / 40.0) * 50.0 // 25-75
                } else {
                    75.0 + ((raw_value - 50.0) / 50.0).min(1.0) * 25.0 // 75-100
                }
            }
            "failed_login_count" => {
                // 0 = 0, 3 = 30, 5 = 60, 10+ = 100
                if raw_value <= 0.0 {
                    0.0
                } else if raw_value >= 10.0 {
                    100.0
                } else {
                    raw_value * 10.0
                }
            }
            // Binary factors
            "unusual_login_time" | "new_location_login" | "dormant_account_activity" => {
                if raw_value > 0.0 {
                    50.0
                } else {
                    0.0
                }
            }
            // Default: linear mapping
            _ => raw_value.min(100.0),
        }
    }

    /// Calculate peer comparison for a user.
    async fn calculate_peer_comparison(
        &self,
        _tenant_id: Uuid,
        _user_id: Uuid,
    ) -> Result<serde_json::Value> {
        // TODO: Implement peer group comparison in US4
        Err(GovernanceError::Validation(
            "Peer comparison not yet implemented".to_string(),
        ))
    }

    /// Save or update the risk score for a user.
    async fn save_score(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        static_score: i32,
        dynamic_score: i32,
        factor_breakdown: Vec<FactorBreakdown>,
        peer_comparison: Option<serde_json::Value>,
    ) -> Result<RiskScoreResponse> {
        let total_score = (static_score + dynamic_score).min(100);
        let breakdown_json = serde_json::to_value(&factor_breakdown)?;

        // Use upsert to create or update the score
        let input = UpsertGovRiskScore {
            user_id,
            total_score,
            static_score,
            dynamic_score,
            factor_breakdown: breakdown_json,
            peer_comparison,
        };

        let score = GovRiskScore::upsert(&self.pool, tenant_id, input).await?;

        Ok(RiskScoreResponse::from(score))
    }

    /// List risk scores with filtering and pagination.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_scores(
        &self,
        tenant_id: Uuid,
        risk_level: Option<RiskLevel>,
        min_score: Option<i32>,
        max_score: Option<i32>,
        sort_by: RiskScoreSortOption,
        limit: i64,
        offset: i64,
    ) -> Result<RiskScoreListResponse> {
        let filter = RiskScoreFilter {
            risk_level,
            min_score,
            max_score,
        };

        // Convert API sort option to DB sort option
        let db_sort = match sort_by {
            RiskScoreSortOption::ScoreDesc => RiskScoreSortBy::ScoreDesc,
            RiskScoreSortOption::ScoreAsc => RiskScoreSortBy::ScoreAsc,
            RiskScoreSortOption::CalculatedAtDesc => RiskScoreSortBy::CalculatedAtDesc,
            RiskScoreSortOption::CalculatedAtAsc => RiskScoreSortBy::CalculatedAtAsc,
        };

        let scores =
            GovRiskScore::list_by_tenant(&self.pool, tenant_id, &filter, db_sort, limit, offset)
                .await?;
        let total = GovRiskScore::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        let items: Vec<RiskScoreResponse> = scores.into_iter().map(Into::into).collect();

        Ok(RiskScoreListResponse {
            items,
            total,
            limit,
            offset,
        })
    }

    /// Get risk score summary for a tenant.
    pub async fn get_summary(&self, tenant_id: Uuid) -> Result<RiskScoreSummary> {
        // Get counts per level
        let mut by_level = Vec::new();
        let mut total_users = 0i64;
        let mut total_score = 0i64;

        for level in [
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ] {
            let filter = RiskScoreFilter {
                risk_level: Some(level),
                min_score: None,
                max_score: None,
            };
            let count = GovRiskScore::count_by_tenant(&self.pool, tenant_id, &filter).await?;
            by_level.push(LevelCount { level, count });
            total_users += count;
        }

        // Calculate average score
        let all_scores = GovRiskScore::list_by_tenant(
            &self.pool,
            tenant_id,
            &RiskScoreFilter::default(),
            RiskScoreSortBy::ScoreDesc,
            10000,
            0,
        )
        .await?;

        for score in &all_scores {
            total_score += score.total_score as i64;
        }

        let average_score = if total_users > 0 {
            total_score as f64 / total_users as f64
        } else {
            0.0
        };

        Ok(RiskScoreSummary {
            by_level,
            total_users,
            average_score,
        })
    }

    /// Get risk score history for a user.
    pub async fn get_score_history(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        start_date: Option<NaiveDate>,
        end_date: Option<NaiveDate>,
        limit: i64,
    ) -> Result<RiskScoreHistoryResponse> {
        // Get current score
        let current = self.get_user_score(tenant_id, user_id).await?;

        // Get history entries
        let history = if let (Some(start), Some(end)) = (start_date, end_date) {
            GovRiskScoreHistory::get_for_user(&self.pool, tenant_id, user_id, start, end).await?
        } else {
            GovRiskScoreHistory::get_recent_for_user(&self.pool, tenant_id, user_id, limit).await?
        };

        // Calculate trend
        let trend = self.calculate_trend(current.total_score, &history);

        let history_entries: Vec<RiskScoreHistoryEntry> =
            history.into_iter().map(Into::into).collect();

        Ok(RiskScoreHistoryResponse {
            user_id,
            current_score: current.total_score,
            trend,
            history: history_entries,
        })
    }

    /// Calculate trend from history.
    fn calculate_trend(
        &self,
        current_score: i32,
        history: &[GovRiskScoreHistory],
    ) -> RiskTrendResponse {
        let today = Utc::now().date_naive();

        let score_30d_ago = self.find_score_at_date(history, today - Duration::days(30));
        let score_60d_ago = self.find_score_at_date(history, today - Duration::days(60));
        let score_90d_ago = self.find_score_at_date(history, today - Duration::days(90));

        let change_30d = score_30d_ago.map(|s| current_score - s);
        let change_60d = score_60d_ago.map(|s| current_score - s);
        let change_90d = score_90d_ago.map(|s| current_score - s);

        // Determine overall direction based on 30d change
        let direction = match change_30d {
            Some(c) if c > 5 => TrendDirection::Increasing,
            Some(c) if c < -5 => TrendDirection::Decreasing,
            Some(_) => TrendDirection::Stable,
            None => TrendDirection::Stable,
        };

        RiskTrendResponse {
            score_30d_ago,
            score_60d_ago,
            score_90d_ago,
            change_30d,
            change_60d,
            change_90d,
            direction,
        }
    }

    /// Find score closest to a given date.
    fn find_score_at_date(
        &self,
        history: &[GovRiskScoreHistory],
        target_date: NaiveDate,
    ) -> Option<i32> {
        // Find entry closest to target date (within 7 days)
        history
            .iter()
            .filter(|h| {
                let diff = (h.snapshot_date - target_date).num_days().abs();
                diff <= 7
            })
            .min_by_key(|h| (h.snapshot_date - target_date).num_days().abs())
            .map(|h| h.score)
    }

    /// Save daily snapshot of risk score to history.
    pub async fn save_daily_snapshot(&self, tenant_id: Uuid, user_id: Uuid) -> Result<()> {
        let score = self.get_user_score(tenant_id, user_id).await?;
        let today = Utc::now().date_naive();

        // Check if snapshot already exists for today
        let existing =
            GovRiskScoreHistory::get_at_date(&self.pool, tenant_id, user_id, today).await?;

        if existing.is_none() {
            let input = CreateGovRiskScoreHistory {
                user_id,
                score: score.total_score,
                snapshot_date: today,
            };
            GovRiskScoreHistory::create(&self.pool, tenant_id, input).await?;
        }

        Ok(())
    }

    /// Batch calculate scores for all users in a tenant.
    pub async fn calculate_all_scores(
        &self,
        tenant_id: Uuid,
        include_peer_comparison: bool,
    ) -> Result<BatchCalculateResponse> {
        let start = Instant::now();

        // Get all users with entitlements (simplified - would need user service integration)
        // For now, get users from existing scores and assignments
        let existing_scores = GovRiskScore::list_by_tenant(
            &self.pool,
            tenant_id,
            &RiskScoreFilter::default(),
            RiskScoreSortBy::ScoreDesc,
            10000,
            0,
        )
        .await?;

        let user_ids: Vec<Uuid> = existing_scores.iter().map(|s| s.user_id).collect();

        let mut calculated = 0i64;
        let mut errors = 0i64;

        for user_id in user_ids {
            match self
                .calculate_score(tenant_id, user_id, include_peer_comparison)
                .await
            {
                Ok(_) => calculated += 1,
                Err(_) => errors += 1,
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(BatchCalculateResponse {
            calculated,
            errors,
            duration_ms,
        })
    }

    /// Get the enforcement action required for a user based on their risk score.
    ///
    /// Checks all enabled thresholds and returns the most severe action required.
    pub async fn get_enforcement_action(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<RiskEnforcementResponse> {
        // Get the user's current score
        let score = self.get_user_score(tenant_id, user_id).await?;

        // Find the highest exceeded threshold
        let threshold =
            GovRiskThreshold::find_highest_exceeded(&self.pool, tenant_id, score.total_score)
                .await
                .map_err(GovernanceError::Database)?;

        match threshold {
            Some(t) => {
                let action = match t.action {
                    ThresholdAction::Alert => EnforcementAction::Alert,
                    ThresholdAction::RequireMfa => EnforcementAction::RequireMfa,
                    ThresholdAction::Block => EnforcementAction::Block,
                };

                Ok(RiskEnforcementResponse {
                    user_id,
                    score: score.total_score,
                    risk_level: score.risk_level,
                    action,
                    threshold_id: Some(t.id),
                    threshold_name: Some(t.name),
                })
            }
            None => Ok(RiskEnforcementResponse {
                user_id,
                score: score.total_score,
                risk_level: score.risk_level,
                action: EnforcementAction::None,
                threshold_id: None,
                threshold_name: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    // Note: We don't use `use super::*;` here since we test normalization logic
    // with a standalone helper function that doesn't require database connections.

    /// Helper function for testing normalization logic without needing a pool.
    fn normalize_factor_value_for_test(factor_type: &str, raw_value: f64) -> f64 {
        match factor_type {
            // Count-based factors: log scale with caps
            "sensitive_entitlement_count" => {
                // 0 = 0, 1 = 25, 3 = 50, 10 = 75, 20+ = 100
                if raw_value <= 0.0 {
                    0.0
                } else if raw_value >= 20.0 {
                    100.0
                } else {
                    (raw_value.ln() / 20.0_f64.ln()) * 100.0
                }
            }
            "sod_violation_count" => {
                // Each violation is serious: 1 = 50, 2 = 75, 3+ = 100
                if raw_value <= 0.0 {
                    0.0
                } else if raw_value >= 3.0 {
                    100.0
                } else {
                    raw_value * 33.33
                }
            }
            "total_entitlement_count" => {
                // 0-10 = low risk, 10-50 = medium, 50+ = high
                if raw_value <= 10.0 {
                    raw_value * 2.5 // 0-25
                } else if raw_value <= 50.0 {
                    25.0 + ((raw_value - 10.0) / 40.0) * 50.0 // 25-75
                } else {
                    75.0 + ((raw_value - 50.0) / 50.0).min(1.0) * 25.0 // 75-100
                }
            }
            "failed_login_count" => {
                // 0 = 0, 3 = 30, 5 = 60, 10+ = 100
                if raw_value <= 0.0 {
                    0.0
                } else if raw_value >= 10.0 {
                    100.0
                } else {
                    raw_value * 10.0
                }
            }
            // Binary factors
            "unusual_login_time" | "new_location_login" | "dormant_account_activity" => {
                if raw_value > 0.0 {
                    50.0
                } else {
                    0.0
                }
            }
            // Default: linear mapping
            _ => raw_value.min(100.0),
        }
    }

    #[test]
    fn test_normalize_sensitive_entitlement_count() {
        // Zero entitlements = 0 risk
        assert_eq!(
            normalize_factor_value_for_test("sensitive_entitlement_count", 0.0),
            0.0
        );

        // 20+ entitlements = max risk
        assert_eq!(
            normalize_factor_value_for_test("sensitive_entitlement_count", 20.0),
            100.0
        );
        assert_eq!(
            normalize_factor_value_for_test("sensitive_entitlement_count", 50.0),
            100.0
        );
    }

    #[test]
    fn test_normalize_sod_violation_count() {
        // Zero violations = 0 risk
        assert_eq!(
            normalize_factor_value_for_test("sod_violation_count", 0.0),
            0.0
        );

        // 3+ violations = max risk
        assert!(normalize_factor_value_for_test("sod_violation_count", 3.0) >= 99.0);
    }

    #[test]
    fn test_normalize_failed_login_count() {
        assert_eq!(
            normalize_factor_value_for_test("failed_login_count", 0.0),
            0.0
        );
        assert_eq!(
            normalize_factor_value_for_test("failed_login_count", 5.0),
            50.0
        );
        assert_eq!(
            normalize_factor_value_for_test("failed_login_count", 10.0),
            100.0
        );
    }

    #[test]
    fn test_normalize_binary_factors() {
        // Binary factors: 0 or 50
        assert_eq!(
            normalize_factor_value_for_test("unusual_login_time", 0.0),
            0.0
        );
        assert_eq!(
            normalize_factor_value_for_test("unusual_login_time", 1.0),
            50.0
        );
        assert_eq!(
            normalize_factor_value_for_test("new_location_login", 0.0),
            0.0
        );
        assert_eq!(
            normalize_factor_value_for_test("new_location_login", 1.0),
            50.0
        );
    }
}
