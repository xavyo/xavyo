//! Risk Assessment Service for calculating and managing user risk scores.

use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

use crate::audit::{AuditStore, EntitlementAuditAction, EntitlementAuditEventInput};
use crate::error::GovernanceError;
use crate::types::{RiskFactorResult, RiskHistory, RiskLevel, RiskScore, RiskThresholds};

use super::history_store::RiskHistoryStore;
use super::threshold_store::RiskThresholdStore;

/// Service for calculating and managing user risk assessments.
///
/// # Example
///
/// ```ignore
/// use xavyo_governance::services::risk::{
///     RiskAssessmentService, InMemoryRiskThresholdStore, InMemoryRiskHistoryStore
/// };
/// use xavyo_governance::audit::InMemoryAuditStore;
/// use xavyo_governance::types::RiskLevel;
/// use std::sync::Arc;
///
/// let service = RiskAssessmentService::new(
///     Arc::new(InMemoryRiskThresholdStore::new()),
///     Arc::new(InMemoryRiskHistoryStore::new()),
///     Arc::new(InMemoryAuditStore::new()),
/// );
///
/// // Calculate risk for a user with entitlements and SoD violations
/// let entitlements = vec![RiskLevel::Low, RiskLevel::Medium, RiskLevel::High];
/// let sod_violations = 1;
///
/// let risk = service.calculate_user_risk(
///     tenant_id,
///     user_id,
///     &entitlements,
///     sod_violations,
/// ).await?;
/// ```
pub struct RiskAssessmentService {
    threshold_store: Arc<dyn RiskThresholdStore>,
    history_store: Arc<dyn RiskHistoryStore>,
    audit_store: Arc<dyn AuditStore>,
}

impl RiskAssessmentService {
    /// Weight for entitlement risk factor (60%).
    const ENTITLEMENT_WEIGHT: f64 = 0.6;
    /// Weight for `SoD` violation factor (40%).
    const SOD_WEIGHT: f64 = 0.4;
    /// Penalty points per `SoD` violation.
    const SOD_PENALTY_PER_VIOLATION: f64 = 25.0;

    /// Create a new risk assessment service.
    pub fn new(
        threshold_store: Arc<dyn RiskThresholdStore>,
        history_store: Arc<dyn RiskHistoryStore>,
        audit_store: Arc<dyn AuditStore>,
    ) -> Self {
        Self {
            threshold_store,
            history_store,
            audit_store,
        }
    }

    /// Calculate risk score for a user.
    ///
    /// # Arguments
    /// * `tenant_id` - Tenant for isolation
    /// * `user_id` - User to assess
    /// * `entitlements` - User's current entitlement risk levels
    /// * `sod_violation_count` - Count of active `SoD` violations
    ///
    /// # Returns
    /// Calculated `RiskScore` with factor breakdown
    ///
    /// # Risk Calculation Formula
    ///
    /// ```text
    /// Final Score = EntitlementFactor × 0.6 + SodViolationFactor × 0.4
    ///
    /// EntitlementFactor = avg(entitlement_scores)
    ///   where: Low=10, Medium=40, High=70, Critical=100
    ///
    /// SodViolationFactor = min(100, violation_count × 25)
    /// ```
    pub async fn calculate_user_risk(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        entitlements: &[RiskLevel],
        sod_violation_count: usize,
    ) -> Result<RiskScore, GovernanceError> {
        // Calculate entitlement factor
        let entitlement_factor = self.calculate_entitlement_factor(entitlements);

        // Calculate SoD violation factor
        let sod_factor = self.calculate_sod_violation_factor(sod_violation_count);

        // Build factor results
        let mut factors = Vec::new();

        factors.push(
            RiskFactorResult::new("entitlements", Self::ENTITLEMENT_WEIGHT, entitlement_factor)
                .with_description(format!(
                    "Average risk from {} entitlements",
                    entitlements.len()
                )),
        );

        factors.push(
            RiskFactorResult::new("sod_violations", Self::SOD_WEIGHT, sod_factor).with_description(
                format!("{sod_violation_count} active SoD violation(s) (25 points each, max 100)"),
            ),
        );

        // Calculate final score
        let raw_score =
            (entitlement_factor * Self::ENTITLEMENT_WEIGHT) + (sod_factor * Self::SOD_WEIGHT);
        let score = (raw_score.round() as u8).min(100);

        // Get risk level based on thresholds
        let level = self.get_risk_level(tenant_id, score).await?;

        Ok(RiskScore::new(tenant_id, user_id, score, level, factors))
    }

    /// Calculate the entitlement risk factor.
    ///
    /// Returns the average of mapped `RiskLevel` scores (0-100).
    fn calculate_entitlement_factor(&self, entitlements: &[RiskLevel]) -> f64 {
        if entitlements.is_empty() {
            return 0.0;
        }

        let sum: f64 = entitlements
            .iter()
            .map(|level| self.risk_level_score(level))
            .sum();
        sum / entitlements.len() as f64
    }

    /// Map `RiskLevel` to a numeric score (0-100).
    fn risk_level_score(&self, level: &RiskLevel) -> f64 {
        match level {
            RiskLevel::Low => 10.0,
            RiskLevel::Medium => 40.0,
            RiskLevel::High => 70.0,
            RiskLevel::Critical => 100.0,
        }
    }

    /// Calculate the `SoD` violation risk factor.
    ///
    /// Returns min(100, `violation_count` × 25).
    fn calculate_sod_violation_factor(&self, violation_count: usize) -> f64 {
        (violation_count as f64 * Self::SOD_PENALTY_PER_VIOLATION).min(100.0)
    }

    /// Get risk level for a given score using tenant's thresholds.
    ///
    /// Uses default thresholds if no custom thresholds are configured.
    pub async fn get_risk_level(
        &self,
        tenant_id: Uuid,
        score: u8,
    ) -> Result<RiskLevel, GovernanceError> {
        let thresholds = self.get_thresholds(tenant_id).await?;
        Ok(thresholds.get_level(score))
    }

    /// Get current thresholds for a tenant (or defaults).
    pub async fn get_thresholds(&self, tenant_id: Uuid) -> Result<RiskThresholds, GovernanceError> {
        match self.threshold_store.get(tenant_id).await? {
            Some(thresholds) => Ok(thresholds),
            None => {
                // Return defaults
                Ok(RiskThresholds {
                    tenant_id,
                    low_max: 25,
                    medium_max: 50,
                    high_max: 75,
                    updated_at: Utc::now(),
                    updated_by: Uuid::nil(),
                })
            }
        }
    }

    /// Configure risk thresholds for a tenant.
    ///
    /// # Validation
    /// - `low_max < medium_max < high_max < 100`
    /// - All values must be positive integers 1-99
    pub async fn configure_thresholds(
        &self,
        tenant_id: Uuid,
        thresholds: RiskThresholds,
        actor_id: Uuid,
    ) -> Result<RiskThresholds, GovernanceError> {
        // Validate thresholds
        if let Err(reason) = thresholds.validate() {
            return Err(GovernanceError::RiskThresholdInvalid { reason });
        }

        // Create thresholds with proper metadata
        let new_thresholds = RiskThresholds {
            tenant_id,
            low_max: thresholds.low_max,
            medium_max: thresholds.medium_max,
            high_max: thresholds.high_max,
            updated_at: Utc::now(),
            updated_by: actor_id,
        };

        // Store
        self.threshold_store.set(new_thresholds.clone()).await?;

        // Audit log - using EntitlementAuditEventInput for threshold configuration changes
        let audit_input = EntitlementAuditEventInput {
            tenant_id,
            actor_id,
            action: EntitlementAuditAction::Updated,
            after_state: Some(serde_json::json!({
                "entity_type": "risk_thresholds",
                "low_max": new_thresholds.low_max,
                "medium_max": new_thresholds.medium_max,
                "high_max": new_thresholds.high_max,
            })),
            metadata: Some(serde_json::json!({
                "entity_type": "risk_thresholds",
            })),
            ..Default::default()
        };
        self.audit_store.log_event(audit_input).await?;

        Ok(new_thresholds)
    }

    /// Record a risk score for historical trending.
    pub async fn record_risk_history(
        &self,
        _tenant_id: Uuid,
        _user_id: Uuid,
        score: &RiskScore,
    ) -> Result<(), GovernanceError> {
        let history = RiskHistory::from_score(score);
        self.history_store.record(history).await
    }

    /// Get risk trend for a user over a time period.
    ///
    /// Returns entries ordered by `recorded_at` ascending.
    pub async fn get_risk_trend(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<Vec<RiskHistory>, GovernanceError> {
        self.history_store
            .get_trend(tenant_id, user_id, since)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::InMemoryAuditStore;
    use crate::services::risk::{InMemoryRiskHistoryStore, InMemoryRiskThresholdStore};
    use chrono::Duration;

    fn create_service() -> RiskAssessmentService {
        RiskAssessmentService::new(
            Arc::new(InMemoryRiskThresholdStore::new()),
            Arc::new(InMemoryRiskHistoryStore::new()),
            Arc::new(InMemoryAuditStore::new()),
        )
    }

    // =========================================================================
    // User Story 1: Calculate User Risk Score
    // =========================================================================

    #[tokio::test]
    async fn test_calculate_user_risk_no_entitlements_returns_zero() {
        let service = create_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let risk = service
            .calculate_user_risk(tenant_id, user_id, &[], 0)
            .await
            .unwrap();

        assert_eq!(risk.score, 0);
        assert_eq!(risk.level, RiskLevel::Low);
    }

    #[tokio::test]
    async fn test_calculate_user_risk_low_entitlements() {
        let service = create_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let entitlements = vec![RiskLevel::Low, RiskLevel::Low, RiskLevel::Low];
        let risk = service
            .calculate_user_risk(tenant_id, user_id, &entitlements, 0)
            .await
            .unwrap();

        // Low = 10, avg = 10, * 0.6 = 6
        assert_eq!(risk.score, 6);
        assert_eq!(risk.level, RiskLevel::Low);
    }

    #[tokio::test]
    async fn test_calculate_user_risk_critical_entitlements() {
        let service = create_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let entitlements = vec![RiskLevel::Critical, RiskLevel::Critical];
        let risk = service
            .calculate_user_risk(tenant_id, user_id, &entitlements, 0)
            .await
            .unwrap();

        // Critical = 100, avg = 100, * 0.6 = 60
        assert_eq!(risk.score, 60);
        assert_eq!(risk.level, RiskLevel::High);
    }

    #[tokio::test]
    async fn test_calculate_user_risk_sod_violations_add_penalty() {
        let service = create_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // No entitlements, 1 SoD violation
        let risk = service
            .calculate_user_risk(tenant_id, user_id, &[], 1)
            .await
            .unwrap();

        // SoD: 25 * 0.4 = 10
        assert_eq!(risk.score, 10);
    }

    #[tokio::test]
    async fn test_calculate_user_risk_sod_violations_cap_at_100() {
        let service = create_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // No entitlements, 5 SoD violations (5*25=125, but capped at 100)
        let risk = service
            .calculate_user_risk(tenant_id, user_id, &[], 5)
            .await
            .unwrap();

        // SoD: min(100, 125) * 0.4 = 40
        assert_eq!(risk.score, 40);
    }

    #[tokio::test]
    async fn test_calculate_user_risk_mixed_inputs() {
        let service = create_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // Mixed entitlements: Low(10) + Medium(40) + High(70) = 120/3 = 40
        let entitlements = vec![RiskLevel::Low, RiskLevel::Medium, RiskLevel::High];
        let risk = service
            .calculate_user_risk(tenant_id, user_id, &entitlements, 1)
            .await
            .unwrap();

        // Entitlement: 40 * 0.6 = 24
        // SoD: 25 * 0.4 = 10
        // Total: 34
        assert_eq!(risk.score, 34);
        assert_eq!(risk.level, RiskLevel::Medium);

        // Verify factors breakdown
        assert_eq!(risk.factors.len(), 2);
        assert_eq!(risk.factors[0].name, "entitlements");
        assert_eq!(risk.factors[1].name, "sod_violations");
    }

    // =========================================================================
    // User Story 2: Classify Risk Levels
    // =========================================================================

    #[tokio::test]
    async fn test_get_risk_level_low_default() {
        let service = create_service();
        let tenant_id = Uuid::new_v4();

        // Default: Low 0-25
        assert_eq!(
            service.get_risk_level(tenant_id, 0).await.unwrap(),
            RiskLevel::Low
        );
        assert_eq!(
            service.get_risk_level(tenant_id, 25).await.unwrap(),
            RiskLevel::Low
        );
    }

    #[tokio::test]
    async fn test_get_risk_level_medium_default() {
        let service = create_service();
        let tenant_id = Uuid::new_v4();

        // Default: Medium 26-50
        assert_eq!(
            service.get_risk_level(tenant_id, 26).await.unwrap(),
            RiskLevel::Medium
        );
        assert_eq!(
            service.get_risk_level(tenant_id, 50).await.unwrap(),
            RiskLevel::Medium
        );
    }

    #[tokio::test]
    async fn test_get_risk_level_high_default() {
        let service = create_service();
        let tenant_id = Uuid::new_v4();

        // Default: High 51-75
        assert_eq!(
            service.get_risk_level(tenant_id, 51).await.unwrap(),
            RiskLevel::High
        );
        assert_eq!(
            service.get_risk_level(tenant_id, 75).await.unwrap(),
            RiskLevel::High
        );
    }

    #[tokio::test]
    async fn test_get_risk_level_critical_default() {
        let service = create_service();
        let tenant_id = Uuid::new_v4();

        // Default: Critical 76-100
        assert_eq!(
            service.get_risk_level(tenant_id, 76).await.unwrap(),
            RiskLevel::Critical
        );
        assert_eq!(
            service.get_risk_level(tenant_id, 100).await.unwrap(),
            RiskLevel::Critical
        );
    }

    #[tokio::test]
    async fn test_calculate_user_risk_includes_correct_level() {
        let service = create_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // Score 60 = High
        let entitlements = vec![RiskLevel::Critical, RiskLevel::Critical];
        let risk = service
            .calculate_user_risk(tenant_id, user_id, &entitlements, 0)
            .await
            .unwrap();

        // Score is 60, which is High (51-75)
        assert_eq!(risk.level, RiskLevel::High);
    }

    // =========================================================================
    // User Story 3: Configure Risk Thresholds
    // =========================================================================

    #[tokio::test]
    async fn test_configure_thresholds_validates_ordering() {
        let service = create_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        // Invalid: low_max >= medium_max
        let invalid = RiskThresholds {
            tenant_id,
            low_max: 50,
            medium_max: 40, // Wrong!
            high_max: 75,
            updated_at: Utc::now(),
            updated_by: actor_id,
        };

        let result = service
            .configure_thresholds(tenant_id, invalid, actor_id)
            .await;

        assert!(matches!(
            result,
            Err(GovernanceError::RiskThresholdInvalid { .. })
        ));
    }

    #[tokio::test]
    async fn test_configure_thresholds_rejects_high_max_100() {
        let service = create_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        // Invalid: high_max >= 100
        let invalid = RiskThresholds {
            tenant_id,
            low_max: 25,
            medium_max: 50,
            high_max: 100, // Must be < 100
            updated_at: Utc::now(),
            updated_by: actor_id,
        };

        let result = service
            .configure_thresholds(tenant_id, invalid, actor_id)
            .await;

        assert!(matches!(
            result,
            Err(GovernanceError::RiskThresholdInvalid { .. })
        ));
    }

    #[tokio::test]
    async fn test_configure_thresholds_stores_and_returns() {
        let service = create_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let thresholds = RiskThresholds {
            tenant_id,
            low_max: 30,
            medium_max: 60,
            high_max: 85,
            updated_at: Utc::now(),
            updated_by: actor_id,
        };

        let result = service
            .configure_thresholds(tenant_id, thresholds, actor_id)
            .await
            .unwrap();

        assert_eq!(result.low_max, 30);
        assert_eq!(result.medium_max, 60);
        assert_eq!(result.high_max, 85);
        assert_eq!(result.updated_by, actor_id);
    }

    #[tokio::test]
    async fn test_get_risk_level_uses_custom_thresholds() {
        let service = create_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        // Configure custom thresholds: Low 0-30, Medium 31-60
        let thresholds = RiskThresholds {
            tenant_id,
            low_max: 30,
            medium_max: 60,
            high_max: 85,
            updated_at: Utc::now(),
            updated_by: actor_id,
        };
        service
            .configure_thresholds(tenant_id, thresholds, actor_id)
            .await
            .unwrap();

        // Score 30 should be Low (with custom thresholds)
        assert_eq!(
            service.get_risk_level(tenant_id, 30).await.unwrap(),
            RiskLevel::Low
        );

        // Score 31 should be Medium (with custom thresholds)
        assert_eq!(
            service.get_risk_level(tenant_id, 31).await.unwrap(),
            RiskLevel::Medium
        );
    }

    #[tokio::test]
    async fn test_configure_thresholds_creates_audit_log() {
        let audit_store = Arc::new(InMemoryAuditStore::new());
        let service = RiskAssessmentService::new(
            Arc::new(InMemoryRiskThresholdStore::new()),
            Arc::new(InMemoryRiskHistoryStore::new()),
            audit_store.clone(),
        );

        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let thresholds = RiskThresholds {
            tenant_id,
            low_max: 30,
            medium_max: 60,
            high_max: 85,
            updated_at: Utc::now(),
            updated_by: actor_id,
        };

        service
            .configure_thresholds(tenant_id, thresholds, actor_id)
            .await
            .unwrap();

        // Check audit log - need to wait for the async write
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let logs = audit_store.get_all();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].actor_id, actor_id);
        assert_eq!(logs[0].action, EntitlementAuditAction::Updated);
        // Check metadata contains entity_type
        let metadata = logs[0].metadata.as_ref().unwrap();
        assert_eq!(metadata["entity_type"], "risk_thresholds");
    }

    // =========================================================================
    // User Story 4: Track Risk Over Time
    // =========================================================================

    #[tokio::test]
    async fn test_record_risk_history_creates_entry() {
        let history_store = Arc::new(InMemoryRiskHistoryStore::new());
        let service = RiskAssessmentService::new(
            Arc::new(InMemoryRiskThresholdStore::new()),
            history_store.clone(),
            Arc::new(InMemoryAuditStore::new()),
        );

        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let score = RiskScore::new(tenant_id, user_id, 50, RiskLevel::Medium, vec![]);

        service
            .record_risk_history(tenant_id, user_id, &score)
            .await
            .unwrap();

        assert_eq!(history_store.count(), 1);
    }

    #[tokio::test]
    async fn test_get_risk_trend_empty_for_new_user() {
        let service = create_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let since = Utc::now() - Duration::days(30);
        let trend = service
            .get_risk_trend(tenant_id, user_id, since)
            .await
            .unwrap();

        assert!(trend.is_empty());
    }

    #[tokio::test]
    async fn test_get_risk_trend_returns_entries_since_date() {
        let history_store = Arc::new(InMemoryRiskHistoryStore::new());
        let service = RiskAssessmentService::new(
            Arc::new(InMemoryRiskThresholdStore::new()),
            history_store.clone(),
            Arc::new(InMemoryAuditStore::new()),
        );

        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // Record multiple scores
        for score in [25, 50, 75] {
            let level = if score <= 25 {
                RiskLevel::Low
            } else if score <= 50 {
                RiskLevel::Medium
            } else {
                RiskLevel::High
            };
            let risk = RiskScore::new(tenant_id, user_id, score, level, vec![]);
            service
                .record_risk_history(tenant_id, user_id, &risk)
                .await
                .unwrap();
        }

        let since = Utc::now() - Duration::hours(1);
        let trend = service
            .get_risk_trend(tenant_id, user_id, since)
            .await
            .unwrap();

        assert_eq!(trend.len(), 3);
    }

    #[tokio::test]
    async fn test_get_risk_trend_respects_tenant_isolation() {
        let history_store = Arc::new(InMemoryRiskHistoryStore::new());
        let service = RiskAssessmentService::new(
            Arc::new(InMemoryRiskThresholdStore::new()),
            history_store.clone(),
            Arc::new(InMemoryAuditStore::new()),
        );

        let tenant1 = Uuid::new_v4();
        let tenant2 = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // Record in tenant1
        let score1 = RiskScore::new(tenant1, user_id, 25, RiskLevel::Low, vec![]);
        service
            .record_risk_history(tenant1, user_id, &score1)
            .await
            .unwrap();

        // Record in tenant2
        let score2 = RiskScore::new(tenant2, user_id, 75, RiskLevel::High, vec![]);
        service
            .record_risk_history(tenant2, user_id, &score2)
            .await
            .unwrap();

        let since = Utc::now() - Duration::hours(1);

        // Get trend for tenant1 - should only see Low
        let trend1 = service
            .get_risk_trend(tenant1, user_id, since)
            .await
            .unwrap();
        assert_eq!(trend1.len(), 1);
        assert_eq!(trend1[0].score, 25);

        // Get trend for tenant2 - should only see High
        let trend2 = service
            .get_risk_trend(tenant2, user_id, since)
            .await
            .unwrap();
        assert_eq!(trend2.len(), 1);
        assert_eq!(trend2[0].score, 75);
    }
}
