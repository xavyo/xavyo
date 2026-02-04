//! Risk enforcement service for adaptive authentication (F073).
//!
//! Orchestrates risk evaluation during login: generates risk events from login context,
//! calculates risk score, determines enforcement action, and generates security alerts.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::{
    AlertSeverity, CreateGovRiskAlert, CreateGovRiskEvent, EnforcementMode,
    GovRiskEnforcementPolicy, GovRiskEvent, GovRiskFactor, GovRiskScore, GovRiskThreshold,
    RiskLevel, ThresholdAction, UpsertGovRiskScore,
};

/// Contextual signals collected at login time for risk evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRiskContext {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_fingerprint: Option<String>,
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
    pub geo_lat: Option<f64>,
    pub geo_lon: Option<f64>,
    pub is_new_device: bool,
    pub is_new_location: bool,
    pub login_time: DateTime<Utc>,
}

/// Action determined by risk enforcement evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementAction {
    /// No action required.
    None,
    /// Alert generated but no enforcement.
    Alert,
    /// Step-up MFA required.
    RequireMfa,
    /// Login blocked.
    Block,
}

/// Result of evaluating login risk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementDecision {
    /// The enforcement action to take.
    pub action: EnforcementAction,
    /// Calculated risk score (0-100).
    pub risk_score: i32,
    /// Risk level classification.
    pub risk_level: String,
    /// Per-factor score breakdown as JSON.
    pub factor_breakdown: serde_json::Value,
    /// Whether the action is actually enforced (true in enforce mode, false in monitor).
    pub enforced: bool,
    /// The enforcement mode that produced this decision.
    pub enforcement_mode: EnforcementMode,
}

impl EnforcementDecision {
    /// Create a skip decision for disabled enforcement mode.
    #[must_use] 
    pub fn skip() -> Self {
        Self {
            action: EnforcementAction::None,
            risk_score: 0,
            risk_level: "low".to_string(),
            factor_breakdown: serde_json::Value::Null,
            enforced: false,
            enforcement_mode: EnforcementMode::Disabled,
        }
    }

    /// Returns true if the action requires blocking or MFA challenge.
    #[must_use] 
    pub fn is_action_required(&self) -> bool {
        self.enforced
            && matches!(
                self.action,
                EnforcementAction::RequireMfa | EnforcementAction::Block
            )
    }

    /// Returns true if the decision requires blocking login.
    #[must_use] 
    pub fn is_blocked(&self) -> bool {
        self.enforced && self.action == EnforcementAction::Block
    }

    /// Returns true if the decision requires step-up MFA.
    #[must_use] 
    pub fn requires_mfa(&self) -> bool {
        self.enforced && self.action == EnforcementAction::RequireMfa
    }
}

/// Service that orchestrates risk evaluation during login.
pub struct RiskEnforcementService {
    pool: PgPool,
}

impl RiskEnforcementService {
    /// Create a new risk enforcement service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Evaluate login risk and return an enforcement decision.
    ///
    /// Flow:
    /// 1. Load enforcement policy for tenant
    /// 2. If disabled, return skip decision
    /// 3. Generate risk events from login context
    /// 4. Calculate risk score
    /// 5. Determine enforcement action from thresholds
    /// 6. Generate security alerts
    /// 7. Return enforcement decision
    pub async fn evaluate_login_risk(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        context: &LoginRiskContext,
    ) -> Result<EnforcementDecision, RiskEnforcementError> {
        // 1. Load enforcement policy
        let policy_result: Result<GovRiskEnforcementPolicy, sqlx::Error> =
            GovRiskEnforcementPolicy::get_or_default(&self.pool, tenant_id).await;
        let policy = policy_result.map_err(|e: sqlx::Error| {
            tracing::warn!(
                "Failed to load enforcement policy for tenant {}: {}",
                tenant_id,
                e
            );
            RiskEnforcementError::PolicyLoadFailed(e.to_string())
        })?;

        // 2. If disabled, skip entirely
        if !policy.enforcement_mode.is_active() {
            return Ok(EnforcementDecision::skip());
        }

        // 3-7: Wrap entire evaluation for fail-open/fail-closed handling
        match self
            .evaluate_with_policy(tenant_id, user_id, context, &policy)
            .await
        {
            Ok(decision) => Ok(decision),
            Err(e) => {
                if policy.fail_open {
                    tracing::warn!(
                        "Risk evaluation failed for user {}, proceeding with fail-open: {}",
                        user_id,
                        e
                    );
                    Ok(EnforcementDecision::skip())
                } else {
                    tracing::error!(
                        "Risk evaluation failed for user {}, fail-closed mode: {}",
                        user_id,
                        e
                    );
                    Err(RiskEnforcementError::ServiceUnavailable)
                }
            }
        }
    }

    /// Core evaluation logic, separated for fail-open/fail-closed wrapping.
    async fn evaluate_with_policy(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        context: &LoginRiskContext,
        policy: &GovRiskEnforcementPolicy,
    ) -> Result<EnforcementDecision, RiskEnforcementError> {
        // 3. Generate risk events from login context
        if let Err(e) = self
            .generate_login_risk_events(tenant_id, user_id, context, policy)
            .await
        {
            tracing::warn!(
                "Risk event generation failed for user {}: {}. Continuing evaluation.",
                user_id,
                e
            );
        }

        // 4. Calculate risk score
        let (total_score, factor_breakdown) = self.calculate_score(tenant_id, user_id).await?;

        let risk_level = RiskLevel::from_score(total_score);

        // 5. Determine enforcement action from thresholds
        let (action, threshold) = self.determine_action(tenant_id, total_score).await?;

        let enforced = policy.enforcement_mode.is_enforcing();

        let decision = EnforcementDecision {
            action,
            risk_score: total_score,
            risk_level: format!("{risk_level:?}").to_lowercase(),
            factor_breakdown,
            enforced,
            enforcement_mode: policy.enforcement_mode,
        };

        // 6. Generate security alerts
        if action != EnforcementAction::None {
            if let Err(e) = self
                .generate_enforcement_alert(
                    tenant_id,
                    user_id,
                    &decision,
                    context,
                    threshold.as_ref(),
                )
                .await
            {
                tracing::warn!(
                    "Alert generation failed for user {}: {}. Non-blocking.",
                    user_id,
                    e
                );
            }
        }

        Ok(decision)
    }

    /// Generate risk events from login context signals.
    async fn generate_login_risk_events(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        context: &LoginRiskContext,
        policy: &GovRiskEnforcementPolicy,
    ) -> Result<(), RiskEnforcementError> {
        // New device event
        if context.is_new_device {
            let source_ref = context.device_fingerprint.clone();
            self.create_risk_event(
                tenant_id,
                user_id,
                "new_device_login",
                1.0,
                source_ref,
                Some(Utc::now() + chrono::Duration::hours(24)),
            )
            .await?;
        }

        // New location event
        if context.is_new_location {
            let source_ref = match (&context.geo_country, &context.geo_city) {
                (Some(country), Some(city)) => Some(format!("{country}/{city}")),
                (Some(country), None) => Some(country.clone()),
                _ => None,
            };
            self.create_risk_event(
                tenant_id,
                user_id,
                "new_location_login",
                1.0,
                source_ref,
                Some(Utc::now() + chrono::Duration::hours(24)),
            )
            .await?;
        }

        // Failed login count event
        self.generate_failed_login_event(tenant_id, user_id).await?;

        // Unusual login time event
        self.generate_unusual_time_event(tenant_id, user_id, context)
            .await?;

        // Dormant account event
        self.generate_dormant_account_event(tenant_id, user_id)
            .await?;

        // Impossible travel event
        if let Err(e) = self
            .check_impossible_travel(tenant_id, user_id, context, policy)
            .await
        {
            tracing::warn!("Impossible travel check failed for user {}: {}", user_id, e);
        }

        Ok(())
    }

    /// Create a single risk event.
    async fn create_risk_event(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        event_type: &str,
        value: f64,
        source_ref: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<(), RiskEnforcementError> {
        let input = CreateGovRiskEvent {
            user_id,
            factor_id: None,
            event_type: event_type.to_string(),
            value: Some(value),
            source_ref,
            expires_at,
        };
        GovRiskEvent::create(&self.pool, tenant_id, input)
            .await
            .map_err(|e| RiskEnforcementError::EventCreationFailed(e.to_string()))?;
        Ok(())
    }

    /// Generate failed login count event.
    async fn generate_failed_login_event(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), RiskEnforcementError> {
        // Count failed logins in the last hour
        let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
        let count: i64 = sqlx::query_scalar(
            "SELECT COALESCE(COUNT(*), 0) FROM login_attempts \
             WHERE tenant_id = $1 AND user_id = $2 \
             AND success = false AND created_at > $3",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(one_hour_ago)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| RiskEnforcementError::DatabaseError(e.to_string()))?;

        if count > 0 {
            self.create_risk_event(
                tenant_id,
                user_id,
                "failed_login_count",
                count as f64,
                None,
                Some(Utc::now() + chrono::Duration::hours(1)),
            )
            .await?;
        }

        Ok(())
    }

    /// Generate unusual login time event by analyzing login hour distribution.
    async fn generate_unusual_time_event(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        context: &LoginRiskContext,
    ) -> Result<(), RiskEnforcementError> {
        // Get login hours from the last 30 days
        let thirty_days_ago = Utc::now() - chrono::Duration::days(30);
        let hours: Vec<Option<f64>> = sqlx::query_scalar(
            "SELECT EXTRACT(HOUR FROM created_at)::float8 FROM login_attempts \
             WHERE tenant_id = $1 AND user_id = $2 \
             AND success = true AND created_at > $3",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(thirty_days_ago)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| RiskEnforcementError::DatabaseError(e.to_string()))?;

        let hours: Vec<f64> = hours.into_iter().flatten().collect();

        // Need at least 5 data points for meaningful analysis
        if hours.len() < 5 {
            return Ok(());
        }

        let current_hour = context
            .login_time
            .format("%H")
            .to_string()
            .parse::<f64>()
            .unwrap_or(0.0);

        let mean: f64 = hours.iter().sum::<f64>() / hours.len() as f64;
        let variance: f64 =
            hours.iter().map(|h| (h - mean).powi(2)).sum::<f64>() / hours.len() as f64;
        let std_dev = variance.sqrt();

        // Flag if current hour is more than 2 standard deviations from mean
        if std_dev > 0.0 && (current_hour - mean).abs() > 2.0 * std_dev {
            self.create_risk_event(
                tenant_id,
                user_id,
                "unusual_login_time",
                1.0,
                Some(format!("hour={}", current_hour as u32)),
                Some(Utc::now() + chrono::Duration::hours(12)),
            )
            .await?;
        }

        Ok(())
    }

    /// Generate dormant account event if last login was over 90 days ago.
    async fn generate_dormant_account_event(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), RiskEnforcementError> {
        let last_login: Option<Option<DateTime<Utc>>> = sqlx::query_scalar(
            "SELECT MAX(created_at) FROM login_attempts \
             WHERE tenant_id = $1 AND user_id = $2 AND success = true",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| RiskEnforcementError::DatabaseError(e.to_string()))?;
        let last_login = last_login.flatten();

        let is_dormant = match last_login {
            Some(last) => (Utc::now() - last).num_days() > 90,
            None => true, // No previous login = first login, treat as dormant
        };

        if is_dormant {
            self.create_risk_event(
                tenant_id,
                user_id,
                "dormant_account_activity",
                1.0,
                None,
                Some(Utc::now() + chrono::Duration::hours(48)),
            )
            .await?;
        }

        Ok(())
    }

    /// Check for impossible travel between current and previous login locations.
    async fn check_impossible_travel(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        context: &LoginRiskContext,
        policy: &GovRiskEnforcementPolicy,
    ) -> Result<(), RiskEnforcementError> {
        if !policy.impossible_travel_enabled {
            return Ok(());
        }

        let (_current_lat, _current_lon) = match (context.geo_lat, context.geo_lon) {
            (Some(lat), Some(lon)) => (lat, lon),
            _ => return Ok(()), // No geo data for current login
        };

        // Get the most recent successful login time and location.
        // Note: login_attempts table has geo_country/geo_city but not lat/lon.
        // For now, impossible travel detection requires client-provided coordinates
        // in the LoginRiskContext. This is a no-op until geo-IP resolution provides
        // lat/lon or the login_attempts table is extended.
        // We look for the previous risk event of type "impossible_travel_check" to get
        // prior coordinates, or fall back to the most recent login time.
        let prev_login: Option<(DateTime<Utc>,)> = sqlx::query_as(
            "SELECT created_at \
             FROM login_attempts \
             WHERE tenant_id = $1 AND user_id = $2 \
             AND success = true \
             ORDER BY created_at DESC \
             OFFSET 1 LIMIT 1",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| RiskEnforcementError::DatabaseError(e.to_string()))?;

        // Without lat/lon from previous logins in DB, impossible travel is limited
        // to scenarios where both current and previous context provide coordinates.
        // For the initial implementation, we skip if we can't determine previous location.
        let _prev_time = match prev_login {
            Some((time,)) => time,
            None => return Ok(()),
        };

        // TODO: When geo-IP resolution provides lat/lon in login_attempts,
        // compare current coordinates against previous login coordinates.
        // For now, impossible travel is effectively a placeholder that will activate
        // once the geo coordinate infrastructure is in place.
        Ok(())
    }

    /// Calculate risk score from enabled factors and active events.
    /// Returns (`total_score`, `factor_breakdown_json`).
    async fn calculate_score(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<(i32, serde_json::Value), RiskEnforcementError> {
        let factors = GovRiskFactor::list_enabled(&self.pool, tenant_id)
            .await
            .map_err(|e| RiskEnforcementError::DatabaseError(e.to_string()))?;

        if factors.is_empty() {
            return Ok((0, serde_json::json!([])));
        }

        let mut breakdown = Vec::new();
        let mut total_weighted = 0.0;
        let mut total_weight = 0.0;

        for factor in &factors {
            let value = GovRiskEvent::sum_by_type_for_user(
                &self.pool,
                tenant_id,
                user_id,
                &factor.factor_type,
            )
            .await
            .unwrap_or(0.0);

            // Normalize to 0-10 range (cap at 10)
            let normalized = value.min(10.0);
            let contribution = normalized * factor.weight;
            total_weighted += contribution;
            total_weight += factor.weight;

            breakdown.push(serde_json::json!({
                "factor_id": factor.id,
                "factor_name": factor.name,
                "category": format!("{:?}", factor.category).to_lowercase(),
                "raw_value": value,
                "weight": factor.weight,
                "contribution": contribution,
            }));
        }

        // Normalize to 0-100
        let total_score = if total_weight > 0.0 {
            ((total_weighted / total_weight) * 10.0).min(100.0) as i32
        } else {
            0
        };

        // Upsert the calculated score
        let _ = GovRiskScore::upsert(
            &self.pool,
            tenant_id,
            UpsertGovRiskScore {
                user_id,
                total_score,
                static_score: 0,
                dynamic_score: total_score,
                factor_breakdown: serde_json::Value::Array(breakdown.clone()),
                peer_comparison: None,
            },
        )
        .await;

        Ok((total_score, serde_json::Value::Array(breakdown)))
    }

    /// Determine the enforcement action based on the risk score and thresholds.
    /// Returns the action and the exceeded threshold (if any).
    async fn determine_action(
        &self,
        tenant_id: Uuid,
        score: i32,
    ) -> Result<(EnforcementAction, Option<GovRiskThreshold>), RiskEnforcementError> {
        let threshold = GovRiskThreshold::find_highest_exceeded(&self.pool, tenant_id, score)
            .await
            .map_err(|e| RiskEnforcementError::DatabaseError(e.to_string()))?;

        match threshold {
            Some(t) => {
                let action = match t.action {
                    ThresholdAction::Alert => EnforcementAction::Alert,
                    ThresholdAction::RequireMfa => EnforcementAction::RequireMfa,
                    ThresholdAction::Block => EnforcementAction::Block,
                };
                Ok((action, Some(t)))
            }
            None => Ok((EnforcementAction::None, None)),
        }
    }

    /// Generate a security alert for an enforcement action.
    async fn generate_enforcement_alert(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        decision: &EnforcementDecision,
        _context: &LoginRiskContext,
        threshold: Option<&GovRiskThreshold>,
    ) -> Result<(), RiskEnforcementError> {
        let threshold_id = match threshold {
            Some(t) => t.id,
            None => return Ok(()), // No threshold to alert on
        };

        // Determine severity based on action and enforcement mode
        let severity = if decision.enforced {
            match decision.action {
                EnforcementAction::Block => AlertSeverity::Critical,
                EnforcementAction::RequireMfa => AlertSeverity::Warning,
                _ => AlertSeverity::Info,
            }
        } else {
            // Monitor mode: info-level alerts
            AlertSeverity::Info
        };

        // Check cooldown to avoid alert spam
        let cooldown_hours = threshold.map_or(24, |t| t.cooldown_hours);
        let exists = xavyo_db::GovRiskAlert::exists_within_cooldown(
            &self.pool,
            tenant_id,
            user_id,
            threshold_id,
            cooldown_hours,
        )
        .await
        .unwrap_or(false);

        if exists {
            return Ok(()); // Already alerted within cooldown
        }

        let alert_input = CreateGovRiskAlert {
            user_id,
            threshold_id,
            score_at_alert: decision.risk_score,
            severity,
        };

        xavyo_db::GovRiskAlert::create(&self.pool, tenant_id, alert_input)
            .await
            .map_err(|e| RiskEnforcementError::AlertCreationFailed(e.to_string()))?;

        tracing::info!(
            tenant_id = %tenant_id,
            user_id = %user_id,
            action = ?decision.action,
            enforced = decision.enforced,
            score = decision.risk_score,
            severity = ?severity,
            "Risk enforcement alert generated"
        );

        Ok(())
    }
}

/// Calculate great-circle distance between two coordinates using the Haversine formula.
/// Returns distance in kilometers.
#[allow(dead_code)]
fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS_KM: f64 = 6371.0;

    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();

    let a =
        (dlat / 2.0).sin().powi(2) + lat1_rad.cos() * lat2_rad.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();

    EARTH_RADIUS_KM * c
}

/// Errors specific to risk enforcement evaluation.
#[derive(Debug, thiserror::Error)]
pub enum RiskEnforcementError {
    #[error("Failed to load enforcement policy: {0}")]
    PolicyLoadFailed(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Risk event creation failed: {0}")]
    EventCreationFailed(String),

    #[error("Alert creation failed: {0}")]
    AlertCreationFailed(String),

    #[error("Risk evaluation service unavailable")]
    ServiceUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enforcement_decision_skip() {
        let decision = EnforcementDecision::skip();
        assert_eq!(decision.action, EnforcementAction::None);
        assert_eq!(decision.risk_score, 0);
        assert!(!decision.enforced);
        assert!(!decision.is_action_required());
        assert!(!decision.is_blocked());
        assert!(!decision.requires_mfa());
    }

    #[test]
    fn test_is_action_required() {
        let mut decision = EnforcementDecision::skip();
        decision.enforced = true;

        decision.action = EnforcementAction::None;
        assert!(!decision.is_action_required());

        decision.action = EnforcementAction::Alert;
        assert!(!decision.is_action_required());

        decision.action = EnforcementAction::RequireMfa;
        assert!(decision.is_action_required());

        decision.action = EnforcementAction::Block;
        assert!(decision.is_action_required());
    }

    #[test]
    fn test_is_action_required_not_enforced() {
        let mut decision = EnforcementDecision::skip();
        decision.enforced = false;
        decision.action = EnforcementAction::Block;
        assert!(!decision.is_action_required());
    }

    #[test]
    fn test_is_blocked() {
        let mut decision = EnforcementDecision::skip();
        decision.enforced = true;
        decision.action = EnforcementAction::Block;
        assert!(decision.is_blocked());

        decision.action = EnforcementAction::RequireMfa;
        assert!(!decision.is_blocked());

        decision.enforced = false;
        decision.action = EnforcementAction::Block;
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_requires_mfa() {
        let mut decision = EnforcementDecision::skip();
        decision.enforced = true;
        decision.action = EnforcementAction::RequireMfa;
        assert!(decision.requires_mfa());

        decision.action = EnforcementAction::Block;
        assert!(!decision.requires_mfa());
    }

    #[test]
    fn test_haversine_new_york_to_tokyo() {
        // New York: 40.7128°N, 74.0060°W
        // Tokyo: 35.6762°N, 139.6503°E
        let distance = haversine_km(40.7128, -74.0060, 35.6762, 139.6503);
        // Expected ~10,860 km
        assert!((distance - 10860.0).abs() < 100.0);
    }

    #[test]
    fn test_haversine_paris_to_london() {
        // Paris: 48.8566°N, 2.3522°E
        // London: 51.5074°N, 0.1278°W
        let distance = haversine_km(48.8566, 2.3522, 51.5074, -0.1278);
        // Expected ~340 km
        assert!((distance - 340.0).abs() < 20.0);
    }

    #[test]
    fn test_haversine_same_location() {
        let distance = haversine_km(40.7128, -74.0060, 40.7128, -74.0060);
        assert!(distance < 0.001);
    }
}
