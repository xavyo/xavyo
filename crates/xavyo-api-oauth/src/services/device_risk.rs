//! Device risk assessment service for Storm-2372 remediation (F117).
//!
//! This service calculates risk scores for device code approval attempts
//! and determines the appropriate action based on risk thresholds:
//! - Score 0-30: Approve immediately (low risk)
//! - Score 31-60: Require email confirmation (medium risk)
//! - Score 61-100: Require MFA and notify admins (high risk)

use crate::error::OAuthError;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use xavyo_db::models::KnownUserIp;

/// Risk score thresholds for determining actions.
pub const THRESHOLD_LOW_RISK: i32 = 30;
pub const THRESHOLD_MEDIUM_RISK: i32 = 60;

/// Risk factor point values.
pub const POINTS_NEW_COUNTRY: i32 = 40;
pub const POINTS_CODE_OLD: i32 = 20;
pub const POINTS_FIRST_LOGIN: i32 = 30;
pub const POINTS_USER_AGENT_MISMATCH: i32 = 10;
pub const POINTS_BLACKLISTED_IP: i32 = 50;

/// How old a device code must be (in minutes) to add risk points.
pub const CODE_AGE_THRESHOLD_MINUTES: i64 = 5;

/// Action to take based on risk score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAction {
    /// Low risk (0-30): Approve immediately.
    Approve,
    /// Medium risk (31-60): Require email confirmation.
    RequireEmailConfirmation,
    /// High risk (61-100): Require MFA and notify admins.
    RequireMfaAndNotify,
}

impl RiskAction {
    /// Get the action for a given risk score.
    #[must_use]
    pub fn from_score(score: i32) -> Self {
        if score <= THRESHOLD_LOW_RISK {
            Self::Approve
        } else if score <= THRESHOLD_MEDIUM_RISK {
            Self::RequireEmailConfirmation
        } else {
            Self::RequireMfaAndNotify
        }
    }
}

/// Individual risk factor with its point contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Name of the risk factor.
    pub name: String,
    /// Points contributed by this factor.
    pub points: i32,
    /// Optional details about the factor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Complete risk assessment result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Total risk score (0-100, capped).
    pub score: i32,
    /// Action to take based on the score.
    pub action: RiskAction,
    /// Individual risk factors that contributed to the score.
    pub factors: Vec<RiskFactor>,
    /// Whether this is the user's first login.
    pub is_first_login: bool,
    /// Country of the approving IP.
    pub approver_country: Option<String>,
    /// Country of the device code origin IP.
    pub origin_country: Option<String>,
}

impl RiskAssessment {
    /// Create a new risk assessment.
    #[must_use]
    pub fn new(factors: Vec<RiskFactor>, is_first_login: bool) -> Self {
        let score = factors.iter().map(|f| f.points).sum::<i32>().clamp(0, 100);
        let action = RiskAction::from_score(score);

        Self {
            score,
            action,
            factors,
            is_first_login,
            approver_country: None,
            origin_country: None,
        }
    }

    /// Set the country information.
    #[must_use]
    pub fn with_countries(
        mut self,
        approver_country: Option<String>,
        origin_country: Option<String>,
    ) -> Self {
        self.approver_country = approver_country;
        self.origin_country = origin_country;
        self
    }
}

/// Context for risk assessment.
#[derive(Debug, Clone)]
pub struct RiskContext {
    /// Tenant ID for the request.
    pub tenant_id: Uuid,
    /// User ID being assessed.
    pub user_id: Uuid,
    /// IP address of the approver.
    pub approver_ip: Option<String>,
    /// Country code of the approver (from headers).
    pub approver_country: Option<String>,
    /// IP address from which the device code was created.
    pub origin_ip: Option<String>,
    /// Country code from which the device code was created.
    pub origin_country: Option<String>,
    /// When the device code was created.
    pub code_created_at: chrono::DateTime<Utc>,
    /// User-Agent of the device code request.
    pub origin_user_agent: Option<String>,
    /// User-Agent of the approval request.
    pub approver_user_agent: Option<String>,
}

/// Trait for admin notification (allows mocking in tests).
#[async_trait::async_trait]
pub trait AdminNotifier: Send + Sync {
    /// Notify admins of a high-risk device code approval.
    async fn notify_high_risk_approval(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        assessment: &RiskAssessment,
        device_code_id: Uuid,
    ) -> Result<(), OAuthError>;
}

/// Default no-op admin notifier (logs only).
pub struct LogOnlyAdminNotifier;

#[async_trait::async_trait]
impl AdminNotifier for LogOnlyAdminNotifier {
    async fn notify_high_risk_approval(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        assessment: &RiskAssessment,
        device_code_id: Uuid,
    ) -> Result<(), OAuthError> {
        tracing::warn!(
            tenant_id = %tenant_id,
            user_id = %user_id,
            device_code_id = %device_code_id,
            risk_score = assessment.score,
            factors = ?assessment.factors,
            "HIGH RISK device code approval attempt - admin notification"
        );
        Ok(())
    }
}

/// Service for assessing device code approval risk.
pub struct DeviceRiskService {
    pool: PgPool,
    admin_notifier: Arc<dyn AdminNotifier>,
}

impl DeviceRiskService {
    /// Create a new device risk service with the default log-only notifier.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            admin_notifier: Arc::new(LogOnlyAdminNotifier),
        }
    }

    /// Create a new device risk service with a custom admin notifier.
    pub fn with_notifier(pool: PgPool, admin_notifier: Arc<dyn AdminNotifier>) -> Self {
        Self {
            pool,
            admin_notifier,
        }
    }

    /// Calculate the risk score for a device code approval attempt.
    ///
    /// # Arguments
    ///
    /// * `context` - The risk assessment context with all relevant data.
    ///
    /// # Returns
    ///
    /// A `RiskAssessment` with the score, action, and contributing factors.
    pub async fn calculate_score(
        &self,
        context: &RiskContext,
    ) -> Result<RiskAssessment, OAuthError> {
        let mut factors = Vec::new();

        // Factor 1: Check if this is a new user (first login)
        let known_ips = KnownUserIp::find_by_user(&self.pool, context.tenant_id, context.user_id)
            .await
            .map_err(|e| OAuthError::Internal(format!("Failed to fetch user IPs: {e}")))?;

        let is_first_login = known_ips.is_empty();
        if is_first_login {
            factors.push(RiskFactor {
                name: "first_login".to_string(),
                points: POINTS_FIRST_LOGIN,
                details: Some("User has no login history".to_string()),
            });
        }

        // Factor 2: Check if the device code is old (> 5 minutes)
        let code_age = Utc::now() - context.code_created_at;
        if code_age > Duration::minutes(CODE_AGE_THRESHOLD_MINUTES) {
            factors.push(RiskFactor {
                name: "code_age".to_string(),
                points: POINTS_CODE_OLD,
                details: Some(format!(
                    "Code is {} minutes old (threshold: {} minutes)",
                    code_age.num_minutes(),
                    CODE_AGE_THRESHOLD_MINUTES
                )),
            });
        }

        // Factor 3: Check for country mismatch
        if let (Some(approver_country), Some(origin_country)) =
            (&context.approver_country, &context.origin_country)
        {
            // Only count mismatch if both countries are known (not "XX")
            if approver_country != "XX"
                && origin_country != "XX"
                && approver_country != origin_country
            {
                // Check if this is a known country for the user
                let known_countries = KnownUserIp::get_known_countries(
                    &self.pool,
                    context.tenant_id,
                    context.user_id,
                )
                .await
                .map_err(|e| {
                    OAuthError::Internal(format!("Failed to fetch known countries: {e}"))
                })?;

                // Country mismatch is more severe if the approver's country is not in the user's history
                if !known_countries.contains(approver_country) {
                    factors.push(RiskFactor {
                        name: "new_country".to_string(),
                        points: POINTS_NEW_COUNTRY,
                        details: Some(format!(
                            "Approval from new country {approver_country} (code from {origin_country})"
                        )),
                    });
                }
            }
        }

        // Factor 4: Check for IP mismatch (even within same country)
        if let (Some(approver_ip), Some(origin_ip)) = (&context.approver_ip, &context.origin_ip) {
            if approver_ip != origin_ip && !is_first_login {
                // Check if this IP is known for the user
                let known_ip = KnownUserIp::find_by_user_ip(
                    &self.pool,
                    context.tenant_id,
                    context.user_id,
                    approver_ip,
                )
                .await
                .map_err(|e| OAuthError::Internal(format!("Failed to check known IP: {e}")))?;

                if known_ip.is_none() {
                    // This is a less severe risk than country mismatch, but still notable
                    // We don't add points here as it's implicitly covered by country checks
                    // but we log it for audit purposes
                    tracing::info!(
                        tenant_id = %context.tenant_id,
                        user_id = %context.user_id,
                        approver_ip = %approver_ip,
                        origin_ip = %origin_ip,
                        "Device code approval from unknown IP"
                    );
                }
            }
        }

        // Factor 5: Check for User-Agent mismatch (CLI vs browser)
        if let (Some(origin_ua), Some(approver_ua)) =
            (&context.origin_user_agent, &context.approver_user_agent)
        {
            // Simple heuristic: CLI user agents are usually short and don't contain "Mozilla"
            let origin_is_cli = !origin_ua.contains("Mozilla") && origin_ua.len() < 100;
            let approver_is_cli = !approver_ua.contains("Mozilla") && approver_ua.len() < 100;

            // Mismatch is expected (CLI creates code, browser approves) but large difference is suspicious
            // For Storm-2372, the concern is different devices entirely
            if origin_is_cli && approver_is_cli {
                // Both are CLI-like - unusual, as browsers typically approve
                factors.push(RiskFactor {
                    name: "user_agent_mismatch".to_string(),
                    points: POINTS_USER_AGENT_MISMATCH,
                    details: Some(
                        "Both origin and approver appear to be CLI/automated".to_string(),
                    ),
                });
            }
        }

        // TODO: Factor 6: Check if IP is blacklisted (requires blacklist infrastructure)
        // This would add POINTS_BLACKLISTED_IP if the approver's IP is in a blacklist

        let assessment = RiskAssessment::new(factors, is_first_login).with_countries(
            context.approver_country.clone(),
            context.origin_country.clone(),
        );

        // Log the assessment
        tracing::info!(
            tenant_id = %context.tenant_id,
            user_id = %context.user_id,
            risk_score = assessment.score,
            risk_action = ?assessment.action,
            factors_count = assessment.factors.len(),
            "Device code risk assessment completed"
        );

        Ok(assessment)
    }

    /// Get the required action based on a risk score.
    #[must_use]
    pub fn get_required_action(score: i32) -> RiskAction {
        RiskAction::from_score(score)
    }

    /// Record a successful user IP after approval.
    ///
    /// This updates the user's known IP history for future risk assessments.
    pub async fn record_user_ip(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        ip_address: &str,
        country_code: Option<&str>,
    ) -> Result<KnownUserIp, OAuthError> {
        KnownUserIp::record_access(&self.pool, tenant_id, user_id, ip_address, country_code)
            .await
            .map_err(|e| OAuthError::Internal(format!("Failed to record user IP: {e}")))
    }

    /// Notify admins of a high-risk approval attempt.
    ///
    /// Should be called when the risk action is `RequireMfaAndNotify`.
    pub async fn notify_admins(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        assessment: &RiskAssessment,
        device_code_id: Uuid,
    ) -> Result<(), OAuthError> {
        self.admin_notifier
            .notify_high_risk_approval(tenant_id, user_id, assessment, device_code_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_action_from_score() {
        // Low risk: 0-30
        assert_eq!(RiskAction::from_score(0), RiskAction::Approve);
        assert_eq!(RiskAction::from_score(15), RiskAction::Approve);
        assert_eq!(RiskAction::from_score(30), RiskAction::Approve);

        // Medium risk: 31-60
        assert_eq!(
            RiskAction::from_score(31),
            RiskAction::RequireEmailConfirmation
        );
        assert_eq!(
            RiskAction::from_score(45),
            RiskAction::RequireEmailConfirmation
        );
        assert_eq!(
            RiskAction::from_score(60),
            RiskAction::RequireEmailConfirmation
        );

        // High risk: 61-100
        assert_eq!(RiskAction::from_score(61), RiskAction::RequireMfaAndNotify);
        assert_eq!(RiskAction::from_score(80), RiskAction::RequireMfaAndNotify);
        assert_eq!(RiskAction::from_score(100), RiskAction::RequireMfaAndNotify);
    }

    #[test]
    fn test_risk_assessment_new() {
        let factors = vec![
            RiskFactor {
                name: "first_login".to_string(),
                points: POINTS_FIRST_LOGIN,
                details: None,
            },
            RiskFactor {
                name: "code_age".to_string(),
                points: POINTS_CODE_OLD,
                details: None,
            },
        ];

        let assessment = RiskAssessment::new(factors.clone(), true);

        assert_eq!(assessment.score, POINTS_FIRST_LOGIN + POINTS_CODE_OLD); // 30 + 20 = 50
        assert_eq!(assessment.action, RiskAction::RequireEmailConfirmation);
        assert_eq!(assessment.factors.len(), 2);
        assert!(assessment.is_first_login);
    }

    #[test]
    fn test_risk_assessment_score_capped() {
        let factors = vec![
            RiskFactor {
                name: "new_country".to_string(),
                points: POINTS_NEW_COUNTRY, // 40
                details: None,
            },
            RiskFactor {
                name: "first_login".to_string(),
                points: POINTS_FIRST_LOGIN, // 30
                details: None,
            },
            RiskFactor {
                name: "code_age".to_string(),
                points: POINTS_CODE_OLD, // 20
                details: None,
            },
            RiskFactor {
                name: "blacklisted".to_string(),
                points: POINTS_BLACKLISTED_IP, // 50
                details: None,
            },
        ];

        let assessment = RiskAssessment::new(factors, true);

        // Total would be 140, but should be capped at 100
        assert_eq!(assessment.score, 100);
        assert_eq!(assessment.action, RiskAction::RequireMfaAndNotify);
    }

    #[test]
    fn test_risk_assessment_with_countries() {
        let factors = vec![];
        let assessment = RiskAssessment::new(factors, false)
            .with_countries(Some("US".to_string()), Some("FR".to_string()));

        assert_eq!(assessment.approver_country, Some("US".to_string()));
        assert_eq!(assessment.origin_country, Some("FR".to_string()));
    }

    #[test]
    fn test_risk_factor_serialization() {
        let factor = RiskFactor {
            name: "new_country".to_string(),
            points: 40,
            details: Some("From US to RU".to_string()),
        };

        let json = serde_json::to_string(&factor).unwrap();
        assert!(json.contains("new_country"));
        assert!(json.contains("40"));
        assert!(json.contains("From US to RU"));

        // Test without details
        let factor_no_details = RiskFactor {
            name: "code_age".to_string(),
            points: 20,
            details: None,
        };

        let json_no_details = serde_json::to_string(&factor_no_details).unwrap();
        assert!(!json_no_details.contains("details"));
    }

    #[test]
    fn test_get_required_action() {
        assert_eq!(
            DeviceRiskService::get_required_action(25),
            RiskAction::Approve
        );
        assert_eq!(
            DeviceRiskService::get_required_action(45),
            RiskAction::RequireEmailConfirmation
        );
        assert_eq!(
            DeviceRiskService::get_required_action(75),
            RiskAction::RequireMfaAndNotify
        );
    }

    #[test]
    fn test_risk_context_creation() {
        let context = RiskContext {
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            approver_ip: Some("192.168.1.1".to_string()),
            approver_country: Some("US".to_string()),
            origin_ip: Some("10.0.0.1".to_string()),
            origin_country: Some("US".to_string()),
            code_created_at: Utc::now(),
            origin_user_agent: Some("xavyo-cli/1.0".to_string()),
            approver_user_agent: Some("Mozilla/5.0...".to_string()),
        };

        assert!(context.approver_ip.is_some());
        assert_eq!(context.approver_country, Some("US".to_string()));
    }

    #[test]
    fn test_points_constants() {
        // Verify point values match the spec
        assert_eq!(POINTS_NEW_COUNTRY, 40);
        assert_eq!(POINTS_CODE_OLD, 20);
        assert_eq!(POINTS_FIRST_LOGIN, 30);
        assert_eq!(POINTS_USER_AGENT_MISMATCH, 10);
        assert_eq!(POINTS_BLACKLISTED_IP, 50);

        // Verify thresholds
        assert_eq!(THRESHOLD_LOW_RISK, 30);
        assert_eq!(THRESHOLD_MEDIUM_RISK, 60);
    }
}
