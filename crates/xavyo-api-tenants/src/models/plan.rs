//! Request and response models for plan management API.
//!
//! F-PLAN-MGMT: Allows system admins to upgrade/downgrade tenant plans.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use xavyo_db::models::{PlanDefinition, PlanTier};

/// Request to upgrade a tenant's plan.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpgradePlanRequest {
    /// Target plan tier to upgrade to.
    pub new_plan: String,
}

impl UpgradePlanRequest {
    /// Validate the request.
    pub fn validate(&self, current_plan: &str) -> Result<PlanTier, String> {
        // Parse the new plan
        let new_tier: PlanTier = self
            .new_plan
            .parse()
            .map_err(|_| format!("Invalid plan tier: {}", self.new_plan))?;

        // Parse the current plan
        let current_tier: PlanTier = current_plan
            .parse()
            .map_err(|_| format!("Invalid current plan: {current_plan}"))?;

        // Ensure it's actually an upgrade
        if !new_tier.is_higher_than(&current_tier) {
            return Err(format!(
                "Cannot upgrade from {} to {}: new plan must be higher tier",
                current_plan, self.new_plan
            ));
        }

        Ok(new_tier)
    }
}

/// Request to downgrade a tenant's plan.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DowngradePlanRequest {
    /// Target plan tier to downgrade to.
    pub new_plan: String,

    /// Optional reason for the downgrade.
    #[serde(default)]
    pub reason: Option<String>,
}

impl DowngradePlanRequest {
    /// Validate the request.
    pub fn validate(&self, current_plan: &str) -> Result<PlanTier, String> {
        // Parse the new plan
        let new_tier: PlanTier = self
            .new_plan
            .parse()
            .map_err(|_| format!("Invalid plan tier: {}", self.new_plan))?;

        // Parse the current plan
        let current_tier: PlanTier = current_plan
            .parse()
            .map_err(|_| format!("Invalid current plan: {current_plan}"))?;

        // Ensure it's actually a downgrade
        if !new_tier.is_lower_than(&current_tier) {
            return Err(format!(
                "Cannot downgrade from {} to {}: new plan must be lower tier",
                current_plan, self.new_plan
            ));
        }

        Ok(new_tier)
    }
}

/// Response after a plan change operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlanChangeResponse {
    /// Unique identifier for the change record.
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,

    /// Tenant ID.
    #[schema(value_type = String, format = "uuid")]
    pub tenant_id: Uuid,

    /// Type of change (upgrade or downgrade).
    pub change_type: String,

    /// Previous plan name.
    pub old_plan: String,

    /// New plan name.
    pub new_plan: String,

    /// When the change takes effect.
    pub effective_at: DateTime<Utc>,

    /// Status of the change (pending, applied, cancelled).
    pub status: String,

    /// Message describing the change.
    pub message: String,
}

/// Response for plan change history.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlanHistoryResponse {
    /// Tenant ID.
    #[schema(value_type = String, format = "uuid")]
    pub tenant_id: Uuid,

    /// Current plan.
    pub current_plan: String,

    /// List of plan changes (most recent first).
    pub changes: Vec<PlanChangeEntry>,

    /// Pending downgrade info, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_downgrade: Option<PendingDowngradeInfo>,
}

/// A single entry in the plan change history.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlanChangeEntry {
    /// Change record ID.
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,

    /// Type of change.
    pub change_type: String,

    /// Previous plan.
    pub old_plan: String,

    /// New plan.
    pub new_plan: String,

    /// When the change took/takes effect.
    pub effective_at: DateTime<Utc>,

    /// Status of the change.
    pub status: String,

    /// Reason for the change (if provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// When the change was created.
    pub created_at: DateTime<Utc>,
}

/// Information about a pending downgrade.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PendingDowngradeInfo {
    /// Change record ID.
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,

    /// Target plan.
    pub new_plan: String,

    /// When the downgrade will take effect.
    pub effective_at: DateTime<Utc>,

    /// Reason for the downgrade (if provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Response for a plan definition.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlanDefinitionResponse {
    /// Plan tier name.
    pub tier: String,

    /// Display name.
    pub display_name: String,

    /// Tier order (0 = lowest, 3 = highest).
    pub tier_order: i32,

    /// Plan limits.
    pub limits: PlanLimitsResponse,
}

/// Plan limits in the response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlanLimitsResponse {
    /// Maximum monthly active users.
    pub max_mau: i64,

    /// Maximum API calls per month.
    pub max_api_calls: i64,

    /// Maximum agent invocations per month.
    pub max_agent_invocations: i64,
}

impl From<PlanDefinition> for PlanDefinitionResponse {
    fn from(def: PlanDefinition) -> Self {
        Self {
            tier: def.tier.as_str().to_string(),
            display_name: def.display_name,
            tier_order: def.tier.tier_order(),
            limits: PlanLimitsResponse {
                max_mau: def.max_mau,
                max_api_calls: def.max_api_calls,
                max_agent_invocations: def.max_agent_invocations,
            },
        }
    }
}

/// Response for listing all available plans.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlansListResponse {
    /// List of available plans in order.
    pub plans: Vec<PlanDefinitionResponse>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // T007: Tests for PlanTier ordering (validation uses PlanTier methods)
    #[test]
    fn test_upgrade_validation_success() {
        let request = UpgradePlanRequest {
            new_plan: "professional".to_string(),
        };
        let result = request.validate("starter");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PlanTier::Professional);
    }

    #[test]
    fn test_upgrade_validation_free_to_enterprise() {
        let request = UpgradePlanRequest {
            new_plan: "enterprise".to_string(),
        };
        let result = request.validate("free");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PlanTier::Enterprise);
    }

    #[test]
    fn test_upgrade_validation_same_tier_fails() {
        let request = UpgradePlanRequest {
            new_plan: "starter".to_string(),
        };
        let result = request.validate("starter");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be higher tier"));
    }

    #[test]
    fn test_upgrade_validation_downgrade_fails() {
        let request = UpgradePlanRequest {
            new_plan: "free".to_string(),
        };
        let result = request.validate("starter");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be higher tier"));
    }

    #[test]
    fn test_upgrade_validation_invalid_new_plan() {
        let request = UpgradePlanRequest {
            new_plan: "invalid".to_string(),
        };
        let result = request.validate("starter");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid plan tier"));
    }

    #[test]
    fn test_upgrade_validation_invalid_current_plan() {
        let request = UpgradePlanRequest {
            new_plan: "professional".to_string(),
        };
        let result = request.validate("unknown");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid current plan"));
    }

    // T008: Tests for DowngradePlanRequest validation
    #[test]
    fn test_downgrade_validation_success() {
        let request = DowngradePlanRequest {
            new_plan: "starter".to_string(),
            reason: Some("Cost reduction".to_string()),
        };
        let result = request.validate("professional");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PlanTier::Starter);
    }

    #[test]
    fn test_downgrade_validation_enterprise_to_free() {
        let request = DowngradePlanRequest {
            new_plan: "free".to_string(),
            reason: None,
        };
        let result = request.validate("enterprise");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PlanTier::Free);
    }

    #[test]
    fn test_downgrade_validation_same_tier_fails() {
        let request = DowngradePlanRequest {
            new_plan: "professional".to_string(),
            reason: None,
        };
        let result = request.validate("professional");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be lower tier"));
    }

    #[test]
    fn test_downgrade_validation_upgrade_fails() {
        let request = DowngradePlanRequest {
            new_plan: "enterprise".to_string(),
            reason: None,
        };
        let result = request.validate("professional");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be lower tier"));
    }

    #[test]
    fn test_downgrade_validation_invalid_plan() {
        let request = DowngradePlanRequest {
            new_plan: "invalid".to_string(),
            reason: None,
        };
        let result = request.validate("professional");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid plan tier"));
    }

    // T026/T031: Tests for response serialization
    #[test]
    fn test_plan_change_response_serialization() {
        let response = PlanChangeResponse {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            change_type: "upgrade".to_string(),
            old_plan: "free".to_string(),
            new_plan: "starter".to_string(),
            effective_at: Utc::now(),
            status: "applied".to_string(),
            message: "Upgrade successful".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("upgrade"));
        assert!(json.contains("free"));
        assert!(json.contains("starter"));
        assert!(json.contains("applied"));
    }

    #[test]
    fn test_plan_history_response_serialization() {
        let response = PlanHistoryResponse {
            tenant_id: Uuid::new_v4(),
            current_plan: "professional".to_string(),
            changes: vec![PlanChangeEntry {
                id: Uuid::new_v4(),
                change_type: "upgrade".to_string(),
                old_plan: "starter".to_string(),
                new_plan: "professional".to_string(),
                effective_at: Utc::now(),
                status: "applied".to_string(),
                reason: None,
                created_at: Utc::now(),
            }],
            pending_downgrade: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("professional"));
        assert!(json.contains("changes"));
        // pending_downgrade should be omitted when None
        assert!(!json.contains("pending_downgrade"));
    }

    #[test]
    fn test_plan_history_with_pending_downgrade() {
        let response = PlanHistoryResponse {
            tenant_id: Uuid::new_v4(),
            current_plan: "professional".to_string(),
            changes: vec![],
            pending_downgrade: Some(PendingDowngradeInfo {
                id: Uuid::new_v4(),
                new_plan: "starter".to_string(),
                effective_at: Utc::now(),
                reason: Some("Budget reduction".to_string()),
            }),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("pending_downgrade"));
        assert!(json.contains("Budget reduction"));
    }

    #[test]
    fn test_plan_definition_response_from_definition() {
        let def = PlanDefinition::for_tier(PlanTier::Professional);
        let response: PlanDefinitionResponse = def.into();

        assert_eq!(response.tier, "professional");
        assert_eq!(response.display_name, "Professional");
        assert_eq!(response.tier_order, 2);
        assert_eq!(response.limits.max_mau, 25_000);
        assert_eq!(response.limits.max_api_calls, 500_000);
        assert_eq!(response.limits.max_agent_invocations, 10_000);
    }

    #[test]
    fn test_plans_list_response_serialization() {
        let response = PlansListResponse {
            plans: PlanDefinition::all()
                .into_iter()
                .map(PlanDefinitionResponse::from)
                .collect(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("free"));
        assert!(json.contains("starter"));
        assert!(json.contains("professional"));
        assert!(json.contains("enterprise"));
    }
}
