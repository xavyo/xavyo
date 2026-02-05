//! Detection rule service for configuring orphan detection rules.
//!
//! Provides CRUD operations and parameter validation for detection rules.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CreateGovDetectionRule, DetectionRuleFilter, DetectionRuleType, GovDetectionRule,
    UpdateGovDetectionRule,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    CreateDetectionRuleRequest, DetectionRuleListResponse, DetectionRuleResponse,
    ListDetectionRulesQuery, UpdateDetectionRuleRequest,
};

/// Service for detection rule configuration.
pub struct DetectionRuleService {
    pool: PgPool,
}

impl DetectionRuleService {
    /// Create a new detection rule service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool reference.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// List detection rules with filtering.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        query: &ListDetectionRulesQuery,
    ) -> Result<DetectionRuleListResponse> {
        let filter = DetectionRuleFilter {
            rule_type: query.rule_type,
            is_enabled: query.is_enabled,
        };

        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0);

        let rules = GovDetectionRule::list(&self.pool, tenant_id, &filter, limit, offset)
            .await
            .map_err(GovernanceError::Database)?;

        let total = GovDetectionRule::count(&self.pool, tenant_id, &filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(DetectionRuleListResponse {
            items: rules.into_iter().map(DetectionRuleResponse::from).collect(),
            total,
            limit,
            offset,
        })
    }

    /// Get a detection rule by ID.
    pub async fn get(&self, tenant_id: Uuid, rule_id: Uuid) -> Result<DetectionRuleResponse> {
        let rule = GovDetectionRule::find_by_id(&self.pool, tenant_id, rule_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::DetectionRuleNotFound(rule_id))?;

        Ok(DetectionRuleResponse::from(rule))
    }

    /// Create a new detection rule.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        request: CreateDetectionRuleRequest,
    ) -> Result<DetectionRuleResponse> {
        // Validate rule-specific parameters
        self.validate_parameters(&request.rule_type, request.parameters.as_ref())?;

        // Check for duplicate name
        if GovDetectionRule::find_by_name(&self.pool, tenant_id, &request.name)
            .await
            .map_err(GovernanceError::Database)?
            .is_some()
        {
            return Err(GovernanceError::DetectionRuleNameExists(request.name));
        }

        let input = CreateGovDetectionRule {
            name: request.name,
            rule_type: request.rule_type,
            is_enabled: Some(request.is_enabled),
            priority: Some(request.priority),
            parameters: request.parameters,
            description: request.description,
        };

        let rule = GovDetectionRule::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            rule_id = %rule.id,
            rule_type = ?rule.rule_type,
            "Detection rule created"
        );

        Ok(DetectionRuleResponse::from(rule))
    }

    /// Update a detection rule.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
        request: UpdateDetectionRuleRequest,
    ) -> Result<DetectionRuleResponse> {
        let existing = GovDetectionRule::find_by_id(&self.pool, tenant_id, rule_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::DetectionRuleNotFound(rule_id))?;

        // Validate parameters if being updated
        if let Some(ref params) = request.parameters {
            self.validate_parameters(&existing.rule_type, Some(params))?;
        }

        // Check for duplicate name if name is being changed
        if let Some(ref new_name) = request.name {
            if new_name != &existing.name
                && GovDetectionRule::find_by_name(&self.pool, tenant_id, new_name)
                    .await
                    .map_err(GovernanceError::Database)?
                    .is_some()
            {
                return Err(GovernanceError::DetectionRuleNameExists(new_name.clone()));
            }
        }

        let update = UpdateGovDetectionRule {
            name: request.name,
            is_enabled: request.is_enabled,
            priority: request.priority,
            parameters: request.parameters,
            description: request.description,
        };

        let updated = GovDetectionRule::update(&self.pool, tenant_id, rule_id, update)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::DetectionRuleNotFound(rule_id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            rule_id = %rule_id,
            "Detection rule updated"
        );

        Ok(DetectionRuleResponse::from(updated))
    }

    /// Delete a detection rule.
    pub async fn delete(&self, tenant_id: Uuid, rule_id: Uuid) -> Result<()> {
        let deleted = GovDetectionRule::delete(&self.pool, tenant_id, rule_id)
            .await
            .map_err(GovernanceError::Database)?;

        if !deleted {
            return Err(GovernanceError::DetectionRuleNotFound(rule_id));
        }

        tracing::info!(
            tenant_id = %tenant_id,
            rule_id = %rule_id,
            "Detection rule deleted"
        );

        Ok(())
    }

    /// Enable a detection rule.
    pub async fn enable(&self, tenant_id: Uuid, rule_id: Uuid) -> Result<DetectionRuleResponse> {
        let rule = GovDetectionRule::enable(&self.pool, tenant_id, rule_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::DetectionRuleNotFound(rule_id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            rule_id = %rule_id,
            "Detection rule enabled"
        );

        Ok(DetectionRuleResponse::from(rule))
    }

    /// Disable a detection rule.
    pub async fn disable(&self, tenant_id: Uuid, rule_id: Uuid) -> Result<DetectionRuleResponse> {
        let rule = GovDetectionRule::disable(&self.pool, tenant_id, rule_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::DetectionRuleNotFound(rule_id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            rule_id = %rule_id,
            "Detection rule disabled"
        );

        Ok(DetectionRuleResponse::from(rule))
    }

    /// Seed default detection rules for a tenant.
    pub async fn seed_defaults(&self, tenant_id: Uuid) -> Result<Vec<DetectionRuleResponse>> {
        let rules = GovDetectionRule::seed_defaults(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            count = rules.len(),
            "Default detection rules seeded"
        );

        Ok(rules.into_iter().map(DetectionRuleResponse::from).collect())
    }

    /// Validate rule-specific parameters.
    fn validate_parameters(
        &self,
        rule_type: &DetectionRuleType,
        parameters: Option<&serde_json::Value>,
    ) -> Result<()> {
        validate_rule_parameters(rule_type, parameters)
    }
}

/// Validate rule-specific parameters (standalone function for testability).
fn validate_rule_parameters(
    rule_type: &DetectionRuleType,
    parameters: Option<&serde_json::Value>,
) -> Result<()> {
    match rule_type {
        DetectionRuleType::Inactive => {
            // Inactivity rule requires days_threshold
            if let Some(params) = parameters {
                if let Some(days) = params.get("days_threshold") {
                    if let Some(days_num) = days.as_i64() {
                        if !(1..=365).contains(&days_num) {
                            return Err(GovernanceError::Validation(
                                "days_threshold must be between 1 and 365".to_string(),
                            ));
                        }
                    } else {
                        return Err(GovernanceError::Validation(
                            "days_threshold must be a number".to_string(),
                        ));
                    }
                }
            }
        }
        DetectionRuleType::Custom => {
            // Custom rules require an expression
            if let Some(params) = parameters {
                if params.get("expression").is_none() {
                    return Err(GovernanceError::Validation(
                        "Custom rules require an expression parameter".to_string(),
                    ));
                }
            } else {
                return Err(GovernanceError::Validation(
                    "Custom rules require parameters with an expression".to_string(),
                ));
            }
        }
        // NoManager and Terminated don't require special parameters
        DetectionRuleType::NoManager | DetectionRuleType::Terminated => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // =========================================================================
    // Inactive Rule Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_inactive_parameters_valid() {
        let params = json!({ "days_threshold": 30 });
        let result = validate_rule_parameters(&DetectionRuleType::Inactive, Some(&params));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_inactive_parameters_valid_min() {
        let params = json!({ "days_threshold": 1 });
        let result = validate_rule_parameters(&DetectionRuleType::Inactive, Some(&params));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_inactive_parameters_valid_max() {
        let params = json!({ "days_threshold": 365 });
        let result = validate_rule_parameters(&DetectionRuleType::Inactive, Some(&params));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_inactive_parameters_too_low() {
        let params = json!({ "days_threshold": 0 });
        let result = validate_rule_parameters(&DetectionRuleType::Inactive, Some(&params));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::Validation(_)
        ));
    }

    #[test]
    fn test_validate_inactive_parameters_too_high() {
        let params = json!({ "days_threshold": 366 });
        let result = validate_rule_parameters(&DetectionRuleType::Inactive, Some(&params));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::Validation(_)
        ));
    }

    #[test]
    fn test_validate_inactive_parameters_not_a_number() {
        let params = json!({ "days_threshold": "thirty" });
        let result = validate_rule_parameters(&DetectionRuleType::Inactive, Some(&params));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::Validation(_)
        ));
    }

    #[test]
    fn test_validate_inactive_parameters_no_threshold() {
        // No days_threshold is allowed (uses default)
        let params = json!({});
        let result = validate_rule_parameters(&DetectionRuleType::Inactive, Some(&params));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_inactive_parameters_none() {
        // None parameters is allowed (uses defaults)
        let result = validate_rule_parameters(&DetectionRuleType::Inactive, None);
        assert!(result.is_ok());
    }

    // =========================================================================
    // Custom Rule Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_custom_parameters_valid() {
        let params = json!({ "expression": "user.department == 'IT'" });
        let result = validate_rule_parameters(&DetectionRuleType::Custom, Some(&params));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_custom_parameters_missing_expression() {
        let params = json!({ "other_field": "value" });
        let result = validate_rule_parameters(&DetectionRuleType::Custom, Some(&params));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, GovernanceError::Validation(msg) if msg.contains("expression")));
    }

    #[test]
    fn test_validate_custom_parameters_none() {
        let result = validate_rule_parameters(&DetectionRuleType::Custom, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, GovernanceError::Validation(msg) if msg.contains("expression")));
    }

    // =========================================================================
    // NoManager and Terminated Rule Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_no_manager_parameters_none() {
        let result = validate_rule_parameters(&DetectionRuleType::NoManager, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_no_manager_parameters_with_extra() {
        let params = json!({ "extra": "ignored" });
        let result = validate_rule_parameters(&DetectionRuleType::NoManager, Some(&params));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_terminated_parameters_none() {
        let result = validate_rule_parameters(&DetectionRuleType::Terminated, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_terminated_parameters_with_extra() {
        let params = json!({ "extra": "ignored" });
        let result = validate_rule_parameters(&DetectionRuleType::Terminated, Some(&params));
        assert!(result.is_ok());
    }
}
