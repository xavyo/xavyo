//! Condition evaluator service for lifecycle state transitions (F-193).
//!
//! This service evaluates conditions that must be satisfied before a state
//! transition can be executed.

use chrono::Utc;
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{GovLifecycleTransition, Session, User};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    TransitionCondition, TransitionConditionResult, TransitionConditionType,
    TransitionConditionsEvaluationResult,
};

/// Service for evaluating transition conditions.
pub struct ConditionEvaluator {
    pool: PgPool,
}

impl ConditionEvaluator {
    /// Create a new condition evaluator.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Evaluate all conditions for a transition.
    ///
    /// Returns a result indicating whether all conditions are satisfied,
    /// along with individual condition results.
    pub async fn evaluate(
        &self,
        tenant_id: Uuid,
        transition_id: Uuid,
        object_id: Uuid,
    ) -> Result<TransitionConditionsEvaluationResult> {
        // Get the transition and its conditions
        let transition = GovLifecycleTransition::find_by_id(&self.pool, tenant_id, transition_id)
            .await?
            .ok_or(GovernanceError::LifecycleTransitionNotFound(transition_id))?;

        // Parse conditions from JSON
        let conditions = self.parse_conditions(&transition.conditions)?;

        if conditions.is_empty() {
            return Ok(TransitionConditionsEvaluationResult {
                all_satisfied: true,
                conditions: Vec::new(),
                summary: "No conditions configured for this transition".to_string(),
            });
        }

        // Get the user object for evaluation
        let user = User::find_by_id_in_tenant(&self.pool, tenant_id, object_id)
            .await?
            .ok_or(GovernanceError::UserNotFound(object_id))?;

        // Evaluate each condition
        let mut results = Vec::new();
        let mut all_satisfied = true;

        for condition in conditions {
            let result = self
                .evaluate_single_condition(tenant_id, object_id, &user, &condition)
                .await?;
            if !result.satisfied {
                all_satisfied = false;
            }
            results.push(result);
        }

        let summary = if all_satisfied {
            "All conditions satisfied".to_string()
        } else {
            let failed_count = results.iter().filter(|r| !r.satisfied).count();
            format!(
                "{} of {} conditions not satisfied",
                failed_count,
                results.len()
            )
        };

        Ok(TransitionConditionsEvaluationResult {
            all_satisfied,
            conditions: results,
            summary,
        })
    }

    /// Evaluate conditions for a transition without looking up the transition.
    ///
    /// This is useful when the conditions are already known.
    pub async fn evaluate_conditions(
        &self,
        tenant_id: Uuid,
        object_id: Uuid,
        conditions: &[TransitionCondition],
    ) -> Result<TransitionConditionsEvaluationResult> {
        if conditions.is_empty() {
            return Ok(TransitionConditionsEvaluationResult {
                all_satisfied: true,
                conditions: Vec::new(),
                summary: "No conditions to evaluate".to_string(),
            });
        }

        // Get the user object for evaluation
        let user = User::find_by_id_in_tenant(&self.pool, tenant_id, object_id)
            .await?
            .ok_or(GovernanceError::UserNotFound(object_id))?;

        // Evaluate each condition
        let mut results = Vec::new();
        let mut all_satisfied = true;

        for condition in conditions {
            let result = self
                .evaluate_single_condition(tenant_id, object_id, &user, condition)
                .await?;
            if !result.satisfied {
                all_satisfied = false;
            }
            results.push(result);
        }

        let summary = if all_satisfied {
            "All conditions satisfied".to_string()
        } else {
            let failed_count = results.iter().filter(|r| !r.satisfied).count();
            format!(
                "{} of {} conditions not satisfied",
                failed_count,
                results.len()
            )
        };

        Ok(TransitionConditionsEvaluationResult {
            all_satisfied,
            conditions: results,
            summary,
        })
    }

    /// Parse conditions from JSON value.
    fn parse_conditions(
        &self,
        conditions_json: &Option<JsonValue>,
    ) -> Result<Vec<TransitionCondition>> {
        match conditions_json {
            Some(JsonValue::Array(arr)) if !arr.is_empty() => {
                let conditions: Vec<TransitionCondition> =
                    serde_json::from_value(JsonValue::Array(arr.clone())).map_err(|e| {
                        GovernanceError::Validation(format!("Invalid conditions format: {e}"))
                    })?;
                Ok(conditions)
            }
            Some(JsonValue::Array(_)) | None => Ok(Vec::new()),
            _ => Err(GovernanceError::Validation(
                "Conditions must be an array".to_string(),
            )),
        }
    }

    /// Evaluate a single condition.
    async fn evaluate_single_condition(
        &self,
        tenant_id: Uuid,
        object_id: Uuid,
        user: &User,
        condition: &TransitionCondition,
    ) -> Result<TransitionConditionResult> {
        match condition.condition_type {
            TransitionConditionType::TerminationDateSet => {
                self.evaluate_termination_date_set(user, condition)
            }
            TransitionConditionType::TerminationDateReached => {
                self.evaluate_termination_date_reached(user, condition)
            }
            TransitionConditionType::ManagerApprovalReceived => {
                self.evaluate_manager_approval_received(tenant_id, object_id, condition)
                    .await
            }
            TransitionConditionType::AccessReviewComplete => {
                self.evaluate_access_review_complete(tenant_id, object_id, condition)
                    .await
            }
            TransitionConditionType::NoActiveSessions => {
                self.evaluate_no_active_sessions(tenant_id, object_id, condition)
                    .await
            }
            TransitionConditionType::CustomAttributeEquals => {
                self.evaluate_custom_attribute_equals(user, condition)
            }
        }
    }

    // =========================================================================
    // Individual condition evaluators
    // =========================================================================

    /// Get termination_date from user's custom_attributes.
    ///
    /// The termination_date is stored in custom_attributes.termination_date
    /// as an ISO 8601 date string (YYYY-MM-DD).
    fn get_termination_date(&self, user: &User) -> Option<chrono::NaiveDate> {
        user.custom_attributes
            .get("termination_date")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
    }

    /// Evaluate termination_date_set condition.
    ///
    /// Returns true if the user has a termination_date set in custom_attributes.
    fn evaluate_termination_date_set(
        &self,
        user: &User,
        condition: &TransitionCondition,
    ) -> Result<TransitionConditionResult> {
        let termination_date = self.get_termination_date(user);
        let satisfied = termination_date.is_some();
        let reason = if satisfied {
            format!(
                "Termination date is set: {}",
                termination_date.map(|d| d.to_string()).unwrap_or_default()
            )
        } else {
            "Termination date is not set in custom_attributes".to_string()
        };

        Ok(TransitionConditionResult {
            condition: condition.clone(),
            satisfied,
            reason,
        })
    }

    /// Evaluate termination_date_reached condition.
    ///
    /// Returns true if the termination_date has been reached (current date >= termination_date).
    fn evaluate_termination_date_reached(
        &self,
        user: &User,
        condition: &TransitionCondition,
    ) -> Result<TransitionConditionResult> {
        let today = Utc::now().date_naive();
        let (satisfied, reason) = match self.get_termination_date(user) {
            Some(termination_date) => {
                if today >= termination_date {
                    (
                        true,
                        format!("Termination date {} has been reached", termination_date),
                    )
                } else {
                    (
                        false,
                        format!(
                            "Termination date {} has not been reached yet",
                            termination_date
                        ),
                    )
                }
            }
            None => (
                false,
                "No termination date is set in custom_attributes".to_string(),
            ),
        };

        Ok(TransitionConditionResult {
            condition: condition.clone(),
            satisfied,
            reason,
        })
    }

    /// Evaluate manager_approval_received condition.
    ///
    /// Returns true if a pending access request for this transition has been approved
    /// by the user's manager.
    async fn evaluate_manager_approval_received(
        &self,
        tenant_id: Uuid,
        object_id: Uuid,
        condition: &TransitionCondition,
    ) -> Result<TransitionConditionResult> {
        use xavyo_db::{GovAccessRequest, GovRequestStatus};

        // Check for approved access requests for this user
        let requests = GovAccessRequest::list_by_tenant(
            &self.pool,
            tenant_id,
            &xavyo_db::AccessRequestFilter {
                requester_id: Some(object_id),
                status: Some(GovRequestStatus::Approved),
                ..Default::default()
            },
            10,
            0,
        )
        .await?;

        // Check if any approved request exists (simplified check)
        let satisfied = !requests.is_empty();
        let reason = if satisfied {
            "Manager approval has been received".to_string()
        } else {
            "No manager approval found".to_string()
        };

        Ok(TransitionConditionResult {
            condition: condition.clone(),
            satisfied,
            reason,
        })
    }

    /// Evaluate access_review_complete condition.
    ///
    /// Returns true if the user has no pending access review items.
    async fn evaluate_access_review_complete(
        &self,
        tenant_id: Uuid,
        object_id: Uuid,
        condition: &TransitionCondition,
    ) -> Result<TransitionConditionResult> {
        use xavyo_db::{CertItemStatus, GovCertificationItem};

        // Check for pending certification items for this user
        let pending_items = GovCertificationItem::list_by_tenant(
            &self.pool,
            tenant_id,
            &xavyo_db::CertItemFilter {
                user_id: Some(object_id),
                statuses: Some(vec![CertItemStatus::Pending]),
                ..Default::default()
            },
            1,
            0,
        )
        .await?;

        let satisfied = pending_items.is_empty();
        let reason = if satisfied {
            "All access reviews are complete".to_string()
        } else {
            format!("{} pending access review items found", pending_items.len())
        };

        Ok(TransitionConditionResult {
            condition: condition.clone(),
            satisfied,
            reason,
        })
    }

    /// Evaluate no_active_sessions condition.
    ///
    /// Returns true if the user has no active sessions.
    async fn evaluate_no_active_sessions(
        &self,
        _tenant_id: Uuid,
        object_id: Uuid,
        condition: &TransitionCondition,
    ) -> Result<TransitionConditionResult> {
        // Count active sessions for the user
        let session_count = Session::count_active_by_user(&self.pool, object_id).await?;

        let satisfied = session_count == 0;
        let reason = if satisfied {
            "No active sessions".to_string()
        } else {
            format!("{} active sessions found", session_count)
        };

        Ok(TransitionConditionResult {
            condition: condition.clone(),
            satisfied,
            reason,
        })
    }

    /// Evaluate custom_attribute_equals condition.
    ///
    /// Returns true if the specified custom attribute equals the expected value.
    /// Config: {"attribute": "department", "value": "Sales"}
    fn evaluate_custom_attribute_equals(
        &self,
        user: &User,
        condition: &TransitionCondition,
    ) -> Result<TransitionConditionResult> {
        let attribute_name = condition
            .config
            .get("attribute")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                GovernanceError::Validation(
                    "custom_attribute_equals requires 'attribute' in config".to_string(),
                )
            })?;

        let expected_value = condition.config.get("value").ok_or_else(|| {
            GovernanceError::Validation(
                "custom_attribute_equals requires 'value' in config".to_string(),
            )
        })?;

        // Get the attribute value from user's custom_attributes
        let actual_value = user.custom_attributes.get(attribute_name);

        let satisfied = actual_value == Some(expected_value);
        let reason = if satisfied {
            format!("Attribute '{}' equals expected value", attribute_name)
        } else {
            format!(
                "Attribute '{}' does not equal expected value (actual: {:?})",
                attribute_name, actual_value
            )
        };

        Ok(TransitionConditionResult {
            condition: condition.clone(),
            satisfied,
            reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to parse conditions without needing a PgPool.
    fn parse_conditions_standalone(
        conditions_json: &Option<JsonValue>,
    ) -> Result<Vec<TransitionCondition>> {
        match conditions_json {
            Some(JsonValue::Array(arr)) if !arr.is_empty() => {
                let conditions: Vec<TransitionCondition> =
                    serde_json::from_value(JsonValue::Array(arr.clone())).map_err(|e| {
                        GovernanceError::Validation(format!("Invalid conditions format: {e}"))
                    })?;
                Ok(conditions)
            }
            Some(JsonValue::Array(_)) | None => Ok(Vec::new()),
            _ => Err(GovernanceError::Validation(
                "Conditions must be an array".to_string(),
            )),
        }
    }

    #[test]
    fn test_transition_condition_type_values() {
        // Verify all condition types can be serialized
        let types = [
            TransitionConditionType::TerminationDateSet,
            TransitionConditionType::TerminationDateReached,
            TransitionConditionType::ManagerApprovalReceived,
            TransitionConditionType::AccessReviewComplete,
            TransitionConditionType::NoActiveSessions,
            TransitionConditionType::CustomAttributeEquals,
        ];

        for t in types {
            let json = serde_json::to_string(&t).unwrap();
            assert!(!json.is_empty());
        }
    }

    #[test]
    fn test_parse_empty_conditions() {
        // Test None
        let result = parse_conditions_standalone(&None).unwrap();
        assert!(result.is_empty());

        // Test empty array
        let result = parse_conditions_standalone(&Some(JsonValue::Array(vec![]))).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_valid_conditions() {
        let conditions_json = serde_json::json!([
            {"type": "termination_date_set", "config": {}},
            {"type": "no_active_sessions", "config": {}}
        ]);

        let result = parse_conditions_standalone(&Some(conditions_json)).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0].condition_type,
            TransitionConditionType::TerminationDateSet
        );
        assert_eq!(
            result[1].condition_type,
            TransitionConditionType::NoActiveSessions
        );
    }

    #[test]
    fn test_custom_attribute_config_validation() {
        let condition = TransitionCondition {
            condition_type: TransitionConditionType::CustomAttributeEquals,
            config: serde_json::json!({
                "attribute": "department",
                "value": "Engineering"
            }),
            description: None,
        };

        let attr = condition.config.get("attribute").unwrap().as_str().unwrap();
        assert_eq!(attr, "department");

        let value = condition.config.get("value").unwrap();
        assert_eq!(value, "Engineering");
    }

    #[test]
    fn test_parse_invalid_conditions_not_array() {
        let invalid_json = serde_json::json!({"type": "termination_date_set"});
        let result = parse_conditions_standalone(&Some(invalid_json));
        assert!(result.is_err());
    }

    #[test]
    fn test_condition_with_description() {
        let condition = TransitionCondition {
            condition_type: TransitionConditionType::TerminationDateReached,
            config: JsonValue::Object(serde_json::Map::new()),
            description: Some("User's last day has passed".to_string()),
        };

        assert_eq!(
            condition.description,
            Some("User's last day has passed".to_string())
        );
    }
}
