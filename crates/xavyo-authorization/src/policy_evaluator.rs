//! Policy evaluator for the authorization engine.
//!
//! Evaluates authorization policies against an authorization request.
//! Policies are evaluated in priority order (deny-first). A policy
//! matches when its `resource_type`, action, and all conditions are satisfied.

use uuid::Uuid;

use crate::types::{
    AuthorizationRequest, ConditionData, PolicyEffect, PolicyWithConditions, ResolvedEntitlement,
};

/// Evaluates authorization policies.
pub struct PolicyEvaluator;

impl PolicyEvaluator {
    /// Evaluate policies in priority order.
    ///
    /// Returns the first matching policy's effect and ID.
    ///
    /// A policy matches if:
    /// - Its `resource_type` is None (wildcard) or matches the request
    /// - Its `action` is None (wildcard) or matches the request
    /// - All its conditions are satisfied (AND-combined)
    ///
    /// Policies are assumed to be pre-sorted (deny-first, then by priority ascending).
    #[must_use]
    pub fn evaluate_policies(
        policies: &[PolicyWithConditions],
        request: &AuthorizationRequest,
        user_attributes: Option<&serde_json::Value>,
        user_entitlements: Option<&[ResolvedEntitlement]>,
    ) -> Option<(PolicyEffect, Uuid)> {
        for policy in policies {
            // Check resource_type match (None = wildcard)
            if let Some(ref rt) = policy.resource_type {
                if rt != &request.resource_type {
                    continue;
                }
            }

            // Check action match (None = wildcard)
            if let Some(ref a) = policy.action {
                if a != &request.action {
                    continue;
                }
            }

            // Check all conditions (AND-combined)
            let all_conditions_match = policy
                .conditions
                .iter()
                .all(|c| Self::evaluate_condition(c, request, user_attributes, user_entitlements));

            if all_conditions_match {
                let effect = PolicyEffect::from_effect_str(&policy.effect);
                return Some((effect, policy.id));
            }
        }

        None
    }

    /// Evaluate a single condition.
    fn evaluate_condition(
        condition: &ConditionData,
        _request: &AuthorizationRequest,
        user_attributes: Option<&serde_json::Value>,
        user_entitlements: Option<&[ResolvedEntitlement]>,
    ) -> bool {
        match condition.condition_type.as_str() {
            "time_window" => Self::evaluate_time_window(&condition.value),
            "user_attribute" => {
                if let (Some(path), Some(op), Some(attrs)) = (
                    &condition.attribute_path,
                    &condition.operator,
                    user_attributes,
                ) {
                    crate::abac::evaluate_abac_condition(attrs, path, op, &condition.value)
                } else {
                    false // Missing data = condition not satisfied (fail-safe)
                }
            }
            "entitlement_check" => {
                Self::evaluate_entitlement_check(&condition.value, user_entitlements)
            }
            _ => false, // Unknown condition type = not satisfied
        }
    }

    /// Evaluate an `entitlement_check` condition.
    ///
    /// Checks if the user has a specific entitlement by ID.
    /// Expected value format: `{"entitlement_id": "uuid-string"}`
    fn evaluate_entitlement_check(
        value: &serde_json::Value,
        user_entitlements: Option<&[ResolvedEntitlement]>,
    ) -> bool {
        let entitlements = match user_entitlements {
            Some(e) => e,
            None => return false, // No entitlement data = fail-safe
        };

        let required_id = match value
            .get("entitlement_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
        {
            Some(id) => id,
            None => return false, // Invalid/missing entitlement_id = fail-safe
        };

        entitlements.iter().any(|e| e.entitlement_id == required_id)
    }

    /// Evaluate a `time_window` condition.
    ///
    /// Checks if the current UTC time is within the specified window.
    /// Expected value format: `{"start_time": "09:00", "end_time": "17:00"}`
    fn evaluate_time_window(value: &serde_json::Value) -> bool {
        let now = chrono::Utc::now();
        let current_time = now.format("%H:%M").to_string();

        let start = value
            .get("start_time")
            .and_then(|v| v.as_str())
            .unwrap_or("00:00");
        let end = value
            .get("end_time")
            .and_then(|v| v.as_str())
            .unwrap_or("23:59");

        current_time.as_str() >= start && current_time.as_str() <= end
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_request(action: &str, resource_type: &str) -> AuthorizationRequest {
        AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: action.to_string(),
            resource_type: resource_type.to_string(),
            resource_id: None,
            delegation: None,
        }
    }

    fn make_policy(
        effect: &str,
        priority: i32,
        resource_type: Option<&str>,
        action: Option<&str>,
        conditions: Vec<ConditionData>,
    ) -> PolicyWithConditions {
        PolicyWithConditions {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: format!("test-policy-{}", priority),
            effect: effect.to_string(),
            priority,
            status: "active".to_string(),
            resource_type: resource_type.map(|s| s.to_string()),
            action: action.map(|s| s.to_string()),
            conditions,
        }
    }

    #[test]
    fn test_wildcard_policy_matches_all() {
        let policies = vec![make_policy("allow", 100, None, None, vec![])];
        let request = make_request("read", "document");

        let result = PolicyEvaluator::evaluate_policies(&policies, &request, None, None);
        assert!(result.is_some());
        let (effect, _) = result.unwrap();
        assert_eq!(effect, PolicyEffect::Allow);
    }

    #[test]
    fn test_resource_type_mismatch_skips_policy() {
        let policies = vec![make_policy("allow", 100, Some("project"), None, vec![])];
        let request = make_request("read", "document");

        let result = PolicyEvaluator::evaluate_policies(&policies, &request, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_action_mismatch_skips_policy() {
        let policies = vec![make_policy("allow", 100, None, Some("write"), vec![])];
        let request = make_request("read", "document");

        let result = PolicyEvaluator::evaluate_policies(&policies, &request, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_exact_match() {
        let policies = vec![make_policy(
            "allow",
            100,
            Some("document"),
            Some("read"),
            vec![],
        )];
        let request = make_request("read", "document");

        let result = PolicyEvaluator::evaluate_policies(&policies, &request, None, None);
        assert!(result.is_some());
        let (effect, _) = result.unwrap();
        assert_eq!(effect, PolicyEffect::Allow);
    }

    #[test]
    fn test_deny_policy_returns_deny() {
        let policies = vec![make_policy(
            "deny",
            10,
            Some("document"),
            Some("delete"),
            vec![],
        )];
        let request = make_request("delete", "document");

        let result = PolicyEvaluator::evaluate_policies(&policies, &request, None, None);
        assert!(result.is_some());
        let (effect, _) = result.unwrap();
        assert_eq!(effect, PolicyEffect::Deny);
    }

    #[test]
    fn test_first_matching_policy_wins() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let policies = vec![
            PolicyWithConditions {
                id: id1,
                tenant_id: Uuid::new_v4(),
                name: "deny-first".to_string(),
                effect: "deny".to_string(),
                priority: 10,
                status: "active".to_string(),
                resource_type: None,
                action: None,
                conditions: vec![],
            },
            PolicyWithConditions {
                id: id2,
                tenant_id: Uuid::new_v4(),
                name: "allow-second".to_string(),
                effect: "allow".to_string(),
                priority: 100,
                status: "active".to_string(),
                resource_type: None,
                action: None,
                conditions: vec![],
            },
        ];
        let request = make_request("read", "document");

        let result = PolicyEvaluator::evaluate_policies(&policies, &request, None, None);
        assert!(result.is_some());
        let (effect, pid) = result.unwrap();
        assert_eq!(effect, PolicyEffect::Deny);
        assert_eq!(pid, id1);
    }

    #[test]
    fn test_user_attribute_condition() {
        let condition = ConditionData {
            id: Uuid::new_v4(),
            condition_type: "user_attribute".to_string(),
            attribute_path: Some("department".to_string()),
            operator: Some("equals".to_string()),
            value: json!("engineering"),
        };
        let policies = vec![make_policy("allow", 100, None, None, vec![condition])];
        let request = make_request("read", "document");

        // Matching attributes
        let attrs = json!({"department": "engineering"});
        let result = PolicyEvaluator::evaluate_policies(&policies, &request, Some(&attrs), None);
        assert!(result.is_some());

        // Non-matching attributes
        let attrs = json!({"department": "marketing"});
        let result = PolicyEvaluator::evaluate_policies(&policies, &request, Some(&attrs), None);
        assert!(result.is_none());

        // Missing attributes
        let result = PolicyEvaluator::evaluate_policies(&policies, &request, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_empty_policies_returns_none() {
        let request = make_request("read", "document");
        let result = PolicyEvaluator::evaluate_policies(&[], &request, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_multiple_conditions_and_combined() {
        let conditions = vec![
            ConditionData {
                id: Uuid::new_v4(),
                condition_type: "user_attribute".to_string(),
                attribute_path: Some("department".to_string()),
                operator: Some("equals".to_string()),
                value: json!("engineering"),
            },
            ConditionData {
                id: Uuid::new_v4(),
                condition_type: "user_attribute".to_string(),
                attribute_path: Some("level".to_string()),
                operator: Some("greater_than".to_string()),
                value: json!(5),
            },
        ];
        let policies = vec![make_policy("allow", 100, None, None, conditions)];
        let request = make_request("read", "document");

        // Both conditions satisfied
        let attrs = json!({"department": "engineering", "level": 7});
        let result = PolicyEvaluator::evaluate_policies(&policies, &request, Some(&attrs), None);
        assert!(result.is_some());

        // Only first condition satisfied
        let attrs = json!({"department": "engineering", "level": 3});
        let result = PolicyEvaluator::evaluate_policies(&policies, &request, Some(&attrs), None);
        assert!(result.is_none());

        // Only second condition satisfied
        let attrs = json!({"department": "marketing", "level": 7});
        let result = PolicyEvaluator::evaluate_policies(&policies, &request, Some(&attrs), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_time_window_always_includes_midnight_to_2359() {
        // A window from 00:00 to 23:59 should always match
        let value = json!({"start_time": "00:00", "end_time": "23:59"});
        assert!(PolicyEvaluator::evaluate_time_window(&value));
    }

    #[test]
    fn test_time_window_defaults() {
        // Empty value should use defaults 00:00 - 23:59
        let value = json!({});
        assert!(PolicyEvaluator::evaluate_time_window(&value));
    }

    #[test]
    fn test_unknown_condition_type_returns_false() {
        let condition = ConditionData {
            id: Uuid::new_v4(),
            condition_type: "unknown_type".to_string(),
            attribute_path: None,
            operator: None,
            value: json!({}),
        };
        let policies = vec![make_policy("allow", 100, None, None, vec![condition])];
        let request = make_request("read", "document");

        let result = PolicyEvaluator::evaluate_policies(&policies, &request, None, None);
        assert!(result.is_none());
    }
}
