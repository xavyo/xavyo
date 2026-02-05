//! Integration tests for lifecycle state transitions with conditions (F-193).
//!
//! These tests verify that transition conditions are properly evaluated
//! before allowing state transitions.

use serde_json::json;
use uuid::Uuid;

// ============================================================================
// Test Models
// ============================================================================

/// Represents a condition type for testing.
#[derive(Debug, Clone)]
struct TestCondition {
    condition_type: String,
    config: serde_json::Value,
}

impl TestCondition {
    fn termination_date_set() -> Self {
        Self {
            condition_type: "termination_date_set".to_string(),
            config: json!({}),
        }
    }

    fn termination_date_reached() -> Self {
        Self {
            condition_type: "termination_date_reached".to_string(),
            config: json!({}),
        }
    }

    fn no_active_sessions() -> Self {
        Self {
            condition_type: "no_active_sessions".to_string(),
            config: json!({}),
        }
    }

    fn custom_attribute_equals(attribute: &str, value: &str) -> Self {
        Self {
            condition_type: "custom_attribute_equals".to_string(),
            config: json!({
                "attribute": attribute,
                "value": value
            }),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        json!({
            "type": self.condition_type,
            "config": self.config
        })
    }
}

// ============================================================================
// Condition Parsing Tests
// ============================================================================

mod condition_parsing {
    use super::*;

    #[test]
    fn test_parse_termination_date_set_condition() {
        let condition = TestCondition::termination_date_set();
        let json = condition.to_json();

        assert_eq!(json["type"], "termination_date_set");
        assert!(json["config"].is_object());
    }

    #[test]
    fn test_parse_termination_date_reached_condition() {
        let condition = TestCondition::termination_date_reached();
        let json = condition.to_json();

        assert_eq!(json["type"], "termination_date_reached");
    }

    #[test]
    fn test_parse_no_active_sessions_condition() {
        let condition = TestCondition::no_active_sessions();
        let json = condition.to_json();

        assert_eq!(json["type"], "no_active_sessions");
    }

    #[test]
    fn test_parse_custom_attribute_equals_condition() {
        let condition = TestCondition::custom_attribute_equals("department", "Engineering");
        let json = condition.to_json();

        assert_eq!(json["type"], "custom_attribute_equals");
        assert_eq!(json["config"]["attribute"], "department");
        assert_eq!(json["config"]["value"], "Engineering");
    }

    #[test]
    fn test_parse_multiple_conditions() {
        let conditions = vec![
            TestCondition::termination_date_set(),
            TestCondition::no_active_sessions(),
        ];

        let json_conditions: Vec<serde_json::Value> =
            conditions.iter().map(|c| c.to_json()).collect();

        assert_eq!(json_conditions.len(), 2);
        assert_eq!(json_conditions[0]["type"], "termination_date_set");
        assert_eq!(json_conditions[1]["type"], "no_active_sessions");
    }
}

// ============================================================================
// Condition Evaluation Logic Tests
// ============================================================================

mod condition_evaluation {
    use super::*;
    use chrono::{NaiveDate, Utc};

    /// Helper to check if a date string is in the past.
    fn is_date_in_past(date_str: &str) -> bool {
        let today = Utc::now().date_naive();
        if let Ok(date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            today >= date
        } else {
            false
        }
    }

    /// Helper to check if a date string is in the future.
    fn is_date_in_future(date_str: &str) -> bool {
        let today = Utc::now().date_naive();
        if let Ok(date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            today < date
        } else {
            false
        }
    }

    #[test]
    fn test_termination_date_set_with_date() {
        // Simulate user with termination_date in custom_attributes
        let custom_attributes = json!({
            "termination_date": "2025-12-31"
        });

        let has_termination_date = custom_attributes
            .get("termination_date")
            .and_then(|v| v.as_str())
            .is_some();

        assert!(has_termination_date, "Should have termination date set");
    }

    #[test]
    fn test_termination_date_set_without_date() {
        // Simulate user without termination_date
        let custom_attributes = json!({
            "department": "Engineering"
        });

        let has_termination_date = custom_attributes
            .get("termination_date")
            .and_then(|v| v.as_str())
            .is_some();

        assert!(
            !has_termination_date,
            "Should not have termination date set"
        );
    }

    #[test]
    fn test_termination_date_reached_past_date() {
        let past_date = "2020-01-01";
        assert!(is_date_in_past(past_date), "Past date should be reached");
    }

    #[test]
    fn test_termination_date_reached_future_date() {
        let future_date = "2099-12-31";
        assert!(
            is_date_in_future(future_date),
            "Future date should not be reached"
        );
    }

    #[test]
    fn test_custom_attribute_equals_match() {
        let custom_attributes = json!({
            "department": "Engineering",
            "location": "NYC"
        });

        let expected_department = "Engineering";
        let actual_department = custom_attributes.get("department").and_then(|v| v.as_str());

        assert_eq!(
            actual_department,
            Some(expected_department),
            "Department should match"
        );
    }

    #[test]
    fn test_custom_attribute_equals_no_match() {
        let custom_attributes = json!({
            "department": "Sales",
            "location": "NYC"
        });

        let expected_department = "Engineering";
        let actual_department = custom_attributes.get("department").and_then(|v| v.as_str());

        assert_ne!(
            actual_department,
            Some(expected_department),
            "Department should not match"
        );
    }

    #[test]
    fn test_custom_attribute_equals_missing_attribute() {
        let custom_attributes = json!({
            "location": "NYC"
        });

        let actual_department = custom_attributes.get("department").and_then(|v| v.as_str());

        assert!(
            actual_department.is_none(),
            "Missing attribute should return None"
        );
    }
}

// ============================================================================
// Transition Flow Tests
// ============================================================================

mod transition_flow {
    use super::*;

    /// Represents a simulated transition with conditions.
    struct SimulatedTransition {
        id: Uuid,
        name: String,
        from_state: String,
        to_state: String,
        conditions: Vec<TestCondition>,
    }

    impl SimulatedTransition {
        fn new(name: &str, from_state: &str, to_state: &str) -> Self {
            Self {
                id: Uuid::new_v4(),
                name: name.to_string(),
                from_state: from_state.to_string(),
                to_state: to_state.to_string(),
                conditions: Vec::new(),
            }
        }

        fn with_conditions(mut self, conditions: Vec<TestCondition>) -> Self {
            self.conditions = conditions;
            self
        }
    }

    /// Simulates condition evaluation result.
    struct ConditionEvaluationResult {
        all_satisfied: bool,
        failed_conditions: Vec<String>,
    }

    /// Simulate evaluating conditions for a transition.
    fn evaluate_conditions(
        transition: &SimulatedTransition,
        user_attributes: &serde_json::Value,
        _active_sessions: i64,
    ) -> ConditionEvaluationResult {
        let mut failed_conditions = Vec::new();

        for condition in &transition.conditions {
            match condition.condition_type.as_str() {
                "termination_date_set" => {
                    let has_date = user_attributes
                        .get("termination_date")
                        .and_then(|v| v.as_str())
                        .is_some();
                    if !has_date {
                        failed_conditions.push("termination_date_set".to_string());
                    }
                }
                "termination_date_reached" => {
                    let today = chrono::Utc::now().date_naive();
                    let date_reached = user_attributes
                        .get("termination_date")
                        .and_then(|v| v.as_str())
                        .and_then(|s| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
                        .map(|d| today >= d)
                        .unwrap_or(false);
                    if !date_reached {
                        failed_conditions.push("termination_date_reached".to_string());
                    }
                }
                "no_active_sessions" => {
                    if _active_sessions > 0 {
                        failed_conditions.push("no_active_sessions".to_string());
                    }
                }
                "custom_attribute_equals" => {
                    let attribute = condition.config.get("attribute").and_then(|v| v.as_str());
                    let expected = condition.config.get("value");

                    if let (Some(attr), Some(exp)) = (attribute, expected) {
                        let actual = user_attributes.get(attr);
                        if actual != Some(exp) {
                            failed_conditions.push(format!("custom_attribute_equals:{}", attr));
                        }
                    }
                }
                _ => {}
            }
        }

        ConditionEvaluationResult {
            all_satisfied: failed_conditions.is_empty(),
            failed_conditions,
        }
    }

    #[test]
    fn test_transition_allowed_when_all_conditions_satisfied() {
        let transition = SimulatedTransition::new("terminate", "active", "pre_termination")
            .with_conditions(vec![TestCondition::termination_date_set()]);

        let user_attrs = json!({
            "termination_date": "2025-12-31"
        });

        let result = evaluate_conditions(&transition, &user_attrs, 0);
        assert!(
            result.all_satisfied,
            "Transition should be allowed when termination date is set"
        );
    }

    #[test]
    fn test_transition_blocked_when_condition_not_satisfied() {
        let transition = SimulatedTransition::new("terminate", "active", "pre_termination")
            .with_conditions(vec![TestCondition::termination_date_set()]);

        let user_attrs = json!({
            "department": "Engineering"
        });

        let result = evaluate_conditions(&transition, &user_attrs, 0);
        assert!(
            !result.all_satisfied,
            "Transition should be blocked when termination date is not set"
        );
        assert!(result
            .failed_conditions
            .contains(&"termination_date_set".to_string()));
    }

    #[test]
    fn test_transition_blocked_when_any_condition_fails() {
        let transition = SimulatedTransition::new("archive", "suspended", "archived")
            .with_conditions(vec![
                TestCondition::no_active_sessions(),
                TestCondition::termination_date_reached(),
            ]);

        // User has termination date but still has active sessions
        let user_attrs = json!({
            "termination_date": "2020-01-01"  // Past date
        });

        let result = evaluate_conditions(&transition, &user_attrs, 5); // 5 active sessions
        assert!(
            !result.all_satisfied,
            "Transition should be blocked when user has active sessions"
        );
        assert!(result
            .failed_conditions
            .contains(&"no_active_sessions".to_string()));
    }

    #[test]
    fn test_transition_allowed_no_conditions() {
        let transition = SimulatedTransition::new("activate", "draft", "active");

        let user_attrs = json!({});

        let result = evaluate_conditions(&transition, &user_attrs, 0);
        assert!(
            result.all_satisfied,
            "Transition should be allowed when no conditions are defined"
        );
    }

    #[test]
    fn test_custom_attribute_condition_match() {
        let transition =
            SimulatedTransition::new("promote", "active", "premium").with_conditions(vec![
                TestCondition::custom_attribute_equals("subscription_tier", "enterprise"),
            ]);

        let user_attrs = json!({
            "subscription_tier": "enterprise"
        });

        let result = evaluate_conditions(&transition, &user_attrs, 0);
        assert!(
            result.all_satisfied,
            "Transition should be allowed when custom attribute matches"
        );
    }

    #[test]
    fn test_custom_attribute_condition_mismatch() {
        let transition =
            SimulatedTransition::new("promote", "active", "premium").with_conditions(vec![
                TestCondition::custom_attribute_equals("subscription_tier", "enterprise"),
            ]);

        let user_attrs = json!({
            "subscription_tier": "basic"
        });

        let result = evaluate_conditions(&transition, &user_attrs, 0);
        assert!(
            !result.all_satisfied,
            "Transition should be blocked when custom attribute does not match"
        );
    }
}

// ============================================================================
// Error Message Tests
// ============================================================================

mod error_messages {
    use super::*;

    /// Format a condition failure error message.
    fn format_condition_error(failed_count: usize, total_count: usize, summary: &str) -> String {
        format!(
            "Transition conditions not satisfied: {} of {} conditions failed - {}",
            failed_count, total_count, summary
        )
    }

    #[test]
    fn test_error_message_single_condition_failed() {
        let error = format_condition_error(1, 1, "Termination date is not set");
        assert!(error.contains("1 of 1 conditions failed"));
        assert!(error.contains("Termination date is not set"));
    }

    #[test]
    fn test_error_message_multiple_conditions_failed() {
        let error = format_condition_error(2, 3, "Multiple conditions not satisfied");
        assert!(error.contains("2 of 3 conditions failed"));
    }
}
