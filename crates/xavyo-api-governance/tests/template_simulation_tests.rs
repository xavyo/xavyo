//! Tests for template simulation models and result types (F058).
//!
//! Since the simulation service requires a database pool for actual simulation,
//! these tests focus on struct construction, serialization, and model correctness.

use serde_json::json;
use uuid::Uuid;
use xavyo_api_governance::models::{
    RuleApplicationResult, SimulationRequest, TemplateSimulationResponse, ValidationError,
};
use xavyo_db::models::TemplateRuleType;

// =============================================================================
// SimulationRequest Tests
// =============================================================================

/// Verify that SimulationRequest can be constructed with sample_object and limit.
#[test]
fn test_simulation_request_construction() {
    let sample = json!({"first_name": "Alice", "department": "Engineering"});
    let request = SimulationRequest {
        sample_object: sample.clone(),
        limit: 50,
    };

    assert_eq!(request.sample_object, sample);
    assert_eq!(request.limit, 50);
}

/// Verify default_simulation_limit is applied when the limit field is absent
/// during deserialization.
#[test]
fn test_simulation_request_default_limit() {
    let value = json!({
        "sample_object": {"name": "Test User"}
    });

    let request: SimulationRequest =
        serde_json::from_value(value).expect("should deserialize without limit field");

    assert_eq!(request.limit, 100, "default simulation limit should be 100");
    assert_eq!(request.sample_object, json!({"name": "Test User"}));
}

// =============================================================================
// TemplateSimulationResponse Tests
// =============================================================================

/// Verify basic construction of an empty TemplateSimulationResponse.
#[test]
fn test_simulation_response_construction() {
    let template_id = Uuid::new_v4();
    let response = TemplateSimulationResponse {
        template_id,
        rules_applied: vec![],
        validation_errors: vec![],
        computed_values: json!({}),
        affected_count: 0,
    };

    assert_eq!(response.template_id, template_id);
    assert!(response.rules_applied.is_empty());
    assert!(response.validation_errors.is_empty());
    assert_eq!(response.computed_values, json!({}));
    assert_eq!(response.affected_count, 0);
}

/// Verify TemplateSimulationResponse can hold multiple RuleApplicationResult items.
#[test]
fn test_simulation_response_with_rules() {
    let template_id = Uuid::new_v4();

    let rule1 = RuleApplicationResult {
        rule_id: Uuid::new_v4(),
        target_attribute: "department".to_string(),
        rule_type: TemplateRuleType::Default,
        before_value: None,
        after_value: json!("Engineering"),
        applied: true,
        skip_reason: None,
    };

    let rule2 = RuleApplicationResult {
        rule_id: Uuid::new_v4(),
        target_attribute: "email".to_string(),
        rule_type: TemplateRuleType::Computed,
        before_value: None,
        after_value: json!("alice@company.com"),
        applied: true,
        skip_reason: None,
    };

    let response = TemplateSimulationResponse {
        template_id,
        rules_applied: vec![rule1, rule2],
        validation_errors: vec![],
        computed_values: json!({}),
        affected_count: 1,
    };

    assert_eq!(response.rules_applied.len(), 2);
}

// =============================================================================
// RuleApplicationResult Tests
// =============================================================================

/// Verify RuleApplicationResult for an applied default-value rule.
#[test]
fn test_rule_application_result_applied() {
    let rule_id = Uuid::new_v4();
    let result = RuleApplicationResult {
        rule_id,
        target_attribute: "email".to_string(),
        rule_type: TemplateRuleType::Default,
        before_value: None,
        after_value: json!("default@company.com"),
        applied: true,
        skip_reason: None,
    };

    assert_eq!(result.rule_id, rule_id);
    assert_eq!(result.target_attribute, "email");
    assert_eq!(result.rule_type, TemplateRuleType::Default);
    assert!(result.before_value.is_none());
    assert_eq!(result.after_value, json!("default@company.com"));
    assert!(result.applied);
    assert!(result.skip_reason.is_none());
}

/// Verify RuleApplicationResult for a skipped rule with a skip_reason.
#[test]
fn test_rule_application_result_skipped() {
    let result = RuleApplicationResult {
        rule_id: Uuid::new_v4(),
        target_attribute: "department".to_string(),
        rule_type: TemplateRuleType::Default,
        before_value: Some(json!("Existing")),
        after_value: json!("Existing"),
        applied: false,
        skip_reason: Some("Condition not met".to_string()),
    };

    assert!(!result.applied);
    assert!(result.skip_reason.is_some());
    assert_eq!(result.skip_reason.as_deref(), Some("Condition not met"));
}

/// Verify RuleApplicationResult for a computed-value rule with before and after values.
#[test]
fn test_rule_application_result_computed() {
    let result = RuleApplicationResult {
        rule_id: Uuid::new_v4(),
        target_attribute: "display_name".to_string(),
        rule_type: TemplateRuleType::Computed,
        before_value: Some(json!("old")),
        after_value: json!("new_computed"),
        applied: true,
        skip_reason: None,
    };

    assert_eq!(result.rule_type, TemplateRuleType::Computed);
    assert_eq!(result.before_value, Some(json!("old")));
    assert_eq!(result.after_value, json!("new_computed"));
}

// =============================================================================
// ValidationError Tests
// =============================================================================

/// Verify ValidationError construction with all fields.
#[test]
fn test_validation_error_construction() {
    let rule_id = Uuid::new_v4();
    let error = ValidationError {
        rule_id,
        target_attribute: "email".to_string(),
        message: "Invalid email format".to_string(),
        expression: "matches(email, '^[^@]+@[^@]+$')".to_string(),
    };

    assert_eq!(error.rule_id, rule_id);
    assert_eq!(error.target_attribute, "email");
    assert_eq!(error.message, "Invalid email format");
    assert_eq!(error.expression, "matches(email, '^[^@]+@[^@]+$')");
}

// =============================================================================
// Serialization Round-Trip Tests
// =============================================================================

/// Verify that a full TemplateSimulationResponse survives a JSON round-trip.
#[test]
fn test_simulation_response_serialization() {
    let template_id = Uuid::new_v4();
    let rule_id = Uuid::new_v4();
    let validation_rule_id = Uuid::new_v4();

    let response = TemplateSimulationResponse {
        template_id,
        rules_applied: vec![RuleApplicationResult {
            rule_id,
            target_attribute: "department".to_string(),
            rule_type: TemplateRuleType::Default,
            before_value: None,
            after_value: json!("Engineering"),
            applied: true,
            skip_reason: None,
        }],
        validation_errors: vec![ValidationError {
            rule_id: validation_rule_id,
            target_attribute: "email".to_string(),
            message: "Invalid email".to_string(),
            expression: "matches(email, '^.+@.+$')".to_string(),
        }],
        computed_values: json!({"displayName": "Test User"}),
        affected_count: 5,
    };

    let serialized = serde_json::to_value(&response).expect("should serialize");
    let deserialized: TemplateSimulationResponse =
        serde_json::from_value(serialized.clone()).expect("should deserialize");

    assert_eq!(deserialized.template_id, template_id);
    assert_eq!(deserialized.rules_applied.len(), 1);
    assert_eq!(deserialized.rules_applied[0].rule_id, rule_id);
    assert_eq!(deserialized.rules_applied[0].target_attribute, "department");
    assert_eq!(
        deserialized.rules_applied[0].after_value,
        json!("Engineering")
    );
    assert!(deserialized.rules_applied[0].applied);
    assert_eq!(deserialized.validation_errors.len(), 1);
    assert_eq!(
        deserialized.validation_errors[0].rule_id,
        validation_rule_id
    );
    assert_eq!(deserialized.validation_errors[0].message, "Invalid email");
    assert_eq!(
        deserialized.computed_values,
        json!({"displayName": "Test User"})
    );
    assert_eq!(deserialized.affected_count, 5);
}

/// Verify computed_values field access with populated JSON data.
#[test]
fn test_simulation_response_with_computed_values() {
    let response = TemplateSimulationResponse {
        template_id: Uuid::new_v4(),
        rules_applied: vec![],
        validation_errors: vec![],
        computed_values: json!({
            "displayName": "John Doe",
            "email": "john.doe@company.com"
        }),
        affected_count: 1,
    };

    assert_eq!(
        response
            .computed_values
            .get("displayName")
            .and_then(|v| v.as_str()),
        Some("John Doe")
    );
    assert_eq!(
        response
            .computed_values
            .get("email")
            .and_then(|v| v.as_str()),
        Some("john.doe@company.com")
    );
}
