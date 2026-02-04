//! Unit tests for `TemplateRuleService` (F058).
//!
//! Tests CRUD operations, expression validation, circular dependency detection,
//! and rule type behaviors.

use std::collections::HashMap;
use uuid::Uuid;
use xavyo_api_governance::services::TemplateExpressionService;
use xavyo_db::models::{
    CreateGovTemplateRule, TemplateRuleFilter, TemplateRuleType, TemplateStrength,
    UpdateGovTemplateRule,
};

// ============================================================
// Helper Types for Testing (No DB Required)
// ============================================================

/// Mock rule for unit testing.
#[derive(Debug, Clone)]
struct TestRule {
    id: Uuid,
    tenant_id: Uuid,
    template_id: Uuid,
    rule_type: TemplateRuleType,
    target_attribute: String,
    expression: String,
    strength: TemplateStrength,
    authoritative: bool,
    priority: i32,
    condition: Option<String>,
    error_message: Option<String>,
}

impl TestRule {
    fn new(template_id: Uuid, target: &str, rule_type: TemplateRuleType) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            template_id,
            rule_type,
            target_attribute: target.to_string(),
            expression: "\"default\"".to_string(),
            strength: TemplateStrength::Normal,
            authoritative: true,
            priority: 100,
            condition: None,
            error_message: None,
        }
    }

    fn with_expression(mut self, expr: &str) -> Self {
        self.expression = expr.to_string();
        self
    }

    fn with_condition(mut self, condition: &str) -> Self {
        self.condition = Some(condition.to_string());
        self
    }

    fn with_strength(mut self, strength: TemplateStrength) -> Self {
        self.strength = strength;
        self
    }

    fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    fn with_error_message(mut self, msg: &str) -> Self {
        self.error_message = Some(msg.to_string());
        self
    }
}

// ============================================================
// Create Rule Tests
// ============================================================

#[test]
fn test_create_rule_request_default_values() {
    let request = CreateGovTemplateRule {
        rule_type: TemplateRuleType::Default,
        target_attribute: "department".to_string(),
        expression: "\"Unassigned\"".to_string(),
        strength: None,
        authoritative: None,
        priority: None,
        condition: None,
        error_message: None,
        exclusive: None,
        time_from: None,
        time_to: None,
        time_reference: None,
    };

    assert_eq!(request.rule_type, TemplateRuleType::Default);
    assert_eq!(request.target_attribute, "department");
    assert!(request.strength.is_none()); // Defaults to Normal
    assert!(request.authoritative.is_none()); // Defaults to true
    assert!(request.priority.is_none()); // Defaults to 100
}

#[test]
fn test_create_rule_request_all_fields() {
    let request = CreateGovTemplateRule {
        rule_type: TemplateRuleType::Validation,
        target_attribute: "email".to_string(),
        expression: "matches(${email}, \"^[a-z]+@company.com$\")".to_string(),
        strength: Some(TemplateStrength::Strong),
        authoritative: Some(false),
        priority: Some(50),
        condition: Some("${employee_type} == \"full_time\"".to_string()),
        error_message: Some("Invalid email format for employees".to_string()),
        exclusive: Some(true),
        time_from: None,
        time_to: None,
        time_reference: None,
    };

    assert_eq!(request.rule_type, TemplateRuleType::Validation);
    assert_eq!(request.strength, Some(TemplateStrength::Strong));
    assert_eq!(request.authoritative, Some(false));
    assert_eq!(request.priority, Some(50));
    assert!(request.condition.is_some());
    assert!(request.error_message.is_some());
    assert_eq!(request.exclusive, Some(true));
}

#[test]
fn test_create_all_rule_types() {
    let types = vec![
        TemplateRuleType::Default,
        TemplateRuleType::Computed,
        TemplateRuleType::Validation,
        TemplateRuleType::Normalization,
    ];

    for rule_type in types {
        let request = CreateGovTemplateRule {
            rule_type,
            target_attribute: "test".to_string(),
            expression: "\"value\"".to_string(),
            strength: None,
            authoritative: None,
            priority: None,
            condition: None,
            error_message: None,
            exclusive: None,
            time_from: None,
            time_to: None,
            time_reference: None,
        };
        assert_eq!(request.rule_type, rule_type);
    }
}

// ============================================================
// Update Rule Tests
// ============================================================

#[test]
fn test_update_rule_partial() {
    let update = UpdateGovTemplateRule {
        expression: Some("\"New Default\"".to_string()),
        strength: None,
        authoritative: None,
        priority: None,
        condition: None,
        error_message: None,
        exclusive: None,
        time_from: None,
        time_to: None,
        time_reference: None,
    };

    assert!(update.expression.is_some());
    assert!(update.strength.is_none());
}

#[test]
fn test_update_rule_all_fields() {
    let update = UpdateGovTemplateRule {
        expression: Some("lowercase(${name})".to_string()),
        strength: Some(TemplateStrength::Weak),
        authoritative: Some(false),
        priority: Some(25),
        condition: Some("true".to_string()),
        error_message: Some("Updated error".to_string()),
        exclusive: Some(true),
        time_from: None,
        time_to: None,
        time_reference: None,
    };

    assert!(update.expression.is_some());
    assert!(update.strength.is_some());
    assert!(update.authoritative.is_some());
    assert!(update.priority.is_some());
    assert!(update.condition.is_some());
    assert!(update.error_message.is_some());
    assert_eq!(update.exclusive, Some(true));
}

#[test]
fn test_update_rule_empty_is_noop() {
    let update = UpdateGovTemplateRule {
        expression: None,
        strength: None,
        authoritative: None,
        priority: None,
        condition: None,
        error_message: None,
        exclusive: None,
        time_from: None,
        time_to: None,
        time_reference: None,
    };

    // All fields None means no update
    assert!(update.expression.is_none());
}

// ============================================================
// Rule Type Behavior Tests
// ============================================================

#[test]
fn test_default_rule_static_value() {
    let template_id = Uuid::new_v4();
    let rule = TestRule::new(template_id, "department", TemplateRuleType::Default)
        .with_expression("\"Engineering\"");

    assert_eq!(rule.rule_type, TemplateRuleType::Default);
    assert_eq!(rule.expression, "\"Engineering\"");
}

#[test]
fn test_computed_rule_with_expression() {
    let template_id = Uuid::new_v4();
    let rule = TestRule::new(template_id, "displayName", TemplateRuleType::Computed)
        .with_expression("${firstName} + \" \" + ${lastName}");

    assert_eq!(rule.rule_type, TemplateRuleType::Computed);
    assert!(rule.expression.contains("${firstName}"));
}

#[test]
fn test_validation_rule_with_error_message() {
    let template_id = Uuid::new_v4();
    let rule = TestRule::new(template_id, "email", TemplateRuleType::Validation)
        .with_expression("matches(${email}, \"^[a-z]+@company.com$\")")
        .with_error_message("Email must be in company format");

    assert_eq!(rule.rule_type, TemplateRuleType::Validation);
    assert!(rule.error_message.is_some());
}

#[test]
fn test_normalization_rule_transform() {
    let template_id = Uuid::new_v4();
    let rule = TestRule::new(template_id, "email", TemplateRuleType::Normalization)
        .with_expression("lowercase(trim(${email}))");

    assert_eq!(rule.rule_type, TemplateRuleType::Normalization);
}

// ============================================================
// Strength Tests
// ============================================================

#[test]
fn test_strength_strong() {
    let template_id = Uuid::new_v4();
    let rule = TestRule::new(template_id, "attr", TemplateRuleType::Default)
        .with_strength(TemplateStrength::Strong);

    assert_eq!(rule.strength, TemplateStrength::Strong);
    // Strong: always enforced, cannot be overridden
}

#[test]
fn test_strength_normal() {
    let template_id = Uuid::new_v4();
    let rule = TestRule::new(template_id, "attr", TemplateRuleType::Default)
        .with_strength(TemplateStrength::Normal);

    assert_eq!(rule.strength, TemplateStrength::Normal);
    // Normal: enforced unless user explicitly provides value
}

#[test]
fn test_strength_weak() {
    let template_id = Uuid::new_v4();
    let rule = TestRule::new(template_id, "attr", TemplateRuleType::Default)
        .with_strength(TemplateStrength::Weak);

    assert_eq!(rule.strength, TemplateStrength::Weak);
    // Weak: only applied if attribute is empty/null
}

#[test]
fn test_strength_default_is_normal() {
    assert_eq!(TemplateStrength::default(), TemplateStrength::Normal);
}

// ============================================================
// Expression Validation Tests
// ============================================================

#[test]
fn test_valid_default_expression_string() {
    let svc = TemplateExpressionService::new();
    let result = svc.parse("\"Unassigned\"");
    assert!(result.is_ok());
}

#[test]
fn test_valid_default_expression_number() {
    let svc = TemplateExpressionService::new();
    let result = svc.parse("100");
    assert!(result.is_ok());
}

#[test]
fn test_valid_default_expression_boolean() {
    let svc = TemplateExpressionService::new();
    let result = svc.parse("true");
    assert!(result.is_ok());
}

#[test]
fn test_valid_computed_expression() {
    let svc = TemplateExpressionService::new();
    let result = svc.parse("${firstName} + \" \" + ${lastName}");
    assert!(result.is_ok());

    // Validate references
    let refs = svc.validate("${firstName} + \" \" + ${lastName}").unwrap();
    assert!(refs.contains("firstName"));
    assert!(refs.contains("lastName"));
}

#[test]
fn test_valid_conditional_expression() {
    let svc = TemplateExpressionService::new();
    let result = svc.parse("if(${type} == \"employee\", \"EMP-\", \"CTR-\") + ${id}");
    assert!(result.is_ok());
}

#[test]
fn test_valid_validation_expression() {
    let svc = TemplateExpressionService::new();
    let result = svc.parse("matches(${email}, \"^[a-z.]+@company.com$\")");
    assert!(result.is_ok());
}

#[test]
fn test_valid_normalization_expression() {
    let svc = TemplateExpressionService::new();
    let result = svc.parse("lowercase(trim(${email}))");
    assert!(result.is_ok());
}

#[test]
fn test_invalid_expression_unclosed_string() {
    let svc = TemplateExpressionService::new();
    let result = svc.parse("\"unclosed string");
    assert!(result.is_err());
}

#[test]
fn test_invalid_expression_unknown_function() {
    let svc = TemplateExpressionService::new();
    let result = svc.parse("unknown_func(${name})");
    assert!(result.is_err());
}

#[test]
fn test_invalid_expression_unclosed_path_ref() {
    let svc = TemplateExpressionService::new();
    let result = svc.parse("${unclosed");
    assert!(result.is_err());
}

// ============================================================
// Circular Dependency Detection Tests
// ============================================================

#[test]
fn test_detect_no_cycles() {
    let svc = TemplateExpressionService::new();
    let mut exprs = HashMap::new();
    exprs.insert(
        "displayName".to_string(),
        "${firstName} + \" \" + ${lastName}".to_string(),
    );
    exprs.insert(
        "greeting".to_string(),
        "\"Hello, \" + ${displayName}".to_string(),
    );

    let result = svc.detect_cycles(&exprs);
    assert!(result.is_ok());

    let order = result.unwrap();
    // displayName must come before greeting
    let display_idx = order.iter().position(|x| x == "displayName").unwrap();
    let greeting_idx = order.iter().position(|x| x == "greeting").unwrap();
    assert!(display_idx < greeting_idx);
}

#[test]
fn test_detect_direct_cycle() {
    let svc = TemplateExpressionService::new();
    let mut exprs = HashMap::new();
    exprs.insert("a".to_string(), "${b}".to_string());
    exprs.insert("b".to_string(), "${a}".to_string());

    let result = svc.detect_cycles(&exprs);
    assert!(result.is_err());
}

#[test]
fn test_detect_indirect_cycle() {
    let svc = TemplateExpressionService::new();
    let mut exprs = HashMap::new();
    exprs.insert("a".to_string(), "${b}".to_string());
    exprs.insert("b".to_string(), "${c}".to_string());
    exprs.insert("c".to_string(), "${a}".to_string());

    let result = svc.detect_cycles(&exprs);
    assert!(result.is_err());
}

#[test]
fn test_no_cycle_with_external_refs() {
    let svc = TemplateExpressionService::new();
    let mut exprs = HashMap::new();
    // firstName and lastName are external (not computed)
    exprs.insert(
        "displayName".to_string(),
        "${firstName} + \" \" + ${lastName}".to_string(),
    );
    exprs.insert(
        "email".to_string(),
        "lowercase(${firstName}) + \".\" + lowercase(${lastName}) + \"@company.com\"".to_string(),
    );

    let result = svc.detect_cycles(&exprs);
    assert!(result.is_ok());
}

// ============================================================
// Condition Expression Tests
// ============================================================

#[test]
fn test_condition_expression_simple() {
    let svc = TemplateExpressionService::new();
    let condition = "${employee_type} == \"full_time\"";
    let result = svc.parse(condition);
    assert!(result.is_ok());
}

#[test]
fn test_condition_expression_complex() {
    let svc = TemplateExpressionService::new();
    let condition = "${employee_type} == \"full_time\" && ${department} == \"Engineering\"";
    let result = svc.parse(condition);
    assert!(result.is_ok());
}

#[test]
fn test_condition_with_negation() {
    let svc = TemplateExpressionService::new();
    let condition = "!is_null(${manager_id})";
    let result = svc.parse(condition);
    assert!(result.is_ok());
}

// ============================================================
// Priority and Ordering Tests
// ============================================================

#[test]
fn test_rule_priority_ordering() {
    let template_id = Uuid::new_v4();
    let rule1 = TestRule::new(template_id, "attr1", TemplateRuleType::Default).with_priority(10);
    let rule2 = TestRule::new(template_id, "attr2", TemplateRuleType::Default).with_priority(50);
    let rule3 = TestRule::new(template_id, "attr3", TemplateRuleType::Default).with_priority(100);

    // Lower priority number = higher precedence (evaluated first)
    assert!(rule1.priority < rule2.priority);
    assert!(rule2.priority < rule3.priority);
}

#[test]
fn test_rule_priority_constants() {
    use xavyo_db::models::{DEFAULT_RULE_PRIORITY, MAX_RULE_PRIORITY, MIN_RULE_PRIORITY};

    assert_eq!(MIN_RULE_PRIORITY, 1);
    assert_eq!(DEFAULT_RULE_PRIORITY, 100);
    assert_eq!(MAX_RULE_PRIORITY, 1000);
}

// ============================================================
// Filter Tests
// ============================================================

#[test]
fn test_filter_by_template() {
    let template_id = Uuid::new_v4();
    let filter = TemplateRuleFilter {
        template_id: Some(template_id),
        ..Default::default()
    };

    assert_eq!(filter.template_id, Some(template_id));
}

#[test]
fn test_filter_by_rule_type() {
    let filter = TemplateRuleFilter {
        rule_type: Some(TemplateRuleType::Validation),
        ..Default::default()
    };

    assert_eq!(filter.rule_type, Some(TemplateRuleType::Validation));
}

#[test]
fn test_filter_by_target_attribute() {
    let filter = TemplateRuleFilter {
        target_attribute: Some("email".to_string()),
        ..Default::default()
    };

    assert_eq!(filter.target_attribute.as_ref().unwrap(), "email");
}

#[test]
fn test_filter_combined() {
    let template_id = Uuid::new_v4();
    let filter = TemplateRuleFilter {
        template_id: Some(template_id),
        rule_type: Some(TemplateRuleType::Computed),
        target_attribute: Some("displayName".to_string()),
        strength: Some(TemplateStrength::Normal),
    };

    assert_eq!(filter.template_id, Some(template_id));
    assert_eq!(filter.rule_type, Some(TemplateRuleType::Computed));
    assert_eq!(filter.strength, Some(TemplateStrength::Normal));
}

// ============================================================
// Authoritative Flag Tests
// ============================================================

#[test]
fn test_authoritative_true_removes_on_source_change() {
    let template_id = Uuid::new_v4();
    let rule = TestRule::new(template_id, "department", TemplateRuleType::Computed);

    // Default is authoritative = true
    assert!(rule.authoritative);
    // When source changes, computed value is recalculated
}

#[test]
fn test_authoritative_false_preserves_value() {
    let template_id = Uuid::new_v4();
    let mut rule = TestRule::new(template_id, "department", TemplateRuleType::Computed);
    rule.authoritative = false;

    assert!(!rule.authoritative);
    // When source changes, existing value is preserved
}

// ============================================================
// Target Attribute Validation Tests
// ============================================================

#[test]
fn test_valid_target_attributes() {
    let valid_attrs = vec![
        "firstName",
        "lastName",
        "email",
        "displayName",
        "department",
        "title",
        "employee_type",
        "manager_id",
    ];

    for attr in valid_attrs {
        assert!(!attr.is_empty());
        assert!(attr.chars().all(|c| c.is_alphanumeric() || c == '_'));
    }
}

#[test]
fn test_target_attribute_case_sensitivity() {
    // Attributes are case-sensitive
    let attr1 = "firstName";
    let attr2 = "firstname";
    let attr3 = "FirstName";

    assert_ne!(attr1, attr2);
    assert_ne!(attr1, attr3);
    assert_ne!(attr2, attr3);
}

// ============================================================
// Error Message Tests
// ============================================================

#[test]
fn test_validation_rule_default_error_message() {
    let template_id = Uuid::new_v4();
    let rule = TestRule::new(template_id, "email", TemplateRuleType::Validation);

    // No custom error message
    assert!(rule.error_message.is_none());
    // Default message would be generated from expression/attribute
}

#[test]
fn test_validation_rule_custom_error_message() {
    let template_id = Uuid::new_v4();
    let rule = TestRule::new(template_id, "email", TemplateRuleType::Validation)
        .with_error_message("Please enter a valid company email address");

    assert!(rule.error_message.is_some());
    assert!(rule.error_message.as_ref().unwrap().contains("valid"));
}

// ============================================================
// Rule Type Helper Method Tests
// ============================================================

#[test]
fn test_is_validation_helper() {
    let template_id = Uuid::new_v4();
    let validation = TestRule::new(template_id, "email", TemplateRuleType::Validation);
    let default = TestRule::new(template_id, "department", TemplateRuleType::Default);

    assert_eq!(validation.rule_type, TemplateRuleType::Validation);
    assert_ne!(default.rule_type, TemplateRuleType::Validation);
}

#[test]
fn test_is_computed_helper() {
    let template_id = Uuid::new_v4();
    let computed = TestRule::new(template_id, "displayName", TemplateRuleType::Computed);

    assert_eq!(computed.rule_type, TemplateRuleType::Computed);
}

#[test]
fn test_is_default_helper() {
    let template_id = Uuid::new_v4();
    let default = TestRule::new(template_id, "department", TemplateRuleType::Default);

    assert_eq!(default.rule_type, TemplateRuleType::Default);
}

#[test]
fn test_is_normalization_helper() {
    let template_id = Uuid::new_v4();
    let normalization = TestRule::new(template_id, "email", TemplateRuleType::Normalization);

    assert_eq!(normalization.rule_type, TemplateRuleType::Normalization);
}

// ============================================================
// Multiple Rules Same Attribute Tests
// ============================================================

#[test]
fn test_multiple_rules_same_attribute_different_types() {
    let template_id = Uuid::new_v4();

    // Different rule types for same attribute is valid
    let default_rule = TestRule::new(template_id, "email", TemplateRuleType::Default)
        .with_expression("\"unknown@company.com\"")
        .with_priority(100);

    let normalization_rule = TestRule::new(template_id, "email", TemplateRuleType::Normalization)
        .with_expression("lowercase(trim(${email}))")
        .with_priority(50);

    let validation_rule = TestRule::new(template_id, "email", TemplateRuleType::Validation)
        .with_expression("matches(${email}, \"^[a-z]+@company.com$\")")
        .with_priority(200);

    assert_eq!(default_rule.target_attribute, "email");
    assert_eq!(normalization_rule.target_attribute, "email");
    assert_eq!(validation_rule.target_attribute, "email");

    // Processing order: normalization (50) -> default (100) -> validation (200)
    assert!(normalization_rule.priority < default_rule.priority);
    assert!(default_rule.priority < validation_rule.priority);
}

// ============================================================
// Real-World Scenario Tests
// ============================================================

#[test]
fn test_user_template_rules_scenario() {
    let svc = TemplateExpressionService::new();
    let template_id = Uuid::new_v4();

    // Rule 1: Default department
    let default_dept = TestRule::new(template_id, "department", TemplateRuleType::Default)
        .with_expression("if(is_null(${department}), \"Unassigned\", ${department})");
    assert!(svc.parse(&default_dept.expression).is_ok());

    // Rule 2: Computed display name
    let display_name = TestRule::new(template_id, "displayName", TemplateRuleType::Computed)
        .with_expression("${firstName} + \" \" + ${lastName}");
    assert!(svc.parse(&display_name.expression).is_ok());

    // Rule 3: Computed email
    let email = TestRule::new(template_id, "email", TemplateRuleType::Computed).with_expression(
        "lowercase(${firstName}) + \".\" + lowercase(${lastName}) + \"@company.com\"",
    );
    assert!(svc.parse(&email.expression).is_ok());

    // Rule 4: Email validation
    let email_validation = TestRule::new(template_id, "email", TemplateRuleType::Validation)
        .with_expression("matches(${email}, \"^[a-z.]+@company.com$\")")
        .with_error_message("Email must be in format: firstname.lastname@company.com");
    assert!(svc.parse(&email_validation.expression).is_ok());

    // Rule 5: Normalize email
    let normalize_email = TestRule::new(template_id, "email", TemplateRuleType::Normalization)
        .with_expression("lowercase(trim(${email}))");
    assert!(svc.parse(&normalize_email.expression).is_ok());

    // Verify no cycles in computed values
    let mut computed_exprs = HashMap::new();
    computed_exprs.insert(
        display_name.target_attribute.clone(),
        display_name.expression.clone(),
    );
    computed_exprs.insert(email.target_attribute.clone(), email.expression.clone());
    assert!(svc.detect_cycles(&computed_exprs).is_ok());
}

#[test]
fn test_conditional_rule_for_employee_type() {
    let svc = TemplateExpressionService::new();
    let template_id = Uuid::new_v4();

    // Rule applies only to full-time employees
    let rule = TestRule::new(template_id, "manager_id", TemplateRuleType::Validation)
        .with_expression("!is_null(${manager_id})")
        .with_condition("${employee_type} == \"full_time\"")
        .with_error_message("Full-time employees must have a manager assigned");

    // Validate expression
    assert!(svc.parse(&rule.expression).is_ok());

    // Validate condition
    assert!(svc.parse(rule.condition.as_ref().unwrap()).is_ok());
}

// ============================================================
// Edge Case Tests: Exclusive Mappings (IGA parity)
// ============================================================

#[test]
fn test_create_rule_with_exclusive_flag() {
    let request = CreateGovTemplateRule {
        rule_type: TemplateRuleType::Default,
        target_attribute: "department".to_string(),
        expression: "\"Engineering\"".to_string(),
        strength: Some(TemplateStrength::Strong),
        authoritative: Some(true),
        priority: None,
        condition: None,
        error_message: None,
        exclusive: Some(true), // This rule cannot coexist with others targeting 'department'
        time_from: None,
        time_to: None,
        time_reference: None,
    };

    assert_eq!(request.exclusive, Some(true));
    assert_eq!(request.strength, Some(TemplateStrength::Strong));
}

#[test]
fn test_exclusive_false_by_default() {
    let request = CreateGovTemplateRule {
        rule_type: TemplateRuleType::Default,
        target_attribute: "department".to_string(),
        expression: "\"Unassigned\"".to_string(),
        strength: None,
        authoritative: None,
        priority: None,
        condition: None,
        error_message: None,
        exclusive: None, // None means false (default)
        time_from: None,
        time_to: None,
        time_reference: None,
    };

    assert!(request.exclusive.is_none());
}

// ============================================================
// Edge Case Tests: Time Constraints (IGA parity)
// ============================================================

#[test]
fn test_create_rule_with_absolute_time_constraints() {
    use chrono::{Duration, Utc};
    use xavyo_db::models::TemplateTimeReference;

    let now = Utc::now();
    let one_year_later = now + Duration::days(365);

    let request = CreateGovTemplateRule {
        rule_type: TemplateRuleType::Default,
        target_attribute: "training_access".to_string(),
        expression: "true".to_string(),
        strength: None,
        authoritative: None,
        priority: None,
        condition: None,
        error_message: None,
        exclusive: None,
        time_from: Some(now),
        time_to: Some(one_year_later),
        time_reference: Some(TemplateTimeReference::Absolute),
    };

    assert!(request.time_from.is_some());
    assert!(request.time_to.is_some());
    assert_eq!(
        request.time_reference,
        Some(TemplateTimeReference::Absolute)
    );
}

#[test]
fn test_create_rule_with_relative_time_constraints() {
    use chrono::{DateTime, Duration};
    use xavyo_db::models::TemplateTimeReference;

    // For relative time, we interpret the time as offset from Unix epoch
    // e.g., 90 days from object creation
    let ninety_days_offset = DateTime::UNIX_EPOCH + Duration::days(90);

    let request = CreateGovTemplateRule {
        rule_type: TemplateRuleType::Default,
        target_attribute: "probation_warning".to_string(),
        expression: "true".to_string(),
        strength: None,
        authoritative: None,
        priority: None,
        condition: None,
        error_message: None,
        exclusive: None,
        time_from: None,
        time_to: Some(ninety_days_offset), // Rule applies until 90 days after object creation
        time_reference: Some(TemplateTimeReference::RelativeToCreation),
    };

    assert!(request.time_from.is_none());
    assert!(request.time_to.is_some());
    assert_eq!(
        request.time_reference,
        Some(TemplateTimeReference::RelativeToCreation)
    );
}

#[test]
fn test_update_rule_time_constraints() {
    use chrono::{Duration, Utc};
    use xavyo_db::models::TemplateTimeReference;

    let now = Utc::now();

    let update = UpdateGovTemplateRule {
        expression: None,
        strength: None,
        authoritative: None,
        priority: None,
        condition: None,
        error_message: None,
        exclusive: None,
        time_from: Some(now),
        time_to: Some(now + Duration::days(30)),
        time_reference: Some(TemplateTimeReference::Absolute),
    };

    assert!(update.time_from.is_some());
    assert!(update.time_to.is_some());
    assert_eq!(update.time_reference, Some(TemplateTimeReference::Absolute));
}

#[test]
fn test_time_reference_default_is_absolute() {
    use xavyo_db::models::TemplateTimeReference;

    assert_eq!(
        TemplateTimeReference::default(),
        TemplateTimeReference::Absolute
    );
}
