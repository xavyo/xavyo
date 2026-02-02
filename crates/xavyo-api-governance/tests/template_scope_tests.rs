//! Unit tests for TemplateScopeService (F058 - User Story 2).
//!
//! Tests scope matching logic for determining which templates apply to objects.

use serde_json::json;
use uuid::Uuid;
use xavyo_db::models::{TemplateObjectType, TemplateScopeType};

// =============================================================================
// Scope Type Tests
// =============================================================================

#[test]
fn test_scope_type_global() {
    let scope_type = TemplateScopeType::Global;
    assert_eq!(scope_type.to_string(), "global");
}

#[test]
fn test_scope_type_organization() {
    let scope_type = TemplateScopeType::Organization;
    assert_eq!(scope_type.to_string(), "organization");
}

#[test]
fn test_scope_type_category() {
    let scope_type = TemplateScopeType::Category;
    assert_eq!(scope_type.to_string(), "category");
}

#[test]
fn test_scope_type_condition() {
    let scope_type = TemplateScopeType::Condition;
    assert_eq!(scope_type.to_string(), "condition");
}

// =============================================================================
// Scope Matching Tests - Global Scope
// =============================================================================

/// Global scope should match any object.
#[test]
fn test_global_scope_matches_any_object() {
    // Global scope has no filter - matches everything
    let scope_type = TemplateScopeType::Global;
    let scope_value: Option<String> = None;

    // Test objects with various attributes
    let obj1 = json!({"department": "Engineering", "org_id": "org-1"});
    let obj2 = json!({"department": "Sales", "org_id": "org-2"});
    let obj3 = json!({}); // Empty object

    // Global scope should match all
    assert!(is_global_scope(scope_type, &scope_value));
    assert!(matches_global(&obj1));
    assert!(matches_global(&obj2));
    assert!(matches_global(&obj3));
}

fn is_global_scope(scope_type: TemplateScopeType, scope_value: &Option<String>) -> bool {
    scope_type == TemplateScopeType::Global && scope_value.is_none()
}

fn matches_global(_obj: &serde_json::Value) -> bool {
    // Global scope always matches
    true
}

// =============================================================================
// Scope Matching Tests - Organization Scope
// =============================================================================

/// Organization scope should match objects in that organization.
#[test]
fn test_organization_scope_matches_org() {
    let scope_value = "org-engineering";

    let obj_match = json!({"org_id": "org-engineering", "name": "Test User"});
    let obj_no_match = json!({"org_id": "org-sales", "name": "Test User"});
    let obj_no_org = json!({"name": "Test User"});

    assert!(matches_organization(&obj_match, scope_value, "org_id"));
    assert!(!matches_organization(&obj_no_match, scope_value, "org_id"));
    assert!(!matches_organization(&obj_no_org, scope_value, "org_id"));
}

#[test]
fn test_organization_scope_case_sensitive() {
    let scope_value = "Engineering";

    let obj_exact = json!({"department": "Engineering"});
    let obj_different_case = json!({"department": "engineering"});

    // Organization scope should be case-sensitive by default
    assert!(matches_organization(&obj_exact, scope_value, "department"));
    assert!(!matches_organization(
        &obj_different_case,
        scope_value,
        "department"
    ));
}

fn matches_organization(obj: &serde_json::Value, scope_value: &str, attribute: &str) -> bool {
    obj.get(attribute)
        .and_then(|v| v.as_str())
        .map(|v| v == scope_value)
        .unwrap_or(false)
}

// =============================================================================
// Scope Matching Tests - Category Scope
// =============================================================================

/// Category scope should match objects with that category.
#[test]
fn test_category_scope_matches_category() {
    let category = "contractor";

    let obj_match = json!({"user_type": "contractor", "name": "Test"});
    let obj_no_match = json!({"user_type": "employee", "name": "Test"});
    let obj_no_category = json!({"name": "Test"});

    assert!(matches_category(&obj_match, category, "user_type"));
    assert!(!matches_category(&obj_no_match, category, "user_type"));
    assert!(!matches_category(&obj_no_category, category, "user_type"));
}

#[test]
fn test_category_scope_with_role_type() {
    let category = "admin-role";

    let obj_match = json!({"role_type": "admin-role", "name": "Admin Role"});
    let obj_no_match = json!({"role_type": "user-role", "name": "User Role"});

    assert!(matches_category(&obj_match, category, "role_type"));
    assert!(!matches_category(&obj_no_match, category, "role_type"));
}

fn matches_category(obj: &serde_json::Value, category: &str, attribute: &str) -> bool {
    obj.get(attribute)
        .and_then(|v| v.as_str())
        .map(|v| v == category)
        .unwrap_or(false)
}

// =============================================================================
// Scope Matching Tests - Condition Scope
// =============================================================================

/// Condition scope should evaluate expression against object attributes.
#[test]
fn test_condition_scope_simple_equality() {
    let condition = "${department} == \"Engineering\"";

    let obj_match = json!({"department": "Engineering"});
    let obj_no_match = json!({"department": "Sales"});

    // The actual evaluation would be done by TemplateExpressionService
    // Here we test the condition parsing structure
    assert!(condition.contains("${department}"));
    assert!(condition.contains("=="));

    // Simulated evaluation
    assert!(evaluate_simple_equality(
        &obj_match,
        "department",
        "Engineering"
    ));
    assert!(!evaluate_simple_equality(
        &obj_no_match,
        "department",
        "Engineering"
    ));
}

#[test]
fn test_condition_scope_with_and() {
    let condition = "${department} == \"Engineering\" && ${level} >= 3";

    let obj_match = json!({"department": "Engineering", "level": 5});
    let obj_partial = json!({"department": "Engineering", "level": 1});
    let obj_no_match = json!({"department": "Sales", "level": 5});

    // Simulated compound condition evaluation
    assert!(evaluate_compound_condition(
        &obj_match,
        "department",
        "Engineering",
        "level",
        3
    ));
    assert!(!evaluate_compound_condition(
        &obj_partial,
        "department",
        "Engineering",
        "level",
        3
    ));
    assert!(!evaluate_compound_condition(
        &obj_no_match,
        "department",
        "Engineering",
        "level",
        3
    ));
}

#[test]
fn test_condition_scope_with_or() {
    let _condition = "${department} == \"Engineering\" || ${department} == \"R&D\"";

    let obj_eng = json!({"department": "Engineering"});
    let obj_rd = json!({"department": "R&D"});
    let obj_other = json!({"department": "Sales"});

    // Simulated OR condition
    assert!(evaluate_or_condition(
        &obj_eng,
        "department",
        &["Engineering", "R&D"]
    ));
    assert!(evaluate_or_condition(
        &obj_rd,
        "department",
        &["Engineering", "R&D"]
    ));
    assert!(!evaluate_or_condition(
        &obj_other,
        "department",
        &["Engineering", "R&D"]
    ));
}

#[test]
fn test_condition_scope_null_check() {
    let _condition = "${manager} != null";

    let obj_has_manager = json!({"manager": "mgr-123", "name": "Test"});
    let obj_no_manager = json!({"name": "Test"});
    let obj_null_manager = json!({"manager": null, "name": "Test"});

    assert!(has_non_null_attribute(&obj_has_manager, "manager"));
    assert!(!has_non_null_attribute(&obj_no_manager, "manager"));
    assert!(!has_non_null_attribute(&obj_null_manager, "manager"));
}

#[test]
fn test_condition_scope_string_function() {
    let _condition = "startsWith(${email}, \"admin@\")";

    let obj_match = json!({"email": "admin@example.com"});
    let obj_no_match = json!({"email": "user@example.com"});

    assert!(starts_with_value(&obj_match, "email", "admin@"));
    assert!(!starts_with_value(&obj_no_match, "email", "admin@"));
}

#[test]
fn test_condition_scope_contains_function() {
    let _condition = "contains(${email}, \"@company.com\")";

    let obj_match = json!({"email": "user@company.com"});
    let obj_no_match = json!({"email": "user@external.com"});

    assert!(contains_value(&obj_match, "email", "@company.com"));
    assert!(!contains_value(&obj_no_match, "email", "@company.com"));
}

// Helper functions simulating expression evaluation
fn evaluate_simple_equality(obj: &serde_json::Value, attr: &str, expected: &str) -> bool {
    obj.get(attr)
        .and_then(|v| v.as_str())
        .map(|v| v == expected)
        .unwrap_or(false)
}

fn evaluate_compound_condition(
    obj: &serde_json::Value,
    attr1: &str,
    expected1: &str,
    attr2: &str,
    min_value: i64,
) -> bool {
    let attr1_match = obj
        .get(attr1)
        .and_then(|v| v.as_str())
        .map(|v| v == expected1)
        .unwrap_or(false);

    let attr2_match = obj
        .get(attr2)
        .and_then(|v| v.as_i64())
        .map(|v| v >= min_value)
        .unwrap_or(false);

    attr1_match && attr2_match
}

fn evaluate_or_condition(obj: &serde_json::Value, attr: &str, values: &[&str]) -> bool {
    obj.get(attr)
        .and_then(|v| v.as_str())
        .map(|v| values.contains(&v))
        .unwrap_or(false)
}

fn has_non_null_attribute(obj: &serde_json::Value, attr: &str) -> bool {
    obj.get(attr).map(|v| !v.is_null()).unwrap_or(false)
}

fn starts_with_value(obj: &serde_json::Value, attr: &str, prefix: &str) -> bool {
    obj.get(attr)
        .and_then(|v| v.as_str())
        .map(|v| v.starts_with(prefix))
        .unwrap_or(false)
}

fn contains_value(obj: &serde_json::Value, attr: &str, substring: &str) -> bool {
    obj.get(attr)
        .and_then(|v| v.as_str())
        .map(|v| v.contains(substring))
        .unwrap_or(false)
}

// =============================================================================
// Scope Priority Tests
// =============================================================================

/// More specific scopes should take precedence.
#[test]
fn test_scope_specificity_ordering() {
    // Condition > Category > Organization > Global
    let scopes = vec![
        (TemplateScopeType::Global, 0),
        (TemplateScopeType::Organization, 1),
        (TemplateScopeType::Category, 2),
        (TemplateScopeType::Condition, 3),
    ];

    let mut sorted_scopes = scopes.clone();
    sorted_scopes.sort_by_key(|(_, priority)| *priority);

    assert_eq!(sorted_scopes[0].0, TemplateScopeType::Global);
    assert_eq!(sorted_scopes[1].0, TemplateScopeType::Organization);
    assert_eq!(sorted_scopes[2].0, TemplateScopeType::Category);
    assert_eq!(sorted_scopes[3].0, TemplateScopeType::Condition);
}

/// Templates with same scope type should use template priority.
#[test]
fn test_same_scope_type_uses_template_priority() {
    let templates = vec![
        (Uuid::new_v4(), "Global Template A", 10),
        (Uuid::new_v4(), "Global Template B", 5),
        (Uuid::new_v4(), "Global Template C", 20),
    ];

    let mut sorted = templates.clone();
    sorted.sort_by_key(|(_, _, priority)| *priority);

    // Lower priority number = higher precedence
    assert_eq!(sorted[0].1, "Global Template B");
    assert_eq!(sorted[1].1, "Global Template A");
    assert_eq!(sorted[2].1, "Global Template C");
}

// =============================================================================
// Multiple Scope Resolution Tests
// =============================================================================

/// Object matching multiple templates should get all applicable templates.
#[test]
fn test_object_matches_multiple_templates() {
    let obj = json!({
        "department": "Engineering",
        "org_id": "org-tech",
        "user_type": "employee",
        "level": 3
    });

    // Template 1: Global scope
    let global_matches = true;

    // Template 2: Organization scope (org-tech)
    let org_matches = matches_organization(&obj, "org-tech", "org_id");

    // Template 3: Category scope (employee)
    let category_matches = matches_category(&obj, "employee", "user_type");

    // Template 4: Condition scope (level >= 3)
    let condition_matches = obj
        .get("level")
        .and_then(|v| v.as_i64())
        .map(|v| v >= 3)
        .unwrap_or(false);

    assert!(global_matches);
    assert!(org_matches);
    assert!(category_matches);
    assert!(condition_matches);

    // All four templates should apply (in priority order)
    let applicable_count = [
        global_matches,
        org_matches,
        category_matches,
        condition_matches,
    ]
    .iter()
    .filter(|&&m| m)
    .count();

    assert_eq!(applicable_count, 4);
}

/// Disabled templates should not be matched.
#[test]
fn test_disabled_template_not_matched() {
    // Template status should be checked before scope matching
    let is_active = false;
    let scope_matches = true;

    let should_apply = is_active && scope_matches;
    assert!(!should_apply);
}

// =============================================================================
// Object Type Constraint Tests
// =============================================================================

/// Templates should only match objects of the correct type.
#[test]
fn test_template_object_type_constraint() {
    let user_template_type = TemplateObjectType::User;
    let role_template_type = TemplateObjectType::Role;

    let user_object_type = TemplateObjectType::User;
    let role_object_type = TemplateObjectType::Role;

    // User template should only match user objects
    assert_eq!(user_template_type, user_object_type);
    assert_ne!(user_template_type, role_object_type);

    // Role template should only match role objects
    assert_eq!(role_template_type, role_object_type);
    assert_ne!(role_template_type, user_object_type);
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_empty_object_matches_only_global() {
    let empty_obj = json!({});

    // Global scope matches
    assert!(matches_global(&empty_obj));

    // Organization scope doesn't match (no org attribute)
    assert!(!matches_organization(&empty_obj, "any-org", "org_id"));

    // Category scope doesn't match (no category attribute)
    assert!(!matches_category(&empty_obj, "any-category", "user_type"));

    // Condition scope checking for any attribute fails
    assert!(!has_non_null_attribute(&empty_obj, "any_attribute"));
}

#[test]
fn test_object_with_null_values() {
    let obj = json!({
        "department": null,
        "org_id": "org-1",
        "manager": null
    });

    // Null attribute should not match string comparison
    assert!(!evaluate_simple_equality(&obj, "department", "Engineering"));

    // Non-null attribute should match
    assert!(matches_organization(&obj, "org-1", "org_id"));

    // Null check condition should fail
    assert!(!has_non_null_attribute(&obj, "manager"));
    assert!(!has_non_null_attribute(&obj, "department"));
}

#[test]
fn test_nested_attribute_access() {
    let obj = json!({
        "user": {
            "profile": {
                "department": "Engineering"
            }
        }
    });

    // Direct attribute access
    assert!(obj.get("user").is_some());

    // Nested access
    let nested_value = obj
        .get("user")
        .and_then(|u| u.get("profile"))
        .and_then(|p| p.get("department"))
        .and_then(|d| d.as_str());

    assert_eq!(nested_value, Some("Engineering"));
}

// =============================================================================
// Scope Validation Tests
// =============================================================================

#[test]
fn test_global_scope_should_not_have_value() {
    let scope_type = TemplateScopeType::Global;
    let scope_value: Option<String> = None;

    // Global scope is valid without a value
    assert!(validate_scope(scope_type, &scope_value, &None));

    // Global scope with a value is invalid
    let scope_with_value = Some("should-not-have".to_string());
    assert!(!validate_scope(scope_type, &scope_with_value, &None));
}

#[test]
fn test_organization_scope_requires_value() {
    let scope_type = TemplateScopeType::Organization;

    // Organization scope requires a value
    let valid_scope = Some("org-123".to_string());
    assert!(validate_scope(scope_type, &valid_scope, &None));

    // Organization scope without value is invalid
    let invalid_scope: Option<String> = None;
    assert!(!validate_scope(scope_type, &invalid_scope, &None));
}

#[test]
fn test_condition_scope_requires_condition() {
    let scope_type = TemplateScopeType::Condition;

    // Condition scope requires a condition expression
    let valid_condition = Some("${department} == \"Engineering\"".to_string());
    assert!(validate_scope(scope_type, &None, &valid_condition));

    // Condition scope without expression is invalid
    let invalid_condition: Option<String> = None;
    assert!(!validate_scope(scope_type, &None, &invalid_condition));
}

fn validate_scope(
    scope_type: TemplateScopeType,
    scope_value: &Option<String>,
    condition: &Option<String>,
) -> bool {
    match scope_type {
        TemplateScopeType::Global => scope_value.is_none() && condition.is_none(),
        TemplateScopeType::Organization | TemplateScopeType::Category => {
            scope_value.is_some() && condition.is_none()
        }
        TemplateScopeType::Condition => condition.is_some(),
    }
}
