//! Integration tests for TemplateExpressionService (F058).
//!
//! These tests verify the expression parsing and evaluation functionality
//! beyond the unit tests included in the service module.

use serde_json::Value;
use std::collections::HashMap;
use xavyo_api_governance::services::TemplateExpressionService;

fn service() -> TemplateExpressionService {
    TemplateExpressionService::new()
}

fn user_context() -> HashMap<String, Value> {
    let mut ctx = HashMap::new();
    ctx.insert("id".to_string(), Value::String("12345".to_string()));
    ctx.insert("first_name".to_string(), Value::String("Alice".to_string()));
    ctx.insert(
        "last_name".to_string(),
        Value::String("Johnson".to_string()),
    );
    ctx.insert(
        "email".to_string(),
        Value::String("alice.johnson@acme.com".to_string()),
    );
    ctx.insert(
        "department".to_string(),
        Value::String("Engineering".to_string()),
    );
    ctx.insert(
        "title".to_string(),
        Value::String("Senior Engineer".to_string()),
    );
    ctx.insert(
        "employee_type".to_string(),
        Value::String("full_time".to_string()),
    );
    ctx.insert("manager_id".to_string(), Value::String("67890".to_string()));
    ctx.insert(
        "location".to_string(),
        Value::String("New York".to_string()),
    );
    ctx.insert("phone".to_string(), Value::Null);
    ctx
}

// ============================================================
// Display Name Computation Tests (Common Use Case)
// ============================================================

#[test]
fn test_compute_display_name_from_first_last() {
    let svc = service();
    let ctx = user_context();
    let expr = svc.parse("${first_name} + \" \" + ${last_name}").unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::String("Alice Johnson".to_string()));
}

#[test]
fn test_compute_display_name_last_first_format() {
    let svc = service();
    let ctx = user_context();
    let expr = svc.parse("${last_name} + \", \" + ${first_name}").unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::String("Johnson, Alice".to_string()));
}

// ============================================================
// Email Generation Tests
// ============================================================

#[test]
fn test_generate_email_from_name() {
    let svc = service();
    let ctx = user_context();
    let expr = svc
        .parse("lowercase(${first_name}) + \".\" + lowercase(${last_name}) + \"@company.com\"")
        .unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(
        result,
        Value::String("alice.johnson@company.com".to_string())
    );
}

#[test]
fn test_validate_email_format() {
    let svc = service();
    let ctx = user_context();
    let expr = svc
        .parse("matches(${email}, \"^[a-z.]+@[a-z]+\\\\.[a-z]+$\")")
        .unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn test_validate_email_domain() {
    let svc = service();
    let ctx = user_context();
    let expr = svc.parse("ends_with(${email}, \"@acme.com\")").unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

// ============================================================
// Employee Type Conditional Logic
// ============================================================

#[test]
fn test_employee_type_prefix() {
    let svc = service();
    let ctx = user_context();
    let expr = svc.parse(
        "if(${employee_type} == \"full_time\", \"EMP\", if(${employee_type} == \"contractor\", \"CTR\", \"OTH\"))"
    ).unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::String("EMP".to_string()));
}

#[test]
fn test_contractor_prefix() {
    let svc = service();
    let mut ctx = user_context();
    ctx.insert(
        "employee_type".to_string(),
        Value::String("contractor".to_string()),
    );
    let expr = svc.parse(
        "if(${employee_type} == \"full_time\", \"EMP\", if(${employee_type} == \"contractor\", \"CTR\", \"OTH\"))"
    ).unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::String("CTR".to_string()));
}

#[test]
fn test_employee_id_generation() {
    let svc = service();
    let ctx = user_context();
    let expr = svc
        .parse("if(${employee_type} == \"full_time\", \"EMP-\", \"CTR-\") + ${id}")
        .unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::String("EMP-12345".to_string()));
}

// ============================================================
// Null/Default Value Handling
// ============================================================

#[test]
fn test_coalesce_null_phone() {
    let svc = service();
    let ctx = user_context();
    let expr = svc.parse("coalesce(${phone}, \"Not Provided\")").unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::String("Not Provided".to_string()));
}

#[test]
fn test_coalesce_with_existing_value() {
    let svc = service();
    let ctx = user_context();
    let expr = svc.parse("coalesce(${department}, \"Unknown\")").unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::String("Engineering".to_string()));
}

#[test]
fn test_is_null_check() {
    let svc = service();
    let ctx = user_context();

    let expr = svc.parse("is_null(${phone})").unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));

    let expr = svc.parse("is_null(${email})").unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::Bool(false));
}

#[test]
fn test_conditional_on_null() {
    let svc = service();
    let ctx = user_context();
    let expr = svc
        .parse("if(is_null(${phone}), \"Contact via email: \" + ${email}, \"Phone: \" + ${phone})")
        .unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(
        result,
        Value::String("Contact via email: alice.johnson@acme.com".to_string())
    );
}

// ============================================================
// String Normalization Tests
// ============================================================

#[test]
fn test_normalize_email_lowercase() {
    let svc = service();
    let mut ctx = HashMap::new();
    ctx.insert(
        "email".to_string(),
        Value::String("ALICE.JOHNSON@ACME.COM".to_string()),
    );
    let expr = svc.parse("lowercase(${email})").unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::String("alice.johnson@acme.com".to_string()));
}

#[test]
fn test_trim_whitespace() {
    let svc = service();
    let mut ctx = HashMap::new();
    ctx.insert(
        "name".to_string(),
        Value::String("  Alice Johnson  ".to_string()),
    );
    let expr = svc.parse("trim(${name})").unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::String("Alice Johnson".to_string()));
}

#[test]
fn test_normalize_department_code() {
    let svc = service();
    let ctx = user_context();
    let expr = svc
        .parse("uppercase(substring(${department}, 0, 3))")
        .unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::String("ENG".to_string()));
}

// ============================================================
// Validation Expression Tests
// ============================================================

#[test]
fn test_validate_name_length() {
    let svc = service();
    let ctx = user_context();
    let expr = svc
        .parse("length(${first_name}) >= 2 && length(${first_name}) <= 50")
        .unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn test_validate_name_too_short() {
    let svc = service();
    let mut ctx = HashMap::new();
    ctx.insert("first_name".to_string(), Value::String("A".to_string()));
    let expr = svc.parse("length(${first_name}) >= 2").unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::Bool(false));
}

#[test]
fn test_validate_department_in_list() {
    let svc = service();
    let ctx = user_context();
    let expr = svc.parse(
        "${department} == \"Engineering\" || ${department} == \"Sales\" || ${department} == \"Marketing\""
    ).unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn test_validate_id_format() {
    let svc = service();
    let ctx = user_context();
    let expr = svc.parse("matches(${id}, \"^[0-9]+$\")").unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

// ============================================================
// Complex Business Rule Tests
// ============================================================

#[test]
fn test_complex_access_badge_id() {
    let svc = service();
    let ctx = user_context();
    // Badge ID: Department code (first 3 chars uppercase) + "-" + employee type prefix + "-" + ID
    let expr = svc.parse(
        "uppercase(substring(${department}, 0, 3)) + \"-\" + if(${employee_type} == \"full_time\", \"E\", \"C\") + \"-\" + ${id}"
    ).unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::String("ENG-E-12345".to_string()));
}

#[test]
fn test_manager_required_for_full_time() {
    let svc = service();
    let ctx = user_context();
    // Full-time employees must have a manager
    let expr = svc
        .parse("${employee_type} != \"full_time\" || !is_null(${manager_id})")
        .unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn test_manager_required_fails_when_null() {
    let svc = service();
    let mut ctx = user_context();
    ctx.insert("manager_id".to_string(), Value::Null);
    // Full-time employees must have a manager
    let expr = svc
        .parse("${employee_type} != \"full_time\" || !is_null(${manager_id})")
        .unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::Bool(false));
}

// ============================================================
// String Manipulation Functions
// ============================================================

#[test]
fn test_replace_domain_in_email() {
    let svc = service();
    let ctx = user_context();
    let expr = svc
        .parse("replace(${email}, \"@acme.com\", \"@newacme.com\")")
        .unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(
        result,
        Value::String("alice.johnson@newacme.com".to_string())
    );
}

#[test]
fn test_extract_username_from_email() {
    let svc = service();
    let ctx = user_context();
    // Split email by @ and take first part
    let expr = svc
        .parse("substring(${email}, 0, length(${email}) - length(\"@acme.com\"))")
        .unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::String("alice.johnson".to_string()));
}

#[test]
fn test_contains_check() {
    let svc = service();
    let ctx = user_context();
    let expr = svc.parse("contains(${title}, \"Engineer\")").unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn test_starts_with_check() {
    let svc = service();
    let ctx = user_context();
    let expr = svc.parse("starts_with(${title}, \"Senior\")").unwrap();
    let result = svc.evaluate(&expr, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

// ============================================================
// Circular Dependency Detection Tests
// ============================================================

#[test]
fn test_detect_direct_cycle() {
    let svc = service();
    let mut expressions = HashMap::new();
    expressions.insert("a".to_string(), "${b}".to_string());
    expressions.insert("b".to_string(), "${a}".to_string());

    let result = svc.detect_cycles(&expressions);
    assert!(result.is_err());
}

#[test]
fn test_detect_indirect_cycle() {
    let svc = service();
    let mut expressions = HashMap::new();
    expressions.insert("a".to_string(), "${b}".to_string());
    expressions.insert("b".to_string(), "${c}".to_string());
    expressions.insert("c".to_string(), "${a}".to_string());

    let result = svc.detect_cycles(&expressions);
    assert!(result.is_err());
}

#[test]
fn test_no_cycle_valid_dependency_chain() {
    let svc = service();
    let mut expressions = HashMap::new();
    expressions.insert(
        "display_name".to_string(),
        "${first_name} + \" \" + ${last_name}".to_string(),
    );
    expressions.insert(
        "email".to_string(),
        "lowercase(${first_name}) + \".\" + lowercase(${last_name}) + \"@company.com\"".to_string(),
    );
    expressions.insert("badge_id".to_string(), "\"ID-\" + ${id}".to_string());

    let result = svc.detect_cycles(&expressions);
    assert!(result.is_ok());
}

#[test]
fn test_cycle_detection_with_dependencies() {
    let svc = service();
    let mut expressions = HashMap::new();
    // display_name depends on fullName
    // fullName is computed from first_name + last_name (external)
    // greeting depends on display_name
    expressions.insert(
        "fullName".to_string(),
        "${first_name} + \" \" + ${last_name}".to_string(),
    );
    expressions.insert(
        "greeting".to_string(),
        "\"Hello, \" + ${fullName}".to_string(),
    );

    let result = svc.detect_cycles(&expressions).unwrap();
    // fullName should come before greeting
    assert_eq!(result[0], "fullName");
    assert_eq!(result[1], "greeting");
}

// ============================================================
// Validation Function Tests
// ============================================================

#[test]
fn test_validate_extracts_all_references() {
    let svc = service();
    let refs = svc
        .validate("${first_name} + \" \" + ${last_name} + \" (\" + ${department} + \")\"")
        .unwrap();
    assert_eq!(refs.len(), 3);
    assert!(refs.contains("first_name"));
    assert!(refs.contains("last_name"));
    assert!(refs.contains("department"));
}

#[test]
fn test_validate_with_nested_functions() {
    let svc = service();
    let refs = svc.validate("uppercase(trim(${name}))").unwrap();
    assert_eq!(refs.len(), 1);
    assert!(refs.contains("name"));
}

#[test]
fn test_validate_with_if_expression() {
    let svc = service();
    let refs = svc
        .validate("if(${condition}, ${true_val}, ${false_val})")
        .unwrap();
    assert_eq!(refs.len(), 3);
    assert!(refs.contains("condition"));
    assert!(refs.contains("true_val"));
    assert!(refs.contains("false_val"));
}

// ============================================================
// Error Handling Tests
// ============================================================

#[test]
fn test_error_unknown_attribute() {
    let svc = service();
    let ctx = user_context();
    let expr = svc.parse("${nonexistent}").unwrap();
    let result = svc.evaluate(&expr, &ctx);
    assert!(result.is_err());
}

#[test]
fn test_error_unknown_function() {
    let svc = service();
    let result = svc.parse("unknown_func(${name})");
    assert!(result.is_err());
}

#[test]
fn test_error_invalid_regex() {
    let svc = service();
    let ctx = user_context();
    let expr = svc.parse("matches(${email}, \"[\")").unwrap();
    let result = svc.evaluate(&expr, &ctx);
    assert!(result.is_err());
}

#[test]
fn test_error_division_by_zero() {
    let svc = service();
    let mut ctx = HashMap::new();
    ctx.insert("num".to_string(), serde_json::json!(10));
    let expr = svc.parse("${num} / 0").unwrap();
    let result = svc.evaluate(&expr, &ctx);
    assert!(result.is_err());
}

#[test]
fn test_error_wrong_argument_count() {
    let svc = service();
    let result = svc.parse("lowercase()");
    // This should fail during evaluation, not parsing
    if let Ok(expr) = result {
        let ctx = HashMap::new();
        let eval_result = svc.evaluate(&expr, &ctx);
        assert!(eval_result.is_err());
    }
}
