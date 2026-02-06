//! Attribute-Based Access Control (ABAC) condition evaluator.
//!
//! Evaluates user attribute conditions against JSON attribute values.
//! Used by the policy evaluator to check `user_attribute` conditions.

/// Evaluates an ABAC condition against user attributes.
///
/// # Arguments
///
/// * `user_attributes` - The user's `custom_attributes` JSONB value
/// * `attribute_path` - Path to the attribute (e.g., "department")
/// * `operator` - Comparison operator as string (e.g., "equals", "`not_equals`")
/// * `value` - Expected value from the condition
///
/// # Returns
///
/// `false` if the attribute is missing (fail-safe: missing data = not satisfied).
#[must_use]
pub fn evaluate_abac_condition(
    user_attributes: &serde_json::Value,
    attribute_path: &str,
    operator: &str,
    value: &serde_json::Value,
) -> bool {
    let user_value = user_attributes.get(attribute_path);

    match user_value {
        None => false, // Missing attribute = condition not satisfied (fail-safe)
        Some(user_val) => match operator {
            "equals" => user_val == value,
            "not_equals" => user_val != value,
            "contains" => {
                // Check if user_val (string) contains value (string)
                match (user_val.as_str(), value.as_str()) {
                    (Some(u), Some(v)) => u.contains(v),
                    _ => false,
                }
            }
            "in_list" => {
                // Check if user_val is in the value array
                match value.as_array() {
                    Some(list) => list.contains(user_val),
                    None => false,
                }
            }
            "greater_than" => compare_values(user_val, value, |a, b| a > b),
            "less_than" => compare_values(user_val, value, |a, b| a < b),
            _ => false, // Unknown operator = condition not satisfied
        },
    }
}

/// Compare two JSON values numerically using the given comparison function.
fn compare_values(a: &serde_json::Value, b: &serde_json::Value, cmp: fn(f64, f64) -> bool) -> bool {
    let a_num = value_to_f64(a);
    let b_num = value_to_f64(b);
    match (a_num, b_num) {
        (Some(a), Some(b)) => cmp(a, b),
        _ => false,
    }
}

/// Attempt to convert a JSON value to f64.
/// Supports: number, integer, or string that parses to a number.
fn value_to_f64(v: &serde_json::Value) -> Option<f64> {
    v.as_f64()
        .or_else(|| v.as_i64().map(|i| i as f64))
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_equals_string() {
        let attrs = json!({"department": "engineering"});
        assert!(evaluate_abac_condition(
            &attrs,
            "department",
            "equals",
            &json!("engineering")
        ));
        assert!(!evaluate_abac_condition(
            &attrs,
            "department",
            "equals",
            &json!("marketing")
        ));
    }

    #[test]
    fn test_equals_number() {
        let attrs = json!({"level": 5});
        assert!(evaluate_abac_condition(
            &attrs,
            "level",
            "equals",
            &json!(5)
        ));
        assert!(!evaluate_abac_condition(
            &attrs,
            "level",
            "equals",
            &json!(3)
        ));
    }

    #[test]
    fn test_not_equals() {
        let attrs = json!({"department": "engineering"});
        assert!(evaluate_abac_condition(
            &attrs,
            "department",
            "not_equals",
            &json!("marketing")
        ));
        assert!(!evaluate_abac_condition(
            &attrs,
            "department",
            "not_equals",
            &json!("engineering")
        ));
    }

    #[test]
    fn test_contains() {
        let attrs = json!({"email": "alice@example.com"});
        assert!(evaluate_abac_condition(
            &attrs,
            "email",
            "contains",
            &json!("@example.com")
        ));
        assert!(!evaluate_abac_condition(
            &attrs,
            "email",
            "contains",
            &json!("@other.com")
        ));
    }

    #[test]
    fn test_in_list() {
        let attrs = json!({"role": "admin"});
        assert!(evaluate_abac_condition(
            &attrs,
            "role",
            "in_list",
            &json!(["admin", "superadmin"])
        ));
        assert!(!evaluate_abac_condition(
            &attrs,
            "role",
            "in_list",
            &json!(["viewer", "editor"])
        ));
    }

    #[test]
    fn test_greater_than() {
        let attrs = json!({"clearance": 7});
        assert!(evaluate_abac_condition(
            &attrs,
            "clearance",
            "greater_than",
            &json!(5)
        ));
        assert!(!evaluate_abac_condition(
            &attrs,
            "clearance",
            "greater_than",
            &json!(10)
        ));
    }

    #[test]
    fn test_less_than() {
        let attrs = json!({"risk_score": 3.5});
        assert!(evaluate_abac_condition(
            &attrs,
            "risk_score",
            "less_than",
            &json!(5.0)
        ));
        assert!(!evaluate_abac_condition(
            &attrs,
            "risk_score",
            "less_than",
            &json!(2.0)
        ));
    }

    #[test]
    fn test_greater_than_string_numbers() {
        let attrs = json!({"score": "42"});
        assert!(evaluate_abac_condition(
            &attrs,
            "score",
            "greater_than",
            &json!("10")
        ));
    }

    #[test]
    fn test_missing_attribute_returns_false() {
        let attrs = json!({"department": "engineering"});
        assert!(!evaluate_abac_condition(
            &attrs,
            "nonexistent",
            "equals",
            &json!("anything")
        ));
    }

    #[test]
    fn test_unknown_operator_returns_false() {
        let attrs = json!({"department": "engineering"});
        assert!(!evaluate_abac_condition(
            &attrs,
            "department",
            "unknown_op",
            &json!("engineering")
        ));
    }

    #[test]
    fn test_contains_non_string_returns_false() {
        let attrs = json!({"level": 5});
        assert!(!evaluate_abac_condition(
            &attrs,
            "level",
            "contains",
            &json!("5")
        ));
    }

    #[test]
    fn test_in_list_non_array_returns_false() {
        let attrs = json!({"role": "admin"});
        assert!(!evaluate_abac_condition(
            &attrs,
            "role",
            "in_list",
            &json!("admin")
        ));
    }

    #[test]
    fn test_compare_non_numeric_returns_false() {
        let attrs = json!({"name": "alice"});
        assert!(!evaluate_abac_condition(
            &attrs,
            "name",
            "greater_than",
            &json!("bob")
        ));
    }

    #[test]
    fn test_value_to_f64() {
        assert_eq!(value_to_f64(&json!(42)), Some(42.0));
        assert_eq!(value_to_f64(&json!(3.14)), Some(3.14));
        assert_eq!(value_to_f64(&json!("99")), Some(99.0));
        assert_eq!(value_to_f64(&json!("not_a_number")), None);
        assert_eq!(value_to_f64(&json!(null)), None);
        assert_eq!(value_to_f64(&json!(true)), None);
    }
}
