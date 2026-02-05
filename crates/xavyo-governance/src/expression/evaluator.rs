//! Expression evaluator against user attributes.
//!
//! Evaluates parsed filter expressions against user data.

use super::ast::{Comparison, ComparisonOp, Expression, Value};
use super::functions::{FunctionContext, FunctionError, FunctionRegistry};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

/// Error during expression evaluation.
#[derive(Debug, Clone)]
pub enum EvalError {
    /// Function evaluation error.
    Function(FunctionError),
    /// Type mismatch during comparison.
    TypeMismatch {
        attribute: String,
        expected: String,
        actual: String,
    },
    /// Unknown attribute.
    UnknownAttribute(String),
    /// Invalid pattern for LIKE operator.
    InvalidPattern(String),
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvalError::Function(e) => write!(f, "{e}"),
            EvalError::TypeMismatch {
                attribute,
                expected,
                actual,
            } => write!(
                f,
                "Type mismatch for '{attribute}': expected {expected}, got {actual}"
            ),
            EvalError::UnknownAttribute(attr) => write!(f, "Unknown attribute: {attr}"),
            EvalError::InvalidPattern(pat) => write!(f, "Invalid LIKE pattern: {pat}"),
        }
    }
}

impl std::error::Error for EvalError {}

impl From<FunctionError> for EvalError {
    fn from(err: FunctionError) -> Self {
        EvalError::Function(err)
    }
}

/// Context for evaluating expressions against user data.
pub struct EvalContext<'a> {
    /// User attributes as key-value pairs.
    pub attributes: HashMap<String, JsonValue>,
    /// Function evaluation context.
    pub function_context: FunctionContext<'a>,
}

impl<'a> EvalContext<'a> {
    /// Create a new evaluation context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            attributes: HashMap::new(),
            function_context: FunctionContext::new(),
        }
    }

    /// Set an attribute value.
    #[must_use]
    pub fn with_attribute(mut self, name: impl Into<String>, value: impl Into<JsonValue>) -> Self {
        self.attributes.insert(name.into(), value.into());
        self
    }

    /// Set multiple attributes from a HashMap.
    #[must_use]
    pub fn with_attributes(mut self, attrs: HashMap<String, JsonValue>) -> Self {
        self.attributes.extend(attrs);
        self
    }

    /// Set the function context.
    #[must_use]
    pub fn with_function_context(mut self, ctx: FunctionContext<'a>) -> Self {
        self.function_context = ctx;
        self
    }

    /// Build context from a user JSON object.
    #[must_use]
    pub fn from_json(json: &JsonValue) -> Self {
        let mut ctx = Self::new();
        if let Some(obj) = json.as_object() {
            for (key, value) in obj {
                ctx.attributes.insert(key.clone(), value.clone());
            }
        }
        ctx
    }
}

impl Default for EvalContext<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Expression evaluator.
pub struct Evaluator;

impl Evaluator {
    /// Evaluate an expression against a context.
    pub fn evaluate(expr: &Expression, ctx: &EvalContext<'_>) -> Result<bool, EvalError> {
        match expr {
            Expression::Comparison(comp) => Self::eval_comparison(comp, ctx),
            Expression::And(left, right) => {
                Ok(Self::evaluate(left, ctx)? && Self::evaluate(right, ctx)?)
            }
            Expression::Or(left, right) => {
                Ok(Self::evaluate(left, ctx)? || Self::evaluate(right, ctx)?)
            }
            Expression::Not(inner) => Ok(!Self::evaluate(inner, ctx)?),
            Expression::Group(inner) => Self::evaluate(inner, ctx),
            Expression::FunctionCall(func) => {
                let result =
                    FunctionRegistry::evaluate(&func.name, &func.arguments, &ctx.function_context)?;
                match result {
                    Value::Boolean(b) => Ok(b),
                    _ => Err(EvalError::TypeMismatch {
                        attribute: func.name.clone(),
                        expected: "boolean".to_string(),
                        actual: Self::value_type_name(&result),
                    }),
                }
            }
        }
    }

    fn eval_comparison(comp: &Comparison, ctx: &EvalContext<'_>) -> Result<bool, EvalError> {
        let attr_value = ctx.attributes.get(&comp.attribute);

        // Handle NULL comparisons specially
        if comp.value == Value::Null {
            return match comp.operator {
                ComparisonOp::Equal => {
                    Ok(attr_value.is_none() || attr_value.map_or(false, |v| v.is_null()))
                }
                ComparisonOp::NotEqual => {
                    Ok(attr_value.is_some() && attr_value.map_or(true, |v| !v.is_null()))
                }
                _ => Err(EvalError::TypeMismatch {
                    attribute: comp.attribute.clone(),
                    expected: "equality operator for NULL".to_string(),
                    actual: comp.operator.to_string(),
                }),
            };
        }

        // For non-NULL comparisons, attribute must exist
        let attr_value = attr_value.ok_or_else(|| {
            // Treat missing attribute as NULL for comparison purposes
            EvalError::UnknownAttribute(comp.attribute.clone())
        })?;

        Self::compare_values(attr_value, &comp.operator, &comp.value, &comp.attribute)
    }

    fn compare_values(
        json_val: &JsonValue,
        op: &ComparisonOp,
        expr_val: &Value,
        attr_name: &str,
    ) -> Result<bool, EvalError> {
        match (json_val, expr_val) {
            // String comparisons
            (JsonValue::String(a), Value::String(b)) => Self::compare_strings(a, b, op, attr_name),

            // Integer comparisons
            (JsonValue::Number(n), Value::Integer(b)) if n.is_i64() => {
                Self::compare_integers(n.as_i64().unwrap(), *b, op)
            }
            (JsonValue::Number(n), Value::Integer(b)) if n.is_u64() => {
                let a = n.as_u64().unwrap();
                if a > i64::MAX as u64 {
                    // Large positive numbers
                    match op {
                        ComparisonOp::Equal => Ok(false),
                        ComparisonOp::NotEqual => Ok(true),
                        ComparisonOp::GreaterThan | ComparisonOp::GreaterThanOrEqual => Ok(true),
                        ComparisonOp::LessThan | ComparisonOp::LessThanOrEqual => Ok(false),
                        _ => Err(EvalError::TypeMismatch {
                            attribute: attr_name.to_string(),
                            expected: "comparable number".to_string(),
                            actual: "large integer".to_string(),
                        }),
                    }
                } else {
                    Self::compare_integers(a as i64, *b, op)
                }
            }

            // Float comparisons
            (JsonValue::Number(n), Value::Float(b)) => {
                let a = n.as_f64().unwrap_or(0.0);
                Self::compare_floats(a, *b, op)
            }
            (JsonValue::Number(n), Value::Integer(b)) if n.is_f64() => {
                let a = n.as_f64().unwrap();
                Self::compare_floats(a, *b as f64, op)
            }

            // Boolean comparisons
            (JsonValue::Bool(a), Value::Boolean(b)) => match op {
                ComparisonOp::Equal => Ok(*a == *b),
                ComparisonOp::NotEqual => Ok(*a != *b),
                _ => Err(EvalError::TypeMismatch {
                    attribute: attr_name.to_string(),
                    expected: "equality operator for boolean".to_string(),
                    actual: op.to_string(),
                }),
            },

            // IN operator with list
            (json_val, Value::List(items)) if *op == ComparisonOp::In => {
                for item in items {
                    if Self::values_equal(json_val, item) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }

            // Null comparisons
            (JsonValue::Null, Value::Null) => match op {
                ComparisonOp::Equal => Ok(true),
                ComparisonOp::NotEqual => Ok(false),
                _ => Err(EvalError::TypeMismatch {
                    attribute: attr_name.to_string(),
                    expected: "equality operator for NULL".to_string(),
                    actual: op.to_string(),
                }),
            },

            // Type mismatch
            (json_val, expr_val) => Err(EvalError::TypeMismatch {
                attribute: attr_name.to_string(),
                expected: Self::value_type_name(expr_val),
                actual: Self::json_type_name(json_val),
            }),
        }
    }

    fn compare_strings(
        a: &str,
        b: &str,
        op: &ComparisonOp,
        attr_name: &str,
    ) -> Result<bool, EvalError> {
        match op {
            ComparisonOp::Equal => Ok(a == b),
            ComparisonOp::NotEqual => Ok(a != b),
            ComparisonOp::LessThan => Ok(a < b),
            ComparisonOp::GreaterThan => Ok(a > b),
            ComparisonOp::LessThanOrEqual => Ok(a <= b),
            ComparisonOp::GreaterThanOrEqual => Ok(a >= b),
            ComparisonOp::Like => Self::like_match(a, b),
            ComparisonOp::In => Err(EvalError::TypeMismatch {
                attribute: attr_name.to_string(),
                expected: "list for IN operator".to_string(),
                actual: "string".to_string(),
            }),
        }
    }

    fn compare_integers(a: i64, b: i64, op: &ComparisonOp) -> Result<bool, EvalError> {
        Ok(match op {
            ComparisonOp::Equal => a == b,
            ComparisonOp::NotEqual => a != b,
            ComparisonOp::LessThan => a < b,
            ComparisonOp::GreaterThan => a > b,
            ComparisonOp::LessThanOrEqual => a <= b,
            ComparisonOp::GreaterThanOrEqual => a >= b,
            ComparisonOp::Like | ComparisonOp::In => {
                return Err(EvalError::TypeMismatch {
                    attribute: "integer".to_string(),
                    expected: "comparable value".to_string(),
                    actual: op.to_string(),
                })
            }
        })
    }

    fn compare_floats(a: f64, b: f64, op: &ComparisonOp) -> Result<bool, EvalError> {
        Ok(match op {
            ComparisonOp::Equal => (a - b).abs() < f64::EPSILON,
            ComparisonOp::NotEqual => (a - b).abs() >= f64::EPSILON,
            ComparisonOp::LessThan => a < b,
            ComparisonOp::GreaterThan => a > b,
            ComparisonOp::LessThanOrEqual => a <= b,
            ComparisonOp::GreaterThanOrEqual => a >= b,
            ComparisonOp::Like | ComparisonOp::In => {
                return Err(EvalError::TypeMismatch {
                    attribute: "float".to_string(),
                    expected: "comparable value".to_string(),
                    actual: op.to_string(),
                })
            }
        })
    }

    fn like_match(value: &str, pattern: &str) -> Result<bool, EvalError> {
        // Convert SQL LIKE pattern to regex
        // % matches any sequence of characters
        // _ matches any single character
        let mut regex_pattern = String::from("^");
        let mut chars = pattern.chars().peekable();

        while let Some(c) = chars.next() {
            match c {
                '%' => regex_pattern.push_str(".*"),
                '_' => regex_pattern.push('.'),
                '\\' => {
                    // Handle escaped characters
                    if let Some(next) = chars.next() {
                        regex_pattern.push_str(&regex::escape(&next.to_string()));
                    }
                }
                // Escape regex special characters
                c => regex_pattern.push_str(&regex::escape(&c.to_string())),
            }
        }

        regex_pattern.push('$');

        regex::Regex::new(&regex_pattern)
            .map_err(|_| EvalError::InvalidPattern(pattern.to_string()))?
            .is_match(value)
            .then_some(true)
            .ok_or_else(|| EvalError::InvalidPattern(pattern.to_string()))
            .or(Ok(regex::Regex::new(&regex_pattern)
                .unwrap()
                .is_match(value)))
    }

    fn values_equal(json_val: &JsonValue, expr_val: &Value) -> bool {
        match (json_val, expr_val) {
            (JsonValue::String(a), Value::String(b)) => a == b,
            (JsonValue::Number(n), Value::Integer(b)) => n.as_i64().map_or(false, |a| a == *b),
            (JsonValue::Number(n), Value::Float(b)) => {
                n.as_f64().map_or(false, |a| (a - b).abs() < f64::EPSILON)
            }
            (JsonValue::Bool(a), Value::Boolean(b)) => *a == *b,
            (JsonValue::Null, Value::Null) => true,
            _ => false,
        }
    }

    fn value_type_name(v: &Value) -> String {
        match v {
            Value::String(_) => "string".to_string(),
            Value::Integer(_) => "integer".to_string(),
            Value::Float(_) => "float".to_string(),
            Value::Boolean(_) => "boolean".to_string(),
            Value::Null => "null".to_string(),
            Value::List(_) => "list".to_string(),
        }
    }

    fn json_type_name(v: &JsonValue) -> String {
        match v {
            JsonValue::Null => "null".to_string(),
            JsonValue::Bool(_) => "boolean".to_string(),
            JsonValue::Number(_) => "number".to_string(),
            JsonValue::String(_) => "string".to_string(),
            JsonValue::Array(_) => "array".to_string(),
            JsonValue::Object(_) => "object".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expression::parser::Parser;

    fn eval(expr_str: &str, ctx: &EvalContext<'_>) -> Result<bool, EvalError> {
        let expr = Parser::parse(expr_str).expect("Parse failed");
        Evaluator::evaluate(&expr, ctx)
    }

    #[test]
    fn test_simple_string_equality() {
        let ctx = EvalContext::new().with_attribute("department", "engineering");
        assert!(eval("department = 'engineering'", &ctx).unwrap());
        assert!(!eval("department = 'sales'", &ctx).unwrap());
    }

    #[test]
    fn test_string_not_equal() {
        let ctx = EvalContext::new().with_attribute("status", "active");
        assert!(eval("status != 'inactive'", &ctx).unwrap());
        assert!(!eval("status != 'active'", &ctx).unwrap());
    }

    #[test]
    fn test_integer_comparison() {
        let ctx = EvalContext::new().with_attribute("age", 25);
        assert!(eval("age = 25", &ctx).unwrap());
        assert!(eval("age > 20", &ctx).unwrap());
        assert!(eval("age >= 25", &ctx).unwrap());
        assert!(eval("age < 30", &ctx).unwrap());
        assert!(eval("age <= 25", &ctx).unwrap());
        assert!(!eval("age > 25", &ctx).unwrap());
    }

    #[test]
    fn test_boolean_comparison() {
        let ctx = EvalContext::new().with_attribute("active", true);
        assert!(eval("active = true", &ctx).unwrap());
        assert!(!eval("active = false", &ctx).unwrap());
    }

    #[test]
    fn test_null_comparison() {
        let ctx = EvalContext::new().with_attribute("manager", JsonValue::Null);
        assert!(eval("manager = NULL", &ctx).unwrap());

        let ctx2 = EvalContext::new().with_attribute("manager", "John");
        assert!(!eval("manager = NULL", &ctx2).unwrap());
        assert!(eval("manager != NULL", &ctx2).unwrap());
    }

    #[test]
    fn test_missing_attribute_as_null() {
        let ctx = EvalContext::new();
        // Missing attribute should return error
        let result = eval("unknown_attr = 'value'", &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_and_expression() {
        let ctx = EvalContext::new()
            .with_attribute("department", "engineering")
            .with_attribute("active", true);

        assert!(eval("department = 'engineering' AND active = true", &ctx).unwrap());
        assert!(!eval("department = 'engineering' AND active = false", &ctx).unwrap());
    }

    #[test]
    fn test_or_expression() {
        let ctx = EvalContext::new()
            .with_attribute("department", "engineering")
            .with_attribute("level", 5);

        assert!(eval("department = 'sales' OR level > 3", &ctx).unwrap());
        assert!(!eval("department = 'sales' OR level < 3", &ctx).unwrap());
    }

    #[test]
    fn test_not_expression() {
        let ctx = EvalContext::new().with_attribute("active", false);
        assert!(eval("NOT active = true", &ctx).unwrap());
        assert!(!eval("NOT active = false", &ctx).unwrap());
    }

    #[test]
    fn test_like_operator() {
        let ctx = EvalContext::new().with_attribute("email", "john@example.com");
        assert!(eval("email LIKE '%@example.com'", &ctx).unwrap());
        assert!(eval("email LIKE 'john%'", &ctx).unwrap());
        assert!(eval("email LIKE '%example%'", &ctx).unwrap());
        assert!(!eval("email LIKE '%@gmail.com'", &ctx).unwrap());
    }

    #[test]
    fn test_in_operator() {
        let ctx = EvalContext::new().with_attribute("status", "active");
        assert!(eval("status IN ('active', 'pending')", &ctx).unwrap());
        assert!(!eval("status IN ('inactive', 'deleted')", &ctx).unwrap());
    }

    #[test]
    fn test_in_operator_with_numbers() {
        let ctx = EvalContext::new().with_attribute("level", 3);
        assert!(eval("level IN (1, 2, 3)", &ctx).unwrap());
        assert!(!eval("level IN (4, 5, 6)", &ctx).unwrap());
    }

    #[test]
    fn test_complex_expression() {
        let ctx = EvalContext::new()
            .with_attribute("department", "engineering")
            .with_attribute("level", 5)
            .with_attribute("active", true);

        let result =
            eval("(department = 'engineering' OR department = 'product') AND level >= 3 AND active = true", &ctx)
                .unwrap();
        assert!(result);
    }

    #[test]
    fn test_has_role_function() {
        let role_names = vec!["developer".to_string(), "admin".to_string()];
        let func_ctx = FunctionContext::new().with_roles(&[], &role_names);
        let ctx = EvalContext::new().with_function_context(func_ctx);

        assert!(eval("has_role('developer')", &ctx).unwrap());
        assert!(eval("has_role('admin')", &ctx).unwrap());
        assert!(!eval("has_role('manager')", &ctx).unwrap());
    }

    #[test]
    fn test_not_has_role() {
        let role_names = vec!["developer".to_string()];
        let func_ctx = FunctionContext::new().with_roles(&[], &role_names);
        let ctx = EvalContext::new().with_function_context(func_ctx);

        assert!(eval("NOT has_role('admin')", &ctx).unwrap());
        assert!(!eval("NOT has_role('developer')", &ctx).unwrap());
    }

    #[test]
    fn test_combined_with_function() {
        let role_names = vec!["developer".to_string()];
        let func_ctx = FunctionContext::new().with_roles(&[], &role_names);
        let ctx = EvalContext::new()
            .with_attribute("department", "engineering")
            .with_attribute("active", true)
            .with_function_context(func_ctx);

        assert!(eval(
            "department = 'engineering' AND active = true AND NOT has_role('admin')",
            &ctx
        )
        .unwrap());
    }

    #[test]
    fn test_float_comparison() {
        let ctx = EvalContext::new().with_attribute("risk_score", 3.14);
        assert!(eval("risk_score > 3.0", &ctx).unwrap());
        assert!(eval("risk_score < 4.0", &ctx).unwrap());
    }

    #[test]
    fn test_type_mismatch_error() {
        let ctx = EvalContext::new().with_attribute("name", "John");
        let result = eval("name > 10", &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_json() {
        let json = serde_json::json!({
            "department": "engineering",
            "level": 5,
            "active": true
        });
        let ctx = EvalContext::from_json(&json);

        assert!(eval("department = 'engineering'", &ctx).unwrap());
        assert!(eval("level > 3", &ctx).unwrap());
        assert!(eval("active = true", &ctx).unwrap());
    }

    #[test]
    fn test_parentheses_grouping() {
        let ctx = EvalContext::new()
            .with_attribute("a", 1)
            .with_attribute("b", 2)
            .with_attribute("c", 3);

        // Without parens: a = 1 OR (b = 2 AND c = 0) = true OR false = true
        assert!(eval("a = 1 OR b = 2 AND c = 0", &ctx).unwrap());

        // With parens: (a = 1 OR b = 2) AND c = 0 = true AND false = false
        assert!(!eval("(a = 1 OR b = 2) AND c = 0", &ctx).unwrap());
    }
}
