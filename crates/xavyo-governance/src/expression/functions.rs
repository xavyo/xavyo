//! Built-in functions for filter expressions.
//!
//! Provides implementations for expression functions like `has_role()` and `today()`.

use super::ast::Value;
use chrono::{NaiveDate, Utc};
use std::collections::HashMap;
use uuid::Uuid;

/// Error during function evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionError {
    /// Error message.
    pub message: String,
}

impl std::fmt::Display for FunctionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Function error: {}", self.message)
    }
}

impl std::error::Error for FunctionError {}

/// Context for evaluating functions.
pub struct FunctionContext<'a> {
    /// User's role IDs.
    pub user_roles: &'a [Uuid],
    /// User's role names (for has_role lookup).
    pub user_role_names: &'a [String],
    /// User's entitlement IDs.
    pub user_entitlements: &'a [Uuid],
    /// User's entitlement names (for has_entitlement lookup).
    pub user_entitlement_names: &'a [String],
    /// User's group IDs.
    pub user_groups: &'a [Uuid],
    /// User's group names (for in_group lookup).
    pub user_group_names: &'a [String],
    /// Additional context variables.
    pub variables: HashMap<String, Value>,
}

impl<'a> Default for FunctionContext<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> FunctionContext<'a> {
    /// Create a new empty function context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            user_roles: &[],
            user_role_names: &[],
            user_entitlements: &[],
            user_entitlement_names: &[],
            user_groups: &[],
            user_group_names: &[],
            variables: HashMap::new(),
        }
    }

    /// Set user roles.
    #[must_use]
    pub fn with_roles(mut self, role_ids: &'a [Uuid], role_names: &'a [String]) -> Self {
        self.user_roles = role_ids;
        self.user_role_names = role_names;
        self
    }

    /// Set user entitlements.
    #[must_use]
    pub fn with_entitlements(
        mut self,
        entitlement_ids: &'a [Uuid],
        entitlement_names: &'a [String],
    ) -> Self {
        self.user_entitlements = entitlement_ids;
        self.user_entitlement_names = entitlement_names;
        self
    }

    /// Set user groups.
    #[must_use]
    pub fn with_groups(mut self, group_ids: &'a [Uuid], group_names: &'a [String]) -> Self {
        self.user_groups = group_ids;
        self.user_group_names = group_names;
        self
    }

    /// Add a variable to the context.
    #[must_use]
    pub fn with_variable(mut self, name: impl Into<String>, value: Value) -> Self {
        self.variables.insert(name.into(), value);
        self
    }
}

/// Registry of built-in functions.
pub struct FunctionRegistry;

impl FunctionRegistry {
    /// Evaluate a function by name.
    pub fn evaluate(
        name: &str,
        args: &[Value],
        context: &FunctionContext<'_>,
    ) -> Result<Value, FunctionError> {
        match name.to_lowercase().as_str() {
            "has_role" => Self::has_role(args, context),
            "has_entitlement" => Self::has_entitlement(args, context),
            "in_group" => Self::in_group(args, context),
            "today" => Self::today(args),
            "now" => Self::now(args),
            "days_since" => Self::days_since(args),
            "days_until" => Self::days_until(args),
            _ => Err(FunctionError {
                message: format!("Unknown function: {name}"),
            }),
        }
    }

    /// Check if a function exists.
    #[must_use]
    pub fn exists(name: &str) -> bool {
        matches!(
            name.to_lowercase().as_str(),
            "has_role"
                | "has_entitlement"
                | "in_group"
                | "today"
                | "now"
                | "days_since"
                | "days_until"
        )
    }

    /// Get the list of supported function names.
    #[must_use]
    pub fn supported_functions() -> Vec<&'static str> {
        vec![
            "has_role",
            "has_entitlement",
            "in_group",
            "today",
            "now",
            "days_since",
            "days_until",
        ]
    }

    /// has_role(role_name) - Check if user has a role by name.
    fn has_role(args: &[Value], context: &FunctionContext<'_>) -> Result<Value, FunctionError> {
        if args.len() != 1 {
            return Err(FunctionError {
                message: "has_role() requires exactly 1 argument".to_string(),
            });
        }

        let role_name = match &args[0] {
            Value::String(s) => s.to_lowercase(),
            _ => {
                return Err(FunctionError {
                    message: "has_role() argument must be a string".to_string(),
                })
            }
        };

        let has_role = context
            .user_role_names
            .iter()
            .any(|r| r.to_lowercase() == role_name);

        Ok(Value::Boolean(has_role))
    }

    /// has_entitlement(entitlement_name) - Check if user has an entitlement by name.
    fn has_entitlement(
        args: &[Value],
        context: &FunctionContext<'_>,
    ) -> Result<Value, FunctionError> {
        if args.len() != 1 {
            return Err(FunctionError {
                message: "has_entitlement() requires exactly 1 argument".to_string(),
            });
        }

        let ent_name = match &args[0] {
            Value::String(s) => s.to_lowercase(),
            _ => {
                return Err(FunctionError {
                    message: "has_entitlement() argument must be a string".to_string(),
                })
            }
        };

        let has_ent = context
            .user_entitlement_names
            .iter()
            .any(|e| e.to_lowercase() == ent_name);

        Ok(Value::Boolean(has_ent))
    }

    /// in_group(group_name) - Check if user is in a group by name.
    fn in_group(args: &[Value], context: &FunctionContext<'_>) -> Result<Value, FunctionError> {
        if args.len() != 1 {
            return Err(FunctionError {
                message: "in_group() requires exactly 1 argument".to_string(),
            });
        }

        let group_name = match &args[0] {
            Value::String(s) => s.to_lowercase(),
            _ => {
                return Err(FunctionError {
                    message: "in_group() argument must be a string".to_string(),
                })
            }
        };

        let in_group = context
            .user_group_names
            .iter()
            .any(|g| g.to_lowercase() == group_name);

        Ok(Value::Boolean(in_group))
    }

    /// today() - Returns current date as a string (YYYY-MM-DD).
    fn today(args: &[Value]) -> Result<Value, FunctionError> {
        if !args.is_empty() {
            return Err(FunctionError {
                message: "today() takes no arguments".to_string(),
            });
        }

        let today = Utc::now().format("%Y-%m-%d").to_string();
        Ok(Value::String(today))
    }

    /// now() - Returns current datetime as ISO 8601 string.
    fn now(args: &[Value]) -> Result<Value, FunctionError> {
        if !args.is_empty() {
            return Err(FunctionError {
                message: "now() takes no arguments".to_string(),
            });
        }

        let now = Utc::now().to_rfc3339();
        Ok(Value::String(now))
    }

    /// days_since(date_string) - Returns number of days since the given date.
    fn days_since(args: &[Value]) -> Result<Value, FunctionError> {
        if args.len() != 1 {
            return Err(FunctionError {
                message: "days_since() requires exactly 1 argument".to_string(),
            });
        }

        let date_str = match &args[0] {
            Value::String(s) => s,
            _ => {
                return Err(FunctionError {
                    message: "days_since() argument must be a date string".to_string(),
                })
            }
        };

        let date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d").map_err(|_| FunctionError {
            message: format!("Invalid date format: {date_str} (expected YYYY-MM-DD)"),
        })?;

        let today = Utc::now().date_naive();
        let days = (today - date).num_days();

        Ok(Value::Integer(days))
    }

    /// days_until(date_string) - Returns number of days until the given date.
    fn days_until(args: &[Value]) -> Result<Value, FunctionError> {
        if args.len() != 1 {
            return Err(FunctionError {
                message: "days_until() requires exactly 1 argument".to_string(),
            });
        }

        let date_str = match &args[0] {
            Value::String(s) => s,
            _ => {
                return Err(FunctionError {
                    message: "days_until() argument must be a date string".to_string(),
                })
            }
        };

        let date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d").map_err(|_| FunctionError {
            message: format!("Invalid date format: {date_str} (expected YYYY-MM-DD)"),
        })?;

        let today = Utc::now().date_naive();
        let days = (date - today).num_days();

        Ok(Value::Integer(days))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_role_true() {
        let role_names = vec!["admin".to_string(), "developer".to_string()];
        let context = FunctionContext::new().with_roles(&[], &role_names);

        let result =
            FunctionRegistry::evaluate("has_role", &[Value::String("admin".into())], &context)
                .unwrap();
        assert_eq!(result, Value::Boolean(true));
    }

    #[test]
    fn test_has_role_false() {
        let role_names = vec!["developer".to_string()];
        let context = FunctionContext::new().with_roles(&[], &role_names);

        let result =
            FunctionRegistry::evaluate("has_role", &[Value::String("admin".into())], &context)
                .unwrap();
        assert_eq!(result, Value::Boolean(false));
    }

    #[test]
    fn test_has_role_case_insensitive() {
        let role_names = vec!["Admin".to_string()];
        let context = FunctionContext::new().with_roles(&[], &role_names);

        let result =
            FunctionRegistry::evaluate("has_role", &[Value::String("admin".into())], &context)
                .unwrap();
        assert_eq!(result, Value::Boolean(true));
    }

    #[test]
    fn test_has_role_wrong_args() {
        let context = FunctionContext::new();

        let result = FunctionRegistry::evaluate("has_role", &[], &context);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("1 argument"));
    }

    #[test]
    fn test_has_entitlement() {
        let ent_names = vec!["read_users".to_string(), "write_users".to_string()];
        let context = FunctionContext::new().with_entitlements(&[], &ent_names);

        let result = FunctionRegistry::evaluate(
            "has_entitlement",
            &[Value::String("read_users".into())],
            &context,
        )
        .unwrap();
        assert_eq!(result, Value::Boolean(true));
    }

    #[test]
    fn test_in_group() {
        let group_names = vec!["engineering".to_string()];
        let context = FunctionContext::new().with_groups(&[], &group_names);

        let result = FunctionRegistry::evaluate(
            "in_group",
            &[Value::String("engineering".into())],
            &context,
        )
        .unwrap();
        assert_eq!(result, Value::Boolean(true));
    }

    #[test]
    fn test_today() {
        let context = FunctionContext::new();
        let result = FunctionRegistry::evaluate("today", &[], &context).unwrap();

        match result {
            Value::String(s) => {
                // Should be in YYYY-MM-DD format
                assert!(s.len() == 10);
                assert!(s.chars().nth(4) == Some('-'));
                assert!(s.chars().nth(7) == Some('-'));
            }
            _ => panic!("Expected string"),
        }
    }

    #[test]
    fn test_today_no_args() {
        let context = FunctionContext::new();
        let result = FunctionRegistry::evaluate("today", &[Value::Integer(1)], &context);
        assert!(result.is_err());
    }

    #[test]
    fn test_now() {
        let context = FunctionContext::new();
        let result = FunctionRegistry::evaluate("now", &[], &context).unwrap();

        match result {
            Value::String(s) => {
                // Should be ISO 8601 format
                assert!(s.contains("T"));
                assert!(s.contains("+") || s.contains("Z"));
            }
            _ => panic!("Expected string"),
        }
    }

    #[test]
    fn test_days_since() {
        let context = FunctionContext::new();
        let yesterday = (Utc::now() - chrono::Duration::days(1))
            .format("%Y-%m-%d")
            .to_string();

        let result =
            FunctionRegistry::evaluate("days_since", &[Value::String(yesterday)], &context)
                .unwrap();
        assert_eq!(result, Value::Integer(1));
    }

    #[test]
    fn test_days_until() {
        let context = FunctionContext::new();
        let tomorrow = (Utc::now() + chrono::Duration::days(1))
            .format("%Y-%m-%d")
            .to_string();

        let result =
            FunctionRegistry::evaluate("days_until", &[Value::String(tomorrow)], &context).unwrap();
        assert_eq!(result, Value::Integer(1));
    }

    #[test]
    fn test_days_since_invalid_date() {
        let context = FunctionContext::new();
        let result =
            FunctionRegistry::evaluate("days_since", &[Value::String("invalid".into())], &context);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("Invalid date"));
    }

    #[test]
    fn test_unknown_function() {
        let context = FunctionContext::new();
        let result = FunctionRegistry::evaluate("unknown_func", &[], &context);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("Unknown function"));
    }

    #[test]
    fn test_function_exists() {
        assert!(FunctionRegistry::exists("has_role"));
        assert!(FunctionRegistry::exists("HAS_ROLE")); // case insensitive
        assert!(FunctionRegistry::exists("today"));
        assert!(!FunctionRegistry::exists("unknown"));
    }

    #[test]
    fn test_supported_functions() {
        let funcs = FunctionRegistry::supported_functions();
        assert!(funcs.contains(&"has_role"));
        assert!(funcs.contains(&"today"));
        assert!(funcs.contains(&"now"));
    }
}
