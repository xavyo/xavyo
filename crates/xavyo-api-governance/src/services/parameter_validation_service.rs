//! Parameter validation service for F057 Parametric Roles.
//!
//! Provides type-specific validation for parameter values according to their
//! constraints. Uses a strategy pattern for each parameter type.

use chrono::NaiveDate;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;
use xavyo_db::{GovRoleParameter, ParameterConstraints, ParameterType};
use xavyo_governance::GovernanceError;

/// Result of validating a single parameter.
#[derive(Debug, Clone)]
pub struct ParameterValidationResult {
    /// Parameter ID.
    pub parameter_id: Uuid,
    /// Parameter name.
    pub parameter_name: String,
    /// Whether validation passed.
    pub is_valid: bool,
    /// Validation errors.
    pub errors: Vec<String>,
    /// Normalized/coerced value (if applicable).
    pub normalized_value: Option<Value>,
}

/// Result of validating all parameters.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether all parameters are valid.
    pub is_valid: bool,
    /// Individual parameter results.
    pub results: Vec<ParameterValidationResult>,
    /// Overall errors (missing required parameters, etc.).
    pub errors: Vec<String>,
}

/// Service for validating parameter values.
pub struct ParameterValidationService;

impl ParameterValidationService {
    /// Create a new validation service instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validate parameter values against parameter definitions.
    ///
    /// # Arguments
    /// * `parameters` - The parameter definitions for the role
    /// * `values` - Map of `parameter_id` -> value to validate
    #[must_use]
    pub fn validate(
        &self,
        parameters: &[GovRoleParameter],
        values: &HashMap<Uuid, Value>,
    ) -> ValidationResult {
        let mut results = Vec::new();
        let mut errors = Vec::new();

        // Check for required parameters
        for param in parameters {
            if param.is_required && !values.contains_key(&param.id) {
                // Check if there's a default value
                if param.default_value.is_none() {
                    errors.push(format!("Required parameter '{}' is missing", param.name));
                    results.push(ParameterValidationResult {
                        parameter_id: param.id,
                        parameter_name: param.name.clone(),
                        is_valid: false,
                        errors: vec!["Required parameter is missing".to_string()],
                        normalized_value: None,
                    });
                }
            }
        }

        // Validate provided values
        for param in parameters {
            if let Some(value) = values.get(&param.id) {
                let result = self.validate_parameter(param, value);
                results.push(result);
            }
        }

        let is_valid = errors.is_empty() && results.iter().all(|r| r.is_valid);

        ValidationResult {
            is_valid,
            results,
            errors,
        }
    }

    /// Validate a single parameter value.
    #[must_use]
    pub fn validate_parameter(
        &self,
        param: &GovRoleParameter,
        value: &Value,
    ) -> ParameterValidationResult {
        let constraints = param.get_constraints().unwrap_or_default();

        let (is_valid, errors, normalized_value) = match param.parameter_type {
            ParameterType::String => self.validate_string(value, &constraints),
            ParameterType::Integer => self.validate_integer(value, &constraints),
            ParameterType::Boolean => self.validate_boolean(value),
            ParameterType::Date => self.validate_date(value, &constraints),
            ParameterType::Enum => self.validate_enum(value, &constraints),
        };

        ParameterValidationResult {
            parameter_id: param.id,
            parameter_name: param.name.clone(),
            is_valid,
            errors,
            normalized_value,
        }
    }

    /// Validate a string parameter.
    fn validate_string(
        &self,
        value: &Value,
        constraints: &ParameterConstraints,
    ) -> (bool, Vec<String>, Option<Value>) {
        let mut errors = Vec::new();

        // Check type
        let string_val = match value.as_str() {
            Some(s) => s.to_string(),
            None => {
                // Try to coerce from other types
                match value {
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => {
                        errors.push("Value must be a string".to_string());
                        return (false, errors, None);
                    }
                }
            }
        };

        // Check min length
        if let Some(min_length) = constraints.min_length {
            if string_val.len() < min_length {
                errors.push(format!(
                    "String length {} is less than minimum {}",
                    string_val.len(),
                    min_length
                ));
            }
        }

        // Check max length
        if let Some(max_length) = constraints.max_length {
            if string_val.len() > max_length {
                errors.push(format!(
                    "String length {} exceeds maximum {}",
                    string_val.len(),
                    max_length
                ));
            }
        }

        // Check pattern
        if let Some(ref pattern) = constraints.pattern {
            match Regex::new(pattern) {
                Ok(regex) => {
                    if !regex.is_match(&string_val) {
                        errors.push(format!("Value does not match pattern '{pattern}'"));
                    }
                }
                Err(e) => {
                    errors.push(format!("Invalid regex pattern: {e}"));
                }
            }
        }

        let is_valid = errors.is_empty();
        let normalized = if is_valid {
            Some(Value::String(string_val))
        } else {
            None
        };

        (is_valid, errors, normalized)
    }

    /// Validate an integer parameter.
    fn validate_integer(
        &self,
        value: &Value,
        constraints: &ParameterConstraints,
    ) -> (bool, Vec<String>, Option<Value>) {
        let mut errors = Vec::new();

        // Check type and extract value
        let int_val = match value {
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    i
                } else if let Some(f) = n.as_f64() {
                    // Allow floats if they're whole numbers
                    if f.fract() == 0.0 {
                        f as i64
                    } else {
                        errors.push("Value must be a whole number".to_string());
                        return (false, errors, None);
                    }
                } else {
                    errors.push("Value must be a valid integer".to_string());
                    return (false, errors, None);
                }
            }
            Value::String(s) => {
                if let Ok(i) = s.parse::<i64>() {
                    i
                } else {
                    errors.push("String value could not be parsed as integer".to_string());
                    return (false, errors, None);
                }
            }
            _ => {
                errors.push("Value must be an integer".to_string());
                return (false, errors, None);
            }
        };

        // Check min value
        if let Some(min_value) = constraints.min_value {
            if int_val < min_value {
                errors.push(format!("Value {int_val} is less than minimum {min_value}"));
            }
        }

        // Check max value
        if let Some(max_value) = constraints.max_value {
            if int_val > max_value {
                errors.push(format!("Value {int_val} exceeds maximum {max_value}"));
            }
        }

        let is_valid = errors.is_empty();
        let normalized = if is_valid {
            Some(Value::Number(serde_json::Number::from(int_val)))
        } else {
            None
        };

        (is_valid, errors, normalized)
    }

    /// Validate a boolean parameter.
    fn validate_boolean(&self, value: &Value) -> (bool, Vec<String>, Option<Value>) {
        let mut errors = Vec::new();

        let bool_val = match value {
            Value::Bool(b) => *b,
            Value::String(s) => match s.to_lowercase().as_str() {
                "true" | "yes" | "1" => true,
                "false" | "no" | "0" => false,
                _ => {
                    errors.push("String value could not be parsed as boolean".to_string());
                    return (false, errors, None);
                }
            },
            Value::Number(n) => {
                if n.as_i64() == Some(0) {
                    false
                } else if n.as_i64() == Some(1) {
                    true
                } else {
                    errors.push(
                        "Number value could not be parsed as boolean (use 0 or 1)".to_string(),
                    );
                    return (false, errors, None);
                }
            }
            _ => {
                errors.push("Value must be a boolean".to_string());
                return (false, errors, None);
            }
        };

        (true, errors, Some(Value::Bool(bool_val)))
    }

    /// Validate a date parameter.
    fn validate_date(
        &self,
        value: &Value,
        constraints: &ParameterConstraints,
    ) -> (bool, Vec<String>, Option<Value>) {
        let mut errors = Vec::new();

        // Dates must be strings in YYYY-MM-DD format
        let date_str = if let Some(s) = value.as_str() {
            s
        } else {
            errors.push("Date must be a string in YYYY-MM-DD format".to_string());
            return (false, errors, None);
        };

        // Parse the date
        let date = if let Ok(d) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            d
        } else {
            errors.push(format!(
                "Invalid date format '{date_str}', expected YYYY-MM-DD"
            ));
            return (false, errors, None);
        };

        // Check min date
        if let Some(ref min_date_str) = constraints.min_date {
            if let Ok(min_date) = NaiveDate::parse_from_str(min_date_str, "%Y-%m-%d") {
                if date < min_date {
                    errors.push(format!(
                        "Date {date_str} is before minimum date {min_date_str}"
                    ));
                }
            }
        }

        // Check max date
        if let Some(ref max_date_str) = constraints.max_date {
            if let Ok(max_date) = NaiveDate::parse_from_str(max_date_str, "%Y-%m-%d") {
                if date > max_date {
                    errors.push(format!(
                        "Date {date_str} is after maximum date {max_date_str}"
                    ));
                }
            }
        }

        let is_valid = errors.is_empty();
        let normalized = if is_valid {
            Some(Value::String(date.format("%Y-%m-%d").to_string()))
        } else {
            None
        };

        (is_valid, errors, normalized)
    }

    /// Validate an enum parameter.
    fn validate_enum(
        &self,
        value: &Value,
        constraints: &ParameterConstraints,
    ) -> (bool, Vec<String>, Option<Value>) {
        let mut errors = Vec::new();

        // Enum values must be strings
        let string_val = if let Some(s) = value.as_str() {
            s.to_string()
        } else {
            errors.push("Enum value must be a string".to_string());
            return (false, errors, None);
        };

        // Check allowed values
        if let Some(ref allowed_values) = constraints.allowed_values {
            if !allowed_values.contains(&string_val) {
                errors.push(format!(
                    "Value '{string_val}' is not in allowed values: {allowed_values:?}"
                ));
            }
        } else {
            errors.push("Enum parameter must have allowed_values constraint defined".to_string());
        }

        let is_valid = errors.is_empty();
        let normalized = if is_valid {
            Some(Value::String(string_val))
        } else {
            None
        };

        (is_valid, errors, normalized)
    }

    /// Compute the parameter hash for a set of parameter values.
    ///
    /// The hash is computed by sorting the parameters by name and hashing
    /// the concatenation of name=value pairs. This ensures that the same
    /// parameters always produce the same hash regardless of input order.
    #[must_use]
    pub fn compute_parameter_hash(
        parameters: &[GovRoleParameter],
        values: &HashMap<Uuid, Value>,
    ) -> String {
        // Create a sorted list of (name, value) pairs
        let mut pairs: Vec<(String, String)> = parameters
            .iter()
            .filter_map(|param| {
                values
                    .get(&param.id)
                    .map(|value| (param.name.clone(), value.to_string()))
            })
            .collect();

        // Sort by name to ensure consistent hash
        pairs.sort_by(|a, b| a.0.cmp(&b.0));

        // Concatenate pairs
        let input: String = pairs
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("|");

        // Compute SHA-256 hash
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let result = hasher.finalize();

        // Return hex-encoded hash
        hex::encode(result)
    }

    /// Check if a parameter schema is compatible with existing values.
    ///
    /// Returns a list of violations if the schema has changed in incompatible ways.
    #[must_use]
    pub fn check_schema_compatibility(
        current_params: &[GovRoleParameter],
        existing_values: &HashMap<Uuid, Value>,
    ) -> Vec<SchemaViolation> {
        let mut violations = Vec::new();

        for param in current_params {
            if let Some(value) = existing_values.get(&param.id) {
                // Validate the existing value against current schema
                let result = ParameterValidationService::new().validate_parameter(param, value);
                if !result.is_valid {
                    violations.push(SchemaViolation {
                        parameter_id: param.id,
                        parameter_name: param.name.clone(),
                        violation_type: SchemaViolationType::ValidationFailed,
                        details: result.errors.join("; "),
                    });
                }
            } else if param.is_required && param.default_value.is_none() {
                // New required parameter without default
                violations.push(SchemaViolation {
                    parameter_id: param.id,
                    parameter_name: param.name.clone(),
                    violation_type: SchemaViolationType::MissingRequired,
                    details: "Required parameter was added without a default value".to_string(),
                });
            }
        }

        violations
    }

    /// Convert a `GovernanceError` for parameter validation failures.
    #[must_use]
    pub fn validation_error(param_name: &str, reason: &str) -> GovernanceError {
        GovernanceError::ParameterValidationFailed {
            parameter_name: param_name.to_string(),
            reason: reason.to_string(),
        }
    }
}

impl Default for ParameterValidationService {
    fn default() -> Self {
        Self::new()
    }
}

/// Type of schema violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaViolationType {
    /// Existing value fails validation against new constraints.
    ValidationFailed,
    /// New required parameter added without default value.
    MissingRequired,
    /// Parameter type changed incompatibly.
    TypeChanged,
}

/// A schema violation for an existing assignment.
#[derive(Debug, Clone)]
pub struct SchemaViolation {
    /// Parameter ID.
    pub parameter_id: Uuid,
    /// Parameter name.
    pub parameter_name: String,
    /// Type of violation.
    pub violation_type: SchemaViolationType,
    /// Detailed description.
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_string_param(
        id: Uuid,
        name: &str,
        constraints: Option<ParameterConstraints>,
    ) -> GovRoleParameter {
        GovRoleParameter {
            id,
            tenant_id: Uuid::new_v4(),
            role_id: Uuid::new_v4(),
            name: name.to_string(),
            display_name: None,
            description: None,
            parameter_type: ParameterType::String,
            is_required: false,
            default_value: None,
            constraints: constraints.map(|c| serde_json::to_value(c).unwrap()),
            display_order: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_int_param(
        id: Uuid,
        name: &str,
        constraints: Option<ParameterConstraints>,
    ) -> GovRoleParameter {
        GovRoleParameter {
            id,
            tenant_id: Uuid::new_v4(),
            role_id: Uuid::new_v4(),
            name: name.to_string(),
            display_name: None,
            description: None,
            parameter_type: ParameterType::Integer,
            is_required: false,
            default_value: None,
            constraints: constraints.map(|c| serde_json::to_value(c).unwrap()),
            display_order: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_string_validation() {
        let service = ParameterValidationService::new();
        let id = Uuid::new_v4();
        let param = make_string_param(
            id,
            "test",
            Some(ParameterConstraints::string(Some(3), Some(10), None)),
        );

        // Valid string
        let result = service.validate_parameter(&param, &Value::String("hello".to_string()));
        assert!(result.is_valid);

        // Too short
        let result = service.validate_parameter(&param, &Value::String("ab".to_string()));
        assert!(!result.is_valid);
        assert!(result.errors[0].contains("less than minimum"));

        // Too long
        let result =
            service.validate_parameter(&param, &Value::String("this is too long".to_string()));
        assert!(!result.is_valid);
        assert!(result.errors[0].contains("exceeds maximum"));
    }

    #[test]
    fn test_string_pattern_validation() {
        let service = ParameterValidationService::new();
        let id = Uuid::new_v4();
        let param = make_string_param(
            id,
            "db_name",
            Some(ParameterConstraints::string(
                None,
                None,
                Some("^[a-z][a-z0-9_]*$".to_string()),
            )),
        );

        // Valid pattern
        let result = service.validate_parameter(&param, &Value::String("my_database".to_string()));
        assert!(result.is_valid);

        // Invalid pattern
        let result = service.validate_parameter(&param, &Value::String("123invalid".to_string()));
        assert!(!result.is_valid);
        assert!(result.errors[0].contains("does not match pattern"));
    }

    #[test]
    fn test_integer_validation() {
        let service = ParameterValidationService::new();
        let id = Uuid::new_v4();
        let param = make_int_param(
            id,
            "port",
            Some(ParameterConstraints::integer(Some(1), Some(65535))),
        );

        // Valid integer
        let result = service.validate_parameter(&param, &Value::Number(8080.into()));
        assert!(result.is_valid);

        // Below minimum
        let result = service.validate_parameter(&param, &Value::Number(0.into()));
        assert!(!result.is_valid);
        assert!(result.errors[0].contains("less than minimum"));

        // Above maximum
        let result = service.validate_parameter(&param, &Value::Number(70000.into()));
        assert!(!result.is_valid);
        assert!(result.errors[0].contains("exceeds maximum"));
    }

    #[test]
    fn test_integer_coercion() {
        let service = ParameterValidationService::new();
        let id = Uuid::new_v4();
        let param = make_int_param(id, "count", None);

        // String to integer coercion
        let result = service.validate_parameter(&param, &Value::String("42".to_string()));
        assert!(result.is_valid);
        assert_eq!(result.normalized_value, Some(Value::Number(42.into())));
    }

    #[test]
    fn test_boolean_validation() {
        let service = ParameterValidationService::new();
        let id = Uuid::new_v4();
        let param = GovRoleParameter {
            id,
            tenant_id: Uuid::new_v4(),
            role_id: Uuid::new_v4(),
            name: "enabled".to_string(),
            display_name: None,
            description: None,
            parameter_type: ParameterType::Boolean,
            is_required: false,
            default_value: None,
            constraints: None,
            display_order: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Boolean true
        let result = service.validate_parameter(&param, &Value::Bool(true));
        assert!(result.is_valid);

        // String "true"
        let result = service.validate_parameter(&param, &Value::String("true".to_string()));
        assert!(result.is_valid);
        assert_eq!(result.normalized_value, Some(Value::Bool(true)));

        // Number 0
        let result = service.validate_parameter(&param, &Value::Number(0.into()));
        assert!(result.is_valid);
        assert_eq!(result.normalized_value, Some(Value::Bool(false)));
    }

    #[test]
    fn test_date_validation() {
        let service = ParameterValidationService::new();
        let id = Uuid::new_v4();
        let param = GovRoleParameter {
            id,
            tenant_id: Uuid::new_v4(),
            role_id: Uuid::new_v4(),
            name: "start_date".to_string(),
            display_name: None,
            description: None,
            parameter_type: ParameterType::Date,
            is_required: false,
            default_value: None,
            constraints: Some(
                serde_json::to_value(ParameterConstraints::date(
                    Some("2020-01-01".to_string()),
                    Some("2030-12-31".to_string()),
                ))
                .unwrap(),
            ),
            display_order: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Valid date
        let result = service.validate_parameter(&param, &Value::String("2025-06-15".to_string()));
        assert!(result.is_valid);

        // Date before min
        let result = service.validate_parameter(&param, &Value::String("2019-01-01".to_string()));
        assert!(!result.is_valid);
        assert!(result.errors[0].contains("before minimum"));

        // Invalid format
        let result = service.validate_parameter(&param, &Value::String("15/06/2025".to_string()));
        assert!(!result.is_valid);
        assert!(result.errors[0].contains("Invalid date format"));
    }

    #[test]
    fn test_enum_validation() {
        let service = ParameterValidationService::new();
        let id = Uuid::new_v4();
        let param = GovRoleParameter {
            id,
            tenant_id: Uuid::new_v4(),
            role_id: Uuid::new_v4(),
            name: "access_level".to_string(),
            display_name: None,
            description: None,
            parameter_type: ParameterType::Enum,
            is_required: false,
            default_value: None,
            constraints: Some(
                serde_json::to_value(ParameterConstraints::enumeration(vec![
                    "read".to_string(),
                    "write".to_string(),
                    "admin".to_string(),
                ]))
                .unwrap(),
            ),
            display_order: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Valid enum value
        let result = service.validate_parameter(&param, &Value::String("write".to_string()));
        assert!(result.is_valid);

        // Invalid enum value
        let result = service.validate_parameter(&param, &Value::String("delete".to_string()));
        assert!(!result.is_valid);
        assert!(result.errors[0].contains("not in allowed values"));
    }

    #[test]
    fn test_required_parameter_validation() {
        let service = ParameterValidationService::new();
        let id = Uuid::new_v4();
        let param = GovRoleParameter {
            id,
            tenant_id: Uuid::new_v4(),
            role_id: Uuid::new_v4(),
            name: "required_param".to_string(),
            display_name: None,
            description: None,
            parameter_type: ParameterType::String,
            is_required: true,
            default_value: None,
            constraints: None,
            display_order: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Missing required parameter
        let result = service.validate(&[param], &HashMap::new());
        assert!(!result.is_valid);
        assert!(result.errors[0].contains("Required parameter"));
    }

    #[test]
    fn test_parameter_hash() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        let params = vec![
            make_string_param(id1, "param_a", None),
            make_string_param(id2, "param_b", None),
        ];

        let mut values1 = HashMap::new();
        values1.insert(id1, Value::String("value1".to_string()));
        values1.insert(id2, Value::String("value2".to_string()));

        let mut values2 = HashMap::new();
        values2.insert(id2, Value::String("value2".to_string()));
        values2.insert(id1, Value::String("value1".to_string()));

        // Same values in different order should produce same hash
        let hash1 = ParameterValidationService::compute_parameter_hash(&params, &values1);
        let hash2 = ParameterValidationService::compute_parameter_hash(&params, &values2);
        assert_eq!(hash1, hash2);

        // Different values should produce different hash
        let mut values3 = HashMap::new();
        values3.insert(id1, Value::String("different".to_string()));
        values3.insert(id2, Value::String("value2".to_string()));

        let hash3 = ParameterValidationService::compute_parameter_hash(&params, &values3);
        assert_ne!(hash1, hash3);
    }
}
