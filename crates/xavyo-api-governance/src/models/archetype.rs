//! Schema extension types and validation for identity archetypes (F-058).
//!
//! This module provides:
//! - `AttributeType`: Supported attribute data types (string, number, date, boolean, enum, uuid)
//! - `AttributeDefinition`: Definition of a custom attribute including type, required, default, constraints
//! - `SchemaExtensions`: Container for attribute definitions with validation
//! - Validation functions for schema structure and user attribute values

use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;

/// Supported attribute types for schema extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AttributeType {
    /// String/text values
    String,
    /// Numeric values (integer or floating point)
    Number,
    /// Date values (ISO 8601 format: YYYY-MM-DD)
    Date,
    /// Date-time values (ISO 8601 format)
    DateTime,
    /// Boolean values (true/false)
    Boolean,
    /// Enumerated values (must match one of allowed_values)
    Enum,
    /// UUID values
    Uuid,
}

impl AttributeType {
    /// Parse attribute type from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "string" => Some(AttributeType::String),
            "number" => Some(AttributeType::Number),
            "date" => Some(AttributeType::Date),
            "datetime" | "date-time" => Some(AttributeType::DateTime),
            "boolean" | "bool" => Some(AttributeType::Boolean),
            "enum" => Some(AttributeType::Enum),
            "uuid" => Some(AttributeType::Uuid),
            _ => None,
        }
    }
}

/// Definition of a custom attribute in the schema extension.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AttributeDefinition {
    /// Attribute name (unique within the schema).
    pub name: String,

    /// Data type for this attribute.
    #[serde(rename = "type")]
    pub attr_type: AttributeType,

    /// Whether this attribute is required.
    #[serde(default)]
    pub required: bool,

    /// Default value for this attribute (must match attr_type).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,

    /// Description of the attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Minimum length for string attributes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,

    /// Maximum length for string attributes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,

    /// Minimum value for number attributes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,

    /// Maximum value for number attributes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,

    /// Regex pattern for string validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,

    /// Allowed values for enum attributes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_values: Option<Vec<String>>,
}

/// Schema extensions container.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct SchemaExtensions {
    /// List of attribute definitions.
    #[serde(default)]
    pub attributes: Vec<AttributeDefinition>,
}

/// Errors that can occur during schema validation.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SchemaValidationError {
    #[error("Invalid JSON structure: {0}")]
    InvalidStructure(String),

    #[error("Duplicate attribute name: {0}")]
    DuplicateAttribute(String),

    #[error("Invalid attribute name: {0}")]
    InvalidAttributeName(String),

    #[error("Invalid attribute type: {0}")]
    InvalidAttributeType(String),

    #[error("Enum attribute '{0}' must have allowed_values")]
    EnumMissingAllowedValues(String),

    #[error("Default value for '{0}' does not match type {1}")]
    DefaultTypeMismatch(String, String),

    #[error("min_length cannot be greater than max_length for attribute '{0}'")]
    InvalidLengthRange(String),

    #[error("min cannot be greater than max for attribute '{0}'")]
    InvalidNumberRange(String),

    #[error("Invalid regex pattern for attribute '{0}': {1}")]
    InvalidPattern(String, String),
}

/// Errors that can occur during user attribute validation.
#[derive(Debug, Clone, Error, PartialEq)]
pub enum AttributeValidationError {
    #[error("Missing required attribute: {0}")]
    MissingRequired(String),

    #[error("Unknown attribute: {0}")]
    UnknownAttribute(String),

    #[error("Invalid type for attribute '{0}': expected {1}")]
    TypeMismatch(String, String),

    #[error("String too short for attribute '{0}': minimum {1} characters")]
    StringTooShort(String, usize),

    #[error("String too long for attribute '{0}': maximum {1} characters")]
    StringTooLong(String, usize),

    #[error("Value too small for attribute '{0}': minimum {1}")]
    NumberTooSmall(String, f64),

    #[error("Value too large for attribute '{0}': maximum {1}")]
    NumberTooLarge(String, f64),

    #[error("Value '{1}' does not match pattern for attribute '{0}'")]
    PatternMismatch(String, String),

    #[error("Invalid enum value '{1}' for attribute '{0}': allowed values are {2}")]
    InvalidEnumValue(String, String, String),

    #[error("Invalid date format for attribute '{0}': expected YYYY-MM-DD")]
    InvalidDateFormat(String),

    #[error("Invalid datetime format for attribute '{0}': expected ISO 8601")]
    InvalidDateTimeFormat(String),

    #[error("Invalid UUID format for attribute '{0}'")]
    InvalidUuidFormat(String),
}

/// Validate schema extensions JSON structure.
///
/// # Arguments
/// * `schema_json` - The schema extensions as JSON value
///
/// # Returns
/// * `Ok(SchemaExtensions)` - Parsed and validated schema extensions
/// * `Err(SchemaValidationError)` - Validation error
pub fn validate_schema_extensions(
    schema_json: &serde_json::Value,
) -> Result<SchemaExtensions, SchemaValidationError> {
    // Parse into SchemaExtensions struct
    let schema: SchemaExtensions = serde_json::from_value(schema_json.clone()).map_err(|e| {
        SchemaValidationError::InvalidStructure(format!("Failed to parse schema: {}", e))
    })?;

    // Check for duplicate attribute names
    let mut seen_names = std::collections::HashSet::new();
    for attr in &schema.attributes {
        // Validate attribute name
        if attr.name.is_empty() {
            return Err(SchemaValidationError::InvalidAttributeName(
                "Attribute name cannot be empty".to_string(),
            ));
        }
        if attr.name.len() > 255 {
            return Err(SchemaValidationError::InvalidAttributeName(format!(
                "Attribute name '{}' exceeds 255 characters",
                attr.name
            )));
        }
        // Check for valid identifier (alphanumeric + underscore, starting with letter)
        if !attr.name.chars().next().is_some_and(|c| c.is_alphabetic()) {
            return Err(SchemaValidationError::InvalidAttributeName(format!(
                "Attribute name '{}' must start with a letter",
                attr.name
            )));
        }
        if !attr.name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(SchemaValidationError::InvalidAttributeName(format!(
                "Attribute name '{}' contains invalid characters (only alphanumeric and underscore allowed)",
                attr.name
            )));
        }

        // Check for duplicates
        if !seen_names.insert(attr.name.to_lowercase()) {
            return Err(SchemaValidationError::DuplicateAttribute(attr.name.clone()));
        }

        // Validate enum has allowed_values
        if attr.attr_type == AttributeType::Enum && attr.allowed_values.is_none() {
            return Err(SchemaValidationError::EnumMissingAllowedValues(
                attr.name.clone(),
            ));
        }

        // Validate length range for strings
        if let (Some(min_len), Some(max_len)) = (attr.min_length, attr.max_length) {
            if min_len > max_len {
                return Err(SchemaValidationError::InvalidLengthRange(attr.name.clone()));
            }
        }

        // Validate number range
        if let (Some(min), Some(max)) = (attr.min, attr.max) {
            if min > max {
                return Err(SchemaValidationError::InvalidNumberRange(attr.name.clone()));
            }
        }

        // Validate regex pattern if provided
        if let Some(pattern) = &attr.pattern {
            if regex::Regex::new(pattern).is_err() {
                return Err(SchemaValidationError::InvalidPattern(
                    attr.name.clone(),
                    format!("Invalid regex: {}", pattern),
                ));
            }
        }

        // Validate default value type matches
        if let Some(default) = &attr.default {
            validate_value_type(default, &attr.attr_type, &attr.name)?;
        }
    }

    Ok(schema)
}

/// Validate that a JSON value matches the expected attribute type.
fn validate_value_type(
    value: &serde_json::Value,
    attr_type: &AttributeType,
    attr_name: &str,
) -> Result<(), SchemaValidationError> {
    match attr_type {
        AttributeType::String => {
            if !value.is_string() {
                return Err(SchemaValidationError::DefaultTypeMismatch(
                    attr_name.to_string(),
                    "string".to_string(),
                ));
            }
        }
        AttributeType::Number => {
            if !value.is_number() {
                return Err(SchemaValidationError::DefaultTypeMismatch(
                    attr_name.to_string(),
                    "number".to_string(),
                ));
            }
        }
        AttributeType::Boolean => {
            if !value.is_boolean() {
                return Err(SchemaValidationError::DefaultTypeMismatch(
                    attr_name.to_string(),
                    "boolean".to_string(),
                ));
            }
        }
        AttributeType::Date => {
            if let Some(s) = value.as_str() {
                // Validate date format YYYY-MM-DD
                if chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_err() {
                    return Err(SchemaValidationError::DefaultTypeMismatch(
                        attr_name.to_string(),
                        "date (YYYY-MM-DD)".to_string(),
                    ));
                }
            } else {
                return Err(SchemaValidationError::DefaultTypeMismatch(
                    attr_name.to_string(),
                    "date".to_string(),
                ));
            }
        }
        AttributeType::DateTime => {
            if let Some(s) = value.as_str() {
                // Validate ISO 8601 datetime
                if chrono::DateTime::parse_from_rfc3339(s).is_err() {
                    return Err(SchemaValidationError::DefaultTypeMismatch(
                        attr_name.to_string(),
                        "datetime (ISO 8601)".to_string(),
                    ));
                }
            } else {
                return Err(SchemaValidationError::DefaultTypeMismatch(
                    attr_name.to_string(),
                    "datetime".to_string(),
                ));
            }
        }
        AttributeType::Enum => {
            if !value.is_string() {
                return Err(SchemaValidationError::DefaultTypeMismatch(
                    attr_name.to_string(),
                    "enum (string)".to_string(),
                ));
            }
        }
        AttributeType::Uuid => {
            if let Some(s) = value.as_str() {
                if uuid::Uuid::parse_str(s).is_err() {
                    return Err(SchemaValidationError::DefaultTypeMismatch(
                        attr_name.to_string(),
                        "uuid".to_string(),
                    ));
                }
            } else {
                return Err(SchemaValidationError::DefaultTypeMismatch(
                    attr_name.to_string(),
                    "uuid".to_string(),
                ));
            }
        }
    }
    Ok(())
}

/// Validate user custom attributes against an archetype schema.
///
/// # Arguments
/// * `user_attrs` - The user's custom attributes as JSON object
/// * `schema` - The archetype schema extensions
///
/// # Returns
/// * `Ok(())` - Validation passed
/// * `Err(Vec<AttributeValidationError>)` - List of validation errors
pub fn validate_user_attributes(
    user_attrs: &serde_json::Value,
    schema: &SchemaExtensions,
) -> Result<(), Vec<AttributeValidationError>> {
    let mut errors = Vec::new();

    // Get user attributes as object
    let user_obj = user_attrs.as_object();

    // Check required attributes and validate provided values
    for attr_def in &schema.attributes {
        let value = user_obj.and_then(|obj| obj.get(&attr_def.name));

        match value {
            None | Some(serde_json::Value::Null) => {
                if attr_def.required && attr_def.default.is_none() {
                    errors.push(AttributeValidationError::MissingRequired(
                        attr_def.name.clone(),
                    ));
                }
            }
            Some(val) => {
                // Validate the value against the attribute definition
                if let Err(e) = validate_attribute_value(val, attr_def) {
                    errors.push(e);
                }
            }
        }
    }

    // Check for unknown attributes (optional - strict mode)
    if let Some(obj) = user_obj {
        let known_attrs: std::collections::HashSet<_> =
            schema.attributes.iter().map(|a| &a.name).collect();
        for key in obj.keys() {
            if !known_attrs.contains(key) {
                errors.push(AttributeValidationError::UnknownAttribute(key.clone()));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate a single attribute value against its definition.
fn validate_attribute_value(
    value: &serde_json::Value,
    attr_def: &AttributeDefinition,
) -> Result<(), AttributeValidationError> {
    match attr_def.attr_type {
        AttributeType::String => validate_string_attribute(value, attr_def),
        AttributeType::Number => validate_number_attribute(value, attr_def),
        AttributeType::Boolean => {
            if !value.is_boolean() {
                Err(AttributeValidationError::TypeMismatch(
                    attr_def.name.clone(),
                    "boolean".to_string(),
                ))
            } else {
                Ok(())
            }
        }
        AttributeType::Date => {
            if let Some(s) = value.as_str() {
                if chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok() {
                    Ok(())
                } else {
                    Err(AttributeValidationError::InvalidDateFormat(
                        attr_def.name.clone(),
                    ))
                }
            } else {
                Err(AttributeValidationError::TypeMismatch(
                    attr_def.name.clone(),
                    "date".to_string(),
                ))
            }
        }
        AttributeType::DateTime => {
            if let Some(s) = value.as_str() {
                if chrono::DateTime::parse_from_rfc3339(s).is_ok() {
                    Ok(())
                } else {
                    Err(AttributeValidationError::InvalidDateTimeFormat(
                        attr_def.name.clone(),
                    ))
                }
            } else {
                Err(AttributeValidationError::TypeMismatch(
                    attr_def.name.clone(),
                    "datetime".to_string(),
                ))
            }
        }
        AttributeType::Enum => validate_enum_attribute(value, attr_def),
        AttributeType::Uuid => {
            if let Some(s) = value.as_str() {
                if uuid::Uuid::parse_str(s).is_ok() {
                    Ok(())
                } else {
                    Err(AttributeValidationError::InvalidUuidFormat(
                        attr_def.name.clone(),
                    ))
                }
            } else {
                Err(AttributeValidationError::TypeMismatch(
                    attr_def.name.clone(),
                    "uuid".to_string(),
                ))
            }
        }
    }
}

fn validate_string_attribute(
    value: &serde_json::Value,
    attr_def: &AttributeDefinition,
) -> Result<(), AttributeValidationError> {
    let s = value.as_str().ok_or_else(|| {
        AttributeValidationError::TypeMismatch(attr_def.name.clone(), "string".to_string())
    })?;

    // Check min length
    if let Some(min_len) = attr_def.min_length {
        if s.len() < min_len {
            return Err(AttributeValidationError::StringTooShort(
                attr_def.name.clone(),
                min_len,
            ));
        }
    }

    // Check max length
    if let Some(max_len) = attr_def.max_length {
        if s.len() > max_len {
            return Err(AttributeValidationError::StringTooLong(
                attr_def.name.clone(),
                max_len,
            ));
        }
    }

    // Check pattern
    if let Some(pattern) = &attr_def.pattern {
        let re = regex::Regex::new(pattern).map_err(|_| {
            AttributeValidationError::PatternMismatch(attr_def.name.clone(), s.to_string())
        })?;
        if !re.is_match(s) {
            return Err(AttributeValidationError::PatternMismatch(
                attr_def.name.clone(),
                s.to_string(),
            ));
        }
    }

    Ok(())
}

fn validate_number_attribute(
    value: &serde_json::Value,
    attr_def: &AttributeDefinition,
) -> Result<(), AttributeValidationError> {
    let n = value.as_f64().ok_or_else(|| {
        AttributeValidationError::TypeMismatch(attr_def.name.clone(), "number".to_string())
    })?;

    // Check min
    if let Some(min) = attr_def.min {
        if n < min {
            return Err(AttributeValidationError::NumberTooSmall(
                attr_def.name.clone(),
                min,
            ));
        }
    }

    // Check max
    if let Some(max) = attr_def.max {
        if n > max {
            return Err(AttributeValidationError::NumberTooLarge(
                attr_def.name.clone(),
                max,
            ));
        }
    }

    Ok(())
}

fn validate_enum_attribute(
    value: &serde_json::Value,
    attr_def: &AttributeDefinition,
) -> Result<(), AttributeValidationError> {
    let s = value.as_str().ok_or_else(|| {
        AttributeValidationError::TypeMismatch(attr_def.name.clone(), "enum (string)".to_string())
    })?;

    if let Some(allowed) = &attr_def.allowed_values {
        if !allowed.contains(&s.to_string()) {
            return Err(AttributeValidationError::InvalidEnumValue(
                attr_def.name.clone(),
                s.to_string(),
                allowed.join(", "),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // T039: Unit tests for schema extension JSON structure validation

    #[test]
    fn test_valid_schema_extensions() {
        let schema_json = json!({
            "attributes": [
                {"name": "employee_id", "type": "string", "required": true},
                {"name": "department", "type": "string", "required": false}
            ]
        });

        let result = validate_schema_extensions(&schema_json);
        assert!(result.is_ok());
        let schema = result.unwrap();
        assert_eq!(schema.attributes.len(), 2);
    }

    #[test]
    fn test_empty_schema_extensions() {
        let schema_json = json!({"attributes": []});
        let result = validate_schema_extensions(&schema_json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_duplicate_attribute_name_fails() {
        let schema_json = json!({
            "attributes": [
                {"name": "employee_id", "type": "string"},
                {"name": "employee_id", "type": "number"}
            ]
        });

        let result = validate_schema_extensions(&schema_json);
        assert!(matches!(
            result,
            Err(SchemaValidationError::DuplicateAttribute(_))
        ));
    }

    #[test]
    fn test_duplicate_attribute_name_case_insensitive() {
        let schema_json = json!({
            "attributes": [
                {"name": "Employee_Id", "type": "string"},
                {"name": "employee_id", "type": "number"}
            ]
        });

        let result = validate_schema_extensions(&schema_json);
        assert!(matches!(
            result,
            Err(SchemaValidationError::DuplicateAttribute(_))
        ));
    }

    #[test]
    fn test_empty_attribute_name_fails() {
        let schema_json = json!({
            "attributes": [
                {"name": "", "type": "string"}
            ]
        });

        let result = validate_schema_extensions(&schema_json);
        assert!(matches!(
            result,
            Err(SchemaValidationError::InvalidAttributeName(_))
        ));
    }

    #[test]
    fn test_attribute_name_must_start_with_letter() {
        let schema_json = json!({
            "attributes": [
                {"name": "_private", "type": "string"}
            ]
        });

        let result = validate_schema_extensions(&schema_json);
        assert!(matches!(
            result,
            Err(SchemaValidationError::InvalidAttributeName(_))
        ));
    }

    #[test]
    fn test_attribute_name_invalid_characters() {
        let schema_json = json!({
            "attributes": [
                {"name": "employee-id", "type": "string"}
            ]
        });

        let result = validate_schema_extensions(&schema_json);
        assert!(matches!(
            result,
            Err(SchemaValidationError::InvalidAttributeName(_))
        ));
    }

    #[test]
    fn test_enum_without_allowed_values_fails() {
        let schema_json = json!({
            "attributes": [
                {"name": "status", "type": "enum"}
            ]
        });

        let result = validate_schema_extensions(&schema_json);
        assert!(matches!(
            result,
            Err(SchemaValidationError::EnumMissingAllowedValues(_))
        ));
    }

    #[test]
    fn test_enum_with_allowed_values_succeeds() {
        let schema_json = json!({
            "attributes": [
                {"name": "status", "type": "enum", "allowed_values": ["active", "inactive", "pending"]}
            ]
        });

        let result = validate_schema_extensions(&schema_json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_length_range_fails() {
        let schema_json = json!({
            "attributes": [
                {"name": "name", "type": "string", "min_length": 10, "max_length": 5}
            ]
        });

        let result = validate_schema_extensions(&schema_json);
        assert!(matches!(
            result,
            Err(SchemaValidationError::InvalidLengthRange(_))
        ));
    }

    #[test]
    fn test_invalid_number_range_fails() {
        let schema_json = json!({
            "attributes": [
                {"name": "age", "type": "number", "min": 100, "max": 10}
            ]
        });

        let result = validate_schema_extensions(&schema_json);
        assert!(matches!(
            result,
            Err(SchemaValidationError::InvalidNumberRange(_))
        ));
    }

    #[test]
    fn test_invalid_regex_pattern_fails() {
        let schema_json = json!({
            "attributes": [
                {"name": "code", "type": "string", "pattern": "[invalid(regex"}
            ]
        });

        let result = validate_schema_extensions(&schema_json);
        assert!(matches!(
            result,
            Err(SchemaValidationError::InvalidPattern(_, _))
        ));
    }

    #[test]
    fn test_valid_regex_pattern() {
        let schema_json = json!({
            "attributes": [
                {"name": "code", "type": "string", "pattern": "^[A-Z]{3}-[0-9]{4}$"}
            ]
        });

        let result = validate_schema_extensions(&schema_json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_default_value_type_mismatch_fails() {
        let schema_json = json!({
            "attributes": [
                {"name": "count", "type": "number", "default": "not a number"}
            ]
        });

        let result = validate_schema_extensions(&schema_json);
        assert!(matches!(
            result,
            Err(SchemaValidationError::DefaultTypeMismatch(_, _))
        ));
    }

    #[test]
    fn test_default_value_matches_type() {
        let schema_json = json!({
            "attributes": [
                {"name": "count", "type": "number", "default": 42}
            ]
        });

        let result = validate_schema_extensions(&schema_json);
        assert!(result.is_ok());
    }

    // T040: Unit tests for attribute type validation

    #[test]
    fn test_string_type_validation() {
        let schema_json = json!({
            "attributes": [
                {"name": "name", "type": "string", "required": true, "min_length": 2, "max_length": 50}
            ]
        });
        let schema = validate_schema_extensions(&schema_json).unwrap();

        // Valid string
        let user_attrs = json!({"name": "John"});
        assert!(validate_user_attributes(&user_attrs, &schema).is_ok());

        // Too short
        let user_attrs = json!({"name": "J"});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());

        // Too long
        let long_name = "x".repeat(100);
        let user_attrs = json!({"name": long_name});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());

        // Wrong type
        let user_attrs = json!({"name": 123});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn test_number_type_validation() {
        let schema_json = json!({
            "attributes": [
                {"name": "age", "type": "number", "required": true, "min": 0, "max": 150}
            ]
        });
        let schema = validate_schema_extensions(&schema_json).unwrap();

        // Valid number
        let user_attrs = json!({"age": 30});
        assert!(validate_user_attributes(&user_attrs, &schema).is_ok());

        // Too small
        let user_attrs = json!({"age": -5});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());

        // Too large
        let user_attrs = json!({"age": 200});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());

        // Wrong type
        let user_attrs = json!({"age": "thirty"});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn test_boolean_type_validation() {
        let schema_json = json!({
            "attributes": [
                {"name": "active", "type": "boolean", "required": true}
            ]
        });
        let schema = validate_schema_extensions(&schema_json).unwrap();

        // Valid boolean
        let user_attrs = json!({"active": true});
        assert!(validate_user_attributes(&user_attrs, &schema).is_ok());

        let user_attrs = json!({"active": false});
        assert!(validate_user_attributes(&user_attrs, &schema).is_ok());

        // Wrong type
        let user_attrs = json!({"active": "yes"});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn test_date_type_validation() {
        let schema_json = json!({
            "attributes": [
                {"name": "hire_date", "type": "date", "required": true}
            ]
        });
        let schema = validate_schema_extensions(&schema_json).unwrap();

        // Valid date
        let user_attrs = json!({"hire_date": "2024-01-15"});
        assert!(validate_user_attributes(&user_attrs, &schema).is_ok());

        // Invalid date format
        let user_attrs = json!({"hire_date": "01/15/2024"});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());

        // Wrong type
        let user_attrs = json!({"hire_date": 20240115});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn test_datetime_type_validation() {
        let schema_json = json!({
            "attributes": [
                {"name": "created_at", "type": "datetime", "required": true}
            ]
        });
        let schema = validate_schema_extensions(&schema_json).unwrap();

        // Valid datetime (RFC 3339)
        let user_attrs = json!({"created_at": "2024-01-15T10:30:00Z"});
        assert!(validate_user_attributes(&user_attrs, &schema).is_ok());

        let user_attrs = json!({"created_at": "2024-01-15T10:30:00+05:30"});
        assert!(validate_user_attributes(&user_attrs, &schema).is_ok());

        // Invalid datetime format
        let user_attrs = json!({"created_at": "2024-01-15 10:30:00"});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn test_enum_type_validation() {
        let schema_json = json!({
            "attributes": [
                {"name": "status", "type": "enum", "required": true, "allowed_values": ["active", "inactive", "pending"]}
            ]
        });
        let schema = validate_schema_extensions(&schema_json).unwrap();

        // Valid enum value
        let user_attrs = json!({"status": "active"});
        assert!(validate_user_attributes(&user_attrs, &schema).is_ok());

        // Invalid enum value
        let user_attrs = json!({"status": "unknown"});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());

        // Wrong type
        let user_attrs = json!({"status": 1});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn test_uuid_type_validation() {
        let schema_json = json!({
            "attributes": [
                {"name": "ref_id", "type": "uuid", "required": true}
            ]
        });
        let schema = validate_schema_extensions(&schema_json).unwrap();

        // Valid UUID
        let user_attrs = json!({"ref_id": "550e8400-e29b-41d4-a716-446655440000"});
        assert!(validate_user_attributes(&user_attrs, &schema).is_ok());

        // Invalid UUID
        let user_attrs = json!({"ref_id": "not-a-uuid"});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());

        // Wrong type
        let user_attrs = json!({"ref_id": 12345});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn test_required_attribute_validation() {
        let schema_json = json!({
            "attributes": [
                {"name": "employee_id", "type": "string", "required": true},
                {"name": "nickname", "type": "string", "required": false}
            ]
        });
        let schema = validate_schema_extensions(&schema_json).unwrap();

        // Missing required
        let user_attrs = json!({"nickname": "JD"});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());

        // Required present, optional missing
        let user_attrs = json!({"employee_id": "E123"});
        assert!(validate_user_attributes(&user_attrs, &schema).is_ok());

        // Both present
        let user_attrs = json!({"employee_id": "E123", "nickname": "JD"});
        assert!(validate_user_attributes(&user_attrs, &schema).is_ok());
    }

    #[test]
    fn test_required_with_default_not_required() {
        let schema_json = json!({
            "attributes": [
                {"name": "status", "type": "string", "required": true, "default": "active"}
            ]
        });
        let schema = validate_schema_extensions(&schema_json).unwrap();

        // Missing but has default - should pass
        let user_attrs = json!({});
        assert!(validate_user_attributes(&user_attrs, &schema).is_ok());
    }

    #[test]
    fn test_unknown_attribute_fails() {
        let schema_json = json!({
            "attributes": [
                {"name": "employee_id", "type": "string"}
            ]
        });
        let schema = validate_schema_extensions(&schema_json).unwrap();

        // Unknown attribute
        let user_attrs = json!({"employee_id": "E123", "unknown_field": "value"});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn test_pattern_validation() {
        let schema_json = json!({
            "attributes": [
                {"name": "employee_id", "type": "string", "pattern": "^E[0-9]{5}$"}
            ]
        });
        let schema = validate_schema_extensions(&schema_json).unwrap();

        // Valid pattern
        let user_attrs = json!({"employee_id": "E12345"});
        assert!(validate_user_attributes(&user_attrs, &schema).is_ok());

        // Invalid pattern
        let user_attrs = json!({"employee_id": "E123"});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());

        let user_attrs = json!({"employee_id": "12345"});
        let result = validate_user_attributes(&user_attrs, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn test_attribute_type_parse() {
        assert_eq!(AttributeType::parse("string"), Some(AttributeType::String));
        assert_eq!(AttributeType::parse("STRING"), Some(AttributeType::String));
        assert_eq!(AttributeType::parse("number"), Some(AttributeType::Number));
        assert_eq!(AttributeType::parse("date"), Some(AttributeType::Date));
        assert_eq!(
            AttributeType::parse("datetime"),
            Some(AttributeType::DateTime)
        );
        assert_eq!(
            AttributeType::parse("date-time"),
            Some(AttributeType::DateTime)
        );
        assert_eq!(
            AttributeType::parse("boolean"),
            Some(AttributeType::Boolean)
        );
        assert_eq!(AttributeType::parse("bool"), Some(AttributeType::Boolean));
        assert_eq!(AttributeType::parse("enum"), Some(AttributeType::Enum));
        assert_eq!(AttributeType::parse("uuid"), Some(AttributeType::Uuid));
        assert_eq!(AttributeType::parse("invalid"), None);
    }

    #[test]
    fn test_complex_schema_validation() {
        // Test a realistic employee schema
        let schema_json = json!({
            "attributes": [
                {
                    "name": "employee_id",
                    "type": "string",
                    "required": true,
                    "pattern": "^E[0-9]{5}$",
                    "description": "Unique employee identifier"
                },
                {
                    "name": "department",
                    "type": "enum",
                    "required": true,
                    "allowed_values": ["engineering", "sales", "marketing", "hr", "finance"]
                },
                {
                    "name": "hire_date",
                    "type": "date",
                    "required": true
                },
                {
                    "name": "salary_band",
                    "type": "number",
                    "required": false,
                    "min": 1,
                    "max": 10
                },
                {
                    "name": "is_manager",
                    "type": "boolean",
                    "required": false,
                    "default": false
                },
                {
                    "name": "manager_id",
                    "type": "uuid",
                    "required": false
                }
            ]
        });

        let schema = validate_schema_extensions(&schema_json).unwrap();
        assert_eq!(schema.attributes.len(), 6);

        // Valid user
        let user_attrs = json!({
            "employee_id": "E12345",
            "department": "engineering",
            "hire_date": "2024-01-15",
            "salary_band": 5,
            "is_manager": true,
            "manager_id": "550e8400-e29b-41d4-a716-446655440000"
        });
        assert!(validate_user_attributes(&user_attrs, &schema).is_ok());

        // Minimal valid user (only required fields)
        let user_attrs = json!({
            "employee_id": "E12345",
            "department": "sales",
            "hire_date": "2024-06-01"
        });
        assert!(validate_user_attributes(&user_attrs, &schema).is_ok());
    }
}
