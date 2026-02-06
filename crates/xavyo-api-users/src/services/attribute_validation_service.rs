//! Attribute validation service for custom user attributes (F070).
//!
//! Validates custom attribute values against tenant-defined attribute definitions.

use chrono::NaiveDate;
use serde_json::Value;
use xavyo_db::models::TenantAttributeDefinition;

/// Supported attribute data types.
#[derive(Debug, Clone, PartialEq)]
pub enum AttributeDataType {
    String,
    Number,
    Boolean,
    Date,
    Json,
    Enum,
}

impl AttributeDataType {
    /// Parse data type from string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "string" => Some(Self::String),
            "number" => Some(Self::Number),
            "boolean" => Some(Self::Boolean),
            "date" => Some(Self::Date),
            "json" => Some(Self::Json),
            "enum" => Some(Self::Enum),
            _ => None,
        }
    }
}

/// A single attribute validation error.
#[derive(Debug, Clone)]
pub struct AttributeFieldError {
    /// Name of the attribute that failed validation.
    pub attribute: String,
    /// Description of the validation failure.
    pub error: String,
}

/// Maximum allowed size for the entire `custom_attributes` JSONB value (64KB).
const MAX_ATTRIBUTES_SIZE: usize = 64 * 1024;

/// Attribute validation service.
pub struct AttributeValidationService;

impl AttributeValidationService {
    /// Validate custom attributes against the tenant's attribute definitions.
    ///
    /// # Arguments
    /// * `definitions` - The tenant's attribute definitions
    /// * `attributes` - The JSONB value to validate
    /// * `is_full_replace` - If true, required attributes must be present. If false (patch/merge), missing required fields are allowed.
    ///
    /// # Returns
    /// * `Ok(())` if all validations pass
    /// * `Err(Vec<AttributeFieldError>)` with all violations (not just the first)
    pub fn validate_attributes(
        definitions: &[TenantAttributeDefinition],
        attributes: &Value,
        is_full_replace: bool,
    ) -> Result<(), Vec<AttributeFieldError>> {
        let mut errors = Vec::new();

        // Check total size limit
        let serialized = serde_json::to_string(attributes).unwrap_or_default();
        if serialized.len() > MAX_ATTRIBUTES_SIZE {
            errors.push(AttributeFieldError {
                attribute: "*".to_string(),
                error: format!(
                    "Total custom attributes size ({} bytes) exceeds maximum ({} bytes)",
                    serialized.len(),
                    MAX_ATTRIBUTES_SIZE
                ),
            });
        }

        // Attributes must be an object
        let attrs = if let Some(obj) = attributes.as_object() {
            obj
        } else {
            errors.push(AttributeFieldError {
                attribute: "*".to_string(),
                error: "Custom attributes must be a JSON object".to_string(),
            });
            return Err(errors);
        };

        // Build definitions lookup by name (only active definitions)
        let active_defs: Vec<&TenantAttributeDefinition> =
            definitions.iter().filter(|d| d.is_active).collect();
        let def_names: std::collections::HashSet<&str> =
            active_defs.iter().map(|d| d.name.as_str()).collect();

        // Check for unknown attributes (not defined in tenant schema)
        for key in attrs.keys() {
            if !def_names.contains(key.as_str()) {
                errors.push(AttributeFieldError {
                    attribute: key.clone(),
                    error: format!("Unknown attribute '{key}': not defined in tenant schema"),
                });
            }
        }

        // Check required attributes (only on full replace)
        if is_full_replace {
            for def in &active_defs {
                if def.required && !attrs.contains_key(&def.name) {
                    errors.push(AttributeFieldError {
                        attribute: def.name.clone(),
                        error: format!("Required attribute '{}' is missing", def.name),
                    });
                }
            }
        }

        // Validate each provided attribute against its definition
        for def in &active_defs {
            if let Some(value) = attrs.get(&def.name) {
                // Skip null values — they represent "unset"
                if value.is_null() {
                    continue;
                }

                let data_type = if let Some(dt) = AttributeDataType::parse(&def.data_type) {
                    dt
                } else {
                    errors.push(AttributeFieldError {
                        attribute: def.name.clone(),
                        error: format!("Unknown data type '{}' in definition", def.data_type),
                    });
                    continue;
                };

                // Type validation
                if let Err(e) = Self::validate_type(&def.name, value, &data_type) {
                    errors.push(e);
                    continue; // Skip further validation if type is wrong
                }

                // Validation rules
                if let Some(rules) = &def.validation_rules {
                    let rule_errors = Self::validate_rules(&def.name, value, rules, &data_type);
                    errors.extend(rule_errors);
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate that a value matches the expected data type.
    fn validate_type(
        name: &str,
        value: &Value,
        expected: &AttributeDataType,
    ) -> Result<(), AttributeFieldError> {
        let valid = match expected {
            AttributeDataType::String => value.is_string(),
            AttributeDataType::Number => value.is_number(),
            AttributeDataType::Boolean => value.is_boolean(),
            AttributeDataType::Date => {
                // Date must be a string in ISO 8601 format (YYYY-MM-DD)
                if let Some(s) = value.as_str() {
                    NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
                } else {
                    false
                }
            }
            AttributeDataType::Json => {
                // Any valid JSON value is acceptable for json type
                value.is_object() || value.is_array()
            }
            AttributeDataType::Enum => {
                // Enum values must be strings (checked against allowed_values in validate_rules)
                value.is_string()
            }
        };

        if valid {
            Ok(())
        } else {
            let expected_str = match expected {
                AttributeDataType::String => "string",
                AttributeDataType::Number => "number",
                AttributeDataType::Boolean => "boolean",
                AttributeDataType::Date => "date (ISO 8601 YYYY-MM-DD string)",
                AttributeDataType::Json => "json (object or array)",
                AttributeDataType::Enum => "enum (string from allowed values)",
            };
            Err(AttributeFieldError {
                attribute: name.to_string(),
                error: format!(
                    "Invalid type for '{}': expected {}, got {}",
                    name,
                    expected_str,
                    Self::value_type_name(value)
                ),
            })
        }
    }

    /// Validate a value against validation rules.
    fn validate_rules(
        name: &str,
        value: &Value,
        rules: &Value,
        data_type: &AttributeDataType,
    ) -> Vec<AttributeFieldError> {
        let mut errors = Vec::new();
        let rules_obj = match rules.as_object() {
            Some(obj) => obj,
            None => return errors,
        };

        // String-specific validations
        if *data_type == AttributeDataType::String || *data_type == AttributeDataType::Date {
            if let Some(s) = value.as_str() {
                // max_length
                if let Some(max) = rules_obj
                    .get("max_length")
                    .and_then(serde_json::Value::as_u64)
                {
                    if s.len() as u64 > max {
                        errors.push(AttributeFieldError {
                            attribute: name.to_string(),
                            error: format!(
                                "'{}' exceeds maximum length of {} (got {})",
                                name,
                                max,
                                s.len()
                            ),
                        });
                    }
                }

                // min_length
                if let Some(min) = rules_obj
                    .get("min_length")
                    .and_then(serde_json::Value::as_u64)
                {
                    if (s.len() as u64) < min {
                        errors.push(AttributeFieldError {
                            attribute: name.to_string(),
                            error: format!(
                                "'{}' is shorter than minimum length of {} (got {})",
                                name,
                                min,
                                s.len()
                            ),
                        });
                    }
                }

                // pattern (regex) — cap compiled automaton size to 1MB to prevent ReDoS
                if let Some(pattern) = rules_obj.get("pattern").and_then(|v| v.as_str()) {
                    match regex::RegexBuilder::new(pattern)
                        .size_limit(1 << 20)
                        .build()
                    {
                        Ok(re) => {
                            if !re.is_match(s) {
                                errors.push(AttributeFieldError {
                                    attribute: name.to_string(),
                                    error: format!(
                                        "'{name}' does not match required pattern '{pattern}'"
                                    ),
                                });
                            }
                        }
                        Err(_) => {
                            errors.push(AttributeFieldError {
                                attribute: name.to_string(),
                                error: format!(
                                    "Invalid regex pattern '{pattern}' in validation rules for '{name}'"
                                ),
                            });
                        }
                    }
                }
            }
        }

        // Number-specific validations
        if *data_type == AttributeDataType::Number {
            if let Some(n) = value.as_f64() {
                // min
                if let Some(min) = rules_obj.get("min").and_then(serde_json::Value::as_f64) {
                    if n < min {
                        errors.push(AttributeFieldError {
                            attribute: name.to_string(),
                            error: format!("'{name}' value {n} is less than minimum {min}"),
                        });
                    }
                }

                // max
                if let Some(max) = rules_obj.get("max").and_then(serde_json::Value::as_f64) {
                    if n > max {
                        errors.push(AttributeFieldError {
                            attribute: name.to_string(),
                            error: format!("'{name}' value {n} exceeds maximum {max}"),
                        });
                    }
                }
            }
        }

        // allowed_values (enum validation — applies to string, number, and enum types)
        if let Some(allowed) = rules_obj.get("allowed_values").and_then(|v| v.as_array()) {
            if !allowed.is_empty() && !allowed.contains(value) {
                let allowed_strs: Vec<String> = allowed
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map_or_else(|| v.to_string(), std::string::ToString::to_string)
                    })
                    .collect();
                errors.push(AttributeFieldError {
                    attribute: name.to_string(),
                    error: format!(
                        "Value '{}' is not in allowed values: [{}]",
                        value.as_str().unwrap_or(&value.to_string()),
                        allowed_strs.join(", ")
                    ),
                });
            }
        }

        errors
    }

    /// Get human-readable name for a JSON value type.
    fn value_type_name(value: &Value) -> &'static str {
        match value {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_def(
        name: &str,
        data_type: &str,
        required: bool,
        validation_rules: Option<Value>,
    ) -> TenantAttributeDefinition {
        TenantAttributeDefinition {
            id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            name: name.to_string(),
            display_label: name.to_string(),
            data_type: data_type.to_string(),
            required,
            validation_rules,
            default_value: None,
            sort_order: 0,
            is_active: true,
            is_well_known: false,
            well_known_slug: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_valid_string_attribute() {
        let defs = vec![make_def("department", "string", false, None)];
        let attrs = json!({"department": "Engineering"});
        assert!(AttributeValidationService::validate_attributes(&defs, &attrs, false).is_ok());
    }

    #[test]
    fn test_valid_number_attribute() {
        let defs = vec![make_def("cost_center", "number", false, None)];
        let attrs = json!({"cost_center": 42});
        assert!(AttributeValidationService::validate_attributes(&defs, &attrs, false).is_ok());
    }

    #[test]
    fn test_valid_boolean_attribute() {
        let defs = vec![make_def("is_contractor", "boolean", false, None)];
        let attrs = json!({"is_contractor": true});
        assert!(AttributeValidationService::validate_attributes(&defs, &attrs, false).is_ok());
    }

    #[test]
    fn test_valid_date_attribute() {
        let defs = vec![make_def("hire_date", "date", false, None)];
        let attrs = json!({"hire_date": "2024-01-15"});
        assert!(AttributeValidationService::validate_attributes(&defs, &attrs, false).is_ok());
    }

    #[test]
    fn test_invalid_date_format() {
        let defs = vec![make_def("hire_date", "date", false, None)];
        let attrs = json!({"hire_date": "01/15/2024"});
        let result = AttributeValidationService::validate_attributes(&defs, &attrs, false);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].attribute, "hire_date");
    }

    #[test]
    fn test_type_mismatch() {
        let defs = vec![make_def("department", "string", false, None)];
        let attrs = json!({"department": 42});
        let result = AttributeValidationService::validate_attributes(&defs, &attrs, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_attribute() {
        let defs = vec![make_def("department", "string", false, None)];
        let attrs = json!({"unknown_field": "value"});
        let result = AttributeValidationService::validate_attributes(&defs, &attrs, false);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].error.contains("Unknown attribute"));
    }

    #[test]
    fn test_required_on_full_replace() {
        let defs = vec![make_def("department", "string", true, None)];
        let attrs = json!({});
        let result = AttributeValidationService::validate_attributes(&defs, &attrs, true);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].error.contains("Required attribute"));
    }

    #[test]
    fn test_required_not_checked_on_patch() {
        let defs = vec![make_def("department", "string", true, None)];
        let attrs = json!({});
        assert!(AttributeValidationService::validate_attributes(&defs, &attrs, false).is_ok());
    }

    #[test]
    fn test_max_length_validation() {
        let defs = vec![make_def(
            "department",
            "string",
            false,
            Some(json!({"max_length": 5})),
        )];
        let attrs = json!({"department": "Engineering"});
        let result = AttributeValidationService::validate_attributes(&defs, &attrs, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_min_max_number_validation() {
        let defs = vec![make_def(
            "cost_center",
            "number",
            false,
            Some(json!({"min": 100, "max": 999})),
        )];

        let attrs_low = json!({"cost_center": 50});
        assert!(AttributeValidationService::validate_attributes(&defs, &attrs_low, false).is_err());

        let attrs_high = json!({"cost_center": 1500});
        assert!(
            AttributeValidationService::validate_attributes(&defs, &attrs_high, false).is_err()
        );

        let attrs_ok = json!({"cost_center": 500});
        assert!(AttributeValidationService::validate_attributes(&defs, &attrs_ok, false).is_ok());
    }

    #[test]
    fn test_allowed_values_validation() {
        let defs = vec![make_def(
            "status",
            "string",
            false,
            Some(json!({"allowed_values": ["active", "inactive", "pending"]})),
        )];
        let attrs = json!({"status": "deleted"});
        let result = AttributeValidationService::validate_attributes(&defs, &attrs, false);
        assert!(result.is_err());

        let attrs_ok = json!({"status": "active"});
        assert!(AttributeValidationService::validate_attributes(&defs, &attrs_ok, false).is_ok());
    }

    #[test]
    fn test_pattern_validation() {
        let defs = vec![make_def(
            "employee_id",
            "string",
            false,
            Some(json!({"pattern": "^EMP-[0-9]{4}$"})),
        )];
        let attrs = json!({"employee_id": "EMP-1234"});
        assert!(AttributeValidationService::validate_attributes(&defs, &attrs, false).is_ok());

        let attrs_bad = json!({"employee_id": "INVALID"});
        assert!(AttributeValidationService::validate_attributes(&defs, &attrs_bad, false).is_err());
    }

    #[test]
    fn test_null_value_skips_validation() {
        let defs = vec![make_def("department", "string", false, None)];
        let attrs = json!({"department": null});
        assert!(AttributeValidationService::validate_attributes(&defs, &attrs, false).is_ok());
    }

    #[test]
    fn test_json_type_attribute() {
        let defs = vec![make_def("metadata", "json", false, None)];
        let attrs = json!({"metadata": {"key": "value"}});
        assert!(AttributeValidationService::validate_attributes(&defs, &attrs, false).is_ok());

        let attrs_array = json!({"metadata": [1, 2, 3]});
        assert!(
            AttributeValidationService::validate_attributes(&defs, &attrs_array, false).is_ok()
        );

        // Primitives are not valid json type
        let attrs_string = json!({"metadata": "not_json"});
        assert!(
            AttributeValidationService::validate_attributes(&defs, &attrs_string, false).is_err()
        );
    }

    #[test]
    fn test_multiple_errors_returned() {
        let defs = vec![
            make_def("department", "string", true, None),
            make_def("cost_center", "number", true, None),
        ];
        let attrs = json!({});
        let result = AttributeValidationService::validate_attributes(&defs, &attrs, true);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 2);
    }

    #[test]
    fn test_enum_valid_value() {
        let defs = vec![make_def(
            "employee_type",
            "enum",
            false,
            Some(json!({"allowed_values": ["full_time", "contractor", "intern"]})),
        )];
        let attrs = json!({"employee_type": "full_time"});
        assert!(AttributeValidationService::validate_attributes(&defs, &attrs, false).is_ok());
    }

    #[test]
    fn test_enum_invalid_value() {
        let defs = vec![make_def(
            "employee_type",
            "enum",
            false,
            Some(json!({"allowed_values": ["full_time", "contractor", "intern"]})),
        )];
        let attrs = json!({"employee_type": "volunteer"});
        let result = AttributeValidationService::validate_attributes(&defs, &attrs, false);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].error.contains("not in allowed values"));
        assert!(errors[0].error.contains("volunteer"));
    }

    #[test]
    fn test_enum_non_string_value_rejected() {
        let defs = vec![make_def(
            "employee_type",
            "enum",
            false,
            Some(json!({"allowed_values": ["full_time", "contractor"]})),
        )];
        let attrs = json!({"employee_type": 42});
        let result = AttributeValidationService::validate_attributes(&defs, &attrs, false);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].error.contains("expected enum"));
    }

    #[test]
    fn test_enum_null_value_skipped() {
        let defs = vec![make_def(
            "employee_type",
            "enum",
            false,
            Some(json!({"allowed_values": ["full_time", "contractor"]})),
        )];
        let attrs = json!({"employee_type": null});
        assert!(AttributeValidationService::validate_attributes(&defs, &attrs, false).is_ok());
    }

    #[test]
    fn test_not_an_object() {
        let defs = vec![make_def("department", "string", false, None)];
        let attrs = json!("not an object");
        let result = AttributeValidationService::validate_attributes(&defs, &attrs, false);
        assert!(result.is_err());
    }
}
