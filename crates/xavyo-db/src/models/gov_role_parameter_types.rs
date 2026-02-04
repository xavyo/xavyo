//! Type definitions for parametric roles (F057).

use serde::{Deserialize, Serialize};
use sqlx::Type;

/// Parameter type enum - matches `gov_parameter_type` in database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_parameter_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ParameterType {
    /// String parameter type.
    String,
    /// Integer parameter type.
    Integer,
    /// Boolean parameter type.
    Boolean,
    /// Date parameter type (YYYY-MM-DD format).
    Date,
    /// Enum parameter type (value must be in `allowed_values`).
    Enum,
}

impl std::fmt::Display for ParameterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String => write!(f, "string"),
            Self::Integer => write!(f, "integer"),
            Self::Boolean => write!(f, "boolean"),
            Self::Date => write!(f, "date"),
            Self::Enum => write!(f, "enum"),
        }
    }
}

/// Parameter audit event type enum - matches `gov_parameter_event_type` in database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_parameter_event_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ParameterEventType {
    /// Initial parameter values on assignment.
    ParametersSet,
    /// Parameter values modified.
    ParametersUpdated,
    /// New parameter added to existing assignment.
    ParameterAdded,
    /// Parameter removed from assignment.
    ParameterRemoved,
    /// Parameter validation rejection (for audit).
    ValidationFailed,
    /// Assignment flagged for schema non-conformance.
    SchemaViolationFlagged,
}

impl std::fmt::Display for ParameterEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParametersSet => write!(f, "parameters_set"),
            Self::ParametersUpdated => write!(f, "parameters_updated"),
            Self::ParameterAdded => write!(f, "parameter_added"),
            Self::ParameterRemoved => write!(f, "parameter_removed"),
            Self::ValidationFailed => write!(f, "validation_failed"),
            Self::SchemaViolationFlagged => write!(f, "schema_violation_flagged"),
        }
    }
}

/// Parameter constraints structure for validation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParameterConstraints {
    // Integer constraints
    /// Minimum value for integer parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_value: Option<i64>,
    /// Maximum value for integer parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_value: Option<i64>,

    // String constraints
    /// Minimum length for string parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,
    /// Maximum length for string parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,
    /// Regex pattern for string parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,

    // Enum constraints
    /// Allowed values for enum parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_values: Option<Vec<String>>,

    // Date constraints
    /// Minimum date for date parameters (YYYY-MM-DD format).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_date: Option<String>,
    /// Maximum date for date parameters (YYYY-MM-DD format).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_date: Option<String>,
}

impl ParameterConstraints {
    /// Create empty constraints.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Create integer constraints with min/max values.
    #[must_use] 
    pub fn integer(min: Option<i64>, max: Option<i64>) -> Self {
        Self {
            min_value: min,
            max_value: max,
            ..Default::default()
        }
    }

    /// Create string constraints with length and pattern.
    #[must_use] 
    pub fn string(
        min_length: Option<usize>,
        max_length: Option<usize>,
        pattern: Option<String>,
    ) -> Self {
        Self {
            min_length,
            max_length,
            pattern,
            ..Default::default()
        }
    }

    /// Create enum constraints with allowed values.
    #[must_use] 
    pub fn enumeration(allowed_values: Vec<String>) -> Self {
        Self {
            allowed_values: Some(allowed_values),
            ..Default::default()
        }
    }

    /// Create date constraints with min/max dates.
    #[must_use] 
    pub fn date(min_date: Option<String>, max_date: Option<String>) -> Self {
        Self {
            min_date,
            max_date,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_type_display() {
        assert_eq!(ParameterType::String.to_string(), "string");
        assert_eq!(ParameterType::Integer.to_string(), "integer");
        assert_eq!(ParameterType::Boolean.to_string(), "boolean");
        assert_eq!(ParameterType::Date.to_string(), "date");
        assert_eq!(ParameterType::Enum.to_string(), "enum");
    }

    #[test]
    fn test_parameter_event_type_display() {
        assert_eq!(
            ParameterEventType::ParametersSet.to_string(),
            "parameters_set"
        );
        assert_eq!(
            ParameterEventType::ParametersUpdated.to_string(),
            "parameters_updated"
        );
        assert_eq!(
            ParameterEventType::ParameterAdded.to_string(),
            "parameter_added"
        );
        assert_eq!(
            ParameterEventType::ParameterRemoved.to_string(),
            "parameter_removed"
        );
        assert_eq!(
            ParameterEventType::ValidationFailed.to_string(),
            "validation_failed"
        );
        assert_eq!(
            ParameterEventType::SchemaViolationFlagged.to_string(),
            "schema_violation_flagged"
        );
    }

    #[test]
    fn test_parameter_constraints_builders() {
        let int_constraints = ParameterConstraints::integer(Some(1), Some(100));
        assert_eq!(int_constraints.min_value, Some(1));
        assert_eq!(int_constraints.max_value, Some(100));

        let str_constraints =
            ParameterConstraints::string(Some(1), Some(255), Some("^[a-z]+$".to_string()));
        assert_eq!(str_constraints.min_length, Some(1));
        assert_eq!(str_constraints.max_length, Some(255));
        assert_eq!(str_constraints.pattern, Some("^[a-z]+$".to_string()));

        let enum_constraints =
            ParameterConstraints::enumeration(vec!["read".to_string(), "write".to_string()]);
        assert_eq!(
            enum_constraints.allowed_values,
            Some(vec!["read".to_string(), "write".to_string()])
        );

        let date_constraints = ParameterConstraints::date(
            Some("2020-01-01".to_string()),
            Some("2030-12-31".to_string()),
        );
        assert_eq!(date_constraints.min_date, Some("2020-01-01".to_string()));
        assert_eq!(date_constraints.max_date, Some("2030-12-31".to_string()));
    }

    #[test]
    fn test_parameter_type_serialization() {
        let json = serde_json::to_string(&ParameterType::String).unwrap();
        assert_eq!(json, "\"string\"");

        let deserialized: ParameterType = serde_json::from_str("\"integer\"").unwrap();
        assert_eq!(deserialized, ParameterType::Integer);
    }

    #[test]
    fn test_constraints_serialization() {
        let constraints = ParameterConstraints {
            min_value: Some(1),
            max_value: Some(100),
            ..Default::default()
        };

        let json = serde_json::to_string(&constraints).unwrap();
        assert!(json.contains("\"min_value\":1"));
        assert!(json.contains("\"max_value\":100"));
        // Empty fields should be skipped
        assert!(!json.contains("min_length"));
    }
}
