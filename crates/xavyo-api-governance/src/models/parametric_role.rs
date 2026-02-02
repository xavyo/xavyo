//! Request and response models for parametric role endpoints (F057).
//!
//! Parametric roles allow roles to have customizable parameters that can be
//! bound at assignment time. This enables a single role definition to be used
//! with different parameter values (e.g., "Database Access" role with a
//! "database_name" parameter).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{
    GovParameterAuditEvent, GovRoleAssignmentParameter, GovRoleParameter, ParameterConstraints,
    ParameterEventType, ParameterType,
};

// ============================================================================
// Role Parameter Definition Models
// ============================================================================

/// Request to create a new role parameter.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateRoleParameterRequest {
    /// Parameter name (alphanumeric with underscores, 1-100 characters).
    #[validate(
        length(
            min = 1,
            max = 100,
            message = "Name must be between 1 and 100 characters"
        ),
        custom(function = "validate_parameter_name")
    )]
    pub name: String,

    /// Human-readable display name (optional, max 255 characters).
    #[validate(length(max = 255, message = "Display name must not exceed 255 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Description of the parameter (optional, max 2000 characters).
    #[validate(length(max = 2000, message = "Description must not exceed 2000 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Parameter type (string, integer, boolean, date, enum).
    pub parameter_type: ParameterType,

    /// Whether a value must be provided at assignment time (default: false).
    #[serde(default)]
    pub is_required: bool,

    /// Default value if not provided at assignment time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<serde_json::Value>,

    /// Validation constraints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<ParameterConstraintsRequest>,

    /// Display order for UI (default: 0).
    #[serde(default)]
    pub display_order: i32,
}

/// Request to update a role parameter.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateRoleParameterRequest {
    /// Updated display name.
    #[validate(length(max = 255, message = "Display name must not exceed 255 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Updated description.
    #[validate(length(max = 2000, message = "Description must not exceed 2000 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Updated required flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_required: Option<bool>,

    /// Updated default value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<serde_json::Value>,

    /// Updated constraints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<ParameterConstraintsRequest>,

    /// Updated display order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_order: Option<i32>,
}

/// Parameter constraints request structure.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ParameterConstraintsRequest {
    /// Minimum value for integer parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_value: Option<i64>,

    /// Maximum value for integer parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_value: Option<i64>,

    /// Minimum length for string parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,

    /// Maximum length for string parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,

    /// Regex pattern for string parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,

    /// Allowed values for enum parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_values: Option<Vec<String>>,

    /// Minimum date for date parameters (YYYY-MM-DD format).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_date: Option<String>,

    /// Maximum date for date parameters (YYYY-MM-DD format).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_date: Option<String>,
}

impl From<ParameterConstraintsRequest> for ParameterConstraints {
    fn from(req: ParameterConstraintsRequest) -> Self {
        Self {
            min_value: req.min_value,
            max_value: req.max_value,
            min_length: req.min_length,
            max_length: req.max_length,
            pattern: req.pattern,
            allowed_values: req.allowed_values,
            min_date: req.min_date,
            max_date: req.max_date,
        }
    }
}

/// Role parameter response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoleParameterResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Role ID.
    pub role_id: Uuid,

    /// Parameter name.
    pub name: String,

    /// Human-readable display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Parameter type.
    pub parameter_type: ParameterType,

    /// Whether value is required.
    pub is_required: bool,

    /// Default value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<serde_json::Value>,

    /// Validation constraints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<serde_json::Value>,

    /// Display order.
    pub display_order: i32,

    /// When the parameter was created.
    pub created_at: DateTime<Utc>,

    /// When the parameter was last updated.
    pub updated_at: DateTime<Utc>,
}

impl From<GovRoleParameter> for RoleParameterResponse {
    fn from(param: GovRoleParameter) -> Self {
        Self {
            id: param.id,
            tenant_id: param.tenant_id,
            role_id: param.role_id,
            name: param.name,
            display_name: param.display_name,
            description: param.description,
            parameter_type: param.parameter_type,
            is_required: param.is_required,
            default_value: param.default_value,
            constraints: param.constraints,
            display_order: param.display_order,
            created_at: param.created_at,
            updated_at: param.updated_at,
        }
    }
}

/// Query parameters for listing role parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct ListRoleParametersQuery {
    /// Filter by parameter type.
    pub parameter_type: Option<ParameterType>,

    /// Filter by required flag.
    pub is_required: Option<bool>,

    /// Filter by name (partial match).
    pub name: Option<String>,
}

/// Paginated list of role parameters.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoleParameterListResponse {
    /// List of parameters.
    pub items: Vec<RoleParameterResponse>,

    /// Total count.
    pub total: i64,
}

// ============================================================================
// Parametric Assignment Models
// ============================================================================

/// Request to create a parametric assignment (role assignment with parameters).
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateParametricAssignmentRequest {
    /// Target type (user or group).
    pub target_type: String,

    /// Target ID (user_id or group_id).
    pub target_id: Uuid,

    /// Justification for the assignment (min 20 characters).
    #[validate(length(min = 20, message = "Justification must be at least 20 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,

    /// When the assignment expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// When the assignment becomes active (for temporal validity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,

    /// When the assignment becomes inactive (for temporal validity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<DateTime<Utc>>,

    /// Parameter values for this assignment.
    #[validate(length(min = 1, message = "At least one parameter value is required"))]
    pub parameters: Vec<ParameterValueRequest>,
}

/// A parameter value in an assignment request.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ParameterValueRequest {
    /// Parameter ID or name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_id: Option<Uuid>,

    /// Parameter name (alternative to ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_name: Option<String>,

    /// Parameter value.
    pub value: serde_json::Value,
}

/// Request to update assignment parameters.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateAssignmentParametersRequest {
    /// Updated parameter values.
    #[validate(length(min = 1, message = "At least one parameter value is required"))]
    pub parameters: Vec<ParameterValueRequest>,
}

/// Assignment parameter response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AssignmentParameterResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Assignment ID.
    pub assignment_id: Uuid,

    /// Parameter ID.
    pub parameter_id: Uuid,

    /// Parameter name.
    pub parameter_name: String,

    /// Parameter display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_display_name: Option<String>,

    /// Parameter type.
    pub parameter_type: String,

    /// Parameter value.
    pub value: serde_json::Value,

    /// When the parameter was set.
    pub created_at: DateTime<Utc>,

    /// When the parameter was last updated.
    pub updated_at: DateTime<Utc>,
}

impl From<GovRoleAssignmentParameter> for AssignmentParameterResponse {
    fn from(param: GovRoleAssignmentParameter) -> Self {
        Self {
            id: param.id,
            assignment_id: param.assignment_id,
            parameter_id: param.parameter_id,
            parameter_name: String::new(), // Will be enriched
            parameter_display_name: None,
            parameter_type: String::new(), // Will be enriched
            value: param.value,
            created_at: param.created_at,
            updated_at: param.updated_at,
        }
    }
}

/// Parametric assignment response (assignment with parameters).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ParametricAssignmentResponse {
    /// Assignment ID.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Role (entitlement) ID.
    pub role_id: Uuid,

    /// Role name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_name: Option<String>,

    /// Target type (user or group).
    pub target_type: String,

    /// Target ID.
    pub target_id: Uuid,

    /// Who made the assignment.
    pub assigned_by: Uuid,

    /// When the assignment was made.
    pub assigned_at: DateTime<Utc>,

    /// Assignment status.
    pub status: String,

    /// Justification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,

    /// When the assignment expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Parameter hash for uniqueness.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_hash: Option<String>,

    /// When the assignment becomes active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,

    /// When the assignment becomes inactive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<DateTime<Utc>>,

    /// Whether the assignment is currently temporally active.
    pub is_temporally_active: bool,

    /// Parameter values.
    pub parameters: Vec<AssignmentParameterResponse>,
}

/// Query parameters for listing parametric assignments.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListParametricAssignmentsQuery {
    /// Filter by role ID.
    pub role_id: Option<Uuid>,

    /// Include temporally inactive assignments (default: false).
    #[serde(default)]
    pub include_inactive: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListParametricAssignmentsQuery {
    fn default() -> Self {
        Self {
            role_id: None,
            include_inactive: Some(false),
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Paginated list of parametric assignments.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ParametricAssignmentListResponse {
    /// List of assignments.
    pub items: Vec<ParametricAssignmentResponse>,

    /// Total count.
    pub total: i64,

    /// Limit used.
    pub limit: i64,

    /// Offset used.
    pub offset: i64,
}

// ============================================================================
// Parameter Validation Models
// ============================================================================

/// Request to validate parameters before assignment.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ValidateParametersRequest {
    /// Parameter values to validate.
    #[validate(length(min = 1, message = "At least one parameter value is required"))]
    pub parameters: Vec<ParameterValueRequest>,
}

/// Parameter validation result.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ValidateParametersResponse {
    /// Whether all parameters are valid.
    pub is_valid: bool,

    /// Validation results per parameter.
    pub results: Vec<ParameterValidationResult>,

    /// Overall errors.
    pub errors: Vec<String>,
}

/// Validation result for a single parameter.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ParameterValidationResult {
    /// Parameter ID.
    pub parameter_id: Uuid,

    /// Parameter name.
    pub parameter_name: String,

    /// Whether this parameter is valid.
    pub is_valid: bool,

    /// Validation errors for this parameter.
    pub errors: Vec<String>,

    /// Normalized/coerced value (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_value: Option<serde_json::Value>,
}

// ============================================================================
// Audit Models
// ============================================================================

/// Query parameters for listing parameter audit events.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListParameterAuditQuery {
    /// Filter by assignment ID.
    pub assignment_id: Option<Uuid>,

    /// Filter by event type.
    pub event_type: Option<ParameterEventType>,

    /// Filter by actor ID.
    pub actor_id: Option<Uuid>,

    /// Filter events from this date.
    pub from_date: Option<DateTime<Utc>>,

    /// Filter events to this date.
    pub to_date: Option<DateTime<Utc>>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListParameterAuditQuery {
    fn default() -> Self {
        Self {
            assignment_id: None,
            event_type: None,
            actor_id: None,
            from_date: None,
            to_date: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Parameter audit event response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ParameterAuditEventResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Assignment ID.
    pub assignment_id: Uuid,

    /// Event type.
    pub event_type: ParameterEventType,

    /// Actor who triggered the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Uuid>,

    /// Previous parameter values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_values: Option<serde_json::Value>,

    /// New parameter values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_values: Option<serde_json::Value>,

    /// Additional metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,

    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

impl From<GovParameterAuditEvent> for ParameterAuditEventResponse {
    fn from(event: GovParameterAuditEvent) -> Self {
        Self {
            id: event.id,
            tenant_id: event.tenant_id,
            assignment_id: event.assignment_id,
            event_type: event.event_type,
            actor_id: event.actor_id,
            old_values: event.old_values,
            new_values: event.new_values,
            metadata: event.metadata,
            created_at: event.created_at,
        }
    }
}

/// Paginated list of parameter audit events.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ParameterAuditListResponse {
    /// List of events.
    pub items: Vec<ParameterAuditEventResponse>,

    /// Total count.
    pub total: i64,

    /// Limit used.
    pub limit: i64,

    /// Offset used.
    pub offset: i64,
}

// ============================================================================
// Effective Entitlements with Parameters
// ============================================================================

/// Effective entitlement with parameter context.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EffectiveEntitlementWithParams {
    /// Entitlement ID.
    pub entitlement_id: Uuid,

    /// Entitlement name.
    pub entitlement_name: String,

    /// Application ID.
    pub application_id: Uuid,

    /// Application name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_name: Option<String>,

    /// Assignment ID.
    pub assignment_id: Uuid,

    /// How the entitlement was obtained (direct, group, role).
    pub source: String,

    /// Whether this is a parametric entitlement.
    pub is_parametric: bool,

    /// Parameter context (if parametric).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Vec<EffectiveParameterValue>>,
}

/// An effective parameter value for provisioning.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EffectiveParameterValue {
    /// Parameter name.
    pub name: String,

    /// Parameter value.
    pub value: serde_json::Value,

    /// Parameter type.
    pub parameter_type: String,
}

// ============================================================================
// Parameter name validation
// ============================================================================

lazy_static::lazy_static! {
    /// Regex for validating parameter names.
    pub static ref PARAMETER_NAME_REGEX: regex::Regex =
        regex::Regex::new(r"^[a-zA-Z][a-zA-Z0-9_]*$").unwrap();
}

/// Custom validator function for parameter names.
fn validate_parameter_name(name: &str) -> Result<(), validator::ValidationError> {
    if PARAMETER_NAME_REGEX.is_match(name) {
        Ok(())
    } else {
        let mut err = validator::ValidationError::new("invalid_parameter_name");
        err.message = Some("Name must start with a letter and contain only alphanumeric characters and underscores".into());
        Err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use validator::Validate;

    #[test]
    fn test_create_parameter_validation() {
        let valid = CreateRoleParameterRequest {
            name: "database_name".to_string(),
            display_name: Some("Database Name".to_string()),
            description: Some("Name of the database to access".to_string()),
            parameter_type: ParameterType::String,
            is_required: true,
            default_value: None,
            constraints: Some(ParameterConstraintsRequest {
                min_length: Some(1),
                max_length: Some(255),
                pattern: Some("^[a-z][a-z0-9_]*$".to_string()),
                min_value: None,
                max_value: None,
                allowed_values: None,
                min_date: None,
                max_date: None,
            }),
            display_order: 0,
        };
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn test_invalid_parameter_name() {
        let invalid = CreateRoleParameterRequest {
            name: "123invalid".to_string(), // Starts with number
            display_name: None,
            description: None,
            parameter_type: ParameterType::String,
            is_required: false,
            default_value: None,
            constraints: None,
            display_order: 0,
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_parameter_value_request() {
        let by_id = ParameterValueRequest {
            parameter_id: Some(Uuid::new_v4()),
            parameter_name: None,
            value: serde_json::json!("production_db"),
        };
        assert!(by_id.parameter_id.is_some());

        let by_name = ParameterValueRequest {
            parameter_id: None,
            parameter_name: Some("database_name".to_string()),
            value: serde_json::json!("production_db"),
        };
        assert!(by_name.parameter_name.is_some());
    }

    #[test]
    fn test_constraints_conversion() {
        let req = ParameterConstraintsRequest {
            min_value: Some(1),
            max_value: Some(100),
            min_length: None,
            max_length: None,
            pattern: None,
            allowed_values: None,
            min_date: None,
            max_date: None,
        };

        let constraints: ParameterConstraints = req.into();
        assert_eq!(constraints.min_value, Some(1));
        assert_eq!(constraints.max_value, Some(100));
    }

    #[test]
    fn test_validation_request() {
        let valid = ValidateParametersRequest {
            parameters: vec![ParameterValueRequest {
                parameter_id: Some(Uuid::new_v4()),
                parameter_name: None,
                value: serde_json::json!("test"),
            }],
        };
        assert!(valid.validate().is_ok());

        let invalid = ValidateParametersRequest { parameters: vec![] };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_list_queries_defaults() {
        let params_query = ListRoleParametersQuery::default();
        assert!(params_query.parameter_type.is_none());

        let assignments_query = ListParametricAssignmentsQuery::default();
        assert_eq!(assignments_query.limit, Some(50));
        assert_eq!(assignments_query.offset, Some(0));

        let audit_query = ListParameterAuditQuery::default();
        assert_eq!(audit_query.limit, Some(50));
        assert_eq!(audit_query.offset, Some(0));
    }
}
