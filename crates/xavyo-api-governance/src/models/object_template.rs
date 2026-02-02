//! Request and response models for object template endpoints (F058).
//!
//! Object templates define default values, computed values, validation rules,
//! and normalization rules that are automatically applied when objects
//! (users, roles, entitlements, applications) are created or modified.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::models::{
    GovObjectTemplate, GovTemplateApplicationEvent, GovTemplateEvent, GovTemplateMergePolicy,
    GovTemplateRule, GovTemplateScope, GovTemplateVersion, ObjectTemplateStatus, TemplateEventType,
    TemplateMergeStrategy, TemplateNullHandling, TemplateObjectType, TemplateRuleType,
    TemplateScopeType, TemplateStrength, TemplateTimeReference, DEFAULT_TEMPLATE_PRIORITY,
};

// ============================================================================
// Object Template Core Models
// ============================================================================

/// Request to create a new object template.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateTemplateRequest {
    /// Display name for the template (1-255 characters).
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Description of the template (max 2000 characters).
    #[validate(length(max = 2000, message = "Description must not exceed 2000 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Type of object this template targets.
    pub object_type: TemplateObjectType,

    /// Priority for template ordering (lower = higher precedence).
    #[validate(range(min = 1, max = 1000, message = "Priority must be between 1 and 1000"))]
    #[serde(default = "default_priority")]
    pub priority: i32,

    /// Parent template for inheritance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_template_id: Option<Uuid>,

    /// Initial rules to create with the template.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub rules: Option<Vec<CreateRuleRequest>>,

    /// Initial scopes to create with the template.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub scopes: Option<Vec<CreateScopeRequest>>,
}

fn default_priority() -> i32 {
    DEFAULT_TEMPLATE_PRIORITY
}

/// Request to update an existing object template.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateTemplateRequest {
    /// Updated display name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Updated description.
    #[validate(length(max = 2000, message = "Description must not exceed 2000 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Updated priority.
    #[validate(range(min = 1, max = 1000, message = "Priority must be between 1 and 1000"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,

    /// Updated parent template for inheritance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_template_id: Option<Uuid>,
}

/// Query parameters for listing object templates.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListObjectTemplatesQuery {
    /// Filter by status.
    pub status: Option<ObjectTemplateStatus>,

    /// Filter by object type.
    pub object_type: Option<TemplateObjectType>,

    /// Filter by name (partial match).
    pub name: Option<String>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListObjectTemplatesQuery {
    fn default() -> Self {
        Self {
            status: None,
            object_type: None,
            name: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Object template response (summary).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TemplateResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Display name.
    pub name: String,

    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Type of object this template targets.
    pub object_type: TemplateObjectType,

    /// Current status.
    pub status: ObjectTemplateStatus,

    /// Priority (lower = higher precedence).
    pub priority: i32,

    /// Parent template for inheritance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_template_id: Option<Uuid>,

    /// User who created this template.
    pub created_by: Uuid,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<GovObjectTemplate> for TemplateResponse {
    fn from(t: GovObjectTemplate) -> Self {
        Self {
            id: t.id,
            tenant_id: t.tenant_id,
            name: t.name,
            description: t.description,
            object_type: t.object_type,
            status: t.status,
            priority: t.priority,
            parent_template_id: t.parent_template_id,
            created_by: t.created_by,
            created_at: t.created_at,
            updated_at: t.updated_at,
        }
    }
}

/// Object template detailed response (with rules, scopes, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TemplateDetailResponse {
    /// Basic template info.
    #[serde(flatten)]
    pub template: TemplateResponse,

    /// Rules associated with this template.
    pub rules: Vec<RuleResponse>,

    /// Scopes where this template applies.
    pub scopes: Vec<ScopeResponse>,

    /// Merge policies for multi-source attributes.
    pub merge_policies: Vec<MergePolicyResponse>,

    /// Current version number.
    pub current_version: Option<i32>,

    /// Parent template details (if inherited).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<Box<TemplateResponse>>,
}

/// Paginated list of templates.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TemplateListResponse {
    /// List of templates.
    pub items: Vec<TemplateResponse>,

    /// Total count of matching templates.
    pub total: i64,

    /// Current page size.
    pub limit: i64,

    /// Current offset.
    pub offset: i64,
}

// ============================================================================
// Template Rule Models
// ============================================================================

/// Request to create a new template rule.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateRuleRequest {
    /// Type of rule.
    pub rule_type: TemplateRuleType,

    /// Target attribute this rule affects.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Target attribute must be between 1 and 255 characters"
    ))]
    pub target_attribute: String,

    /// Expression or value for the rule.
    #[validate(length(min = 1, message = "Expression cannot be empty"))]
    pub expression: String,

    /// Mapping strength (strong, normal, weak).
    #[serde(default)]
    pub strength: TemplateStrength,

    /// Whether values are removed when source changes.
    #[serde(default = "default_authoritative")]
    pub authoritative: bool,

    /// Priority within the template (lower = first).
    #[validate(range(min = 1, max = 1000, message = "Priority must be between 1 and 1000"))]
    #[serde(default = "default_rule_priority")]
    pub priority: i32,

    /// Optional condition expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,

    /// Custom error message for validation rules.
    #[validate(length(max = 500, message = "Error message must not exceed 500 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    /// If true, no other rule can target the same attribute (IGA exclusive mapping).
    #[serde(default)]
    pub exclusive: bool,

    /// Rule only applies after this timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_from: Option<DateTime<Utc>>,

    /// Rule only applies before this timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_to: Option<DateTime<Utc>>,

    /// How to interpret time_from/time_to (absolute or relative to object creation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_reference: Option<TemplateTimeReference>,
}

fn default_authoritative() -> bool {
    true
}

fn default_rule_priority() -> i32 {
    100
}

/// Request to update a template rule.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateRuleRequest {
    /// Updated expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,

    /// Updated strength.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strength: Option<TemplateStrength>,

    /// Updated authoritative flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authoritative: Option<bool>,

    /// Updated priority.
    #[validate(range(min = 1, max = 1000, message = "Priority must be between 1 and 1000"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,

    /// Updated condition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,

    /// Updated error message.
    #[validate(length(max = 500, message = "Error message must not exceed 500 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    /// Updated exclusive flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclusive: Option<bool>,

    /// Updated time_from constraint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_from: Option<DateTime<Utc>>,

    /// Updated time_to constraint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_to: Option<DateTime<Utc>>,

    /// Updated time reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_reference: Option<TemplateTimeReference>,
}

/// Template rule response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RuleResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Parent template ID.
    pub template_id: Uuid,

    /// Type of rule.
    pub rule_type: TemplateRuleType,

    /// Target attribute.
    pub target_attribute: String,

    /// Expression or value.
    pub expression: String,

    /// Mapping strength.
    pub strength: TemplateStrength,

    /// Authoritative flag.
    pub authoritative: bool,

    /// Priority within template.
    pub priority: i32,

    /// Condition expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,

    /// Custom error message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    /// Exclusive mapping flag.
    pub exclusive: bool,

    /// Rule only applies after this timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_from: Option<DateTime<Utc>>,

    /// Rule only applies before this timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_to: Option<DateTime<Utc>>,

    /// Time reference type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_reference: Option<TemplateTimeReference>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<GovTemplateRule> for RuleResponse {
    fn from(r: GovTemplateRule) -> Self {
        Self {
            id: r.id,
            template_id: r.template_id,
            rule_type: r.rule_type,
            target_attribute: r.target_attribute,
            expression: r.expression,
            strength: r.strength,
            authoritative: r.authoritative,
            priority: r.priority,
            condition: r.condition,
            error_message: r.error_message,
            exclusive: r.exclusive,
            time_from: r.time_from,
            time_to: r.time_to,
            time_reference: r.time_reference,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// Query parameters for listing template rules.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListTemplateRulesQuery {
    /// Filter by rule type.
    pub rule_type: Option<TemplateRuleType>,

    /// Filter by target attribute.
    pub target_attribute: Option<String>,

    /// Filter by strength.
    pub strength: Option<TemplateStrength>,

    /// Maximum number of results (default: 100, max: 500).
    #[param(minimum = 1, maximum = 500)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListTemplateRulesQuery {
    fn default() -> Self {
        Self {
            rule_type: None,
            target_attribute: None,
            strength: None,
            limit: Some(100),
            offset: Some(0),
        }
    }
}

/// Paginated list of rules.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RuleListResponse {
    /// List of rules.
    pub items: Vec<RuleResponse>,

    /// Total count.
    pub total: i64,

    /// Current page size.
    pub limit: i64,

    /// Current offset.
    pub offset: i64,
}

// ============================================================================
// Template Scope Models
// ============================================================================

/// Request to create a template scope.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateScopeRequest {
    /// Type of scope.
    pub scope_type: TemplateScopeType,

    /// Scope value (org ID, category name, etc.).
    #[validate(length(max = 500, message = "Scope value must not exceed 500 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_value: Option<String>,

    /// Condition expression for condition-type scopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
}

/// Template scope response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScopeResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Parent template ID.
    pub template_id: Uuid,

    /// Type of scope.
    pub scope_type: TemplateScopeType,

    /// Scope value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_value: Option<String>,

    /// Condition expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

impl From<GovTemplateScope> for ScopeResponse {
    fn from(s: GovTemplateScope) -> Self {
        Self {
            id: s.id,
            template_id: s.template_id,
            scope_type: s.scope_type,
            scope_value: s.scope_value,
            condition: s.condition,
            created_at: s.created_at,
        }
    }
}

/// List of scopes.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScopeListResponse {
    /// List of scopes.
    pub items: Vec<ScopeResponse>,
}

// ============================================================================
// Template Version Models
// ============================================================================

/// Query parameters for listing template versions.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListVersionsQuery {
    /// Maximum number of results.
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListVersionsQuery {
    fn default() -> Self {
        Self {
            limit: Some(20),
            offset: Some(0),
        }
    }
}

/// Template version response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VersionResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Parent template ID.
    pub template_id: Uuid,

    /// Version number.
    pub version_number: i32,

    /// Rules snapshot at this version.
    pub rules_snapshot: Value,

    /// Scopes snapshot at this version.
    pub scopes_snapshot: Value,

    /// User who created this version.
    pub created_by: Uuid,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

impl From<GovTemplateVersion> for VersionResponse {
    fn from(v: GovTemplateVersion) -> Self {
        Self {
            id: v.id,
            template_id: v.template_id,
            version_number: v.version_number,
            rules_snapshot: v.rules_snapshot,
            scopes_snapshot: v.scopes_snapshot,
            created_by: v.created_by,
            created_at: v.created_at,
        }
    }
}

/// Paginated list of versions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VersionListResponse {
    /// List of versions.
    pub items: Vec<VersionResponse>,

    /// Total count.
    pub total: i64,

    /// Current page size.
    pub limit: i64,

    /// Current offset.
    pub offset: i64,
}

// ============================================================================
// Merge Policy Models
// ============================================================================

/// Request to create a merge policy.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateMergePolicyRequest {
    /// Target attribute.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Attribute must be between 1 and 255 characters"
    ))]
    pub attribute: String,

    /// Merge strategy.
    pub strategy: TemplateMergeStrategy,

    /// Source precedence order (for source_precedence strategy).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_precedence: Option<Vec<String>>,

    /// Null handling behavior.
    #[serde(default)]
    pub null_handling: TemplateNullHandling,
}

/// Request to update a merge policy.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateMergePolicyRequest {
    /// Updated merge strategy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<TemplateMergeStrategy>,

    /// Updated source precedence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_precedence: Option<Vec<String>>,

    /// Updated null handling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub null_handling: Option<TemplateNullHandling>,
}

/// Merge policy response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MergePolicyResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Parent template ID.
    pub template_id: Uuid,

    /// Target attribute.
    pub attribute: String,

    /// Merge strategy.
    pub strategy: TemplateMergeStrategy,

    /// Source precedence order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_precedence: Option<Value>,

    /// Null handling behavior.
    pub null_handling: TemplateNullHandling,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<GovTemplateMergePolicy> for MergePolicyResponse {
    fn from(p: GovTemplateMergePolicy) -> Self {
        Self {
            id: p.id,
            template_id: p.template_id,
            attribute: p.attribute,
            strategy: p.strategy,
            source_precedence: p.source_precedence,
            null_handling: p.null_handling,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

/// List of merge policies.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MergePolicyListResponse {
    /// List of merge policies.
    pub items: Vec<MergePolicyResponse>,
}

// ============================================================================
// Simulation Models
// ============================================================================

/// Request to simulate template application.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct SimulationRequest {
    /// Sample object data to test template against.
    pub sample_object: Value,

    /// Limit number of results.
    #[serde(default = "default_simulation_limit")]
    pub limit: i32,
}

fn default_simulation_limit() -> i32 {
    100
}

/// Result of a template simulation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TemplateSimulationResponse {
    /// Template that was simulated.
    pub template_id: Uuid,

    /// Rules that would be applied.
    pub rules_applied: Vec<RuleApplicationResult>,

    /// Validation errors that would occur.
    pub validation_errors: Vec<ValidationError>,

    /// Computed values that would be generated.
    pub computed_values: Value,

    /// Total objects affected (for batch simulation).
    pub affected_count: i32,
}

/// Result of applying a single rule.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RuleApplicationResult {
    /// Rule ID.
    pub rule_id: Uuid,

    /// Target attribute.
    pub target_attribute: String,

    /// Rule type.
    pub rule_type: TemplateRuleType,

    /// Value before rule application.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_value: Option<Value>,

    /// Value after rule application.
    pub after_value: Value,

    /// Whether the rule was applied.
    pub applied: bool,

    /// Reason if not applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

/// Validation error from template application.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ValidationError {
    /// Rule ID that failed.
    pub rule_id: Uuid,

    /// Target attribute.
    pub target_attribute: String,

    /// Error message.
    pub message: String,

    /// Expression that failed.
    pub expression: String,
}

// ============================================================================
// Event Models
// ============================================================================

/// Query parameters for listing template events.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListTemplateEventsQuery {
    /// Filter by event type.
    pub event_type: Option<TemplateEventType>,

    /// Maximum number of results.
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListTemplateEventsQuery {
    fn default() -> Self {
        Self {
            event_type: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Template event response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TemplateEventResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Template ID.
    pub template_id: Option<Uuid>,

    /// Event type.
    pub event_type: TemplateEventType,

    /// Actor who triggered the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Uuid>,

    /// Change details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changes: Option<Value>,

    /// Event timestamp.
    pub created_at: DateTime<Utc>,
}

impl From<GovTemplateEvent> for TemplateEventResponse {
    fn from(e: GovTemplateEvent) -> Self {
        Self {
            id: e.id,
            template_id: e.template_id,
            event_type: e.event_type,
            actor_id: e.actor_id,
            changes: e.changes,
            created_at: e.created_at,
        }
    }
}

/// Paginated list of events.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TemplateEventListResponse {
    /// List of events.
    pub items: Vec<TemplateEventResponse>,

    /// Total count.
    pub total: i64,

    /// Current page size.
    pub limit: i64,

    /// Current offset.
    pub offset: i64,
}

// ============================================================================
// Application Event Models
// ============================================================================

/// Query parameters for listing application events.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListApplicationEventsQuery {
    /// Filter by object type.
    pub object_type: Option<TemplateObjectType>,

    /// Filter by object ID.
    pub object_id: Option<Uuid>,

    /// Maximum number of results.
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListApplicationEventsQuery {
    fn default() -> Self {
        Self {
            object_type: None,
            object_id: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Application event response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApplicationEventResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Template ID.
    pub template_id: Uuid,

    /// Template version ID.
    pub template_version_id: Uuid,

    /// Type of object affected.
    pub object_type: TemplateObjectType,

    /// ID of affected object.
    pub object_id: Uuid,

    /// Operation type (create/update).
    pub operation: String,

    /// Rules that were applied.
    pub rules_applied: Value,

    /// Changes made to the object.
    pub changes_made: Value,

    /// Validation errors if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_errors: Option<Value>,

    /// Actor who triggered the operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Uuid>,

    /// Event timestamp.
    pub created_at: DateTime<Utc>,
}

impl From<GovTemplateApplicationEvent> for ApplicationEventResponse {
    fn from(e: GovTemplateApplicationEvent) -> Self {
        Self {
            id: e.id,
            template_id: e.template_id.unwrap_or(Uuid::nil()),
            template_version_id: e.template_version_id.unwrap_or(Uuid::nil()),
            object_type: e.object_type,
            object_id: e.object_id,
            operation: e.operation.to_string(),
            rules_applied: e.rules_applied,
            changes_made: e.changes_made,
            validation_errors: e.validation_errors,
            actor_id: e.actor_id,
            created_at: e.created_at,
        }
    }
}

/// Paginated list of application events.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApplicationEventListResponse {
    /// List of events.
    pub items: Vec<ApplicationEventResponse>,

    /// Total count.
    pub total: i64,

    /// Current page size.
    pub limit: i64,

    /// Current offset.
    pub offset: i64,
}

// ============================================================================
// Validation Helper
// ============================================================================

/// Validation result for expressions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExpressionValidationResult {
    /// Whether the expression is valid.
    pub valid: bool,

    /// Attribute references found in the expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,

    /// Error message if invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_template_request_defaults() {
        let request = CreateTemplateRequest {
            name: "Test Template".to_string(),
            description: None,
            object_type: TemplateObjectType::User,
            priority: default_priority(),
            parent_template_id: None,
            rules: None,
            scopes: None,
        };

        assert_eq!(request.priority, DEFAULT_TEMPLATE_PRIORITY);
    }

    #[test]
    fn test_list_templates_query_defaults() {
        let query = ListObjectTemplatesQuery::default();
        assert_eq!(query.limit, Some(50));
        assert_eq!(query.offset, Some(0));
    }

    #[test]
    fn test_create_rule_request_defaults() {
        let request = CreateRuleRequest {
            rule_type: TemplateRuleType::Default,
            target_attribute: "department".to_string(),
            expression: "\"Unassigned\"".to_string(),
            strength: TemplateStrength::default(),
            authoritative: default_authoritative(),
            priority: default_rule_priority(),
            condition: None,
            error_message: None,
            exclusive: false,
            time_from: None,
            time_to: None,
            time_reference: None,
        };

        assert!(request.authoritative);
        assert_eq!(request.priority, 100);
        assert_eq!(request.strength, TemplateStrength::Normal);
        assert!(!request.exclusive);
    }

    #[test]
    fn test_simulation_request_defaults() {
        let limit = default_simulation_limit();
        assert_eq!(limit, 100);
    }
}
