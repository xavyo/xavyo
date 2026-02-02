//! Request and response models for meta-role endpoints (F056).
//!
//! Meta-roles enable hierarchical role inheritance where a meta-role can define
//! entitlements, constraints, and policies that are automatically inherited by
//! all roles matching specific criteria.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{
    CriteriaLogic, CriteriaOperator, GovMetaRole, GovMetaRoleConflict, GovMetaRoleCriteria,
    GovMetaRoleEvent, GovMetaRoleInheritance, InheritanceStatus, MetaRoleConflictType,
    MetaRoleEventStats, MetaRoleEventType, MetaRoleStatus, PermissionType, ResolutionStatus,
};

// ============================================================================
// Meta-Role Core Models
// ============================================================================

/// Request to create a new meta-role.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateMetaRoleRequest {
    /// Display name for the meta-role (1-255 characters).
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Description of the meta-role (max 2000 characters).
    #[validate(length(max = 2000, message = "Description must not exceed 2000 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Priority for conflict resolution (lower = higher priority, default: 100).
    #[validate(range(min = 1, max = 1000, message = "Priority must be between 1 and 1000"))]
    #[serde(default = "default_priority")]
    pub priority: i32,

    /// Logic for combining criteria (AND or OR, default: AND).
    #[serde(default)]
    pub criteria_logic: CriteriaLogic,

    /// Matching criteria for this meta-role.
    #[validate(length(min = 1, message = "At least one criterion is required"))]
    pub criteria: Vec<CreateMetaRoleCriteriaRequest>,

    /// Entitlements to inherit (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlements: Option<Vec<CreateMetaRoleEntitlementRequest>>,

    /// Constraints to inherit (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Vec<CreateMetaRoleConstraintRequest>>,
}

fn default_priority() -> i32 {
    100
}

/// Request to update an existing meta-role.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateMetaRoleRequest {
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

    /// Updated criteria logic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub criteria_logic: Option<CriteriaLogic>,
}

/// Query parameters for listing meta-roles.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListMetaRolesQuery {
    /// Filter by status.
    pub status: Option<MetaRoleStatus>,

    /// Filter by name (partial match).
    pub name: Option<String>,

    /// Filter by creator.
    pub created_by: Option<Uuid>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListMetaRolesQuery {
    fn default() -> Self {
        Self {
            status: None,
            name: None,
            created_by: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Meta-role response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MetaRoleResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Display name.
    pub name: String,

    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Priority for conflict resolution.
    pub priority: i32,

    /// Meta-role status.
    pub status: MetaRoleStatus,

    /// Logic for combining criteria.
    pub criteria_logic: CriteriaLogic,

    /// User who created this meta-role.
    pub created_by: Uuid,

    /// When the meta-role was created.
    pub created_at: DateTime<Utc>,

    /// When the meta-role was last updated.
    pub updated_at: DateTime<Utc>,
}

impl From<GovMetaRole> for MetaRoleResponse {
    fn from(meta_role: GovMetaRole) -> Self {
        Self {
            id: meta_role.id,
            tenant_id: meta_role.tenant_id,
            name: meta_role.name,
            description: meta_role.description,
            priority: meta_role.priority,
            status: meta_role.status,
            criteria_logic: meta_role.criteria_logic,
            created_by: meta_role.created_by,
            created_at: meta_role.created_at,
            updated_at: meta_role.updated_at,
        }
    }
}

/// Meta-role response with full details.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MetaRoleWithDetailsResponse {
    /// Core meta-role details.
    #[serde(flatten)]
    pub meta_role: MetaRoleResponse,

    /// Matching criteria.
    pub criteria: Vec<MetaRoleCriteriaResponse>,

    /// Inherited entitlements.
    pub entitlements: Vec<MetaRoleEntitlementResponse>,

    /// Inherited constraints.
    pub constraints: Vec<MetaRoleConstraintResponse>,

    /// Statistics about this meta-role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<MetaRoleStatsResponse>,
}

/// Statistics for a meta-role.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MetaRoleStatsResponse {
    /// Number of active inheritances.
    pub active_inheritances: i64,

    /// Number of unresolved conflicts.
    pub unresolved_conflicts: i64,

    /// Total criteria count.
    pub criteria_count: i64,

    /// Total entitlements count.
    pub entitlements_count: i64,

    /// Total constraints count.
    pub constraints_count: i64,
}

/// Paginated list of meta-roles.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MetaRoleListResponse {
    /// List of meta-roles.
    pub items: Vec<MetaRoleResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

// ============================================================================
// Criteria Models
// ============================================================================

/// Request to create a meta-role criterion.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateMetaRoleCriteriaRequest {
    /// Field to match against (risk_level, application_id, owner_id, status, is_delegable, metadata).
    #[validate(length(
        min = 1,
        max = 100,
        message = "Field must be between 1 and 100 characters"
    ))]
    pub field: String,

    /// Operator for comparison.
    pub operator: CriteriaOperator,

    /// Value to compare against (JSON format for flexibility).
    pub value: serde_json::Value,
}

/// Meta-role criterion response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MetaRoleCriteriaResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Parent meta-role ID.
    pub meta_role_id: Uuid,

    /// Field being matched.
    pub field: String,

    /// Comparison operator.
    pub operator: CriteriaOperator,

    /// Value being compared.
    pub value: serde_json::Value,

    /// When the criterion was created.
    pub created_at: DateTime<Utc>,
}

impl From<GovMetaRoleCriteria> for MetaRoleCriteriaResponse {
    fn from(criteria: GovMetaRoleCriteria) -> Self {
        Self {
            id: criteria.id,
            meta_role_id: criteria.meta_role_id,
            field: criteria.field,
            operator: criteria.operator,
            value: criteria.value,
            created_at: criteria.created_at,
        }
    }
}

// ============================================================================
// Entitlement Models
// ============================================================================

/// Request to add an entitlement to a meta-role.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateMetaRoleEntitlementRequest {
    /// The entitlement ID to inherit.
    pub entitlement_id: Uuid,

    /// Permission type (grant or deny, default: grant).
    #[serde(default)]
    pub permission_type: Option<PermissionType>,
}

/// Request to add an entitlement to an existing meta-role.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct AddMetaRoleEntitlementRequest {
    /// The entitlement ID to inherit.
    pub entitlement_id: Uuid,

    /// Permission type (grant or deny, default: grant).
    #[serde(default)]
    pub permission_type: Option<PermissionType>,
}

/// Meta-role entitlement response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MetaRoleEntitlementResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Parent meta-role ID.
    pub meta_role_id: Uuid,

    /// Entitlement ID.
    pub entitlement_id: Uuid,

    /// Permission type.
    pub permission_type: PermissionType,

    /// When the entitlement was added.
    pub created_at: DateTime<Utc>,

    /// Entitlement details (optional, populated on request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement: Option<MetaRoleEntitlementSummary>,
}

/// Summary of an entitlement for display.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MetaRoleEntitlementSummary {
    /// Entitlement ID.
    pub id: Uuid,

    /// Entitlement name.
    pub name: String,

    /// Application ID.
    pub application_id: Uuid,

    /// Application name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_name: Option<String>,

    /// Risk level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
}

// ============================================================================
// Constraint Models
// ============================================================================

/// Request to add a constraint to a meta-role.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateMetaRoleConstraintRequest {
    /// Constraint type (max_session_duration, require_mfa, ip_whitelist, approval_required).
    #[validate(length(
        min = 1,
        max = 100,
        message = "Constraint type must be between 1 and 100 characters"
    ))]
    pub constraint_type: String,

    /// Constraint configuration (JSON format).
    pub constraint_value: serde_json::Value,
}

/// Request to add a constraint to an existing meta-role.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct AddMetaRoleConstraintRequest {
    /// Constraint type.
    #[validate(length(
        min = 1,
        max = 100,
        message = "Constraint type must be between 1 and 100 characters"
    ))]
    pub constraint_type: String,

    /// Constraint configuration.
    pub constraint_value: serde_json::Value,
}

/// Request to update a constraint value.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateMetaRoleConstraintRequest {
    /// Updated constraint value.
    pub constraint_value: serde_json::Value,
}

/// Meta-role constraint response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MetaRoleConstraintResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Parent meta-role ID.
    pub meta_role_id: Uuid,

    /// Constraint type.
    pub constraint_type: String,

    /// Constraint configuration.
    pub constraint_value: serde_json::Value,

    /// When the constraint was created.
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// Inheritance Models
// ============================================================================

/// Query parameters for listing inheritances.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListInheritancesQuery {
    /// Filter by meta-role ID.
    pub meta_role_id: Option<Uuid>,

    /// Filter by child role ID.
    pub child_role_id: Option<Uuid>,

    /// Filter by status.
    pub status: Option<InheritanceStatus>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListInheritancesQuery {
    fn default() -> Self {
        Self {
            meta_role_id: None,
            child_role_id: None,
            status: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Inheritance relationship response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InheritanceResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Parent meta-role ID.
    pub meta_role_id: Uuid,

    /// Child role (entitlement) ID.
    pub child_role_id: Uuid,

    /// Why this role matched.
    pub match_reason: serde_json::Value,

    /// Inheritance status.
    pub status: InheritanceStatus,

    /// When the inheritance was established.
    pub matched_at: DateTime<Utc>,

    /// When the inheritance was last updated.
    pub updated_at: DateTime<Utc>,

    /// Meta-role summary (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta_role: Option<MetaRoleSummary>,

    /// Child role summary (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_role: Option<ChildRoleSummary>,
}

impl From<GovMetaRoleInheritance> for InheritanceResponse {
    fn from(inheritance: GovMetaRoleInheritance) -> Self {
        Self {
            id: inheritance.id,
            tenant_id: inheritance.tenant_id,
            meta_role_id: inheritance.meta_role_id,
            child_role_id: inheritance.child_role_id,
            match_reason: inheritance.match_reason,
            status: inheritance.status,
            matched_at: inheritance.matched_at,
            updated_at: inheritance.updated_at,
            meta_role: None,
            child_role: None,
        }
    }
}

/// Summary of a meta-role for display.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MetaRoleSummary {
    /// Meta-role ID.
    pub id: Uuid,

    /// Meta-role name.
    pub name: String,

    /// Meta-role priority.
    pub priority: i32,

    /// Meta-role status.
    pub status: MetaRoleStatus,
}

/// Summary of a child role for display.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChildRoleSummary {
    /// Role ID.
    pub id: Uuid,

    /// Role name.
    pub name: String,

    /// Application ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<Uuid>,

    /// Application name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_name: Option<String>,
}

/// Paginated list of inheritances.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InheritanceListResponse {
    /// List of inheritances.
    pub items: Vec<InheritanceResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

// ============================================================================
// Conflict Models
// ============================================================================

/// Query parameters for listing conflicts.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListConflictsQuery {
    /// Filter by affected role ID.
    pub affected_role_id: Option<Uuid>,

    /// Filter by meta-role ID (involved in conflict).
    pub meta_role_id: Option<Uuid>,

    /// Filter by conflict type.
    pub conflict_type: Option<MetaRoleConflictType>,

    /// Filter by resolution status.
    pub resolution_status: Option<ResolutionStatus>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListConflictsQuery {
    fn default() -> Self {
        Self {
            affected_role_id: None,
            meta_role_id: None,
            conflict_type: None,
            resolution_status: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Request to resolve a conflict.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ResolveConflictRequest {
    /// Resolution status (resolved_priority, resolved_manual, ignored).
    pub resolution_status: ResolutionStatus,

    /// Resolution choice (which meta-role wins, custom configuration, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_choice: Option<serde_json::Value>,

    /// Comment/justification for the resolution.
    #[validate(length(max = 2000, message = "Comment must not exceed 2000 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Conflict response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConflictResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// First conflicting meta-role.
    pub meta_role_a_id: Uuid,

    /// Second conflicting meta-role.
    pub meta_role_b_id: Uuid,

    /// Affected role ID.
    pub affected_role_id: Uuid,

    /// Type of conflict.
    pub conflict_type: MetaRoleConflictType,

    /// Details of conflicting items.
    pub conflicting_items: serde_json::Value,

    /// Resolution status.
    pub resolution_status: ResolutionStatus,

    /// Who resolved the conflict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<Uuid>,

    /// Resolution choice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_choice: Option<serde_json::Value>,

    /// When the conflict was detected.
    pub detected_at: DateTime<Utc>,

    /// When the conflict was resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime<Utc>>,

    /// Meta-role A summary (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta_role_a: Option<MetaRoleSummary>,

    /// Meta-role B summary (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta_role_b: Option<MetaRoleSummary>,

    /// Affected role summary (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_role: Option<ChildRoleSummary>,
}

impl From<GovMetaRoleConflict> for ConflictResponse {
    fn from(conflict: GovMetaRoleConflict) -> Self {
        Self {
            id: conflict.id,
            tenant_id: conflict.tenant_id,
            meta_role_a_id: conflict.meta_role_a_id,
            meta_role_b_id: conflict.meta_role_b_id,
            affected_role_id: conflict.affected_role_id,
            conflict_type: conflict.conflict_type,
            conflicting_items: conflict.conflicting_items,
            resolution_status: conflict.resolution_status,
            resolved_by: conflict.resolved_by,
            resolution_choice: conflict.resolution_choice,
            detected_at: conflict.detected_at,
            resolved_at: conflict.resolved_at,
            meta_role_a: None,
            meta_role_b: None,
            affected_role: None,
        }
    }
}

/// Paginated list of conflicts.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConflictListResponse {
    /// List of conflicts.
    pub items: Vec<ConflictResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

// ============================================================================
// Event (Audit Trail) Models
// ============================================================================

/// Query parameters for listing events.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListEventsQuery {
    /// Filter by meta-role ID.
    pub meta_role_id: Option<Uuid>,

    /// Filter by event type.
    pub event_type: Option<MetaRoleEventType>,

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

impl Default for ListEventsQuery {
    fn default() -> Self {
        Self {
            meta_role_id: None,
            event_type: None,
            actor_id: None,
            from_date: None,
            to_date: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Event response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EventResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Related meta-role ID (NULL for cascade events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta_role_id: Option<Uuid>,

    /// Event type.
    pub event_type: MetaRoleEventType,

    /// Actor who triggered the event (NULL for system events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Uuid>,

    /// Before/after state changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changes: Option<serde_json::Value>,

    /// Affected role IDs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_roles: Option<serde_json::Value>,

    /// Additional context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,

    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

impl From<GovMetaRoleEvent> for EventResponse {
    fn from(event: GovMetaRoleEvent) -> Self {
        Self {
            id: event.id,
            tenant_id: event.tenant_id,
            meta_role_id: event.meta_role_id,
            event_type: event.event_type,
            actor_id: event.actor_id,
            changes: event.changes,
            affected_roles: event.affected_roles,
            metadata: event.metadata,
            created_at: event.created_at,
        }
    }
}

/// Paginated list of events.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EventListResponse {
    /// List of events.
    pub items: Vec<EventResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Event statistics response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EventStatsResponse {
    /// Total events.
    pub total: i64,

    /// Created events.
    pub created: i64,

    /// Updated events.
    pub updated: i64,

    /// Deleted events.
    pub deleted: i64,

    /// Disabled events.
    pub disabled: i64,

    /// Enabled events.
    pub enabled: i64,

    /// Inheritance applied events.
    pub inheritance_applied: i64,

    /// Inheritance removed events.
    pub inheritance_removed: i64,

    /// Conflict detected events.
    pub conflict_detected: i64,

    /// Conflict resolved events.
    pub conflict_resolved: i64,

    /// Cascade started events.
    pub cascade_started: i64,

    /// Cascade completed events.
    pub cascade_completed: i64,

    /// Cascade failed events.
    pub cascade_failed: i64,
}

impl From<MetaRoleEventStats> for EventStatsResponse {
    fn from(stats: MetaRoleEventStats) -> Self {
        Self {
            total: stats.total,
            created: stats.created,
            updated: stats.updated,
            deleted: stats.deleted,
            disabled: stats.disabled,
            enabled: stats.enabled,
            inheritance_applied: stats.inheritance_applied,
            inheritance_removed: stats.inheritance_removed,
            conflict_detected: stats.conflict_detected,
            conflict_resolved: stats.conflict_resolved,
            cascade_started: stats.cascade_started,
            cascade_completed: stats.cascade_completed,
            cascade_failed: stats.cascade_failed,
        }
    }
}

// ============================================================================
// Simulation Models
// ============================================================================

/// Request to simulate meta-role changes.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct SimulateMetaRoleRequest {
    /// Type of simulation.
    pub simulation_type: MetaRoleSimulationType,

    /// Meta-role ID (for update/delete simulations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta_role_id: Option<Uuid>,

    /// Updated meta-role data (for create/update simulations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta_role_data: Option<CreateMetaRoleRequest>,

    /// Updated criteria (for criteria change simulations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub criteria_changes: Option<Vec<CreateMetaRoleCriteriaRequest>>,

    /// Limit results (default: 100).
    #[serde(default = "default_simulation_limit")]
    pub limit: i64,
}

fn default_simulation_limit() -> i64 {
    100
}

/// Type of meta-role simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MetaRoleSimulationType {
    /// Simulate creating a new meta-role.
    Create,
    /// Simulate updating an existing meta-role.
    Update,
    /// Simulate deleting a meta-role.
    Delete,
    /// Simulate changing criteria.
    CriteriaChange,
    /// Simulate enabling a disabled meta-role.
    Enable,
    /// Simulate disabling an active meta-role.
    Disable,
}

/// Simulation result response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulationResultResponse {
    /// Type of simulation performed.
    pub simulation_type: MetaRoleSimulationType,

    /// Roles that would gain inheritance.
    pub roles_to_add: Vec<SimulationRoleChange>,

    /// Roles that would lose inheritance.
    pub roles_to_remove: Vec<SimulationRoleChange>,

    /// Potential conflicts that would be created.
    pub potential_conflicts: Vec<SimulationConflict>,

    /// Potential conflicts that would be resolved.
    pub conflicts_to_resolve: Vec<SimulationConflict>,

    /// Summary statistics.
    pub summary: SimulationSummary,
}

/// A role change in simulation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulationRoleChange {
    /// Role ID.
    pub role_id: Uuid,

    /// Role name.
    pub role_name: String,

    /// Application ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<Uuid>,

    /// Why this role matches/unmatches.
    pub reason: serde_json::Value,

    /// Entitlements that would be inherited/removed.
    pub entitlements_affected: Vec<Uuid>,

    /// Constraints that would be inherited/removed.
    pub constraints_affected: Vec<String>,
}

/// A potential conflict in simulation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulationConflict {
    /// First meta-role ID.
    pub meta_role_a_id: Uuid,

    /// First meta-role name.
    pub meta_role_a_name: String,

    /// Second meta-role ID.
    pub meta_role_b_id: Uuid,

    /// Second meta-role name.
    pub meta_role_b_name: String,

    /// Affected role ID.
    pub affected_role_id: Uuid,

    /// Affected role name.
    pub affected_role_name: String,

    /// Type of conflict.
    pub conflict_type: MetaRoleConflictType,

    /// Details of the conflict.
    pub conflicting_items: serde_json::Value,
}

/// Summary of simulation results.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulationSummary {
    /// Total roles that would be affected.
    pub total_roles_affected: i64,

    /// Roles gaining inheritance.
    pub roles_gaining_inheritance: i64,

    /// Roles losing inheritance.
    pub roles_losing_inheritance: i64,

    /// New conflicts that would be created.
    pub new_conflicts: i64,

    /// Conflicts that would be resolved.
    pub resolved_conflicts: i64,

    /// Whether the change is safe to apply.
    pub is_safe: bool,

    /// Warnings about potential issues.
    pub warnings: Vec<String>,
}

// ============================================================================
// Cascade Models
// ============================================================================

/// Request to trigger a cascade propagation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TriggerCascadeRequest {
    /// Meta-role ID to cascade from.
    pub meta_role_id: Uuid,

    /// Whether to run in dry-run mode (default: false).
    #[serde(default)]
    pub dry_run: bool,
}

/// Cascade status response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CascadeStatusResponse {
    /// Meta-role ID.
    pub meta_role_id: Uuid,

    /// Whether cascade is in progress.
    pub in_progress: bool,

    /// Number of roles processed.
    pub processed_count: i64,

    /// Number of roles remaining.
    pub remaining_count: i64,

    /// Number of successful applications.
    pub success_count: i64,

    /// Number of failures.
    pub failure_count: i64,

    /// When the cascade started.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,

    /// When the cascade completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,

    /// Failure details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failures: Option<Vec<CascadeFailure>>,
}

/// A failure during cascade.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CascadeFailure {
    /// Role ID that failed.
    pub role_id: Uuid,

    /// Error message.
    pub error: String,

    /// When the failure occurred.
    pub failed_at: DateTime<Utc>,
}

// ============================================================================
// Matching/Evaluation Models
// ============================================================================

/// Request to evaluate which meta-roles match a role.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EvaluateRoleMatchRequest {
    /// Role ID to evaluate.
    pub role_id: Uuid,
}

/// Response showing which meta-roles match a role.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoleMatchResponse {
    /// Role ID evaluated.
    pub role_id: Uuid,

    /// Matching meta-roles.
    pub matching_meta_roles: Vec<MatchingMetaRole>,

    /// Total matches.
    pub total_matches: i64,

    /// Whether this role has unresolved conflicts.
    pub has_conflicts: bool,
}

/// A meta-role that matches a role.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MatchingMetaRole {
    /// Meta-role ID.
    pub meta_role_id: Uuid,

    /// Meta-role name.
    pub name: String,

    /// Meta-role priority.
    pub priority: i32,

    /// Why this meta-role matches.
    pub match_reason: serde_json::Value,

    /// Whether already applied.
    pub already_applied: bool,

    /// Inheritance ID if already applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inheritance_id: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use validator::Validate;

    #[test]
    fn test_create_meta_role_validation() {
        let valid = CreateMetaRoleRequest {
            name: "High Risk Roles".to_string(),
            description: Some("Meta-role for all high-risk entitlements".to_string()),
            priority: 100,
            criteria_logic: CriteriaLogic::And,
            criteria: vec![CreateMetaRoleCriteriaRequest {
                field: "risk_level".to_string(),
                operator: CriteriaOperator::Eq,
                value: serde_json::json!("critical"),
            }],
            entitlements: None,
            constraints: None,
        };
        assert!(valid.validate().is_ok());

        // Test empty name
        let invalid_name = CreateMetaRoleRequest {
            name: "".to_string(),
            ..valid.clone()
        };
        assert!(invalid_name.validate().is_err());

        // Test empty criteria
        let invalid_criteria = CreateMetaRoleRequest {
            criteria: vec![],
            ..valid.clone()
        };
        assert!(invalid_criteria.validate().is_err());

        // Test invalid priority
        let invalid_priority = CreateMetaRoleRequest {
            priority: 0,
            ..valid.clone()
        };
        assert!(invalid_priority.validate().is_err());
    }

    #[test]
    fn test_update_meta_role_validation() {
        let valid = UpdateMetaRoleRequest {
            name: Some("Updated Name".to_string()),
            description: None,
            priority: Some(50),
            criteria_logic: None,
        };
        assert!(valid.validate().is_ok());

        let invalid_priority = UpdateMetaRoleRequest {
            priority: Some(0),
            ..valid.clone()
        };
        assert!(invalid_priority.validate().is_err());
    }

    #[test]
    fn test_resolve_conflict_validation() {
        let valid = ResolveConflictRequest {
            resolution_status: ResolutionStatus::ResolvedManual,
            resolution_choice: Some(serde_json::json!({"winner": "meta_role_a"})),
            comment: Some("Resolved manually by admin".to_string()),
        };
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn test_list_queries_defaults() {
        let meta_role_query = ListMetaRolesQuery::default();
        assert_eq!(meta_role_query.limit, Some(50));
        assert_eq!(meta_role_query.offset, Some(0));

        let conflicts_query = ListConflictsQuery::default();
        assert_eq!(conflicts_query.limit, Some(50));
        assert_eq!(conflicts_query.offset, Some(0));

        let events_query = ListEventsQuery::default();
        assert_eq!(events_query.limit, Some(50));
        assert_eq!(events_query.offset, Some(0));
    }

    #[test]
    fn test_simulation_types() {
        assert_eq!(
            serde_json::to_string(&MetaRoleSimulationType::Create).unwrap(),
            "\"create\""
        );
        assert_eq!(
            serde_json::to_string(&MetaRoleSimulationType::Delete).unwrap(),
            "\"delete\""
        );
    }
}
