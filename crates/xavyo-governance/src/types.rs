//! Type definitions for the governance domain.
//!
//! Includes newtype wrappers for IDs and enums for domain values.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

// ============================================================================
// ID Types (Newtype Pattern)
// ============================================================================

/// Unique identifier for an application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApplicationId(pub Uuid);

impl ApplicationId {
    /// Create a new random ApplicationId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for ApplicationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ApplicationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for ApplicationId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<ApplicationId> for Uuid {
    fn from(id: ApplicationId) -> Self {
        id.0
    }
}

/// Unique identifier for an entitlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntitlementId(pub Uuid);

impl EntitlementId {
    /// Create a new random EntitlementId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for EntitlementId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EntitlementId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for EntitlementId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<EntitlementId> for Uuid {
    fn from(id: EntitlementId) -> Self {
        id.0
    }
}

/// Unique identifier for an entitlement assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AssignmentId(pub Uuid);

impl AssignmentId {
    /// Create a new random AssignmentId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for AssignmentId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AssignmentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for AssignmentId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<AssignmentId> for Uuid {
    fn from(id: AssignmentId) -> Self {
        id.0
    }
}

// ============================================================================
// Enums
// ============================================================================

/// Application type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "gov_app_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AppType {
    /// Internal application owned by the organization.
    Internal,
    /// External third-party application.
    External,
}

impl fmt::Display for AppType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Internal => write!(f, "internal"),
            Self::External => write!(f, "external"),
        }
    }
}

/// Application status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "gov_app_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AppStatus {
    /// Application is active and can have entitlements assigned.
    Active,
    /// Application is inactive; no new assignments allowed.
    Inactive,
}

impl fmt::Display for AppStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Inactive => write!(f, "inactive"),
        }
    }
}

/// Risk level classification for entitlements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "gov_risk_level", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Low risk entitlement.
    #[default]
    Low,
    /// Medium risk entitlement.
    Medium,
    /// High risk entitlement.
    High,
    /// Critical risk entitlement requiring enhanced governance.
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Entitlement status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "gov_entitlement_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum EntitlementStatus {
    /// Entitlement is active.
    Active,
    /// Entitlement is inactive (manually disabled).
    Inactive,
    /// Entitlement is suspended (e.g., parent application deactivated).
    Suspended,
}

impl fmt::Display for EntitlementStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Inactive => write!(f, "inactive"),
            Self::Suspended => write!(f, "suspended"),
        }
    }
}

/// Assignment target type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "gov_assignment_target_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AssignmentTargetType {
    /// Assignment to a user.
    User,
    /// Assignment to a group.
    Group,
}

impl fmt::Display for AssignmentTargetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User => write!(f, "user"),
            Self::Group => write!(f, "group"),
        }
    }
}

/// Assignment status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "gov_assignment_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AssignmentStatus {
    /// Assignment is active.
    Active,
    /// Assignment is suspended.
    Suspended,
    /// Assignment has expired.
    Expired,
}

impl fmt::Display for AssignmentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Suspended => write!(f, "suspended"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

/// Source of an entitlement in effective access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssignmentSource {
    /// Direct assignment to the user.
    Direct,
    /// Inherited from a group membership.
    Group,
    /// Inherited from a role assignment.
    Role,
}

impl fmt::Display for AssignmentSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::Group => write!(f, "group"),
            Self::Role => write!(f, "role"),
        }
    }
}

// ============================================================================
// Lifecycle Types (F052)
// ============================================================================

/// Object types that can have lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "gov_lifecycle_object_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum LifecycleObjectType {
    /// User identity object.
    User,
    /// Entitlement object.
    Entitlement,
    /// Role object.
    Role,
}

impl fmt::Display for LifecycleObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User => write!(f, "user"),
            Self::Entitlement => write!(f, "entitlement"),
            Self::Role => write!(f, "role"),
        }
    }
}

/// Action to take on entitlements when entering a lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "gov_entitlement_action", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum EntitlementAction {
    /// No automatic action on entitlements.
    #[default]
    None,
    /// Pause (suspend) all entitlements - can be resumed.
    Pause,
    /// Permanently revoke all entitlements.
    Revoke,
}

impl fmt::Display for EntitlementAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Pause => write!(f, "pause"),
            Self::Revoke => write!(f, "revoke"),
        }
    }
}

/// Status of a state transition request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "gov_transition_request_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TransitionRequestStatus {
    /// Request created, awaiting processing.
    Pending,
    /// Awaiting approval from workflow.
    PendingApproval,
    /// Approved by workflow, ready to execute.
    Approved,
    /// Transition executed successfully.
    Executed,
    /// Request rejected by workflow.
    Rejected,
    /// Request cancelled by user.
    Cancelled,
    /// Request expired (approval timeout).
    Expired,
    /// Transition was rolled back within grace period.
    RolledBack,
}

impl fmt::Display for TransitionRequestStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::PendingApproval => write!(f, "pending_approval"),
            Self::Approved => write!(f, "approved"),
            Self::Executed => write!(f, "executed"),
            Self::Rejected => write!(f, "rejected"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Expired => write!(f, "expired"),
            Self::RolledBack => write!(f, "rolled_back"),
        }
    }
}

/// Status of a scheduled transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "gov_schedule_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ScheduleStatus {
    /// Scheduled and awaiting execution.
    Pending,
    /// Executed successfully.
    Executed,
    /// Cancelled before execution.
    Cancelled,
    /// Execution failed.
    Failed,
}

impl fmt::Display for ScheduleStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Executed => write!(f, "executed"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Status of a bulk state operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "gov_bulk_operation_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum BulkOperationStatus {
    /// Operation created, not yet started.
    Pending,
    /// Operation currently processing.
    Running,
    /// Operation completed (may have partial failures).
    Completed,
    /// Operation failed entirely.
    Failed,
    /// Operation cancelled.
    Cancelled,
}

impl fmt::Display for BulkOperationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Type of audit action for state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "gov_audit_action_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AuditActionType {
    /// Transition executed.
    Execute,
    /// Transition rolled back.
    Rollback,
}

impl fmt::Display for AuditActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Execute => write!(f, "execute"),
            Self::Rollback => write!(f, "rollback"),
        }
    }
}

/// Unique identifier for a lifecycle configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LifecycleConfigId(pub Uuid);

impl LifecycleConfigId {
    /// Create a new random LifecycleConfigId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for LifecycleConfigId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for LifecycleConfigId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for LifecycleConfigId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<LifecycleConfigId> for Uuid {
    fn from(id: LifecycleConfigId) -> Self {
        id.0
    }
}

/// Unique identifier for a lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LifecycleStateId(pub Uuid);

impl LifecycleStateId {
    /// Create a new random LifecycleStateId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for LifecycleStateId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for LifecycleStateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for LifecycleStateId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<LifecycleStateId> for Uuid {
    fn from(id: LifecycleStateId) -> Self {
        id.0
    }
}

/// Unique identifier for a lifecycle transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LifecycleTransitionId(pub Uuid);

impl LifecycleTransitionId {
    /// Create a new random LifecycleTransitionId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for LifecycleTransitionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for LifecycleTransitionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for LifecycleTransitionId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<LifecycleTransitionId> for Uuid {
    fn from(id: LifecycleTransitionId) -> Self {
        id.0
    }
}

/// Unique identifier for a state transition request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransitionRequestId(pub Uuid);

impl TransitionRequestId {
    /// Create a new random TransitionRequestId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for TransitionRequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TransitionRequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for TransitionRequestId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<TransitionRequestId> for Uuid {
    fn from(id: TransitionRequestId) -> Self {
        id.0
    }
}

/// Unique identifier for a bulk state operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BulkOperationId(pub Uuid);

impl BulkOperationId {
    /// Create a new random BulkOperationId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for BulkOperationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for BulkOperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for BulkOperationId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<BulkOperationId> for Uuid {
    fn from(id: BulkOperationId) -> Self {
        id.0
    }
}

// ============================================================================
// SoD (Separation of Duties) Types (F-005)
// ============================================================================

/// Unique identifier for an SoD rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SodRuleId(pub Uuid);

impl SodRuleId {
    /// Create a new random SodRuleId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for SodRuleId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SodRuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for SodRuleId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<SodRuleId> for Uuid {
    fn from(id: SodRuleId) -> Self {
        id.0
    }
}

/// Unique identifier for an SoD violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SodViolationId(pub Uuid);

impl SodViolationId {
    /// Create a new random SodViolationId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for SodViolationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SodViolationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for SodViolationId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<SodViolationId> for Uuid {
    fn from(id: SodViolationId) -> Self {
        id.0
    }
}

/// Unique identifier for an SoD exemption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SodExemptionId(pub Uuid);

impl SodExemptionId {
    /// Create a new random SodExemptionId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for SodExemptionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SodExemptionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for SodExemptionId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<SodExemptionId> for Uuid {
    fn from(id: SodExemptionId) -> Self {
        id.0
    }
}

/// SoD conflict type - how entitlements conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SodConflictType {
    /// User cannot have both entitlements (mutually exclusive).
    Exclusive,
    /// User can have at most N of M entitlements.
    Cardinality,
    /// User must have all or none of specified entitlements.
    Inclusive,
}

impl fmt::Display for SodConflictType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exclusive => write!(f, "exclusive"),
            Self::Cardinality => write!(f, "cardinality"),
            Self::Inclusive => write!(f, "inclusive"),
        }
    }
}

/// SoD rule severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SodSeverity {
    /// Low severity - informational.
    Low,
    /// Medium severity - should be addressed.
    #[default]
    Medium,
    /// High severity - requires attention.
    High,
    /// Critical severity - must be resolved immediately.
    Critical,
}

impl fmt::Display for SodSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// SoD rule status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SodRuleStatus {
    /// Rule is active and enforced.
    #[default]
    Active,
    /// Rule is inactive (disabled).
    Inactive,
}

impl fmt::Display for SodRuleStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Inactive => write!(f, "inactive"),
        }
    }
}

/// SoD violation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SodViolationStatus {
    /// Violation is active (not resolved).
    #[default]
    Active,
    /// Violation has been resolved.
    Resolved,
}

impl fmt::Display for SodViolationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Resolved => write!(f, "resolved"),
        }
    }
}

// ============================================================================
// Risk Assessment Types (F-006)
// ============================================================================

/// Unique identifier for a risk history record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RiskHistoryId(pub Uuid);

impl RiskHistoryId {
    /// Create a new random RiskHistoryId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for RiskHistoryId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RiskHistoryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for RiskHistoryId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<RiskHistoryId> for Uuid {
    fn from(id: RiskHistoryId) -> Self {
        id.0
    }
}

/// Represents the contribution of a single factor to the risk score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskFactorResult {
    /// Factor identifier (e.g., "entitlements", "sod_violations").
    pub name: String,
    /// Configured weight for this factor (0.0-1.0).
    pub weight: f64,
    /// Factor's raw score before weighting (0-100).
    pub raw_value: f64,
    /// Weighted contribution to final score.
    pub contribution: f64,
    /// Human-readable explanation.
    pub description: Option<String>,
}

impl RiskFactorResult {
    /// Create a new risk factor result.
    pub fn new(name: impl Into<String>, weight: f64, raw_value: f64) -> Self {
        let contribution = raw_value * weight;
        Self {
            name: name.into(),
            weight,
            raw_value,
            contribution,
            description: None,
        }
    }

    /// Add a description to the factor result.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// Represents a calculated risk value for a user at a point in time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskScore {
    /// User being assessed.
    pub user_id: Uuid,
    /// Tenant for isolation.
    pub tenant_id: Uuid,
    /// Calculated risk score (0-100).
    pub score: u8,
    /// Classified risk level.
    pub level: RiskLevel,
    /// Breakdown of contributing factors.
    pub factors: Vec<RiskFactorResult>,
    /// When score was calculated.
    pub calculated_at: chrono::DateTime<chrono::Utc>,
}

impl RiskScore {
    /// Create a new risk score.
    pub fn new(
        tenant_id: Uuid,
        user_id: Uuid,
        score: u8,
        level: RiskLevel,
        factors: Vec<RiskFactorResult>,
    ) -> Self {
        Self {
            user_id,
            tenant_id,
            score,
            level,
            factors,
            calculated_at: chrono::Utc::now(),
        }
    }
}

/// Per-tenant configuration for risk level classification boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskThresholds {
    /// Tenant identifier.
    pub tenant_id: Uuid,
    /// Max score for "Low" level (default: 25).
    pub low_max: u8,
    /// Max score for "Medium" level (default: 50).
    pub medium_max: u8,
    /// Max score for "High" level (default: 75).
    pub high_max: u8,
    /// Last modification timestamp.
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Actor who made the change.
    pub updated_by: Uuid,
}

impl RiskThresholds {
    /// Create new thresholds with custom values.
    pub fn new(
        tenant_id: Uuid,
        low_max: u8,
        medium_max: u8,
        high_max: u8,
        updated_by: Uuid,
    ) -> Self {
        Self {
            tenant_id,
            low_max,
            medium_max,
            high_max,
            updated_at: chrono::Utc::now(),
            updated_by,
        }
    }

    /// Create default thresholds for a tenant.
    pub fn default_for_tenant(tenant_id: Uuid, updated_by: Uuid) -> Self {
        Self {
            tenant_id,
            low_max: 25,
            medium_max: 50,
            high_max: 75,
            updated_at: chrono::Utc::now(),
            updated_by,
        }
    }

    /// Validate threshold boundaries.
    ///
    /// Returns `Ok(())` if thresholds are valid, or an error message if not.
    pub fn validate(&self) -> Result<(), String> {
        if self.low_max == 0 {
            return Err("low_max must be greater than 0".to_string());
        }
        if self.low_max >= self.medium_max {
            return Err(format!(
                "low_max ({}) must be less than medium_max ({})",
                self.low_max, self.medium_max
            ));
        }
        if self.medium_max >= self.high_max {
            return Err(format!(
                "medium_max ({}) must be less than high_max ({})",
                self.medium_max, self.high_max
            ));
        }
        if self.high_max >= 100 {
            return Err(format!(
                "high_max ({}) must be less than 100",
                self.high_max
            ));
        }
        Ok(())
    }

    /// Get the risk level for a given score.
    pub fn get_level(&self, score: u8) -> RiskLevel {
        if score <= self.low_max {
            RiskLevel::Low
        } else if score <= self.medium_max {
            RiskLevel::Medium
        } else if score <= self.high_max {
            RiskLevel::High
        } else {
            RiskLevel::Critical
        }
    }
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self {
            tenant_id: Uuid::nil(),
            low_max: 25,
            medium_max: 50,
            high_max: 75,
            updated_at: chrono::Utc::now(),
            updated_by: Uuid::nil(),
        }
    }
}

/// Historical record of risk scores for trend analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskHistory {
    /// Unique history record ID.
    pub id: RiskHistoryId,
    /// Tenant for isolation.
    pub tenant_id: Uuid,
    /// User whose risk was recorded.
    pub user_id: Uuid,
    /// Risk score at this point.
    pub score: u8,
    /// Risk level at this point.
    pub level: RiskLevel,
    /// When this record was created.
    pub recorded_at: chrono::DateTime<chrono::Utc>,
}

impl RiskHistory {
    /// Create a new risk history record.
    pub fn new(tenant_id: Uuid, user_id: Uuid, score: u8, level: RiskLevel) -> Self {
        Self {
            id: RiskHistoryId::new(),
            tenant_id,
            user_id,
            score,
            level,
            recorded_at: chrono::Utc::now(),
        }
    }

    /// Create from a RiskScore.
    pub fn from_score(score: &RiskScore) -> Self {
        Self {
            id: RiskHistoryId::new(),
            tenant_id: score.tenant_id,
            user_id: score.user_id,
            score: score.score,
            level: score.level,
            recorded_at: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_application_id() {
        let id = ApplicationId::new();
        let uuid: Uuid = id.into();
        let back: ApplicationId = uuid.into();
        assert_eq!(id, back);
    }

    #[test]
    fn test_risk_level_display() {
        assert_eq!(RiskLevel::Low.to_string(), "low");
        assert_eq!(RiskLevel::Critical.to_string(), "critical");
    }

    #[test]
    fn test_app_type_serialization() {
        let internal = AppType::Internal;
        let json = serde_json::to_string(&internal).unwrap();
        assert_eq!(json, "\"internal\"");
    }

    #[test]
    fn test_sod_rule_id() {
        let id = SodRuleId::new();
        let uuid: Uuid = id.into();
        let back: SodRuleId = uuid.into();
        assert_eq!(id, back);
    }

    #[test]
    fn test_sod_conflict_type_display() {
        assert_eq!(SodConflictType::Exclusive.to_string(), "exclusive");
        assert_eq!(SodConflictType::Cardinality.to_string(), "cardinality");
        assert_eq!(SodConflictType::Inclusive.to_string(), "inclusive");
    }

    #[test]
    fn test_sod_severity_display() {
        assert_eq!(SodSeverity::Low.to_string(), "low");
        assert_eq!(SodSeverity::Medium.to_string(), "medium");
        assert_eq!(SodSeverity::High.to_string(), "high");
        assert_eq!(SodSeverity::Critical.to_string(), "critical");
    }

    #[test]
    fn test_sod_severity_default() {
        let severity = SodSeverity::default();
        assert_eq!(severity, SodSeverity::Medium);
    }

    #[test]
    fn test_sod_rule_status_display() {
        assert_eq!(SodRuleStatus::Active.to_string(), "active");
        assert_eq!(SodRuleStatus::Inactive.to_string(), "inactive");
    }

    #[test]
    fn test_sod_violation_status_display() {
        assert_eq!(SodViolationStatus::Active.to_string(), "active");
        assert_eq!(SodViolationStatus::Resolved.to_string(), "resolved");
    }

    // =========================================================================
    // Risk Assessment Types Tests (F-006)
    // =========================================================================

    #[test]
    fn test_risk_history_id() {
        let id = RiskHistoryId::new();
        let uuid: Uuid = id.into();
        let back: RiskHistoryId = uuid.into();
        assert_eq!(id, back);
    }

    #[test]
    fn test_risk_factor_result_new() {
        let factor = RiskFactorResult::new("test", 0.5, 80.0);
        assert_eq!(factor.name, "test");
        assert_eq!(factor.weight, 0.5);
        assert_eq!(factor.raw_value, 80.0);
        assert_eq!(factor.contribution, 40.0); // 80 * 0.5
        assert!(factor.description.is_none());
    }

    #[test]
    fn test_risk_factor_result_with_description() {
        let factor = RiskFactorResult::new("test", 0.5, 80.0).with_description("Test description");
        assert_eq!(factor.description, Some("Test description".to_string()));
    }

    #[test]
    fn test_risk_score_new() {
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let factors = vec![RiskFactorResult::new("test", 1.0, 50.0)];

        let score = RiskScore::new(tenant_id, user_id, 50, RiskLevel::Medium, factors.clone());

        assert_eq!(score.tenant_id, tenant_id);
        assert_eq!(score.user_id, user_id);
        assert_eq!(score.score, 50);
        assert_eq!(score.level, RiskLevel::Medium);
        assert_eq!(score.factors.len(), 1);
    }

    #[test]
    fn test_risk_thresholds_default() {
        let thresholds = RiskThresholds::default();
        assert_eq!(thresholds.low_max, 25);
        assert_eq!(thresholds.medium_max, 50);
        assert_eq!(thresholds.high_max, 75);
    }

    #[test]
    fn test_risk_thresholds_validate_valid() {
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let thresholds = RiskThresholds::new(tenant_id, 25, 50, 75, actor_id);
        assert!(thresholds.validate().is_ok());
    }

    #[test]
    fn test_risk_thresholds_validate_invalid_ordering() {
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let thresholds = RiskThresholds::new(tenant_id, 50, 25, 75, actor_id);
        assert!(thresholds.validate().is_err());
    }

    #[test]
    fn test_risk_thresholds_validate_high_max_too_large() {
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let thresholds = RiskThresholds::new(tenant_id, 25, 50, 100, actor_id);
        assert!(thresholds.validate().is_err());
    }

    #[test]
    fn test_risk_thresholds_get_level() {
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let thresholds = RiskThresholds::new(tenant_id, 25, 50, 75, actor_id);

        assert_eq!(thresholds.get_level(0), RiskLevel::Low);
        assert_eq!(thresholds.get_level(25), RiskLevel::Low);
        assert_eq!(thresholds.get_level(26), RiskLevel::Medium);
        assert_eq!(thresholds.get_level(50), RiskLevel::Medium);
        assert_eq!(thresholds.get_level(51), RiskLevel::High);
        assert_eq!(thresholds.get_level(75), RiskLevel::High);
        assert_eq!(thresholds.get_level(76), RiskLevel::Critical);
        assert_eq!(thresholds.get_level(100), RiskLevel::Critical);
    }

    #[test]
    fn test_risk_history_new() {
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let history = RiskHistory::new(tenant_id, user_id, 50, RiskLevel::Medium);

        assert_eq!(history.tenant_id, tenant_id);
        assert_eq!(history.user_id, user_id);
        assert_eq!(history.score, 50);
        assert_eq!(history.level, RiskLevel::Medium);
    }

    #[test]
    fn test_risk_history_from_score() {
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let score = RiskScore::new(tenant_id, user_id, 75, RiskLevel::High, vec![]);
        let history = RiskHistory::from_score(&score);

        assert_eq!(history.tenant_id, tenant_id);
        assert_eq!(history.user_id, user_id);
        assert_eq!(history.score, 75);
        assert_eq!(history.level, RiskLevel::High);
    }
}
