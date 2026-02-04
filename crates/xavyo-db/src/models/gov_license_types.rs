//! License Management type definitions (F065).
//!
//! Defines enums, newtypes, and shared types for license management.

use serde::{Deserialize, Serialize};
use sqlx::Type;
use uuid::Uuid;

// ============================================================================
// NEWTYPE IDS
// ============================================================================

/// Unique identifier for a license pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct LicensePoolId(pub Uuid);

impl LicensePoolId {
    /// Create a new random license pool ID.
    #[must_use] 
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    #[must_use] 
    pub fn inner(&self) -> Uuid {
        self.0
    }
}

impl Default for LicensePoolId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for LicensePoolId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<LicensePoolId> for Uuid {
    fn from(id: LicensePoolId) -> Self {
        id.0
    }
}

/// Unique identifier for a license assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct LicenseAssignmentId(pub Uuid);

impl LicenseAssignmentId {
    /// Create a new random license assignment ID.
    #[must_use] 
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    #[must_use] 
    pub fn inner(&self) -> Uuid {
        self.0
    }
}

impl Default for LicenseAssignmentId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for LicenseAssignmentId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<LicenseAssignmentId> for Uuid {
    fn from(id: LicenseAssignmentId) -> Self {
        id.0
    }
}

/// Unique identifier for a license-entitlement link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct LicenseEntitlementLinkId(pub Uuid);

impl LicenseEntitlementLinkId {
    /// Create a new random link ID.
    #[must_use] 
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    #[must_use] 
    pub fn inner(&self) -> Uuid {
        self.0
    }
}

impl Default for LicenseEntitlementLinkId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for LicenseEntitlementLinkId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<LicenseEntitlementLinkId> for Uuid {
    fn from(id: LicenseEntitlementLinkId) -> Self {
        id.0
    }
}

/// Unique identifier for a license reclamation rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct LicenseReclamationRuleId(pub Uuid);

impl LicenseReclamationRuleId {
    /// Create a new random rule ID.
    #[must_use] 
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    #[must_use] 
    pub fn inner(&self) -> Uuid {
        self.0
    }
}

impl Default for LicenseReclamationRuleId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for LicenseReclamationRuleId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<LicenseReclamationRuleId> for Uuid {
    fn from(id: LicenseReclamationRuleId) -> Self {
        id.0
    }
}

/// Unique identifier for a license incompatibility rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct LicenseIncompatibilityId(pub Uuid);

impl LicenseIncompatibilityId {
    /// Create a new random incompatibility ID.
    #[must_use] 
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    #[must_use] 
    pub fn inner(&self) -> Uuid {
        self.0
    }
}

impl Default for LicenseIncompatibilityId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for LicenseIncompatibilityId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<LicenseIncompatibilityId> for Uuid {
    fn from(id: LicenseIncompatibilityId) -> Self {
        id.0
    }
}

/// Unique identifier for a license audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct LicenseAuditEventId(pub Uuid);

impl LicenseAuditEventId {
    /// Create a new random audit event ID.
    #[must_use] 
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID.
    #[must_use] 
    pub fn inner(&self) -> Uuid {
        self.0
    }
}

impl Default for LicenseAuditEventId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for LicenseAuditEventId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<LicenseAuditEventId> for Uuid {
    fn from(id: LicenseAuditEventId) -> Self {
        id.0
    }
}

// ============================================================================
// ENUMS
// ============================================================================

/// License type: named (permanent assignment) or concurrent (floating).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "license_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum LicenseType {
    /// Named license: permanently assigned to a user.
    #[default]
    Named,
    /// Concurrent/floating license: checked out during active session.
    Concurrent,
}

/// Billing period for license cost tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "license_billing_period", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum LicenseBillingPeriod {
    /// Monthly billing.
    Monthly,
    /// Annual billing.
    Annual,
    /// Perpetual/one-time purchase.
    Perpetual,
}

/// Policy to enforce when a license pool expires.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "license_expiration_policy", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum LicenseExpirationPolicy {
    /// Block new assignments but keep existing ones.
    #[default]
    BlockNew,
    /// Revoke all current assignments.
    RevokeAll,
    /// Only warn, don't block or revoke.
    WarnOnly,
}

/// License pool lifecycle status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "license_pool_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum LicensePoolStatus {
    /// Pool is active and licenses can be assigned.
    #[default]
    Active,
    /// Pool has expired based on `expiration_date`.
    Expired,
    /// Pool has been archived (soft delete).
    Archived,
}

/// License assignment status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "license_assignment_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum LicenseAssignmentStatus {
    /// Assignment is active.
    #[default]
    Active,
    /// License was reclaimed (e.g., due to inactivity).
    Reclaimed,
    /// License expired when the pool expired.
    Expired,
    /// License was manually released/deallocated.
    Released,
}

/// Source of how a license was assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "license_assignment_source", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum LicenseAssignmentSource {
    /// Manually assigned by an administrator.
    Manual,
    /// Automatically assigned by the system.
    Automatic,
    /// Assigned via entitlement grant.
    Entitlement,
}

/// Trigger type for reclamation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "license_reclamation_trigger", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum LicenseReclamationTrigger {
    /// Reclaim based on user inactivity (no login for N days).
    Inactivity,
    /// Reclaim when user enters a specific lifecycle state (e.g., terminated).
    LifecycleState,
}

/// Reason for license reclamation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "license_reclaim_reason", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum LicenseReclaimReason {
    /// Reclaimed due to user inactivity.
    Inactivity,
    /// Reclaimed due to user termination.
    Termination,
    /// Manually reclaimed by administrator.
    Manual,
    /// Reclaimed due to pool expiration.
    Expiration,
}

/// License audit event action types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum LicenseAuditAction {
    // Pool actions
    PoolCreated,
    PoolUpdated,
    PoolDeleted,
    PoolArchived,
    PoolExpired,

    // Assignment actions
    LicenseAssigned,
    LicenseDeallocated,
    LicenseReclaimed,
    LicenseExpired,

    // Link actions
    LinkCreated,
    LinkUpdated,
    LinkDeleted,

    // Rule actions
    RuleCreated,
    RuleUpdated,
    RuleDeleted,

    // Incompatibility actions
    IncompatibilityCreated,
    IncompatibilityDeleted,

    // Bulk actions
    BulkAssign,
    BulkReclaim,
}

impl LicenseAuditAction {
    /// Get the string representation for database storage.
    #[must_use] 
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PoolCreated => "pool_created",
            Self::PoolUpdated => "pool_updated",
            Self::PoolDeleted => "pool_deleted",
            Self::PoolArchived => "pool_archived",
            Self::PoolExpired => "pool_expired",
            Self::LicenseAssigned => "license_assigned",
            Self::LicenseDeallocated => "license_deallocated",
            Self::LicenseReclaimed => "license_reclaimed",
            Self::LicenseExpired => "license_expired",
            Self::LinkCreated => "link_created",
            Self::LinkUpdated => "link_updated",
            Self::LinkDeleted => "link_deleted",
            Self::RuleCreated => "rule_created",
            Self::RuleUpdated => "rule_updated",
            Self::RuleDeleted => "rule_deleted",
            Self::IncompatibilityCreated => "incompatibility_created",
            Self::IncompatibilityDeleted => "incompatibility_deleted",
            Self::BulkAssign => "bulk_assign",
            Self::BulkReclaim => "bulk_reclaim",
        }
    }

    /// Parse from string.
    #[must_use] 
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pool_created" => Some(Self::PoolCreated),
            "pool_updated" => Some(Self::PoolUpdated),
            "pool_deleted" => Some(Self::PoolDeleted),
            "pool_archived" => Some(Self::PoolArchived),
            "pool_expired" => Some(Self::PoolExpired),
            "license_assigned" => Some(Self::LicenseAssigned),
            "license_deallocated" => Some(Self::LicenseDeallocated),
            "license_reclaimed" => Some(Self::LicenseReclaimed),
            "license_expired" => Some(Self::LicenseExpired),
            "link_created" => Some(Self::LinkCreated),
            "link_updated" => Some(Self::LinkUpdated),
            "link_deleted" => Some(Self::LinkDeleted),
            "rule_created" => Some(Self::RuleCreated),
            "rule_updated" => Some(Self::RuleUpdated),
            "rule_deleted" => Some(Self::RuleDeleted),
            "incompatibility_created" => Some(Self::IncompatibilityCreated),
            "incompatibility_deleted" => Some(Self::IncompatibilityDeleted),
            "bulk_assign" => Some(Self::BulkAssign),
            "bulk_reclaim" => Some(Self::BulkReclaim),
            _ => None,
        }
    }
}

impl std::fmt::Display for LicenseAuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// Default warning days before license expiration.
pub const DEFAULT_WARNING_DAYS: i32 = 60;

/// Default notification days before reclamation.
pub const DEFAULT_NOTIFICATION_DAYS_BEFORE: i32 = 7;

/// Maximum bulk operation size for license operations.
pub const LICENSE_MAX_BULK_OPERATION_SIZE: usize = 1000;

/// Underutilization threshold for recommendations (60%).
pub const UNDERUTILIZATION_THRESHOLD: f64 = 0.60;

/// Underutilization duration for recommendations (30 days).
pub const UNDERUTILIZATION_DAYS: i32 = 30;

/// High utilization warning threshold (90%).
pub const HIGH_UTILIZATION_THRESHOLD: f64 = 0.90;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_type_serialization() {
        assert_eq!(
            serde_json::to_string(&LicenseType::Named).unwrap(),
            "\"named\""
        );
        assert_eq!(
            serde_json::to_string(&LicenseType::Concurrent).unwrap(),
            "\"concurrent\""
        );
    }

    #[test]
    fn test_audit_action_roundtrip() {
        for action in [
            LicenseAuditAction::PoolCreated,
            LicenseAuditAction::LicenseAssigned,
            LicenseAuditAction::BulkReclaim,
        ] {
            let s = action.as_str();
            let parsed = LicenseAuditAction::parse(s);
            assert_eq!(parsed, Some(action));
        }
    }

    #[test]
    fn test_newtype_id_creation() {
        let pool_id = LicensePoolId::new();
        let assignment_id = LicenseAssignmentId::new();

        assert_ne!(pool_id.inner(), assignment_id.inner());
    }

    #[test]
    fn test_defaults() {
        assert_eq!(LicenseType::default(), LicenseType::Named);
        assert_eq!(LicensePoolStatus::default(), LicensePoolStatus::Active);
        assert_eq!(
            LicenseAssignmentStatus::default(),
            LicenseAssignmentStatus::Active
        );
        assert_eq!(
            LicenseExpirationPolicy::default(),
            LicenseExpirationPolicy::BlockNew
        );
    }
}
