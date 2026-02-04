//! Shared enum types for meta-role management (F056).

#![allow(clippy::derivable_impls)]

use serde::{Deserialize, Serialize};
use sqlx::Type;

/// Meta-role status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_meta_role_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum MetaRoleStatus {
    /// Meta-role is active and applying to matching roles.
    Active,
    /// Meta-role is disabled and not applying to any roles.
    Disabled,
}

impl Default for MetaRoleStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// Criteria logic for combining multiple conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_meta_role_criteria_logic", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum CriteriaLogic {
    /// All conditions must match (logical AND).
    And,
    /// Any condition can match (logical OR).
    Or,
}

impl Default for CriteriaLogic {
    fn default() -> Self {
        Self::And
    }
}

/// Operator for criteria comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(
    type_name = "gov_meta_role_criteria_operator",
    rename_all = "snake_case"
)]
#[serde(rename_all = "snake_case")]
pub enum CriteriaOperator {
    /// Equals.
    Eq,
    /// Not equals.
    Neq,
    /// In list.
    In,
    /// Not in list.
    NotIn,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Gte,
    /// Less than.
    Lt,
    /// Less than or equal.
    Lte,
    /// Contains substring.
    Contains,
    /// Starts with prefix.
    StartsWith,
}

/// Permission type for inherited entitlements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_meta_role_permission_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum PermissionType {
    /// Grant the entitlement.
    Grant,
    /// Deny the entitlement.
    Deny,
}

impl Default for PermissionType {
    fn default() -> Self {
        Self::Grant
    }
}

/// Status of an inheritance relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(
    type_name = "gov_meta_role_inheritance_status",
    rename_all = "lowercase"
)]
#[serde(rename_all = "lowercase")]
pub enum InheritanceStatus {
    /// Inheritance is active.
    Active,
    /// Inheritance is suspended (meta-role disabled).
    Suspended,
    /// Inheritance was removed (role no longer matches).
    Removed,
}

impl Default for InheritanceStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// Type of conflict between meta-roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_meta_role_conflict_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MetaRoleConflictType {
    /// Same entitlement with grant vs deny.
    EntitlementConflict,
    /// Same constraint type with different values.
    ConstraintConflict,
    /// Contradicting boolean policies.
    PolicyConflict,
}

/// Status of conflict resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(
    type_name = "gov_meta_role_resolution_status",
    rename_all = "snake_case"
)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStatus {
    /// Conflict is not yet resolved.
    Unresolved,
    /// Resolved using priority rules.
    ResolvedPriority,
    /// Resolved manually by an administrator.
    ResolvedManual,
    /// Conflict was acknowledged and ignored.
    Ignored,
}

impl Default for ResolutionStatus {
    fn default() -> Self {
        Self::Unresolved
    }
}

/// Event type for audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_meta_role_event_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MetaRoleEventType {
    /// Meta-role was created.
    Created,
    /// Meta-role was updated.
    Updated,
    /// Meta-role was deleted.
    Deleted,
    /// Meta-role was disabled.
    Disabled,
    /// Meta-role was enabled.
    Enabled,
    /// Inheritance was applied to a role.
    InheritanceApplied,
    /// Inheritance was removed from a role.
    InheritanceRemoved,
    /// Conflict was detected.
    ConflictDetected,
    /// Conflict was resolved.
    ConflictResolved,
    /// Cascade propagation started.
    CascadeStarted,
    /// Cascade propagation completed.
    CascadeCompleted,
    /// Cascade propagation failed.
    CascadeFailed,
}

/// Supported fields for criteria matching.
pub const SUPPORTED_CRITERIA_FIELDS: &[&str] = &[
    "risk_level",
    "application_id",
    "owner_id",
    "status",
    "name",
    "is_delegable",
    "metadata",
];

/// Constraint types supported by meta-roles.
pub const SUPPORTED_CONSTRAINT_TYPES: &[&str] = &[
    "max_session_duration",
    "require_mfa",
    "ip_whitelist",
    "approval_required",
];

impl CriteriaOperator {
    /// Returns true if this operator requires a list value.
    #[must_use] 
    pub fn requires_list(&self) -> bool {
        matches!(self, Self::In | Self::NotIn)
    }

    /// Returns true if this operator is for numeric comparison.
    #[must_use] 
    pub fn is_numeric(&self) -> bool {
        matches!(self, Self::Gt | Self::Gte | Self::Lt | Self::Lte)
    }

    /// Returns true if this operator is for string matching.
    #[must_use] 
    pub fn is_string_match(&self) -> bool {
        matches!(self, Self::Contains | Self::StartsWith)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_criteria_operator_requires_list() {
        assert!(CriteriaOperator::In.requires_list());
        assert!(CriteriaOperator::NotIn.requires_list());
        assert!(!CriteriaOperator::Eq.requires_list());
    }

    #[test]
    fn test_criteria_operator_is_numeric() {
        assert!(CriteriaOperator::Gt.is_numeric());
        assert!(CriteriaOperator::Gte.is_numeric());
        assert!(CriteriaOperator::Lt.is_numeric());
        assert!(CriteriaOperator::Lte.is_numeric());
        assert!(!CriteriaOperator::Eq.is_numeric());
    }

    #[test]
    fn test_criteria_operator_is_string_match() {
        assert!(CriteriaOperator::Contains.is_string_match());
        assert!(CriteriaOperator::StartsWith.is_string_match());
        assert!(!CriteriaOperator::Eq.is_string_match());
    }

    #[test]
    fn test_default_values() {
        assert_eq!(MetaRoleStatus::default(), MetaRoleStatus::Active);
        assert_eq!(CriteriaLogic::default(), CriteriaLogic::And);
        assert_eq!(PermissionType::default(), PermissionType::Grant);
        assert_eq!(InheritanceStatus::default(), InheritanceStatus::Active);
        assert_eq!(ResolutionStatus::default(), ResolutionStatus::Unresolved);
    }
}
