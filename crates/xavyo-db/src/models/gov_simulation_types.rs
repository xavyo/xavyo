//! Enum types for enhanced simulation features (F060).

use serde::{Deserialize, Serialize};

/// Type of policy simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "policy_simulation_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum PolicySimulationType {
    /// Simulate a Separation of Duties rule.
    SodRule,
    /// Simulate a birthright policy.
    BirthrightPolicy,
}

impl PolicySimulationType {
    /// Check if this is an `SoD` rule simulation.
    #[must_use] 
    pub fn is_sod_rule(&self) -> bool {
        matches!(self, Self::SodRule)
    }

    /// Check if this is a birthright policy simulation.
    #[must_use] 
    pub fn is_birthright_policy(&self) -> bool {
        matches!(self, Self::BirthrightPolicy)
    }
}

/// Type of batch simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "batch_simulation_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum BatchSimulationType {
    /// Add a role to selected users.
    RoleAdd,
    /// Remove a role from selected users.
    RoleRemove,
    /// Add an entitlement to selected users.
    EntitlementAdd,
    /// Remove an entitlement from selected users.
    EntitlementRemove,
}

impl BatchSimulationType {
    /// Check if this is a role operation.
    #[must_use] 
    pub fn is_role_operation(&self) -> bool {
        matches!(self, Self::RoleAdd | Self::RoleRemove)
    }

    /// Check if this is an entitlement operation.
    #[must_use] 
    pub fn is_entitlement_operation(&self) -> bool {
        matches!(self, Self::EntitlementAdd | Self::EntitlementRemove)
    }

    /// Check if this is an add operation.
    #[must_use] 
    pub fn is_add(&self) -> bool {
        matches!(self, Self::RoleAdd | Self::EntitlementAdd)
    }

    /// Check if this is a remove operation.
    #[must_use] 
    pub fn is_remove(&self) -> bool {
        matches!(self, Self::RoleRemove | Self::EntitlementRemove)
    }
}

/// User selection mode for batch simulations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "selection_mode", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SelectionMode {
    /// Explicit list of user IDs.
    UserList,
    /// Filter criteria to match users.
    Filter,
}

impl SelectionMode {
    /// Check if this is user list mode.
    #[must_use] 
    pub fn is_user_list(&self) -> bool {
        matches!(self, Self::UserList)
    }

    /// Check if this is filter mode.
    #[must_use] 
    pub fn is_filter(&self) -> bool {
        matches!(self, Self::Filter)
    }
}

/// Impact type for simulation results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "impact_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ImpactType {
    /// `SoD` violation would be introduced.
    Violation,
    /// User would gain entitlement(s).
    EntitlementGain,
    /// User would lose entitlement(s).
    EntitlementLoss,
    /// No change to user's access.
    NoChange,
    /// Warning about potential issue (e.g., deleted reference).
    Warning,
}

impl ImpactType {
    /// Check if this is a violation.
    #[must_use] 
    pub fn is_violation(&self) -> bool {
        matches!(self, Self::Violation)
    }

    /// Check if this represents an access gain.
    #[must_use] 
    pub fn is_gain(&self) -> bool {
        matches!(self, Self::EntitlementGain)
    }

    /// Check if this represents an access loss.
    #[must_use] 
    pub fn is_loss(&self) -> bool {
        matches!(self, Self::EntitlementLoss)
    }

    /// Check if this is a warning.
    #[must_use] 
    pub fn is_warning(&self) -> bool {
        matches!(self, Self::Warning)
    }

    /// Check if this indicates no change.
    #[must_use] 
    pub fn is_no_change(&self) -> bool {
        matches!(self, Self::NoChange)
    }
}

/// Comparison type for simulation comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "comparison_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ComparisonType {
    /// Compare two simulations.
    SimulationVsSimulation,
    /// Compare simulation to current state.
    SimulationVsCurrent,
}

impl ComparisonType {
    /// Check if this compares two simulations.
    #[must_use] 
    pub fn is_simulation_vs_simulation(&self) -> bool {
        matches!(self, Self::SimulationVsSimulation)
    }

    /// Check if this compares simulation to current state.
    #[must_use] 
    pub fn is_simulation_vs_current(&self) -> bool {
        matches!(self, Self::SimulationVsCurrent)
    }
}

/// Impact summary statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ImpactSummary {
    /// Total users analyzed.
    pub total_users_analyzed: i64,
    /// Number of affected users.
    pub affected_users: i64,
    /// Counts by severity level.
    pub by_severity: SeverityCounts,
    /// Counts by impact type.
    pub by_impact_type: ImpactTypeCounts,
}

/// Counts by severity level.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SeverityCounts {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

/// Counts by impact type.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ImpactTypeCounts {
    pub violation: i64,
    pub entitlement_gain: i64,
    pub entitlement_loss: i64,
    pub no_change: i64,
    pub warning: i64,
}

/// Batch impact summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BatchImpactSummary {
    /// Total users in selection.
    pub total_users: i64,
    /// Users with access changes.
    pub affected_users: i64,
    /// Total entitlements that would be gained.
    pub entitlements_gained: i64,
    /// Total entitlements that would be lost.
    pub entitlements_lost: i64,
    /// `SoD` violations that would be introduced.
    pub sod_violations_introduced: i64,
    /// Warning messages.
    pub warnings: Vec<String>,
}

/// Comparison summary statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ComparisonSummary {
    /// Users affected in both simulations.
    pub users_in_both: i64,
    /// Users only in simulation A.
    pub users_only_in_a: i64,
    /// Users only in simulation B.
    pub users_only_in_b: i64,
    /// Users with different impacts between simulations.
    pub different_impacts: i64,
    /// Total additions across all users.
    pub total_additions: i64,
    /// Total removals across all users.
    pub total_removals: i64,
}

/// Filter criteria for batch user selection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FilterCriteria {
    /// Filter by department(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<Vec<String>>,
    /// Filter by user status (active, inactive, suspended).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Filter by role membership.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_ids: Option<Vec<uuid::Uuid>>,
    /// Filter by entitlement assignment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement_ids: Option<Vec<uuid::Uuid>>,
    /// Filter by title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Filter by custom metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Change specification for batch simulations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ChangeSpec {
    /// The operation to perform.
    pub operation: BatchSimulationType,
    /// Role ID (for role operations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_id: Option<uuid::Uuid>,
    /// Entitlement ID (for entitlement operations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement_id: Option<uuid::Uuid>,
    /// Justification for the change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_simulation_type_methods() {
        assert!(PolicySimulationType::SodRule.is_sod_rule());
        assert!(!PolicySimulationType::SodRule.is_birthright_policy());
        assert!(PolicySimulationType::BirthrightPolicy.is_birthright_policy());
        assert!(!PolicySimulationType::BirthrightPolicy.is_sod_rule());
    }

    #[test]
    fn test_batch_simulation_type_methods() {
        assert!(BatchSimulationType::RoleAdd.is_role_operation());
        assert!(BatchSimulationType::RoleAdd.is_add());
        assert!(!BatchSimulationType::RoleAdd.is_remove());

        assert!(BatchSimulationType::EntitlementRemove.is_entitlement_operation());
        assert!(BatchSimulationType::EntitlementRemove.is_remove());
        assert!(!BatchSimulationType::EntitlementRemove.is_add());
    }

    #[test]
    fn test_selection_mode_methods() {
        assert!(SelectionMode::UserList.is_user_list());
        assert!(!SelectionMode::UserList.is_filter());
        assert!(SelectionMode::Filter.is_filter());
        assert!(!SelectionMode::Filter.is_user_list());
    }

    #[test]
    fn test_impact_type_methods() {
        assert!(ImpactType::Violation.is_violation());
        assert!(ImpactType::EntitlementGain.is_gain());
        assert!(ImpactType::EntitlementLoss.is_loss());
        assert!(ImpactType::Warning.is_warning());
        assert!(ImpactType::NoChange.is_no_change());
    }

    #[test]
    fn test_comparison_type_methods() {
        assert!(ComparisonType::SimulationVsSimulation.is_simulation_vs_simulation());
        assert!(ComparisonType::SimulationVsCurrent.is_simulation_vs_current());
    }

    #[test]
    fn test_policy_simulation_type_serialization() {
        let sod = PolicySimulationType::SodRule;
        let json = serde_json::to_string(&sod).unwrap();
        assert_eq!(json, "\"sod_rule\"");

        let birthright = PolicySimulationType::BirthrightPolicy;
        let json = serde_json::to_string(&birthright).unwrap();
        assert_eq!(json, "\"birthright_policy\"");
    }

    #[test]
    fn test_batch_simulation_type_serialization() {
        let role_add = BatchSimulationType::RoleAdd;
        let json = serde_json::to_string(&role_add).unwrap();
        assert_eq!(json, "\"role_add\"");

        let ent_remove = BatchSimulationType::EntitlementRemove;
        let json = serde_json::to_string(&ent_remove).unwrap();
        assert_eq!(json, "\"entitlement_remove\"");
    }

    #[test]
    fn test_impact_summary_default() {
        let summary = ImpactSummary::default();
        assert_eq!(summary.total_users_analyzed, 0);
        assert_eq!(summary.affected_users, 0);
        assert_eq!(summary.by_severity.critical, 0);
    }

    #[test]
    fn test_filter_criteria_serialization() {
        let criteria = FilterCriteria {
            department: Some(vec!["Engineering".to_string(), "Product".to_string()]),
            status: Some("active".to_string()),
            role_ids: None,
            entitlement_ids: None,
            title: None,
            metadata: None,
        };

        let json = serde_json::to_string(&criteria).unwrap();
        assert!(json.contains("Engineering"));
        assert!(json.contains("active"));
        assert!(!json.contains("role_ids")); // None fields should be skipped
    }

    #[test]
    fn test_change_spec_validation() {
        let spec = ChangeSpec {
            operation: BatchSimulationType::RoleAdd,
            role_id: Some(uuid::Uuid::new_v4()),
            entitlement_id: None,
            justification: Some("Test justification".to_string()),
        };

        assert!(spec.operation.is_role_operation());
        assert!(spec.role_id.is_some());
    }
}
