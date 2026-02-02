//! Meta-role simulation service for previewing changes (F056 - US4).
//!
//! Provides "what-if" analysis to preview the impact of meta-role changes
//! without making actual modifications to the system.

use std::collections::HashSet;
use std::sync::Arc;

use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use xavyo_db::{
    CriteriaLogic, GovEntitlement, GovMetaRole, GovMetaRoleConflict, GovMetaRoleEntitlement,
    GovMetaRoleInheritance, InheritanceStatus, MetaRoleConflictType, MetaRoleStatus,
    PermissionType,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    CreateMetaRoleCriteriaRequest, MetaRoleSimulationType, SimulationConflict,
    SimulationRoleChange, SimulationSummary,
};
use crate::services::MetaRoleMatchingService;

/// Result of a simulation.
#[derive(Debug, Clone)]
pub struct SimulationResult {
    /// Type of simulation performed.
    pub simulation_type: MetaRoleSimulationType,
    /// Roles that would gain inheritance.
    pub roles_to_add: Vec<SimulationRoleChange>,
    /// Roles that would lose inheritance.
    pub roles_to_remove: Vec<SimulationRoleChange>,
    /// Potential conflicts that would be created.
    pub potential_conflicts: Vec<SimulationConflict>,
    /// Conflicts that would be resolved.
    pub conflicts_to_resolve: Vec<SimulationConflict>,
    /// Summary statistics.
    pub summary: SimulationSummary,
}

/// Service for simulating meta-role changes.
pub struct MetaRoleSimulationService {
    pool: Arc<PgPool>,
    matching_service: Arc<MetaRoleMatchingService>,
}

impl MetaRoleSimulationService {
    /// Create a new simulation service.
    pub fn new(pool: Arc<PgPool>, matching_service: Arc<MetaRoleMatchingService>) -> Self {
        Self {
            pool,
            matching_service,
        }
    }

    // =========================================================================
    // Main Simulation Entry Point
    // =========================================================================

    /// Simulate criteria changes for an existing meta-role (T068, T069).
    pub async fn simulate_criteria_change(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        new_criteria: Vec<CreateMetaRoleCriteriaRequest>,
        limit: i64,
    ) -> Result<SimulationResult> {
        info!(
            tenant_id = %tenant_id,
            meta_role_id = %meta_role_id,
            criteria_count = new_criteria.len(),
            "Simulating criteria change"
        );

        // Get the meta-role
        let meta_role = GovMetaRole::find_by_id(&self.pool, tenant_id, meta_role_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleNotFound(meta_role_id))?;

        // Get current inheritances
        let current_inheritances = GovMetaRoleInheritance::list_by_meta_role(
            &self.pool,
            tenant_id,
            meta_role_id,
            Some(InheritanceStatus::Active),
            1000,
            0,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let current_role_ids: HashSet<Uuid> = current_inheritances
            .iter()
            .map(|i| i.child_role_id)
            .collect();

        // Evaluate which roles would match with new criteria
        let criteria_logic_str = match meta_role.criteria_logic {
            CriteriaLogic::And => "and",
            CriteriaLogic::Or => "or",
        };
        let matching_role_ids = self
            .evaluate_criteria_matches(tenant_id, &new_criteria, criteria_logic_str, limit)
            .await?;

        // Calculate differences
        let roles_to_add = self
            .get_roles_to_add(tenant_id, &matching_role_ids, &current_role_ids, limit)
            .await?;
        let roles_to_remove = self
            .get_roles_to_remove(tenant_id, &matching_role_ids, &current_role_ids, limit)
            .await?;

        // Detect potential conflicts for new roles
        let potential_conflicts = self
            .detect_potential_conflicts(tenant_id, meta_role_id, &matching_role_ids)
            .await?;

        // Conflicts that would be resolved (roles losing inheritance)
        let role_ids_to_remove: HashSet<Uuid> = roles_to_remove.iter().map(|r| r.role_id).collect();
        let conflicts_to_resolve = self
            .get_conflicts_to_resolve(tenant_id, meta_role_id, &role_ids_to_remove)
            .await?;

        let has_conflicts = !potential_conflicts.is_empty();
        let summary = SimulationSummary {
            total_roles_affected: (roles_to_add.len() + roles_to_remove.len()) as i64,
            roles_gaining_inheritance: roles_to_add.len() as i64,
            roles_losing_inheritance: roles_to_remove.len() as i64,
            new_conflicts: potential_conflicts.len() as i64,
            resolved_conflicts: conflicts_to_resolve.len() as i64,
            is_safe: !has_conflicts,
            warnings: if has_conflicts {
                vec!["This change will create new conflicts".to_string()]
            } else {
                vec![]
            },
        };

        Ok(SimulationResult {
            simulation_type: MetaRoleSimulationType::CriteriaChange,
            roles_to_add,
            roles_to_remove,
            potential_conflicts,
            conflicts_to_resolve,
            summary,
        })
    }

    /// Simulate adding an entitlement to a meta-role (T070).
    pub async fn simulate_add_entitlement(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        entitlement_id: Uuid,
        permission_type: PermissionType,
        limit: i64,
    ) -> Result<SimulationResult> {
        info!(
            tenant_id = %tenant_id,
            meta_role_id = %meta_role_id,
            entitlement_id = %entitlement_id,
            permission_type = ?permission_type,
            "Simulating add entitlement"
        );

        // Get affected roles (all roles with active inheritance)
        let inheritances = GovMetaRoleInheritance::list_by_meta_role(
            &self.pool,
            tenant_id,
            meta_role_id,
            Some(InheritanceStatus::Active),
            limit,
            0,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let affected_role_ids: Vec<Uuid> = inheritances.iter().map(|i| i.child_role_id).collect();

        // Check for conflicts (e.g., if adding a "deny" and another meta-role grants)
        let potential_conflicts = self
            .detect_entitlement_conflicts(
                tenant_id,
                meta_role_id,
                entitlement_id,
                permission_type,
                &affected_role_ids,
            )
            .await?;

        // Build role changes (all affected roles would receive this entitlement)
        let roles_to_add = self
            .build_role_changes(
                tenant_id,
                &affected_role_ids,
                serde_json::json!({
                    "entitlement_added": entitlement_id,
                    "permission_type": format!("{:?}", permission_type)
                }),
            )
            .await?;

        let has_conflicts = !potential_conflicts.is_empty();
        let summary = SimulationSummary {
            total_roles_affected: roles_to_add.len() as i64,
            roles_gaining_inheritance: 0, // Not changing inheritance, just entitlement
            roles_losing_inheritance: 0,
            new_conflicts: potential_conflicts.len() as i64,
            resolved_conflicts: 0,
            is_safe: !has_conflicts,
            warnings: if has_conflicts {
                vec!["Adding this entitlement will create conflicts".to_string()]
            } else {
                vec![]
            },
        };

        Ok(SimulationResult {
            simulation_type: MetaRoleSimulationType::Update,
            roles_to_add,
            roles_to_remove: vec![],
            potential_conflicts,
            conflicts_to_resolve: vec![],
            summary,
        })
    }

    /// Simulate removing an entitlement from a meta-role (T072).
    pub async fn simulate_remove_entitlement(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        entitlement_id: Uuid,
        limit: i64,
    ) -> Result<SimulationResult> {
        info!(
            tenant_id = %tenant_id,
            meta_role_id = %meta_role_id,
            entitlement_id = %entitlement_id,
            "Simulating remove entitlement"
        );

        // Get affected roles
        let inheritances = GovMetaRoleInheritance::list_by_meta_role(
            &self.pool,
            tenant_id,
            meta_role_id,
            Some(InheritanceStatus::Active),
            limit,
            0,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let affected_role_ids: Vec<Uuid> = inheritances.iter().map(|i| i.child_role_id).collect();

        // Conflicts that would be resolved by removing this entitlement
        let conflicts_to_resolve = self
            .get_entitlement_conflicts_to_resolve(tenant_id, meta_role_id, entitlement_id)
            .await?;

        let roles_to_remove = self
            .build_role_changes(
                tenant_id,
                &affected_role_ids,
                serde_json::json!({
                    "entitlement_removed": entitlement_id
                }),
            )
            .await?;

        let summary = SimulationSummary {
            total_roles_affected: roles_to_remove.len() as i64,
            roles_gaining_inheritance: 0,
            roles_losing_inheritance: 0,
            new_conflicts: 0,
            resolved_conflicts: conflicts_to_resolve.len() as i64,
            is_safe: true,
            warnings: vec![],
        };

        Ok(SimulationResult {
            simulation_type: MetaRoleSimulationType::Update,
            roles_to_add: vec![],
            roles_to_remove,
            potential_conflicts: vec![],
            conflicts_to_resolve,
            summary,
        })
    }

    /// Simulate adding a constraint to a meta-role (T071).
    pub async fn simulate_add_constraint(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        constraint_type: String,
        constraint_value: serde_json::Value,
        limit: i64,
    ) -> Result<SimulationResult> {
        info!(
            tenant_id = %tenant_id,
            meta_role_id = %meta_role_id,
            constraint_type = %constraint_type,
            "Simulating add constraint"
        );

        // Get affected roles
        let inheritances = GovMetaRoleInheritance::list_by_meta_role(
            &self.pool,
            tenant_id,
            meta_role_id,
            Some(InheritanceStatus::Active),
            limit,
            0,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let affected_role_ids: Vec<Uuid> = inheritances.iter().map(|i| i.child_role_id).collect();

        // Check for constraint conflicts
        let potential_conflicts = self
            .detect_constraint_conflicts(
                tenant_id,
                meta_role_id,
                &constraint_type,
                &constraint_value,
                &affected_role_ids,
            )
            .await?;

        let roles_to_add = self
            .build_role_changes(
                tenant_id,
                &affected_role_ids,
                serde_json::json!({
                    "constraint_added": constraint_type,
                    "constraint_value": constraint_value
                }),
            )
            .await?;

        let has_conflicts = !potential_conflicts.is_empty();
        let summary = SimulationSummary {
            total_roles_affected: roles_to_add.len() as i64,
            roles_gaining_inheritance: 0,
            roles_losing_inheritance: 0,
            new_conflicts: potential_conflicts.len() as i64,
            resolved_conflicts: 0,
            is_safe: !has_conflicts,
            warnings: if has_conflicts {
                vec!["Adding this constraint will create conflicts".to_string()]
            } else {
                vec![]
            },
        };

        Ok(SimulationResult {
            simulation_type: MetaRoleSimulationType::Update,
            roles_to_add,
            roles_to_remove: vec![],
            potential_conflicts,
            conflicts_to_resolve: vec![],
            summary,
        })
    }

    /// Simulate enabling a disabled meta-role.
    pub async fn simulate_enable(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        limit: i64,
    ) -> Result<SimulationResult> {
        info!(
            tenant_id = %tenant_id,
            meta_role_id = %meta_role_id,
            "Simulating enable meta-role"
        );

        // Get the meta-role
        let meta_role = GovMetaRole::find_by_id(&self.pool, tenant_id, meta_role_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleNotFound(meta_role_id))?;

        if meta_role.status == MetaRoleStatus::Active {
            warn!(
                meta_role_id = %meta_role_id,
                "Meta-role is already active"
            );
            return Ok(SimulationResult {
                simulation_type: MetaRoleSimulationType::Enable,
                roles_to_add: vec![],
                roles_to_remove: vec![],
                potential_conflicts: vec![],
                conflicts_to_resolve: vec![],
                summary: SimulationSummary {
                    total_roles_affected: 0,
                    roles_gaining_inheritance: 0,
                    roles_losing_inheritance: 0,
                    new_conflicts: 0,
                    resolved_conflicts: 0,
                    is_safe: true,
                    warnings: vec![],
                },
            });
        }

        // Get suspended inheritances that would be reactivated
        let suspended_inheritances = GovMetaRoleInheritance::list_by_meta_role(
            &self.pool,
            tenant_id,
            meta_role_id,
            Some(InheritanceStatus::Suspended),
            limit,
            0,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let role_ids: Vec<Uuid> = suspended_inheritances
            .iter()
            .map(|i| i.child_role_id)
            .collect();

        // Detect potential conflicts when re-enabling
        let potential_conflicts = self
            .detect_potential_conflicts(
                tenant_id,
                meta_role_id,
                &role_ids.iter().cloned().collect(),
            )
            .await?;

        let roles_to_add = self
            .build_role_changes(
                tenant_id,
                &role_ids,
                serde_json::json!({"reason": "meta-role re-enabled"}),
            )
            .await?;

        let has_conflicts = !potential_conflicts.is_empty();
        let summary = SimulationSummary {
            total_roles_affected: roles_to_add.len() as i64,
            roles_gaining_inheritance: roles_to_add.len() as i64,
            roles_losing_inheritance: 0,
            new_conflicts: potential_conflicts.len() as i64,
            resolved_conflicts: 0,
            is_safe: !has_conflicts,
            warnings: if has_conflicts {
                vec!["Enabling this meta-role will create conflicts".to_string()]
            } else {
                vec![]
            },
        };

        Ok(SimulationResult {
            simulation_type: MetaRoleSimulationType::Enable,
            roles_to_add,
            roles_to_remove: vec![],
            potential_conflicts,
            conflicts_to_resolve: vec![],
            summary,
        })
    }

    /// Simulate disabling an active meta-role.
    pub async fn simulate_disable(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        limit: i64,
    ) -> Result<SimulationResult> {
        info!(
            tenant_id = %tenant_id,
            meta_role_id = %meta_role_id,
            "Simulating disable meta-role"
        );

        // Get active inheritances that would be suspended
        let active_inheritances = GovMetaRoleInheritance::list_by_meta_role(
            &self.pool,
            tenant_id,
            meta_role_id,
            Some(InheritanceStatus::Active),
            limit,
            0,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let role_ids: Vec<Uuid> = active_inheritances
            .iter()
            .map(|i| i.child_role_id)
            .collect();

        // Conflicts that would be resolved when disabling
        let conflicts_to_resolve = self
            .get_conflicts_to_resolve(tenant_id, meta_role_id, &role_ids.iter().cloned().collect())
            .await?;

        let roles_to_remove = self
            .build_role_changes(
                tenant_id,
                &role_ids,
                serde_json::json!({"reason": "meta-role disabled"}),
            )
            .await?;

        let summary = SimulationSummary {
            total_roles_affected: roles_to_remove.len() as i64,
            roles_gaining_inheritance: 0,
            roles_losing_inheritance: roles_to_remove.len() as i64,
            new_conflicts: 0,
            resolved_conflicts: conflicts_to_resolve.len() as i64,
            is_safe: true,
            warnings: vec![],
        };

        Ok(SimulationResult {
            simulation_type: MetaRoleSimulationType::Disable,
            roles_to_add: vec![],
            roles_to_remove,
            potential_conflicts: vec![],
            conflicts_to_resolve,
            summary,
        })
    }

    /// Simulate deleting a meta-role.
    pub async fn simulate_delete(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        limit: i64,
    ) -> Result<SimulationResult> {
        info!(
            tenant_id = %tenant_id,
            meta_role_id = %meta_role_id,
            "Simulating delete meta-role"
        );

        // Get all inheritances (active and suspended) that would be removed
        let all_inheritances = GovMetaRoleInheritance::list_by_meta_role(
            &self.pool,
            tenant_id,
            meta_role_id,
            None, // All statuses
            limit,
            0,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let role_ids: Vec<Uuid> = all_inheritances.iter().map(|i| i.child_role_id).collect();

        // All conflicts involving this meta-role would be resolved
        let conflicts_to_resolve = self
            .get_all_conflicts_for_meta_role(tenant_id, meta_role_id)
            .await?;

        let roles_to_remove = self
            .build_role_changes(
                tenant_id,
                &role_ids,
                serde_json::json!({"reason": "meta-role deleted"}),
            )
            .await?;

        let summary = SimulationSummary {
            total_roles_affected: roles_to_remove.len() as i64,
            roles_gaining_inheritance: 0,
            roles_losing_inheritance: roles_to_remove.len() as i64,
            new_conflicts: 0,
            resolved_conflicts: conflicts_to_resolve.len() as i64,
            is_safe: true,
            warnings: vec![],
        };

        Ok(SimulationResult {
            simulation_type: MetaRoleSimulationType::Delete,
            roles_to_add: vec![],
            roles_to_remove,
            potential_conflicts: vec![],
            conflicts_to_resolve,
            summary,
        })
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Evaluate which roles would match given criteria.
    async fn evaluate_criteria_matches(
        &self,
        tenant_id: Uuid,
        criteria: &[CreateMetaRoleCriteriaRequest],
        criteria_logic: &str,
        limit: i64,
    ) -> Result<HashSet<Uuid>> {
        // Get all role-type entitlements
        let roles: Vec<GovEntitlement> = sqlx::query_as(
            r#"
            SELECT * FROM gov_entitlements
            WHERE tenant_id = $1 AND entitlement_type = 'role'
            LIMIT $2
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(GovernanceError::Database)?;

        let mut matching_ids = HashSet::new();

        for role in roles {
            if self
                .matching_service
                .role_matches_criteria(&role, criteria, criteria_logic)
            {
                matching_ids.insert(role.id);
            }
        }

        Ok(matching_ids)
    }

    /// Get roles that would gain inheritance.
    async fn get_roles_to_add(
        &self,
        tenant_id: Uuid,
        new_matches: &HashSet<Uuid>,
        current_roles: &HashSet<Uuid>,
        limit: i64,
    ) -> Result<Vec<SimulationRoleChange>> {
        let to_add: Vec<Uuid> = new_matches
            .difference(current_roles)
            .take(limit as usize)
            .cloned()
            .collect();

        self.build_role_changes(
            tenant_id,
            &to_add,
            serde_json::json!({"reason": "newly matches criteria"}),
        )
        .await
    }

    /// Get roles that would lose inheritance.
    async fn get_roles_to_remove(
        &self,
        tenant_id: Uuid,
        new_matches: &HashSet<Uuid>,
        current_roles: &HashSet<Uuid>,
        limit: i64,
    ) -> Result<Vec<SimulationRoleChange>> {
        let to_remove: Vec<Uuid> = current_roles
            .difference(new_matches)
            .take(limit as usize)
            .cloned()
            .collect();

        self.build_role_changes(
            tenant_id,
            &to_remove,
            serde_json::json!({"reason": "no longer matches criteria"}),
        )
        .await
    }

    /// Build role change records.
    async fn build_role_changes(
        &self,
        tenant_id: Uuid,
        role_ids: &[Uuid],
        reason: serde_json::Value,
    ) -> Result<Vec<SimulationRoleChange>> {
        if role_ids.is_empty() {
            return Ok(vec![]);
        }

        let roles: Vec<GovEntitlement> = sqlx::query_as(
            r#"
            SELECT * FROM gov_entitlements
            WHERE tenant_id = $1 AND id = ANY($2)
            "#,
        )
        .bind(tenant_id)
        .bind(role_ids)
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(GovernanceError::Database)?;

        Ok(roles
            .into_iter()
            .map(|r| SimulationRoleChange {
                role_id: r.id,
                role_name: r.name,
                application_id: Some(r.application_id),
                reason: reason.clone(),
                entitlements_affected: vec![],
                constraints_affected: vec![],
            })
            .collect())
    }

    /// Detect potential conflicts for new role inheritances.
    async fn detect_potential_conflicts(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        affected_role_ids: &HashSet<Uuid>,
    ) -> Result<Vec<SimulationConflict>> {
        let mut conflicts = vec![];

        // Get meta-role details
        let meta_role = GovMetaRole::find_by_id(&self.pool, tenant_id, meta_role_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleNotFound(meta_role_id))?;

        // Get meta-role's entitlements
        let entitlements =
            GovMetaRoleEntitlement::list_by_meta_role(&self.pool, tenant_id, meta_role_id)
                .await
                .map_err(GovernanceError::Database)?;

        // For each affected role, check if other meta-roles have conflicting entitlements
        for role_id in affected_role_ids {
            // Fetch role info for the affected role name
            let affected_role: Option<GovEntitlement> =
                sqlx::query_as("SELECT * FROM gov_entitlements WHERE tenant_id = $1 AND id = $2")
                    .bind(tenant_id)
                    .bind(*role_id)
                    .fetch_optional(self.pool.as_ref())
                    .await
                    .map_err(GovernanceError::Database)?;

            let affected_role_name = affected_role
                .map(|r| r.name)
                .unwrap_or_else(|| "Unknown".to_string());

            let other_inheritances = GovMetaRoleInheritance::list_by_child_role(
                &self.pool,
                tenant_id,
                *role_id,
                Some(InheritanceStatus::Active),
            )
            .await
            .map_err(GovernanceError::Database)?;

            for other_inheritance in other_inheritances {
                if other_inheritance.meta_role_id == meta_role_id {
                    continue;
                }

                // Get other meta-role's entitlements
                let other_entitlements = GovMetaRoleEntitlement::list_by_meta_role(
                    &self.pool,
                    tenant_id,
                    other_inheritance.meta_role_id,
                )
                .await
                .map_err(GovernanceError::Database)?;

                let other_meta_role =
                    GovMetaRole::find_by_id(&self.pool, tenant_id, other_inheritance.meta_role_id)
                        .await
                        .map_err(GovernanceError::Database)?;

                // Check for grant vs deny conflicts
                for ent in &entitlements {
                    for other_ent in &other_entitlements {
                        if ent.entitlement_id == other_ent.entitlement_id
                            && ent.permission_type != other_ent.permission_type
                        {
                            if let Some(ref other_mr) = other_meta_role {
                                conflicts.push(SimulationConflict {
                                    meta_role_a_id: meta_role_id,
                                    meta_role_a_name: meta_role.name.clone(),
                                    meta_role_b_id: other_inheritance.meta_role_id,
                                    meta_role_b_name: other_mr.name.clone(),
                                    affected_role_id: *role_id,
                                    affected_role_name: affected_role_name.clone(),
                                    conflict_type: MetaRoleConflictType::EntitlementConflict,
                                    conflicting_items: serde_json::json!({
                                        "entitlement_id": ent.entitlement_id,
                                        "permission_a": format!("{:?}", ent.permission_type),
                                        "permission_b": format!("{:?}", other_ent.permission_type)
                                    }),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(conflicts)
    }

    /// Detect entitlement conflicts for a specific entitlement addition.
    async fn detect_entitlement_conflicts(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        entitlement_id: Uuid,
        permission_type: PermissionType,
        affected_role_ids: &[Uuid],
    ) -> Result<Vec<SimulationConflict>> {
        let mut conflicts = vec![];

        let meta_role = GovMetaRole::find_by_id(&self.pool, tenant_id, meta_role_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleNotFound(meta_role_id))?;

        for role_id in affected_role_ids {
            // Fetch role info for the affected role name
            let affected_role: Option<GovEntitlement> =
                sqlx::query_as("SELECT * FROM gov_entitlements WHERE tenant_id = $1 AND id = $2")
                    .bind(tenant_id)
                    .bind(*role_id)
                    .fetch_optional(self.pool.as_ref())
                    .await
                    .map_err(GovernanceError::Database)?;

            let affected_role_name = affected_role
                .map(|r| r.name)
                .unwrap_or_else(|| "Unknown".to_string());

            let other_inheritances = GovMetaRoleInheritance::list_by_child_role(
                &self.pool,
                tenant_id,
                *role_id,
                Some(InheritanceStatus::Active),
            )
            .await
            .map_err(GovernanceError::Database)?;

            for other_inheritance in other_inheritances {
                if other_inheritance.meta_role_id == meta_role_id {
                    continue;
                }

                let other_entitlements = GovMetaRoleEntitlement::list_by_meta_role(
                    &self.pool,
                    tenant_id,
                    other_inheritance.meta_role_id,
                )
                .await
                .map_err(GovernanceError::Database)?;

                for other_ent in other_entitlements {
                    if other_ent.entitlement_id == entitlement_id
                        && other_ent.permission_type != permission_type
                    {
                        let other_meta_role = GovMetaRole::find_by_id(
                            &self.pool,
                            tenant_id,
                            other_inheritance.meta_role_id,
                        )
                        .await
                        .map_err(GovernanceError::Database)?;

                        if let Some(other_mr) = other_meta_role {
                            conflicts.push(SimulationConflict {
                                meta_role_a_id: meta_role_id,
                                meta_role_a_name: meta_role.name.clone(),
                                meta_role_b_id: other_inheritance.meta_role_id,
                                meta_role_b_name: other_mr.name,
                                affected_role_id: *role_id,
                                affected_role_name: affected_role_name.clone(),
                                conflict_type: MetaRoleConflictType::EntitlementConflict,
                                conflicting_items: serde_json::json!({
                                    "entitlement_id": entitlement_id,
                                    "new_permission": format!("{:?}", permission_type),
                                    "existing_permission": format!("{:?}", other_ent.permission_type)
                                }),
                            });
                        }
                    }
                }
            }
        }

        Ok(conflicts)
    }

    /// Detect constraint conflicts.
    async fn detect_constraint_conflicts(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        constraint_type: &str,
        constraint_value: &serde_json::Value,
        affected_role_ids: &[Uuid],
    ) -> Result<Vec<SimulationConflict>> {
        let mut conflicts = vec![];

        let meta_role = GovMetaRole::find_by_id(&self.pool, tenant_id, meta_role_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleNotFound(meta_role_id))?;

        for role_id in affected_role_ids {
            // Fetch role info for the affected role name
            let affected_role: Option<GovEntitlement> =
                sqlx::query_as("SELECT * FROM gov_entitlements WHERE tenant_id = $1 AND id = $2")
                    .bind(tenant_id)
                    .bind(*role_id)
                    .fetch_optional(self.pool.as_ref())
                    .await
                    .map_err(GovernanceError::Database)?;

            let affected_role_name = affected_role
                .map(|r| r.name)
                .unwrap_or_else(|| "Unknown".to_string());

            let other_inheritances = GovMetaRoleInheritance::list_by_child_role(
                &self.pool,
                tenant_id,
                *role_id,
                Some(InheritanceStatus::Active),
            )
            .await
            .map_err(GovernanceError::Database)?;

            for other_inheritance in other_inheritances {
                if other_inheritance.meta_role_id == meta_role_id {
                    continue;
                }

                // Check other meta-role's constraints
                let other_constraints: Vec<(String, serde_json::Value)> = sqlx::query_as(
                    r#"
                    SELECT constraint_type, constraint_value
                    FROM gov_meta_role_constraints
                    WHERE tenant_id = $1 AND meta_role_id = $2
                    "#,
                )
                .bind(tenant_id)
                .bind(other_inheritance.meta_role_id)
                .fetch_all(self.pool.as_ref())
                .await
                .map_err(GovernanceError::Database)?;

                for (other_type, other_value) in other_constraints {
                    if other_type == constraint_type && other_value != *constraint_value {
                        let other_meta_role = GovMetaRole::find_by_id(
                            &self.pool,
                            tenant_id,
                            other_inheritance.meta_role_id,
                        )
                        .await
                        .map_err(GovernanceError::Database)?;

                        if let Some(other_mr) = other_meta_role {
                            conflicts.push(SimulationConflict {
                                meta_role_a_id: meta_role_id,
                                meta_role_a_name: meta_role.name.clone(),
                                meta_role_b_id: other_inheritance.meta_role_id,
                                meta_role_b_name: other_mr.name,
                                affected_role_id: *role_id,
                                affected_role_name: affected_role_name.clone(),
                                conflict_type: MetaRoleConflictType::ConstraintConflict,
                                conflicting_items: serde_json::json!({
                                    "constraint_type": constraint_type,
                                    "new_value": constraint_value,
                                    "existing_value": other_value
                                }),
                            });
                        }
                    }
                }
            }
        }

        Ok(conflicts)
    }

    /// Get conflicts that would be resolved.
    async fn get_conflicts_to_resolve(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        role_ids: &HashSet<Uuid>,
    ) -> Result<Vec<SimulationConflict>> {
        let mut result = vec![];

        for role_id in role_ids {
            // Fetch role info for the affected role name
            let affected_role: Option<GovEntitlement> =
                sqlx::query_as("SELECT * FROM gov_entitlements WHERE tenant_id = $1 AND id = $2")
                    .bind(tenant_id)
                    .bind(*role_id)
                    .fetch_optional(self.pool.as_ref())
                    .await
                    .map_err(GovernanceError::Database)?;

            let affected_role_name = affected_role
                .map(|r| r.name)
                .unwrap_or_else(|| "Unknown".to_string());

            let conflicts: Vec<GovMetaRoleConflict> = sqlx::query_as(
                r#"
                SELECT * FROM gov_meta_role_conflicts
                WHERE tenant_id = $1
                  AND (meta_role_a_id = $2 OR meta_role_b_id = $2)
                  AND affected_role_id = $3
                  AND resolution_status = 'unresolved'
                "#,
            )
            .bind(tenant_id)
            .bind(meta_role_id)
            .bind(role_id)
            .fetch_all(self.pool.as_ref())
            .await
            .map_err(GovernanceError::Database)?;

            for conflict in conflicts {
                let meta_role_a =
                    GovMetaRole::find_by_id(&self.pool, tenant_id, conflict.meta_role_a_id)
                        .await
                        .map_err(GovernanceError::Database)?;
                let meta_role_b =
                    GovMetaRole::find_by_id(&self.pool, tenant_id, conflict.meta_role_b_id)
                        .await
                        .map_err(GovernanceError::Database)?;

                result.push(SimulationConflict {
                    meta_role_a_id: conflict.meta_role_a_id,
                    meta_role_a_name: meta_role_a.map(|m| m.name).unwrap_or_default(),
                    meta_role_b_id: conflict.meta_role_b_id,
                    meta_role_b_name: meta_role_b.map(|m| m.name).unwrap_or_default(),
                    affected_role_id: conflict.affected_role_id,
                    affected_role_name: affected_role_name.clone(),
                    conflict_type: conflict.conflict_type,
                    conflicting_items: conflict.conflicting_items,
                });
            }
        }

        Ok(result)
    }

    /// Get entitlement-specific conflicts to resolve.
    async fn get_entitlement_conflicts_to_resolve(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Vec<SimulationConflict>> {
        let conflicts: Vec<GovMetaRoleConflict> = sqlx::query_as(
            r#"
            SELECT * FROM gov_meta_role_conflicts
            WHERE tenant_id = $1
              AND (meta_role_a_id = $2 OR meta_role_b_id = $2)
              AND conflict_type = 'entitlement_conflict'
              AND conflicting_items->>'entitlement_id' = $3
              AND resolution_status = 'unresolved'
            "#,
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .bind(entitlement_id.to_string())
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(GovernanceError::Database)?;

        let mut result = vec![];
        for conflict in conflicts {
            // Fetch role info for the affected role name
            let affected_role: Option<GovEntitlement> =
                sqlx::query_as("SELECT * FROM gov_entitlements WHERE tenant_id = $1 AND id = $2")
                    .bind(tenant_id)
                    .bind(conflict.affected_role_id)
                    .fetch_optional(self.pool.as_ref())
                    .await
                    .map_err(GovernanceError::Database)?;

            let affected_role_name = affected_role
                .map(|r| r.name)
                .unwrap_or_else(|| "Unknown".to_string());

            let meta_role_a =
                GovMetaRole::find_by_id(&self.pool, tenant_id, conflict.meta_role_a_id)
                    .await
                    .map_err(GovernanceError::Database)?;
            let meta_role_b =
                GovMetaRole::find_by_id(&self.pool, tenant_id, conflict.meta_role_b_id)
                    .await
                    .map_err(GovernanceError::Database)?;

            result.push(SimulationConflict {
                meta_role_a_id: conflict.meta_role_a_id,
                meta_role_a_name: meta_role_a.map(|m| m.name).unwrap_or_default(),
                meta_role_b_id: conflict.meta_role_b_id,
                meta_role_b_name: meta_role_b.map(|m| m.name).unwrap_or_default(),
                affected_role_id: conflict.affected_role_id,
                affected_role_name,
                conflict_type: conflict.conflict_type,
                conflicting_items: conflict.conflicting_items,
            });
        }

        Ok(result)
    }

    /// Get all conflicts involving a meta-role.
    async fn get_all_conflicts_for_meta_role(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
    ) -> Result<Vec<SimulationConflict>> {
        let conflicts: Vec<GovMetaRoleConflict> = sqlx::query_as(
            r#"
            SELECT * FROM gov_meta_role_conflicts
            WHERE tenant_id = $1
              AND (meta_role_a_id = $2 OR meta_role_b_id = $2)
              AND resolution_status = 'unresolved'
            "#,
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(GovernanceError::Database)?;

        let mut result = vec![];
        for conflict in conflicts {
            // Fetch role info for the affected role name
            let affected_role: Option<GovEntitlement> =
                sqlx::query_as("SELECT * FROM gov_entitlements WHERE tenant_id = $1 AND id = $2")
                    .bind(tenant_id)
                    .bind(conflict.affected_role_id)
                    .fetch_optional(self.pool.as_ref())
                    .await
                    .map_err(GovernanceError::Database)?;

            let affected_role_name = affected_role
                .map(|r| r.name)
                .unwrap_or_else(|| "Unknown".to_string());

            let meta_role_a =
                GovMetaRole::find_by_id(&self.pool, tenant_id, conflict.meta_role_a_id)
                    .await
                    .map_err(GovernanceError::Database)?;
            let meta_role_b =
                GovMetaRole::find_by_id(&self.pool, tenant_id, conflict.meta_role_b_id)
                    .await
                    .map_err(GovernanceError::Database)?;

            result.push(SimulationConflict {
                meta_role_a_id: conflict.meta_role_a_id,
                meta_role_a_name: meta_role_a.map(|m| m.name).unwrap_or_default(),
                meta_role_b_id: conflict.meta_role_b_id,
                meta_role_b_name: meta_role_b.map(|m| m.name).unwrap_or_default(),
                affected_role_id: conflict.affected_role_id,
                affected_role_name,
                conflict_type: conflict.conflict_type,
                conflicting_items: conflict.conflicting_items,
            });
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulation_result_defaults() {
        let result = SimulationResult {
            simulation_type: MetaRoleSimulationType::Create,
            roles_to_add: vec![],
            roles_to_remove: vec![],
            potential_conflicts: vec![],
            conflicts_to_resolve: vec![],
            summary: SimulationSummary {
                total_roles_affected: 0,
                roles_gaining_inheritance: 0,
                roles_losing_inheritance: 0,
                new_conflicts: 0,
                resolved_conflicts: 0,
                is_safe: true,
                warnings: vec![],
            },
        };

        assert_eq!(result.summary.total_roles_affected, 0);
        assert!(result.roles_to_add.is_empty());
        assert!(result.potential_conflicts.is_empty());
        assert!(result.summary.is_safe);
        assert!(result.summary.warnings.is_empty());
    }
}
