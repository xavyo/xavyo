//! Simulation service for what-if role change analysis.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CreateRoleSimulation, GovRoleSimulation, RoleSimulationFilter, ScenarioType, SimulationChanges,
    SimulationStatus,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for role simulation operations.
pub struct SimulationService {
    pool: PgPool,
}

impl SimulationService {
    /// Create a new simulation service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a simulation by ID.
    pub async fn get(&self, tenant_id: Uuid, simulation_id: Uuid) -> Result<GovRoleSimulation> {
        GovRoleSimulation::find_by_id(&self.pool, tenant_id, simulation_id)
            .await?
            .ok_or(GovernanceError::RoleSimulationNotFound(simulation_id))
    }

    /// List simulations with filtering and pagination.
    #[allow(clippy::too_many_arguments)]
    pub async fn list(
        &self,
        tenant_id: Uuid,
        scenario_type: Option<ScenarioType>,
        status: Option<SimulationStatus>,
        target_role_id: Option<Uuid>,
        created_by: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovRoleSimulation>, i64)> {
        let filter = RoleSimulationFilter {
            scenario_type,
            status,
            target_role_id,
            created_by,
        };

        let simulations =
            GovRoleSimulation::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total = GovRoleSimulation::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((simulations, total))
    }

    /// Create a new simulation.
    pub async fn create_simulation(
        &self,
        tenant_id: Uuid,
        name: String,
        scenario_type: ScenarioType,
        target_role_id: Option<Uuid>,
        changes: SimulationChanges,
        created_by: Uuid,
    ) -> Result<GovRoleSimulation> {
        // Validate name
        if name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Simulation name cannot be empty".to_string(),
            ));
        }

        if name.len() > 255 {
            return Err(GovernanceError::Validation(
                "Simulation name cannot exceed 255 characters".to_string(),
            ));
        }

        // Validate scenario type requirements
        validate_changes(&scenario_type, &changes, target_role_id)?;

        let input = CreateRoleSimulation {
            name,
            scenario_type,
            target_role_id,
            changes,
            created_by,
        };

        let simulation = GovRoleSimulation::create(&self.pool, tenant_id, input).await?;

        tracing::info!(
            simulation_id = %simulation.id,
            tenant_id = %tenant_id,
            scenario_type = ?scenario_type,
            "Created role simulation"
        );

        Ok(simulation)
    }

    /// Execute a simulation (calculate impact without applying changes).
    pub async fn execute_simulation(
        &self,
        tenant_id: Uuid,
        simulation_id: Uuid,
    ) -> Result<GovRoleSimulation> {
        let simulation = self.get(tenant_id, simulation_id).await?;

        if !simulation.status.can_execute() {
            return Err(GovernanceError::RoleSimulationNotDraft(simulation_id));
        }

        let changes = simulation.parse_changes();
        let target_role_id = simulation.target_role_id.or(changes.role_id);

        // Calculate impact based on scenario type
        let (affected_users, access_gained, access_lost) = match simulation.scenario_type {
            ScenarioType::AddEntitlement => {
                self.calculate_add_entitlement_impact(
                    tenant_id,
                    target_role_id,
                    changes.entitlement_id,
                )
                .await?
            }
            ScenarioType::RemoveEntitlement => {
                self.calculate_remove_entitlement_impact(
                    tenant_id,
                    target_role_id,
                    changes.entitlement_id,
                )
                .await?
            }
            ScenarioType::AddRole => self.calculate_add_role_impact(tenant_id, &changes).await?,
            ScenarioType::RemoveRole => {
                self.calculate_remove_role_impact(tenant_id, target_role_id)
                    .await?
            }
            ScenarioType::ModifyRole => {
                self.calculate_modify_role_impact(tenant_id, target_role_id, &changes)
                    .await?
            }
        };

        let simulation = GovRoleSimulation::execute(
            &self.pool,
            tenant_id,
            simulation_id,
            affected_users.clone(),
            access_gained,
            access_lost,
        )
        .await?
        .ok_or(GovernanceError::RoleSimulationNotDraft(simulation_id))?;

        tracing::info!(
            simulation_id = %simulation.id,
            tenant_id = %tenant_id,
            affected_users = affected_users.len(),
            "Executed role simulation"
        );

        Ok(simulation)
    }

    /// Calculate impact of adding an entitlement to a role.
    async fn calculate_add_entitlement_impact(
        &self,
        tenant_id: Uuid,
        role_id: Option<Uuid>,
        entitlement_id: Option<Uuid>,
    ) -> Result<(Vec<Uuid>, serde_json::Value, serde_json::Value)> {
        let role_id = role_id.ok_or_else(|| {
            GovernanceError::Validation("Role ID required for add entitlement".to_string())
        })?;
        let ent_id = entitlement_id.ok_or_else(|| {
            GovernanceError::Validation("Entitlement ID required for add entitlement".to_string())
        })?;

        // Get users who are members of this group/role
        let affected_users: Vec<Uuid> = sqlx::query_scalar(
            r"
            SELECT DISTINCT user_id
            FROM user_groups
            WHERE tenant_id = $1 AND group_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        // All affected users would gain the new entitlement
        let access_gained = serde_json::json!(affected_users
            .iter()
            .map(|uid| {
                serde_json::json!({
                    "user_id": uid,
                    "entitlement_id": ent_id
                })
            })
            .collect::<Vec<_>>());

        let access_lost = serde_json::json!([]);

        Ok((affected_users, access_gained, access_lost))
    }

    /// Calculate impact of removing an entitlement from a role.
    async fn calculate_remove_entitlement_impact(
        &self,
        tenant_id: Uuid,
        role_id: Option<Uuid>,
        entitlement_id: Option<Uuid>,
    ) -> Result<(Vec<Uuid>, serde_json::Value, serde_json::Value)> {
        let role_id = role_id.ok_or_else(|| {
            GovernanceError::Validation("Role ID required for remove entitlement".to_string())
        })?;
        let ent_id = entitlement_id.ok_or_else(|| {
            GovernanceError::Validation(
                "Entitlement ID required for remove entitlement".to_string(),
            )
        })?;

        // Get users who have this entitlement through the role
        let affected_users: Vec<Uuid> = sqlx::query_scalar(
            r"
            SELECT DISTINCT ug.user_id
            FROM user_groups ug
            INNER JOIN gov_entitlement_assignments ea ON ea.target_id = ug.group_id
                AND ea.target_type = 'group'
                AND ea.entitlement_id = $3
                AND ea.status = 'active'
            WHERE ug.tenant_id = $1 AND ug.group_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .bind(ent_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        let access_gained = serde_json::json!([]);
        let access_lost = serde_json::json!(affected_users
            .iter()
            .map(|uid| {
                serde_json::json!({
                    "user_id": uid,
                    "entitlement_id": ent_id
                })
            })
            .collect::<Vec<_>>());

        Ok((affected_users, access_gained, access_lost))
    }

    /// Calculate impact of adding a new role.
    async fn calculate_add_role_impact(
        &self,
        _tenant_id: Uuid,
        changes: &SimulationChanges,
    ) -> Result<(Vec<Uuid>, serde_json::Value, serde_json::Value)> {
        // New role has no members yet, so no impact
        // But we can show what users would gain if they join
        let affected_users: Vec<Uuid> = changes.user_ids.clone().unwrap_or_default();

        let entitlements = changes.entitlement_ids.clone().unwrap_or_default();
        let access_gained = serde_json::json!(affected_users
            .iter()
            .flat_map(|uid| {
                entitlements.iter().map(move |ent_id| {
                    serde_json::json!({
                        "user_id": uid,
                        "entitlement_id": ent_id
                    })
                })
            })
            .collect::<Vec<_>>());

        let access_lost = serde_json::json!([]);

        Ok((affected_users, access_gained, access_lost))
    }

    /// Calculate impact of removing a role.
    async fn calculate_remove_role_impact(
        &self,
        tenant_id: Uuid,
        role_id: Option<Uuid>,
    ) -> Result<(Vec<Uuid>, serde_json::Value, serde_json::Value)> {
        let role_id = role_id.ok_or_else(|| {
            GovernanceError::Validation("Role ID required for remove role".to_string())
        })?;

        // Get all users in this role
        let affected_users: Vec<Uuid> = sqlx::query_scalar(
            r"
            SELECT DISTINCT user_id
            FROM user_groups
            WHERE tenant_id = $1 AND group_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        // Get all entitlements assigned to this role
        let entitlement_ids: Vec<Uuid> = sqlx::query_scalar(
            r"
            SELECT DISTINCT entitlement_id
            FROM gov_entitlement_assignments
            WHERE tenant_id = $1 AND target_type = 'group' AND target_id = $2 AND status = 'active'
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        let access_gained = serde_json::json!([]);
        let access_lost = serde_json::json!(affected_users
            .iter()
            .flat_map(|uid| {
                entitlement_ids.iter().map(move |ent_id| {
                    serde_json::json!({
                        "user_id": uid,
                        "entitlement_id": ent_id
                    })
                })
            })
            .collect::<Vec<_>>());

        Ok((affected_users, access_gained, access_lost))
    }

    /// Calculate impact of modifying a role (change in entitlements).
    async fn calculate_modify_role_impact(
        &self,
        tenant_id: Uuid,
        role_id: Option<Uuid>,
        changes: &SimulationChanges,
    ) -> Result<(Vec<Uuid>, serde_json::Value, serde_json::Value)> {
        let role_id = role_id.ok_or_else(|| {
            GovernanceError::Validation("Role ID required for modify role".to_string())
        })?;

        // Get all users in this role
        let affected_users: Vec<Uuid> = sqlx::query_scalar(
            r"
            SELECT DISTINCT user_id
            FROM user_groups
            WHERE tenant_id = $1 AND group_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        // Build access gained/lost from changes
        // For modify_role scenario, entitlement_ids represents entitlements to add
        // A separate field or convention would be needed for removals
        let mut gained = Vec::new();
        let lost: Vec<serde_json::Value> = Vec::new();

        if let Some(ent_ids) = &changes.entitlement_ids {
            for ent_id in ent_ids {
                for uid in &affected_users {
                    gained.push(serde_json::json!({
                        "user_id": uid,
                        "entitlement_id": ent_id
                    }));
                }
            }
        }

        Ok((
            affected_users,
            serde_json::json!(gained),
            serde_json::json!(lost),
        ))
    }

    /// Apply a simulation (commit the changes).
    pub async fn apply_simulation(
        &self,
        tenant_id: Uuid,
        simulation_id: Uuid,
        applied_by: Uuid,
    ) -> Result<GovRoleSimulation> {
        let simulation = self.get(tenant_id, simulation_id).await?;

        if !simulation.status.can_apply() {
            return Err(GovernanceError::RoleSimulationNotExecuted(simulation_id));
        }

        let changes = simulation.parse_changes();
        let target_role_id = simulation.target_role_id.or(changes.role_id);

        // Apply changes based on scenario type
        match simulation.scenario_type {
            ScenarioType::AddEntitlement => {
                self.apply_add_entitlement(tenant_id, target_role_id, &changes, applied_by)
                    .await?;
            }
            ScenarioType::RemoveEntitlement => {
                self.apply_remove_entitlement(tenant_id, target_role_id, &changes)
                    .await?;
            }
            ScenarioType::AddRole => {
                self.apply_add_role(tenant_id, &changes, applied_by).await?;
            }
            ScenarioType::RemoveRole => {
                self.apply_remove_role(tenant_id, target_role_id).await?;
            }
            ScenarioType::ModifyRole => {
                self.apply_modify_role(tenant_id, target_role_id, &changes, applied_by)
                    .await?;
            }
        }

        let simulation = GovRoleSimulation::apply(&self.pool, tenant_id, simulation_id, applied_by)
            .await?
            .ok_or(GovernanceError::RoleSimulationNotExecuted(simulation_id))?;

        tracing::info!(
            simulation_id = %simulation.id,
            tenant_id = %tenant_id,
            applied_by = %applied_by,
            "Applied role simulation"
        );

        Ok(simulation)
    }

    /// Apply add entitlement change.
    async fn apply_add_entitlement(
        &self,
        tenant_id: Uuid,
        role_id: Option<Uuid>,
        changes: &SimulationChanges,
        assigned_by: Uuid,
    ) -> Result<()> {
        let role_id = role_id.ok_or_else(|| {
            GovernanceError::Validation("Role ID required for add entitlement".to_string())
        })?;
        let ent_id = changes.entitlement_id.ok_or_else(|| {
            GovernanceError::Validation("Entitlement ID required for add entitlement".to_string())
        })?;

        // Check if assignment already exists
        use xavyo_db::{CreateGovAssignment, GovAssignmentTargetType, GovEntitlementAssignment};

        let existing = GovEntitlementAssignment::find_by_target(
            &self.pool,
            tenant_id,
            ent_id,
            GovAssignmentTargetType::Group,
            role_id,
        )
        .await?;

        if existing.is_some() {
            tracing::info!(
                entitlement_id = %ent_id,
                role_id = %role_id,
                "Assignment already exists, skipping"
            );
            return Ok(());
        }

        let input = CreateGovAssignment {
            entitlement_id: ent_id,
            target_type: GovAssignmentTargetType::Group,
            target_id: role_id,
            assigned_by,
            expires_at: None,
            justification: Some("Applied from role simulation".to_string()),
            parameter_hash: None,
            valid_from: None,
            valid_to: None,
        };

        GovEntitlementAssignment::create(&self.pool, tenant_id, input).await?;

        tracing::info!(
            entitlement_id = %ent_id,
            role_id = %role_id,
            "Created entitlement assignment from simulation"
        );

        Ok(())
    }

    /// Apply remove entitlement change.
    async fn apply_remove_entitlement(
        &self,
        tenant_id: Uuid,
        role_id: Option<Uuid>,
        changes: &SimulationChanges,
    ) -> Result<()> {
        let role_id = role_id.ok_or_else(|| {
            GovernanceError::Validation("Role ID required for remove entitlement".to_string())
        })?;
        let ent_id = changes.entitlement_id.ok_or_else(|| {
            GovernanceError::Validation(
                "Entitlement ID required for remove entitlement".to_string(),
            )
        })?;

        use xavyo_db::{GovAssignmentTargetType, GovEntitlementAssignment};

        // Find and delete the assignment
        let existing = GovEntitlementAssignment::find_by_target(
            &self.pool,
            tenant_id,
            ent_id,
            GovAssignmentTargetType::Group,
            role_id,
        )
        .await?;

        if let Some(assignment) = existing {
            GovEntitlementAssignment::revoke(&self.pool, tenant_id, assignment.id).await?;

            tracing::info!(
                entitlement_id = %ent_id,
                role_id = %role_id,
                "Revoked entitlement assignment from simulation"
            );
        }

        Ok(())
    }

    /// Apply modify role changes.
    async fn apply_modify_role(
        &self,
        tenant_id: Uuid,
        role_id: Option<Uuid>,
        changes: &SimulationChanges,
        assigned_by: Uuid,
    ) -> Result<()> {
        // Add entitlements from entitlement_ids list
        if let Some(ent_ids) = &changes.entitlement_ids {
            for ent_id in ent_ids {
                let add_changes = SimulationChanges {
                    entitlement_id: Some(*ent_id),
                    ..Default::default()
                };
                self.apply_add_entitlement(tenant_id, role_id, &add_changes, assigned_by)
                    .await?;
            }
        }

        Ok(())
    }

    /// Apply add role - create a new group with specified entitlements.
    async fn apply_add_role(
        &self,
        tenant_id: Uuid,
        changes: &SimulationChanges,
        created_by: Uuid,
    ) -> Result<Uuid> {
        let role_name = changes.role_name.as_ref().ok_or_else(|| {
            GovernanceError::Validation("role_name is required for AddRole simulation".to_string())
        })?;

        // Check if group with this name already exists
        let existing: Option<Uuid> =
            sqlx::query_scalar(r"SELECT id FROM groups WHERE tenant_id = $1 AND name = $2")
                .bind(tenant_id)
                .bind(role_name)
                .fetch_optional(&self.pool)
                .await?;

        if existing.is_some() {
            return Err(GovernanceError::Validation(format!(
                "A group with name '{role_name}' already exists"
            )));
        }

        // Create the group
        let description = changes
            .role_description
            .clone()
            .unwrap_or_else(|| "Role created from simulation".to_string());

        let group_id: Uuid = sqlx::query_scalar(
            r"
            INSERT INTO groups (tenant_id, name, description, created_at, updated_at)
            VALUES ($1, $2, $3, NOW(), NOW())
            RETURNING id
            ",
        )
        .bind(tenant_id)
        .bind(role_name)
        .bind(&description)
        .fetch_one(&self.pool)
        .await?;

        // Assign entitlements to the new role if specified
        if let Some(ent_ids) = &changes.entitlement_ids {
            for ent_id in ent_ids {
                let add_changes = SimulationChanges {
                    entitlement_id: Some(*ent_id),
                    ..Default::default()
                };
                self.apply_add_entitlement(tenant_id, Some(group_id), &add_changes, created_by)
                    .await?;
            }
        }

        tracing::info!(
            tenant_id = %tenant_id,
            group_id = %group_id,
            role_name = %role_name,
            "Created role from simulation"
        );

        Ok(group_id)
    }

    /// Apply remove role - delete a group and its entitlement assignments.
    async fn apply_remove_role(&self, tenant_id: Uuid, role_id: Option<Uuid>) -> Result<()> {
        let role_id = role_id.ok_or_else(|| {
            GovernanceError::Validation(
                "target_role_id is required for RemoveRole simulation".to_string(),
            )
        })?;

        // Verify the group exists
        let exists: Option<Uuid> =
            sqlx::query_scalar(r"SELECT id FROM groups WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(role_id)
                .fetch_optional(&self.pool)
                .await?;

        if exists.is_none() {
            return Err(GovernanceError::Validation(format!(
                "Group {role_id} not found"
            )));
        }

        // Remove all entitlement assignments for this group
        sqlx::query(
            r"
            DELETE FROM gov_entitlement_assignments
            WHERE tenant_id = $1 AND target_type = 'group' AND target_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .execute(&self.pool)
        .await?;

        // Remove all user memberships from this group
        sqlx::query(
            r"
            DELETE FROM user_groups
            WHERE tenant_id = $1 AND group_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .execute(&self.pool)
        .await?;

        // Delete the group itself
        sqlx::query(
            r"
            DELETE FROM groups
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .execute(&self.pool)
        .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            role_id = %role_id,
            "Removed role from simulation"
        );

        Ok(())
    }

    /// Cancel a simulation.
    pub async fn cancel_simulation(
        &self,
        tenant_id: Uuid,
        simulation_id: Uuid,
    ) -> Result<GovRoleSimulation> {
        let simulation = self.get(tenant_id, simulation_id).await?;

        if !simulation.status.can_cancel() {
            return Err(GovernanceError::RoleSimulationAlreadyApplied(simulation_id));
        }

        let simulation = GovRoleSimulation::cancel(&self.pool, tenant_id, simulation_id)
            .await?
            .ok_or(GovernanceError::RoleSimulationNotFound(simulation_id))?;

        tracing::info!(
            simulation_id = %simulation.id,
            tenant_id = %tenant_id,
            "Cancelled role simulation"
        );

        Ok(simulation)
    }

    /// Delete a simulation (only draft or cancelled).
    pub async fn delete(&self, tenant_id: Uuid, simulation_id: Uuid) -> Result<()> {
        let deleted = GovRoleSimulation::delete(&self.pool, tenant_id, simulation_id).await?;

        if !deleted {
            return Err(GovernanceError::RoleSimulationNotFound(simulation_id));
        }

        tracing::info!(
            simulation_id = %simulation_id,
            tenant_id = %tenant_id,
            "Deleted role simulation"
        );

        Ok(())
    }
}

/// Validate changes for a given scenario type.
fn validate_changes(
    scenario_type: &ScenarioType,
    changes: &SimulationChanges,
    target_role_id: Option<Uuid>,
) -> Result<()> {
    match scenario_type {
        ScenarioType::AddEntitlement | ScenarioType::RemoveEntitlement => {
            if target_role_id.is_none() && changes.role_id.is_none() {
                return Err(GovernanceError::Validation(
                    "target_role_id or changes.role_id is required for entitlement changes"
                        .to_string(),
                ));
            }
            if changes.entitlement_id.is_none() {
                return Err(GovernanceError::Validation(
                    "changes.entitlement_id is required for entitlement changes".to_string(),
                ));
            }
        }
        ScenarioType::AddRole => {
            if changes.role_name.is_none() {
                return Err(GovernanceError::Validation(
                    "changes.role_name is required for add_role scenario".to_string(),
                ));
            }
        }
        ScenarioType::RemoveRole => {
            if target_role_id.is_none() && changes.role_id.is_none() {
                return Err(GovernanceError::Validation(
                    "target_role_id or changes.role_id is required for remove_role scenario"
                        .to_string(),
                ));
            }
        }
        ScenarioType::ModifyRole => {
            if target_role_id.is_none() && changes.role_id.is_none() {
                return Err(GovernanceError::Validation(
                    "target_role_id or changes.role_id is required for modify_role scenario"
                        .to_string(),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_changes_add_entitlement_valid() {
        let changes = SimulationChanges {
            role_id: Some(Uuid::new_v4()),
            entitlement_id: Some(Uuid::new_v4()),
            ..Default::default()
        };

        assert!(validate_changes(&ScenarioType::AddEntitlement, &changes, None).is_ok());
    }

    #[test]
    fn test_validate_changes_add_entitlement_missing_role() {
        let changes = SimulationChanges {
            entitlement_id: Some(Uuid::new_v4()),
            ..Default::default()
        };

        assert!(validate_changes(&ScenarioType::AddEntitlement, &changes, None).is_err());
    }

    #[test]
    fn test_validate_changes_add_entitlement_missing_entitlement() {
        let changes = SimulationChanges {
            role_id: Some(Uuid::new_v4()),
            ..Default::default()
        };

        assert!(validate_changes(&ScenarioType::AddEntitlement, &changes, None).is_err());
    }

    #[test]
    fn test_validate_changes_add_role_valid() {
        let changes = SimulationChanges {
            role_name: Some("New Role".to_string()),
            ..Default::default()
        };

        assert!(validate_changes(&ScenarioType::AddRole, &changes, None).is_ok());
    }

    #[test]
    fn test_validate_changes_add_role_missing_name() {
        let changes = SimulationChanges::default();

        assert!(validate_changes(&ScenarioType::AddRole, &changes, None).is_err());
    }
}
