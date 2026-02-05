//! Governance Role Simulation model.
//!
//! Represents what-if simulation scenarios for role changes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Type of simulation scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "scenario_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ScenarioType {
    /// Add an entitlement to a role.
    AddEntitlement,
    /// Remove an entitlement from a role.
    RemoveEntitlement,
    /// Add a new role.
    AddRole,
    /// Remove an existing role.
    RemoveRole,
    /// Modify role membership or entitlements.
    ModifyRole,
}

/// Status for a simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "simulation_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SimulationStatus {
    /// Simulation is in draft (not executed yet).
    Draft,
    /// Simulation was executed (impact calculated).
    Executed,
    /// Simulation changes were applied.
    Applied,
    /// Simulation was cancelled.
    Cancelled,
}

impl SimulationStatus {
    /// Check if simulation can be executed.
    #[must_use]
    pub fn can_execute(&self) -> bool {
        matches!(self, Self::Draft)
    }

    /// Check if simulation can be applied.
    #[must_use]
    pub fn can_apply(&self) -> bool {
        matches!(self, Self::Executed)
    }

    /// Check if simulation can be cancelled.
    #[must_use]
    pub fn can_cancel(&self) -> bool {
        matches!(self, Self::Draft | Self::Executed)
    }
}

/// Details of access changes for affected users.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AccessChange {
    /// Entitlement ID affected.
    pub entitlement_id: Option<Uuid>,
    /// Role ID affected.
    pub role_id: Option<Uuid>,
    /// Number of users affected.
    pub user_count: i32,
    /// Description of the change.
    pub description: Option<String>,
}

/// Simulation changes specification.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SimulationChanges {
    /// Type of change.
    #[serde(rename = "type")]
    pub change_type: Option<String>,
    /// Role being modified.
    pub role_id: Option<Uuid>,
    /// Entitlement being added/removed.
    pub entitlement_id: Option<Uuid>,
    /// Entitlements for new role.
    pub entitlement_ids: Option<Vec<Uuid>>,
    /// Users to assign to new role.
    pub user_ids: Option<Vec<Uuid>>,
    /// New role name (for `add_role`).
    pub role_name: Option<String>,
    /// New role description (for `add_role`).
    pub role_description: Option<String>,
}

/// A role change simulation.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovRoleSimulation {
    /// Unique identifier for the simulation.
    pub id: Uuid,

    /// The tenant this simulation belongs to.
    pub tenant_id: Uuid,

    /// Simulation name.
    pub name: String,

    /// Type of scenario.
    pub scenario_type: ScenarioType,

    /// Target role (if applicable).
    pub target_role_id: Option<Uuid>,

    /// Change specification.
    pub changes: serde_json::Value,

    /// Users affected by this change.
    pub affected_users: Vec<Uuid>,

    /// Access that would be gained.
    pub access_gained: serde_json::Value,

    /// Access that would be lost.
    pub access_lost: serde_json::Value,

    /// Simulation status.
    pub status: SimulationStatus,

    /// When the simulation was applied.
    pub applied_at: Option<DateTime<Utc>>,

    /// Who applied the simulation.
    pub applied_by: Option<Uuid>,

    /// Who created the simulation.
    pub created_by: Uuid,

    /// When the simulation was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRoleSimulation {
    pub name: String,
    pub scenario_type: ScenarioType,
    pub target_role_id: Option<Uuid>,
    pub changes: SimulationChanges,
    pub created_by: Uuid,
}

/// Filter options for listing simulations.
#[derive(Debug, Clone, Default)]
pub struct RoleSimulationFilter {
    pub scenario_type: Option<ScenarioType>,
    pub status: Option<SimulationStatus>,
    pub target_role_id: Option<Uuid>,
    pub created_by: Option<Uuid>,
}

impl GovRoleSimulation {
    /// Find a simulation by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_role_simulations
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List simulations for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &RoleSimulationFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_role_simulations
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.scenario_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND scenario_type = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.target_role_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND target_role_id = ${param_count}"));
        }
        if filter.created_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_by = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovRoleSimulation>(&query).bind(tenant_id);

        if let Some(scenario_type) = filter.scenario_type {
            q = q.bind(scenario_type);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(target_role_id) = filter.target_role_id {
            q = q.bind(target_role_id);
        }
        if let Some(created_by) = filter.created_by {
            q = q.bind(created_by);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count simulations for a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &RoleSimulationFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_role_simulations
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.scenario_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND scenario_type = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.target_role_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND target_role_id = ${param_count}"));
        }
        if filter.created_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_by = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(scenario_type) = filter.scenario_type {
            q = q.bind(scenario_type);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(target_role_id) = filter.target_role_id {
            q = q.bind(target_role_id);
        }
        if let Some(created_by) = filter.created_by {
            q = q.bind(created_by);
        }

        q.fetch_one(pool).await
    }

    /// Create a new simulation.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateRoleSimulation,
    ) -> Result<Self, sqlx::Error> {
        let changes =
            serde_json::to_value(&input.changes).unwrap_or_else(|_| serde_json::json!({}));

        sqlx::query_as(
            r"
            INSERT INTO gov_role_simulations (
                tenant_id, name, scenario_type, target_role_id, changes, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(input.scenario_type)
        .bind(input.target_role_id)
        .bind(&changes)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Execute simulation (calculate impact).
    pub async fn execute(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        affected_users: Vec<Uuid>,
        access_gained: serde_json::Value,
        access_lost: serde_json::Value,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_role_simulations
            SET status = 'executed', affected_users = $3,
                access_gained = $4, access_lost = $5
            WHERE id = $1 AND tenant_id = $2 AND status = 'draft'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&affected_users)
        .bind(&access_gained)
        .bind(&access_lost)
        .fetch_optional(pool)
        .await
    }

    /// Apply simulation (commit changes).
    pub async fn apply(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        applied_by: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_role_simulations
            SET status = 'applied', applied_at = NOW(), applied_by = $3
            WHERE id = $1 AND tenant_id = $2 AND status = 'executed'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(applied_by)
        .fetch_optional(pool)
        .await
    }

    /// Cancel a simulation.
    pub async fn cancel(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_role_simulations
            SET status = 'cancelled'
            WHERE id = $1 AND tenant_id = $2 AND status IN ('draft', 'executed')
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a simulation (only draft or cancelled).
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_role_simulations
            WHERE id = $1 AND tenant_id = $2 AND status IN ('draft', 'cancelled')
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Parse the simulation changes.
    #[must_use]
    pub fn parse_changes(&self) -> SimulationChanges {
        serde_json::from_value(self.changes.clone()).unwrap_or_default()
    }

    /// Parse access gained.
    #[must_use]
    pub fn parse_access_gained(&self) -> Vec<AccessChange> {
        serde_json::from_value(self.access_gained.clone()).unwrap_or_default()
    }

    /// Parse access lost.
    #[must_use]
    pub fn parse_access_lost(&self) -> Vec<AccessChange> {
        serde_json::from_value(self.access_lost.clone()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulation_status_methods() {
        assert!(SimulationStatus::Draft.can_execute());
        assert!(!SimulationStatus::Executed.can_execute());

        assert!(!SimulationStatus::Draft.can_apply());
        assert!(SimulationStatus::Executed.can_apply());
        assert!(!SimulationStatus::Applied.can_apply());

        assert!(SimulationStatus::Draft.can_cancel());
        assert!(SimulationStatus::Executed.can_cancel());
        assert!(!SimulationStatus::Applied.can_cancel());
        assert!(!SimulationStatus::Cancelled.can_cancel());
    }

    #[test]
    fn test_scenario_type_serialization() {
        let add_ent = ScenarioType::AddEntitlement;
        let json = serde_json::to_string(&add_ent).unwrap();
        assert_eq!(json, "\"add_entitlement\"");

        let remove_ent = ScenarioType::RemoveEntitlement;
        let json = serde_json::to_string(&remove_ent).unwrap();
        assert_eq!(json, "\"remove_entitlement\"");

        let add_role = ScenarioType::AddRole;
        let json = serde_json::to_string(&add_role).unwrap();
        assert_eq!(json, "\"add_role\"");
    }

    #[test]
    fn test_simulation_status_serialization() {
        let draft = SimulationStatus::Draft;
        let json = serde_json::to_string(&draft).unwrap();
        assert_eq!(json, "\"draft\"");

        let executed = SimulationStatus::Executed;
        let json = serde_json::to_string(&executed).unwrap();
        assert_eq!(json, "\"executed\"");

        let applied = SimulationStatus::Applied;
        let json = serde_json::to_string(&applied).unwrap();
        assert_eq!(json, "\"applied\"");
    }

    #[test]
    fn test_simulation_changes_parsing() {
        let json = serde_json::json!({
            "type": "add_entitlement",
            "role_id": "00000000-0000-0000-0000-000000000001",
            "entitlement_id": "00000000-0000-0000-0000-000000000002"
        });

        let changes: SimulationChanges = serde_json::from_value(json).unwrap();
        assert_eq!(changes.change_type, Some("add_entitlement".to_string()));
        assert!(changes.role_id.is_some());
        assert!(changes.entitlement_id.is_some());
    }
}
