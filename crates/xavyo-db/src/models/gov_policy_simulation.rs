//! Governance Policy Simulation model (F060).
//!
//! Represents what-if analysis for `SoD` rules and birthright policies.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{ImpactSummary, PolicySimulationType, SimulationStatus};

/// A policy simulation for what-if analysis.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovPolicySimulation {
    /// Unique identifier for the simulation.
    pub id: Uuid,

    /// The tenant this simulation belongs to.
    pub tenant_id: Uuid,

    /// Simulation name.
    pub name: String,

    /// Type of policy being simulated.
    pub simulation_type: PolicySimulationType,

    /// Reference to existing policy (optional).
    pub policy_id: Option<Uuid>,

    /// Draft policy configuration to simulate.
    pub policy_config: serde_json::Value,

    /// Simulation status.
    pub status: SimulationStatus,

    /// Users affected by this simulation.
    pub affected_users: Vec<Uuid>,

    /// Impact summary statistics.
    pub impact_summary: serde_json::Value,

    /// Detailed results (deprecated - use results table).
    pub detailed_results: serde_json::Value,

    /// Timestamp when input data was captured.
    pub data_snapshot_at: Option<DateTime<Utc>>,

    /// Whether the simulation is archived.
    pub is_archived: bool,

    /// Cannot delete before this timestamp.
    pub retain_until: Option<DateTime<Utc>>,

    /// Notes/comments on the simulation.
    pub notes: Option<String>,

    /// Who created the simulation.
    pub created_by: Uuid,

    /// When the simulation was created.
    pub created_at: DateTime<Utc>,

    /// When the simulation was executed.
    pub executed_at: Option<DateTime<Utc>>,

    /// When the simulation was applied.
    pub applied_at: Option<DateTime<Utc>>,

    /// Who applied the simulation.
    pub applied_by: Option<Uuid>,
}

/// Request to create a policy simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePolicySimulation {
    pub name: String,
    pub simulation_type: PolicySimulationType,
    pub policy_id: Option<Uuid>,
    pub policy_config: serde_json::Value,
    pub created_by: Uuid,
}

/// Filter options for listing policy simulations.
#[derive(Debug, Clone, Default)]
pub struct PolicySimulationFilter {
    pub simulation_type: Option<PolicySimulationType>,
    pub status: Option<SimulationStatus>,
    pub created_by: Option<Uuid>,
    pub include_archived: bool,
}

impl GovPolicySimulation {
    /// Find a simulation by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_policy_simulations
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
        filter: &PolicySimulationFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_policy_simulations
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if !filter.include_archived {
            query.push_str(" AND is_archived = FALSE");
        }

        if filter.simulation_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND simulation_type = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
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

        let mut q = sqlx::query_as::<_, GovPolicySimulation>(&query).bind(tenant_id);

        if let Some(simulation_type) = filter.simulation_type {
            q = q.bind(simulation_type);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
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
        filter: &PolicySimulationFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_policy_simulations
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if !filter.include_archived {
            query.push_str(" AND is_archived = FALSE");
        }

        if filter.simulation_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND simulation_type = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.created_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_by = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(simulation_type) = filter.simulation_type {
            q = q.bind(simulation_type);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(created_by) = filter.created_by {
            q = q.bind(created_by);
        }

        q.fetch_one(pool).await
    }

    /// Create a new policy simulation.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreatePolicySimulation,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_policy_simulations (
                tenant_id, name, simulation_type, policy_id, policy_config, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(input.simulation_type)
        .bind(input.policy_id)
        .bind(&input.policy_config)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Execute simulation (set impact results).
    pub async fn execute(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        affected_users: Vec<Uuid>,
        impact_summary: ImpactSummary,
    ) -> Result<Option<Self>, sqlx::Error> {
        let summary_json =
            serde_json::to_value(&impact_summary).unwrap_or_else(|_| serde_json::json!({}));

        sqlx::query_as(
            r"
            UPDATE gov_policy_simulations
            SET status = 'executed',
                affected_users = $3,
                impact_summary = $4,
                executed_at = NOW(),
                data_snapshot_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'draft'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&affected_users)
        .bind(&summary_json)
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
            UPDATE gov_policy_simulations
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

    /// Archive a simulation.
    pub async fn archive(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_policy_simulations
            SET is_archived = TRUE
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Restore an archived simulation.
    pub async fn restore(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_policy_simulations
            SET is_archived = FALSE
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Update notes on a simulation.
    pub async fn update_notes(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        notes: Option<String>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_policy_simulations
            SET notes = $3
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(notes)
        .fetch_optional(pool)
        .await
    }

    /// Delete a simulation (only draft, cancelled, or past retention).
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_policy_simulations
            WHERE id = $1 AND tenant_id = $2
              AND status IN ('draft', 'cancelled')
              AND (retain_until IS NULL OR retain_until < NOW())
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Parse the impact summary.
    #[must_use] 
    pub fn parse_impact_summary(&self) -> ImpactSummary {
        serde_json::from_value(self.impact_summary.clone()).unwrap_or_default()
    }

    /// Check if the simulation is stale (data changed since execution).
    pub async fn check_staleness(&self, pool: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
        if self.data_snapshot_at.is_none() {
            return Ok(false); // Not executed yet
        }

        let snapshot_at = self.data_snapshot_at.unwrap();

        // Check if relevant policies have been updated
        match self.simulation_type {
            PolicySimulationType::SodRule => {
                if let Some(policy_id) = self.policy_id {
                    let updated: Option<DateTime<Utc>> = sqlx::query_scalar(
                        r"
                        SELECT updated_at FROM gov_sod_rules
                        WHERE id = $1 AND updated_at > $2
                        ",
                    )
                    .bind(policy_id)
                    .bind(snapshot_at)
                    .fetch_optional(pool)
                    .await?;

                    return Ok(updated.is_some());
                }
            }
            PolicySimulationType::BirthrightPolicy => {
                if let Some(policy_id) = self.policy_id {
                    let updated: Option<DateTime<Utc>> = sqlx::query_scalar(
                        r"
                        SELECT updated_at FROM gov_birthright_policies
                        WHERE id = $1 AND updated_at > $2
                        ",
                    )
                    .bind(policy_id)
                    .bind(snapshot_at)
                    .fetch_optional(pool)
                    .await?;

                    return Ok(updated.is_some());
                }
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_simulation_filter_default() {
        let filter = PolicySimulationFilter::default();
        assert!(filter.simulation_type.is_none());
        assert!(filter.status.is_none());
        assert!(filter.created_by.is_none());
        assert!(!filter.include_archived);
    }

    #[test]
    fn test_create_policy_simulation_serialization() {
        let input = CreatePolicySimulation {
            name: "Test SoD Simulation".to_string(),
            simulation_type: PolicySimulationType::SodRule,
            policy_id: None,
            policy_config: serde_json::json!({
                "first_entitlement_id": "uuid1",
                "second_entitlement_id": "uuid2"
            }),
            created_by: Uuid::new_v4(),
        };

        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("Test SoD Simulation"));
        assert!(json.contains("sod_rule"));
    }

    #[test]
    fn test_parse_impact_summary() {
        let simulation = GovPolicySimulation {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            simulation_type: PolicySimulationType::SodRule,
            policy_id: None,
            policy_config: serde_json::json!({}),
            status: SimulationStatus::Executed,
            affected_users: vec![],
            impact_summary: serde_json::json!({
                "total_users_analyzed": 100,
                "affected_users": 5,
                "by_severity": {"critical": 2, "high": 3, "medium": 0, "low": 0},
                "by_impact_type": {"violation": 5, "entitlement_gain": 0, "entitlement_loss": 0, "no_change": 0, "warning": 0}
            }),
            detailed_results: serde_json::json!({}),
            data_snapshot_at: Some(Utc::now()),
            is_archived: false,
            retain_until: None,
            notes: None,
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
            executed_at: Some(Utc::now()),
            applied_at: None,
            applied_by: None,
        };

        let summary = simulation.parse_impact_summary();
        assert_eq!(summary.total_users_analyzed, 100);
        assert_eq!(summary.affected_users, 5);
        assert_eq!(summary.by_severity.critical, 2);
    }
}
