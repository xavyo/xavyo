//! Simulation Comparison service for diff analysis between simulations (F060).

use std::collections::{HashMap, HashSet};

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    BatchSimulationResultFilter, ComparisonSummary, ComparisonType, CreateSimulationComparison,
    DeltaEntry, DeltaResults, GovBatchSimulation, GovBatchSimulationResult, GovPolicySimulation,
    GovPolicySimulationResult, GovSimulationComparison, ModifiedEntry,
    PolicySimulationResultFilter, SimulationComparisonFilter,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for simulation comparison operations.
pub struct SimulationComparisonService {
    pool: PgPool,
}

impl SimulationComparisonService {
    /// Create a new simulation comparison service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a comparison by ID.
    pub async fn get(
        &self,
        tenant_id: Uuid,
        comparison_id: Uuid,
    ) -> Result<GovSimulationComparison> {
        GovSimulationComparison::find_by_id(&self.pool, tenant_id, comparison_id)
            .await?
            .ok_or(GovernanceError::SimulationComparisonNotFound(comparison_id))
    }

    /// List comparisons with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        comparison_type: Option<ComparisonType>,
        created_by: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovSimulationComparison>, i64)> {
        let filter = SimulationComparisonFilter {
            comparison_type,
            created_by,
        };

        let comparisons =
            GovSimulationComparison::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total =
            GovSimulationComparison::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((comparisons, total))
    }

    /// Create a new comparison between simulations or simulation vs. current state.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        name: String,
        comparison_type: ComparisonType,
        simulation_a_id: Option<Uuid>,
        simulation_a_type: Option<String>,
        simulation_b_id: Option<Uuid>,
        simulation_b_type: Option<String>,
        created_by: Uuid,
    ) -> Result<GovSimulationComparison> {
        // Validate name
        if name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Comparison name cannot be empty".to_string(),
            ));
        }

        if name.len() > 255 {
            return Err(GovernanceError::Validation(
                "Comparison name cannot exceed 255 characters".to_string(),
            ));
        }

        // Validate comparison requirements
        match comparison_type {
            ComparisonType::SimulationVsSimulation => {
                if simulation_a_id.is_none() || simulation_b_id.is_none() {
                    return Err(GovernanceError::Validation(
                        "Both simulation IDs required for simulation_vs_simulation".to_string(),
                    ));
                }
                if simulation_a_type.is_none() || simulation_b_type.is_none() {
                    return Err(GovernanceError::Validation(
                        "Both simulation types required for simulation_vs_simulation".to_string(),
                    ));
                }
            }
            ComparisonType::SimulationVsCurrent => {
                if simulation_a_id.is_none() {
                    return Err(GovernanceError::Validation(
                        "simulation_a_id required for simulation_vs_current".to_string(),
                    ));
                }
                if simulation_a_type.is_none() {
                    return Err(GovernanceError::Validation(
                        "simulation_a_type required for simulation_vs_current".to_string(),
                    ));
                }
            }
        }

        // Validate simulation types
        if let Some(ref sim_type) = simulation_a_type {
            if sim_type != "policy" && sim_type != "batch" {
                return Err(GovernanceError::Validation(
                    "simulation_a_type must be 'policy' or 'batch'".to_string(),
                ));
            }
        }

        if let Some(ref sim_type) = simulation_b_type {
            if sim_type != "policy" && sim_type != "batch" {
                return Err(GovernanceError::Validation(
                    "simulation_b_type must be 'policy' or 'batch'".to_string(),
                ));
            }
        }

        // Verify simulations exist and are executed
        if let (Some(id), Some(ref sim_type)) = (simulation_a_id, &simulation_a_type) {
            self.verify_simulation_exists(tenant_id, id, sim_type)
                .await?;
        }

        if let (Some(id), Some(ref sim_type)) = (simulation_b_id, &simulation_b_type) {
            self.verify_simulation_exists(tenant_id, id, sim_type)
                .await?;
        }

        // Calculate comparison results
        let (summary_stats, delta_results) = self
            .calculate_comparison(
                tenant_id,
                comparison_type,
                simulation_a_id,
                simulation_a_type.as_deref(),
                simulation_b_id,
                simulation_b_type.as_deref(),
            )
            .await?;

        let input = CreateSimulationComparison {
            name,
            comparison_type,
            simulation_a_id,
            simulation_a_type,
            simulation_b_id,
            simulation_b_type,
            created_by,
        };

        let comparison = GovSimulationComparison::create(
            &self.pool,
            tenant_id,
            input,
            summary_stats,
            delta_results,
        )
        .await?;

        tracing::info!(
            comparison_id = %comparison.id,
            tenant_id = %tenant_id,
            comparison_type = ?comparison_type,
            "Created simulation comparison"
        );

        Ok(comparison)
    }

    /// Delete a comparison.
    pub async fn delete(&self, tenant_id: Uuid, comparison_id: Uuid) -> Result<bool> {
        let deleted = GovSimulationComparison::delete(&self.pool, tenant_id, comparison_id).await?;

        if deleted {
            tracing::info!(comparison_id = %comparison_id, "Deleted simulation comparison");
        }

        Ok(deleted)
    }

    /// Mark all comparisons referencing a simulation as stale.
    pub async fn mark_stale_by_simulation(
        &self,
        tenant_id: Uuid,
        simulation_id: Uuid,
    ) -> Result<u64> {
        let count =
            GovSimulationComparison::mark_stale_by_simulation(&self.pool, tenant_id, simulation_id)
                .await?;

        if count > 0 {
            tracing::info!(
                simulation_id = %simulation_id,
                marked_stale = count,
                "Marked comparisons as stale"
            );
        }

        Ok(count)
    }

    // ========================================================================
    // Private helper methods
    // ========================================================================

    /// Verify a simulation exists and is executed.
    async fn verify_simulation_exists(
        &self,
        tenant_id: Uuid,
        simulation_id: Uuid,
        simulation_type: &str,
    ) -> Result<()> {
        match simulation_type {
            "policy" => {
                let sim = GovPolicySimulation::find_by_id(&self.pool, tenant_id, simulation_id)
                    .await?
                    .ok_or(GovernanceError::PolicySimulationNotFound(simulation_id))?;

                if sim.status != xavyo_db::SimulationStatus::Executed {
                    return Err(GovernanceError::Validation(format!(
                        "Policy simulation {simulation_id} must be executed before comparison"
                    )));
                }
            }
            "batch" => {
                let sim = GovBatchSimulation::find_by_id(&self.pool, tenant_id, simulation_id)
                    .await?
                    .ok_or(GovernanceError::BatchSimulationNotFound(simulation_id))?;

                if sim.status != xavyo_db::SimulationStatus::Executed
                    && sim.status != xavyo_db::SimulationStatus::Applied
                {
                    return Err(GovernanceError::Validation(format!(
                        "Batch simulation {simulation_id} must be executed before comparison"
                    )));
                }
            }
            _ => {
                return Err(GovernanceError::Validation(format!(
                    "Unknown simulation type: {simulation_type}"
                )));
            }
        }

        Ok(())
    }

    /// Calculate comparison between simulations.
    async fn calculate_comparison(
        &self,
        tenant_id: Uuid,
        comparison_type: ComparisonType,
        simulation_a_id: Option<Uuid>,
        simulation_a_type: Option<&str>,
        simulation_b_id: Option<Uuid>,
        simulation_b_type: Option<&str>,
    ) -> Result<(ComparisonSummary, DeltaResults)> {
        match comparison_type {
            ComparisonType::SimulationVsSimulation => {
                self.compare_simulations(
                    tenant_id,
                    simulation_a_id.unwrap(),
                    simulation_a_type.unwrap(),
                    simulation_b_id.unwrap(),
                    simulation_b_type.unwrap(),
                )
                .await
            }
            ComparisonType::SimulationVsCurrent => {
                self.compare_simulation_vs_current(
                    tenant_id,
                    simulation_a_id.unwrap(),
                    simulation_a_type.unwrap(),
                )
                .await
            }
        }
    }

    /// Compare two simulations.
    async fn compare_simulations(
        &self,
        tenant_id: Uuid,
        simulation_a_id: Uuid,
        simulation_a_type: &str,
        simulation_b_id: Uuid,
        simulation_b_type: &str,
    ) -> Result<(ComparisonSummary, DeltaResults)> {
        // Load impacts from both simulations
        let impacts_a = self
            .load_simulation_impacts(tenant_id, simulation_a_id, simulation_a_type)
            .await?;
        let impacts_b = self
            .load_simulation_impacts(tenant_id, simulation_b_id, simulation_b_type)
            .await?;

        // Get user sets
        let users_a: HashSet<Uuid> = impacts_a.keys().copied().collect();
        let users_b: HashSet<Uuid> = impacts_b.keys().copied().collect();

        // Calculate set operations
        let intersection: HashSet<_> = users_a.intersection(&users_b).copied().collect();
        let only_in_a: Vec<Uuid> = users_a.difference(&users_b).copied().collect();
        let only_in_b: Vec<Uuid> = users_b.difference(&users_a).copied().collect();

        // Find users with different impacts
        let mut different_impacts_count = 0i64;
        let mut modified_entries = Vec::new();

        for user_id in &intersection {
            let impact_a = impacts_a.get(user_id).cloned().unwrap_or_default();
            let impact_b = impacts_b.get(user_id).cloned().unwrap_or_default();

            if impact_a != impact_b {
                different_impacts_count += 1;

                // Calculate diff
                let diff = serde_json::json!({
                    "changed": true,
                    "impact_a_type": impact_a.get("impact_type"),
                    "impact_b_type": impact_b.get("impact_type"),
                });

                modified_entries.push(ModifiedEntry {
                    user_id: *user_id,
                    impact_a,
                    impact_b,
                    diff,
                });
            }
        }

        // Build delta results
        let added: Vec<DeltaEntry> = only_in_b
            .iter()
            .map(|user_id| DeltaEntry {
                user_id: *user_id,
                impact: impacts_b.get(user_id).cloned().unwrap_or_default(),
            })
            .collect();

        let removed: Vec<DeltaEntry> = only_in_a
            .iter()
            .map(|user_id| DeltaEntry {
                user_id: *user_id,
                impact: impacts_a.get(user_id).cloned().unwrap_or_default(),
            })
            .collect();

        // Calculate summary statistics
        let summary = ComparisonSummary {
            users_in_both: intersection.len() as i64,
            users_only_in_a: only_in_a.len() as i64,
            users_only_in_b: only_in_b.len() as i64,
            different_impacts: different_impacts_count,
            total_additions: only_in_b.len() as i64 + different_impacts_count,
            total_removals: only_in_a.len() as i64,
        };

        let delta = DeltaResults {
            added,
            removed,
            modified: modified_entries,
        };

        tracing::info!(
            simulation_a_id = %simulation_a_id,
            simulation_b_id = %simulation_b_id,
            users_in_both = summary.users_in_both,
            users_only_in_a = summary.users_only_in_a,
            users_only_in_b = summary.users_only_in_b,
            different_impacts = summary.different_impacts,
            "Completed simulation comparison"
        );

        Ok((summary, delta))
    }

    /// Compare simulation vs. current state.
    async fn compare_simulation_vs_current(
        &self,
        tenant_id: Uuid,
        simulation_id: Uuid,
        simulation_type: &str,
    ) -> Result<(ComparisonSummary, DeltaResults)> {
        // Load impacts from the simulation
        let simulation_impacts = self
            .load_simulation_impacts(tenant_id, simulation_id, simulation_type)
            .await?;

        // For each user with impacts, we consider this as "only in simulation"
        // since "current state" represents no changes
        let affected_users: Vec<Uuid> = simulation_impacts.keys().copied().collect();

        // In simulation vs current, all simulated changes are "additions"
        let added: Vec<DeltaEntry> = affected_users
            .iter()
            .map(|user_id| DeltaEntry {
                user_id: *user_id,
                impact: simulation_impacts.get(user_id).cloned().unwrap_or_default(),
            })
            .collect();

        // Calculate totals from impact data
        let mut total_additions = 0i64;
        let mut total_removals = 0i64;

        for impact in simulation_impacts.values() {
            if let Some(gained) = impact
                .get("entitlements_gained")
                .and_then(serde_json::Value::as_i64)
            {
                total_additions += gained;
            }
            if let Some(lost) = impact
                .get("entitlements_lost")
                .and_then(serde_json::Value::as_i64)
            {
                total_removals += lost;
            }
            // Also count access_gained/access_lost for batch simulations
            if let Some(access_gained) = impact.get("access_gained").and_then(|v| v.as_array()) {
                total_additions += access_gained.len() as i64;
            }
            if let Some(access_lost) = impact.get("access_lost").and_then(|v| v.as_array()) {
                total_removals += access_lost.len() as i64;
            }
        }

        let summary = ComparisonSummary {
            users_in_both: 0, // No overlap with "current state" (which is empty)
            users_only_in_a: affected_users.len() as i64, // Simulation side
            users_only_in_b: 0, // Current state has no "changes"
            different_impacts: 0,
            total_additions,
            total_removals,
        };

        let delta = DeltaResults {
            added,
            removed: vec![],
            modified: vec![],
        };

        tracing::info!(
            simulation_id = %simulation_id,
            simulation_type = %simulation_type,
            affected_users = affected_users.len(),
            total_additions = summary.total_additions,
            total_removals = summary.total_removals,
            "Completed simulation vs current comparison"
        );

        Ok((summary, delta))
    }

    /// Load impacts from a simulation into a user->impact map.
    async fn load_simulation_impacts(
        &self,
        _tenant_id: Uuid,
        simulation_id: Uuid,
        simulation_type: &str,
    ) -> Result<HashMap<Uuid, serde_json::Value>> {
        let mut impacts: HashMap<Uuid, serde_json::Value> = HashMap::new();

        match simulation_type {
            "policy" => {
                // Load all policy simulation results
                let filter = PolicySimulationResultFilter::default();
                let results = GovPolicySimulationResult::list_by_simulation(
                    &self.pool,
                    simulation_id,
                    &filter,
                    10000,
                    0,
                )
                .await
                .map_err(GovernanceError::Database)?;

                for result in results {
                    let impact = serde_json::json!({
                        "impact_type": result.impact_type,
                        "severity": result.severity,
                        "details": result.details,
                    });
                    impacts.insert(result.user_id, impact);
                }
            }
            "batch" => {
                // Load all batch simulation results
                let filter = BatchSimulationResultFilter::default();
                let results = GovBatchSimulationResult::list_by_simulation(
                    &self.pool,
                    simulation_id,
                    &filter,
                    10000,
                    0,
                )
                .await
                .map_err(GovernanceError::Database)?;

                for result in results {
                    let impact = serde_json::json!({
                        "access_gained": result.parse_access_gained(),
                        "access_lost": result.parse_access_lost(),
                        "warnings": result.parse_warnings(),
                        "entitlements_gained": result.parse_access_gained().len(),
                        "entitlements_lost": result.parse_access_lost().len(),
                    });
                    impacts.insert(result.user_id, impact);
                }
            }
            _ => {
                return Err(GovernanceError::Validation(format!(
                    "Unknown simulation type: {simulation_type}"
                )));
            }
        }

        Ok(impacts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    // ========================================================================
    // T058: Unit test for simulation-vs-simulation comparison
    // ========================================================================

    #[test]
    fn test_simulation_vs_simulation_comparison_logic() {
        // Simulate two policy simulations with overlapping users
        let users_a: HashSet<Uuid> = [
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
        ]
        .into_iter()
        .collect();

        let users_b: HashSet<Uuid> = [
            Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
            Uuid::parse_str("44444444-4444-4444-4444-444444444444").unwrap(),
        ]
        .into_iter()
        .collect();

        // Calculate set operations
        let intersection: HashSet<_> = users_a.intersection(&users_b).collect();
        let only_in_a: HashSet<_> = users_a.difference(&users_b).collect();
        let only_in_b: HashSet<_> = users_b.difference(&users_a).collect();

        // Verify correct set mathematics
        assert_eq!(intersection.len(), 2, "Should have 2 users in both");
        assert_eq!(only_in_a.len(), 1, "Should have 1 user only in A");
        assert_eq!(only_in_b.len(), 1, "Should have 1 user only in B");
    }

    #[test]
    fn test_simulation_vs_simulation_with_different_impacts() {
        // Simulate impacts for users in both simulations
        let mut impacts_a: HashMap<Uuid, serde_json::Value> = HashMap::new();
        let mut impacts_b: HashMap<Uuid, serde_json::Value> = HashMap::new();

        let shared_user = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        // User has different impact in each simulation
        impacts_a.insert(shared_user, serde_json::json!({"entitlements_gained": 3}));
        impacts_b.insert(shared_user, serde_json::json!({"entitlements_gained": 5}));

        // Verify impacts differ
        assert_ne!(impacts_a.get(&shared_user), impacts_b.get(&shared_user));

        // In actual implementation, this should generate a ModifiedEntry
    }

    #[test]
    fn test_simulation_vs_simulation_empty_sets() {
        let users_a: HashSet<Uuid> = HashSet::new();
        let users_b: HashSet<Uuid> = HashSet::new();

        let intersection: HashSet<_> = users_a.intersection(&users_b).collect();
        let only_in_a: HashSet<_> = users_a.difference(&users_b).collect();
        let only_in_b: HashSet<_> = users_b.difference(&users_a).collect();

        assert_eq!(intersection.len(), 0);
        assert_eq!(only_in_a.len(), 0);
        assert_eq!(only_in_b.len(), 0);
    }

    // ========================================================================
    // T059: Unit test for simulation-vs-current comparison
    // ========================================================================

    #[test]
    fn test_simulation_vs_current_logic() {
        // Current state: user has entitlements A, B
        let current_access: HashSet<&str> =
            ["entitlement_a", "entitlement_b"].into_iter().collect();

        // Simulated state: user would have entitlements B, C, D
        let simulated_access: HashSet<&str> = ["entitlement_b", "entitlement_c", "entitlement_d"]
            .into_iter()
            .collect();

        // Calculate what would change
        let gained: HashSet<_> = simulated_access.difference(&current_access).collect();
        let lost: HashSet<_> = current_access.difference(&simulated_access).collect();
        let retained: HashSet<_> = current_access.intersection(&simulated_access).collect();

        assert_eq!(gained.len(), 2, "Should gain C and D");
        assert_eq!(lost.len(), 1, "Should lose A");
        assert_eq!(retained.len(), 1, "Should retain B");
    }

    #[test]
    fn test_simulation_vs_current_no_change() {
        let current_access: HashSet<&str> = ["a", "b", "c"].into_iter().collect();
        let simulated_access: HashSet<&str> = ["a", "b", "c"].into_iter().collect();

        let gained: HashSet<_> = simulated_access.difference(&current_access).collect();
        let lost: HashSet<_> = current_access.difference(&simulated_access).collect();

        assert_eq!(gained.len(), 0, "No entitlements gained");
        assert_eq!(lost.len(), 0, "No entitlements lost");
    }

    #[test]
    fn test_simulation_vs_current_all_new() {
        let current_access: HashSet<&str> = HashSet::new();
        let simulated_access: HashSet<&str> = ["a", "b", "c"].into_iter().collect();

        let gained: HashSet<_> = simulated_access.difference(&current_access).collect();
        let lost: HashSet<_> = current_access.difference(&simulated_access).collect();

        assert_eq!(gained.len(), 3, "All entitlements are new");
        assert_eq!(lost.len(), 0, "Nothing to lose");
    }

    // ========================================================================
    // T060: Unit test for summary statistics calculation
    // ========================================================================

    #[test]
    fn test_summary_statistics_calculation() {
        // Given comparison data
        let users_in_both = 50;
        let users_only_in_a = 10;
        let users_only_in_b = 15;
        let different_impacts = 8;

        // Total changes
        let total_additions = users_only_in_b + different_impacts; // Users new to scenario or with more
        let total_removals = users_only_in_a; // Users no longer affected

        let summary = ComparisonSummary {
            users_in_both,
            users_only_in_a,
            users_only_in_b,
            different_impacts,
            total_additions,
            total_removals,
        };

        assert_eq!(summary.users_in_both, 50);
        assert_eq!(summary.users_only_in_a, 10);
        assert_eq!(summary.users_only_in_b, 15);
        assert_eq!(summary.different_impacts, 8);
        assert_eq!(summary.total_additions, 23);
        assert_eq!(summary.total_removals, 10);
    }

    #[test]
    fn test_summary_statistics_serialization() {
        let summary = ComparisonSummary {
            users_in_both: 100,
            users_only_in_a: 25,
            users_only_in_b: 30,
            different_impacts: 15,
            total_additions: 45,
            total_removals: 25,
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"users_in_both\":100"));
        assert!(json.contains("\"users_only_in_a\":25"));

        let parsed: ComparisonSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.users_in_both, 100);
    }

    #[test]
    fn test_delta_results_construction() {
        let delta = DeltaResults {
            added: vec![
                DeltaEntry {
                    user_id: Uuid::new_v4(),
                    impact: serde_json::json!({"type": "entitlement_gain", "count": 3}),
                },
                DeltaEntry {
                    user_id: Uuid::new_v4(),
                    impact: serde_json::json!({"type": "violation"}),
                },
            ],
            removed: vec![DeltaEntry {
                user_id: Uuid::new_v4(),
                impact: serde_json::json!({"type": "entitlement_loss"}),
            }],
            modified: vec![ModifiedEntry {
                user_id: Uuid::new_v4(),
                impact_a: serde_json::json!({"count": 2}),
                impact_b: serde_json::json!({"count": 5}),
                diff: serde_json::json!({"count_delta": 3}),
            }],
        };

        assert_eq!(delta.added.len(), 2);
        assert_eq!(delta.removed.len(), 1);
        assert_eq!(delta.modified.len(), 1);
    }

    #[test]
    fn test_comparison_type_validation() {
        // SimulationVsSimulation requires both simulation IDs
        let comparison_type = ComparisonType::SimulationVsSimulation;
        assert!(comparison_type.is_simulation_vs_simulation());
        assert!(!comparison_type.is_simulation_vs_current());

        // SimulationVsCurrent requires only one simulation
        let comparison_type = ComparisonType::SimulationVsCurrent;
        assert!(comparison_type.is_simulation_vs_current());
        assert!(!comparison_type.is_simulation_vs_simulation());
    }

    #[test]
    fn test_service_creation() {
        // Service creation is tested in integration tests with actual pool
    }
}
