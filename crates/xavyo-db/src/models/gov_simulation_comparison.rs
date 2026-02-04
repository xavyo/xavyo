//! Simulation Comparison model (F060).
//!
//! Represents comparison between two simulations or simulation vs. current state.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{ComparisonSummary, ComparisonType};

/// A comparison between simulations or simulation vs. current state.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovSimulationComparison {
    /// Unique identifier for the comparison.
    pub id: Uuid,

    /// The tenant this comparison belongs to.
    pub tenant_id: Uuid,

    /// Comparison name.
    pub name: String,

    /// Type of comparison.
    pub comparison_type: ComparisonType,

    /// First simulation ID.
    pub simulation_a_id: Option<Uuid>,

    /// Type of first simulation ("policy" or "batch").
    pub simulation_a_type: Option<String>,

    /// Second simulation ID (nullable for `vs_current`).
    pub simulation_b_id: Option<Uuid>,

    /// Type of second simulation.
    pub simulation_b_type: Option<String>,

    /// Summary statistics.
    pub summary_stats: serde_json::Value,

    /// Detailed delta results.
    pub delta_results: serde_json::Value,

    /// Whether the comparison is stale (underlying simulations changed).
    pub is_stale: bool,

    /// Who created the comparison.
    pub created_by: Uuid,

    /// When the comparison was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSimulationComparison {
    pub name: String,
    pub comparison_type: ComparisonType,
    pub simulation_a_id: Option<Uuid>,
    pub simulation_a_type: Option<String>,
    pub simulation_b_id: Option<Uuid>,
    pub simulation_b_type: Option<String>,
    pub created_by: Uuid,
}

/// Delta results structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeltaResults {
    /// Users added in comparison (only in A or B).
    pub added: Vec<DeltaEntry>,
    /// Users removed in comparison (only in other side).
    pub removed: Vec<DeltaEntry>,
    /// Users with different impacts.
    pub modified: Vec<ModifiedEntry>,
}

/// A delta entry for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeltaEntry {
    pub user_id: Uuid,
    pub impact: serde_json::Value,
}

/// A modified entry showing differences.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ModifiedEntry {
    pub user_id: Uuid,
    pub impact_a: serde_json::Value,
    pub impact_b: serde_json::Value,
    pub diff: serde_json::Value,
}

/// Filter options for listing comparisons.
#[derive(Debug, Clone, Default)]
pub struct SimulationComparisonFilter {
    pub comparison_type: Option<ComparisonType>,
    pub created_by: Option<Uuid>,
}

impl GovSimulationComparison {
    /// Find a comparison by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_simulation_comparisons
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List comparisons for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &SimulationComparisonFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_simulation_comparisons
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.comparison_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND comparison_type = ${param_count}"));
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

        let mut q = sqlx::query_as::<_, GovSimulationComparison>(&query).bind(tenant_id);

        if let Some(comparison_type) = filter.comparison_type {
            q = q.bind(comparison_type);
        }
        if let Some(created_by) = filter.created_by {
            q = q.bind(created_by);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count comparisons for a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &SimulationComparisonFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_simulation_comparisons
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.comparison_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND comparison_type = ${param_count}"));
        }
        if filter.created_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_by = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(comparison_type) = filter.comparison_type {
            q = q.bind(comparison_type);
        }
        if let Some(created_by) = filter.created_by {
            q = q.bind(created_by);
        }

        q.fetch_one(pool).await
    }

    /// Create a new comparison.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateSimulationComparison,
        summary_stats: ComparisonSummary,
        delta_results: DeltaResults,
    ) -> Result<Self, sqlx::Error> {
        let summary_json =
            serde_json::to_value(&summary_stats).unwrap_or_else(|_| serde_json::json!({}));
        let delta_json =
            serde_json::to_value(&delta_results).unwrap_or_else(|_| serde_json::json!({}));

        sqlx::query_as(
            r"
            INSERT INTO gov_simulation_comparisons (
                tenant_id, name, comparison_type, simulation_a_id, simulation_a_type,
                simulation_b_id, simulation_b_type, summary_stats, delta_results, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(input.comparison_type)
        .bind(input.simulation_a_id)
        .bind(&input.simulation_a_type)
        .bind(input.simulation_b_id)
        .bind(&input.simulation_b_type)
        .bind(&summary_json)
        .bind(&delta_json)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Mark comparison as stale.
    pub async fn mark_stale(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_simulation_comparisons
            SET is_stale = TRUE
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a comparison.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_simulation_comparisons
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Parse summary statistics.
    #[must_use] 
    pub fn parse_summary_stats(&self) -> ComparisonSummary {
        serde_json::from_value(self.summary_stats.clone()).unwrap_or_default()
    }

    /// Parse delta results.
    #[must_use] 
    pub fn parse_delta_results(&self) -> DeltaResults {
        serde_json::from_value(self.delta_results.clone()).unwrap_or_default()
    }

    /// Check if comparison references a specific simulation.
    #[must_use] 
    pub fn references_simulation(&self, simulation_id: Uuid) -> bool {
        self.simulation_a_id == Some(simulation_id) || self.simulation_b_id == Some(simulation_id)
    }

    /// Mark all comparisons referencing a simulation as stale.
    pub async fn mark_stale_by_simulation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        simulation_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_simulation_comparisons
            SET is_stale = TRUE
            WHERE tenant_id = $1
              AND (simulation_a_id = $2 OR simulation_b_id = $2)
              AND is_stale = FALSE
            ",
        )
        .bind(tenant_id)
        .bind(simulation_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comparison_filter_default() {
        let filter = SimulationComparisonFilter::default();
        assert!(filter.comparison_type.is_none());
        assert!(filter.created_by.is_none());
    }

    #[test]
    fn test_delta_results_serialization() {
        let delta = DeltaResults {
            added: vec![DeltaEntry {
                user_id: Uuid::new_v4(),
                impact: serde_json::json!({"type": "gain"}),
            }],
            removed: vec![],
            modified: vec![ModifiedEntry {
                user_id: Uuid::new_v4(),
                impact_a: serde_json::json!({"access": ["a"]}),
                impact_b: serde_json::json!({"access": ["a", "b"]}),
                diff: serde_json::json!({"added": ["b"]}),
            }],
        };

        let json = serde_json::to_string(&delta).unwrap();
        assert!(json.contains("added"));
        assert!(json.contains("modified"));
    }

    #[test]
    fn test_references_simulation() {
        let comparison = GovSimulationComparison {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            comparison_type: ComparisonType::SimulationVsSimulation,
            simulation_a_id: Some(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
            simulation_a_type: Some("policy".to_string()),
            simulation_b_id: Some(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()),
            simulation_b_type: Some("policy".to_string()),
            summary_stats: serde_json::json!({}),
            delta_results: serde_json::json!({}),
            is_stale: false,
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
        };

        assert!(comparison.references_simulation(
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
        ));
        assert!(comparison.references_simulation(
            Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()
        ));
        assert!(!comparison.references_simulation(
            Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()
        ));
    }

    #[test]
    fn test_parse_summary_stats() {
        let comparison = GovSimulationComparison {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            comparison_type: ComparisonType::SimulationVsSimulation,
            simulation_a_id: None,
            simulation_a_type: None,
            simulation_b_id: None,
            simulation_b_type: None,
            summary_stats: serde_json::json!({
                "users_in_both": 100,
                "users_only_in_a": 10,
                "users_only_in_b": 5,
                "different_impacts": 20,
                "total_additions": 15,
                "total_removals": 5
            }),
            delta_results: serde_json::json!({}),
            is_stale: false,
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
        };

        let stats = comparison.parse_summary_stats();
        assert_eq!(stats.users_in_both, 100);
        assert_eq!(stats.users_only_in_a, 10);
        assert_eq!(stats.total_additions, 15);
    }
}
