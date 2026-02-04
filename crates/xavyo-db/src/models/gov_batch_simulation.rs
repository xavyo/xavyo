//! Governance Batch Simulation model (F060).
//!
//! Represents simulation of access changes for multiple users at once.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    BatchImpactSummary, BatchSimulationType, ChangeSpec, FilterCriteria, SelectionMode,
    SimulationStatus,
};

/// A batch simulation for multi-user access changes.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovBatchSimulation {
    /// Unique identifier for the simulation.
    pub id: Uuid,

    /// The tenant this simulation belongs to.
    pub tenant_id: Uuid,

    /// Simulation name.
    pub name: String,

    /// Type of batch operation.
    pub batch_type: BatchSimulationType,

    /// How users are selected.
    pub selection_mode: SelectionMode,

    /// Explicit user IDs (for `user_list` mode).
    pub user_ids: Vec<Uuid>,

    /// Filter criteria (for filter mode).
    pub filter_criteria: serde_json::Value,

    /// What change to simulate.
    pub change_spec: serde_json::Value,

    /// Simulation status.
    pub status: SimulationStatus,

    /// Total users in selection.
    pub total_users: i32,

    /// Users processed so far.
    pub processed_users: i32,

    /// Impact summary statistics.
    pub impact_summary: serde_json::Value,

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

/// Request to create a batch simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBatchSimulation {
    pub name: String,
    pub batch_type: BatchSimulationType,
    pub selection_mode: SelectionMode,
    pub user_ids: Vec<Uuid>,
    pub filter_criteria: FilterCriteria,
    pub change_spec: ChangeSpec,
    pub created_by: Uuid,
}

/// Filter options for listing batch simulations.
#[derive(Debug, Clone, Default)]
pub struct BatchSimulationFilter {
    pub batch_type: Option<BatchSimulationType>,
    pub status: Option<SimulationStatus>,
    pub created_by: Option<Uuid>,
    pub include_archived: bool,
}

/// Scope warning threshold (number of affected users).
pub const SCOPE_WARNING_THRESHOLD: i32 = 100;

impl GovBatchSimulation {
    /// Find a simulation by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_batch_simulations
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
        filter: &BatchSimulationFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_batch_simulations
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if !filter.include_archived {
            query.push_str(" AND is_archived = FALSE");
        }

        if filter.batch_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND batch_type = ${param_count}"));
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

        let mut q = sqlx::query_as::<_, GovBatchSimulation>(&query).bind(tenant_id);

        if let Some(batch_type) = filter.batch_type {
            q = q.bind(batch_type);
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
        filter: &BatchSimulationFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_batch_simulations
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if !filter.include_archived {
            query.push_str(" AND is_archived = FALSE");
        }

        if filter.batch_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND batch_type = ${param_count}"));
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

        if let Some(batch_type) = filter.batch_type {
            q = q.bind(batch_type);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(created_by) = filter.created_by {
            q = q.bind(created_by);
        }

        q.fetch_one(pool).await
    }

    /// Create a new batch simulation.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateBatchSimulation,
    ) -> Result<Self, sqlx::Error> {
        let filter_criteria =
            serde_json::to_value(&input.filter_criteria).unwrap_or_else(|_| serde_json::json!({}));
        let change_spec =
            serde_json::to_value(&input.change_spec).unwrap_or_else(|_| serde_json::json!({}));

        sqlx::query_as(
            r"
            INSERT INTO gov_batch_simulations (
                tenant_id, name, batch_type, selection_mode, user_ids,
                filter_criteria, change_spec, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(input.batch_type)
        .bind(input.selection_mode)
        .bind(&input.user_ids)
        .bind(&filter_criteria)
        .bind(&change_spec)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Update progress during execution.
    pub async fn update_progress(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        total_users: i32,
        processed_users: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_batch_simulations
            SET total_users = $3, processed_users = $4
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(total_users)
        .bind(processed_users)
        .fetch_optional(pool)
        .await
    }

    /// Execute simulation (set impact results).
    pub async fn execute(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        total_users: i32,
        impact_summary: BatchImpactSummary,
    ) -> Result<Option<Self>, sqlx::Error> {
        let summary_json =
            serde_json::to_value(&impact_summary).unwrap_or_else(|_| serde_json::json!({}));

        sqlx::query_as(
            r"
            UPDATE gov_batch_simulations
            SET status = 'executed',
                total_users = $3,
                processed_users = $3,
                impact_summary = $4,
                executed_at = NOW(),
                data_snapshot_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'draft'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(total_users)
        .bind(&summary_json)
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
            UPDATE gov_batch_simulations
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
            UPDATE gov_batch_simulations
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
            UPDATE gov_batch_simulations
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
            UPDATE gov_batch_simulations
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
            UPDATE gov_batch_simulations
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
            DELETE FROM gov_batch_simulations
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

    /// Parse the filter criteria.
    #[must_use] 
    pub fn parse_filter_criteria(&self) -> FilterCriteria {
        serde_json::from_value(self.filter_criteria.clone()).unwrap_or_default()
    }

    /// Parse the change specification.
    #[must_use] 
    pub fn parse_change_spec(&self) -> Option<ChangeSpec> {
        serde_json::from_value(self.change_spec.clone()).ok()
    }

    /// Parse the impact summary.
    #[must_use] 
    pub fn parse_impact_summary(&self) -> BatchImpactSummary {
        serde_json::from_value(self.impact_summary.clone()).unwrap_or_default()
    }

    /// Check if the simulation exceeds the scope warning threshold.
    #[must_use] 
    pub fn has_scope_warning(&self) -> bool {
        self.parse_impact_summary().affected_users > i64::from(SCOPE_WARNING_THRESHOLD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_simulation_filter_default() {
        let filter = BatchSimulationFilter::default();
        assert!(filter.batch_type.is_none());
        assert!(filter.status.is_none());
        assert!(filter.created_by.is_none());
        assert!(!filter.include_archived);
    }

    #[test]
    fn test_scope_warning_threshold() {
        assert_eq!(SCOPE_WARNING_THRESHOLD, 100);
    }

    #[test]
    fn test_has_scope_warning() {
        let simulation = GovBatchSimulation {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            batch_type: BatchSimulationType::RoleAdd,
            selection_mode: SelectionMode::Filter,
            user_ids: vec![],
            filter_criteria: serde_json::json!({}),
            change_spec: serde_json::json!({}),
            status: SimulationStatus::Executed,
            total_users: 150,
            processed_users: 150,
            impact_summary: serde_json::json!({
                "total_users": 150,
                "affected_users": 150,
                "entitlements_gained": 300,
                "entitlements_lost": 0,
                "sod_violations_introduced": 2,
                "warnings": []
            }),
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

        assert!(simulation.has_scope_warning());
    }

    #[test]
    fn test_no_scope_warning() {
        let simulation = GovBatchSimulation {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            batch_type: BatchSimulationType::RoleAdd,
            selection_mode: SelectionMode::UserList,
            user_ids: vec![],
            filter_criteria: serde_json::json!({}),
            change_spec: serde_json::json!({}),
            status: SimulationStatus::Executed,
            total_users: 50,
            processed_users: 50,
            impact_summary: serde_json::json!({
                "total_users": 50,
                "affected_users": 50,
                "entitlements_gained": 100,
                "entitlements_lost": 0,
                "sod_violations_introduced": 0,
                "warnings": []
            }),
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

        assert!(!simulation.has_scope_warning());
    }
}
