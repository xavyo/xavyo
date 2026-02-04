//! Batch Simulation Result model (F060).
//!
//! Stores per-user impact details for batch simulations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Per-user result for a batch simulation.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovBatchSimulationResult {
    /// Unique identifier for this result.
    pub id: Uuid,

    /// Reference to the parent simulation.
    pub simulation_id: Uuid,

    /// The affected user.
    pub user_id: Uuid,

    /// Access that would be gained.
    pub access_gained: serde_json::Value,

    /// Access that would be lost.
    pub access_lost: serde_json::Value,

    /// Warning messages.
    pub warnings: serde_json::Value,

    /// When this result was created.
    pub created_at: DateTime<Utc>,
}

/// Input for creating a batch simulation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBatchSimulationResult {
    pub simulation_id: Uuid,
    pub user_id: Uuid,
    pub access_gained: Vec<AccessItem>,
    pub access_lost: Vec<AccessItem>,
    pub warnings: Vec<String>,
}

/// An access item (entitlement or role) gained or lost.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AccessItem {
    /// Item ID.
    pub id: Uuid,
    /// Item name.
    pub name: String,
    /// Item type ("entitlement" or "role").
    pub item_type: String,
    /// How the access is gained/lost (e.g., "via role assignment").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Filter options for listing results.
#[derive(Debug, Clone, Default)]
pub struct BatchSimulationResultFilter {
    pub user_id: Option<Uuid>,
    pub has_warnings: Option<bool>,
}

impl GovBatchSimulationResult {
    /// Create a new batch simulation result.
    pub async fn create(
        pool: &sqlx::PgPool,
        input: CreateBatchSimulationResult,
    ) -> Result<Self, sqlx::Error> {
        let access_gained =
            serde_json::to_value(&input.access_gained).unwrap_or_else(|_| serde_json::json!([]));
        let access_lost =
            serde_json::to_value(&input.access_lost).unwrap_or_else(|_| serde_json::json!([]));
        let warnings =
            serde_json::to_value(&input.warnings).unwrap_or_else(|_| serde_json::json!([]));

        sqlx::query_as(
            r"
            INSERT INTO gov_batch_simulation_results (
                simulation_id, user_id, access_gained, access_lost, warnings
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(input.simulation_id)
        .bind(input.user_id)
        .bind(&access_gained)
        .bind(&access_lost)
        .bind(&warnings)
        .fetch_one(pool)
        .await
    }

    /// Bulk insert results (more efficient for large batches).
    pub async fn bulk_create(
        pool: &sqlx::PgPool,
        results: &[CreateBatchSimulationResult],
    ) -> Result<u64, sqlx::Error> {
        if results.is_empty() {
            return Ok(0);
        }

        // Build bulk insert query
        let mut query = String::from(
            "INSERT INTO gov_batch_simulation_results (simulation_id, user_id, access_gained, access_lost, warnings) VALUES ",
        );

        let mut values = Vec::new();
        for (i, _result) in results.iter().enumerate() {
            let offset = i * 5;
            values.push(format!(
                "(${}, ${}, ${}, ${}, ${})",
                offset + 1,
                offset + 2,
                offset + 3,
                offset + 4,
                offset + 5
            ));
        }
        query.push_str(&values.join(", "));

        let mut q = sqlx::query(&query);
        for result in results {
            let access_gained = serde_json::to_value(&result.access_gained)
                .unwrap_or_else(|_| serde_json::json!([]));
            let access_lost =
                serde_json::to_value(&result.access_lost).unwrap_or_else(|_| serde_json::json!([]));
            let warnings =
                serde_json::to_value(&result.warnings).unwrap_or_else(|_| serde_json::json!([]));

            q = q
                .bind(result.simulation_id)
                .bind(result.user_id)
                .bind(access_gained)
                .bind(access_lost)
                .bind(warnings);
        }

        let result = q.execute(pool).await?;
        Ok(result.rows_affected())
    }

    /// List results for a simulation with filtering and pagination.
    pub async fn list_by_simulation(
        pool: &sqlx::PgPool,
        simulation_id: Uuid,
        filter: &BatchSimulationResultFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_batch_simulation_results
            WHERE simulation_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.has_warnings == Some(true) {
            query.push_str(" AND warnings != '[]'::jsonb");
        } else if filter.has_warnings == Some(false) {
            query.push_str(" AND warnings = '[]'::jsonb");
        }

        query.push_str(&format!(
            " ORDER BY created_at ASC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovBatchSimulationResult>(&query).bind(simulation_id);

        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count results for a simulation with filtering.
    pub async fn count_by_simulation(
        pool: &sqlx::PgPool,
        simulation_id: Uuid,
        filter: &BatchSimulationResultFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_batch_simulation_results
            WHERE simulation_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.has_warnings == Some(true) {
            query.push_str(" AND warnings != '[]'::jsonb");
        } else if filter.has_warnings == Some(false) {
            query.push_str(" AND warnings = '[]'::jsonb");
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(simulation_id);

        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }

        q.fetch_one(pool).await
    }

    /// Delete all results for a simulation.
    pub async fn delete_by_simulation(
        pool: &sqlx::PgPool,
        simulation_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_batch_simulation_results
            WHERE simulation_id = $1
            ",
        )
        .bind(simulation_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Parse access gained.
    #[must_use] 
    pub fn parse_access_gained(&self) -> Vec<AccessItem> {
        serde_json::from_value(self.access_gained.clone()).unwrap_or_default()
    }

    /// Parse access lost.
    #[must_use] 
    pub fn parse_access_lost(&self) -> Vec<AccessItem> {
        serde_json::from_value(self.access_lost.clone()).unwrap_or_default()
    }

    /// Parse warnings.
    #[must_use] 
    pub fn parse_warnings(&self) -> Vec<String> {
        serde_json::from_value(self.warnings.clone()).unwrap_or_default()
    }

    /// Check if this result has any warnings.
    #[must_use] 
    pub fn has_warnings(&self) -> bool {
        !self.parse_warnings().is_empty()
    }

    /// Check if this result has any access changes.
    #[must_use] 
    pub fn has_changes(&self) -> bool {
        !self.parse_access_gained().is_empty() || !self.parse_access_lost().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_item_serialization() {
        let item = AccessItem {
            id: Uuid::new_v4(),
            name: "GitHub Access".to_string(),
            item_type: "entitlement".to_string(),
            source: Some("Engineering Role".to_string()),
        };

        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("GitHub Access"));
        assert!(json.contains("entitlement"));
        assert!(json.contains("Engineering Role"));
    }

    #[test]
    fn test_result_filter_default() {
        let filter = BatchSimulationResultFilter::default();
        assert!(filter.user_id.is_none());
        assert!(filter.has_warnings.is_none());
    }

    #[test]
    fn test_create_batch_simulation_result() {
        let input = CreateBatchSimulationResult {
            simulation_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            access_gained: vec![AccessItem {
                id: Uuid::new_v4(),
                name: "Test Entitlement".to_string(),
                item_type: "entitlement".to_string(),
                source: None,
            }],
            access_lost: vec![],
            warnings: vec!["User already has similar access".to_string()],
        };

        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("Test Entitlement"));
        assert!(json.contains("already has similar access"));
    }

    #[test]
    fn test_has_changes() {
        let result = GovBatchSimulationResult {
            id: Uuid::new_v4(),
            simulation_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            access_gained: serde_json::json!([]),
            access_lost: serde_json::json!([]),
            warnings: serde_json::json!([]),
            created_at: Utc::now(),
        };

        assert!(!result.has_changes());
        assert!(!result.has_warnings());

        let item_id = Uuid::new_v4();
        let result_with_changes = GovBatchSimulationResult {
            id: Uuid::new_v4(),
            simulation_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            access_gained: serde_json::json!([{"id": item_id.to_string(), "name": "Test", "item_type": "entitlement"}]),
            access_lost: serde_json::json!([]),
            warnings: serde_json::json!(["Some warning"]),
            created_at: Utc::now(),
        };

        assert!(result_with_changes.has_changes());
        assert!(result_with_changes.has_warnings());
    }
}
