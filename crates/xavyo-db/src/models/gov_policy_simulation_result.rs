//! Policy Simulation Result model (F060).
//!
//! Stores per-user impact details for policy simulations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::ImpactType;

/// Per-user result for a policy simulation.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovPolicySimulationResult {
    /// Unique identifier for this result.
    pub id: Uuid,

    /// Reference to the parent simulation.
    pub simulation_id: Uuid,

    /// The affected user.
    pub user_id: Uuid,

    /// Type of impact.
    pub impact_type: ImpactType,

    /// Detailed impact information.
    pub details: serde_json::Value,

    /// Severity level (if applicable).
    pub severity: Option<String>,

    /// When this result was created.
    pub created_at: DateTime<Utc>,
}

/// Input for creating a simulation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePolicySimulationResult {
    pub simulation_id: Uuid,
    pub user_id: Uuid,
    pub impact_type: ImpactType,
    pub details: serde_json::Value,
    pub severity: Option<String>,
}

/// `SoD` violation details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SodViolationDetails {
    /// The `SoD` rule that would be violated.
    pub rule_id: Uuid,
    /// Rule name.
    pub rule_name: String,
    /// First conflicting entitlement.
    pub first_entitlement: EntitlementInfo,
    /// Second conflicting entitlement.
    pub second_entitlement: EntitlementInfo,
    /// How the user currently has these entitlements.
    pub current_assignments: Vec<String>,
}

/// Birthright entitlement change details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BirthrightChangeDetails {
    /// The policy that would be applied.
    pub policy_id: Uuid,
    /// Policy name.
    pub policy_name: String,
    /// Conditions that matched.
    pub matched_conditions: Vec<ConditionMatch>,
    /// Entitlements that would be affected.
    pub entitlements_affected: Vec<EntitlementChange>,
}

/// Information about an entitlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EntitlementInfo {
    pub id: Uuid,
    pub name: String,
}

/// A matched condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConditionMatch {
    pub attribute: String,
    pub operator: String,
    pub value: serde_json::Value,
}

/// An entitlement change.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EntitlementChange {
    pub id: Uuid,
    pub name: String,
    /// "grant" or "revoke"
    pub action: String,
}

/// Filter options for listing results.
#[derive(Debug, Clone, Default)]
pub struct PolicySimulationResultFilter {
    pub impact_type: Option<ImpactType>,
    pub severity: Option<String>,
    pub user_id: Option<Uuid>,
}

impl GovPolicySimulationResult {
    /// Create a new simulation result.
    pub async fn create(
        pool: &sqlx::PgPool,
        input: CreatePolicySimulationResult,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_policy_simulation_results (
                simulation_id, user_id, impact_type, details, severity
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(input.simulation_id)
        .bind(input.user_id)
        .bind(input.impact_type)
        .bind(&input.details)
        .bind(&input.severity)
        .fetch_one(pool)
        .await
    }

    /// Bulk insert results (more efficient for large simulations).
    pub async fn bulk_create(
        pool: &sqlx::PgPool,
        results: &[CreatePolicySimulationResult],
    ) -> Result<u64, sqlx::Error> {
        if results.is_empty() {
            return Ok(0);
        }

        // Build bulk insert query
        let mut query = String::from(
            "INSERT INTO gov_policy_simulation_results (simulation_id, user_id, impact_type, details, severity) VALUES ",
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
            q = q
                .bind(result.simulation_id)
                .bind(result.user_id)
                .bind(result.impact_type)
                .bind(&result.details)
                .bind(&result.severity);
        }

        let result = q.execute(pool).await?;
        Ok(result.rows_affected())
    }

    /// List results for a simulation with filtering and pagination.
    pub async fn list_by_simulation(
        pool: &sqlx::PgPool,
        simulation_id: Uuid,
        filter: &PolicySimulationResultFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_policy_simulation_results
            WHERE simulation_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.impact_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND impact_type = ${param_count}"));
        }
        if filter.severity.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND severity = ${param_count}"));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY created_at ASC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovPolicySimulationResult>(&query).bind(simulation_id);

        if let Some(impact_type) = filter.impact_type {
            q = q.bind(impact_type);
        }
        if let Some(ref severity) = filter.severity {
            q = q.bind(severity);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count results for a simulation with filtering.
    pub async fn count_by_simulation(
        pool: &sqlx::PgPool,
        simulation_id: Uuid,
        filter: &PolicySimulationResultFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_policy_simulation_results
            WHERE simulation_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.impact_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND impact_type = ${param_count}"));
        }
        if filter.severity.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND severity = ${param_count}"));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(simulation_id);

        if let Some(impact_type) = filter.impact_type {
            q = q.bind(impact_type);
        }
        if let Some(ref severity) = filter.severity {
            q = q.bind(severity);
        }
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
            DELETE FROM gov_policy_simulation_results
            WHERE simulation_id = $1
            ",
        )
        .bind(simulation_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Parse `SoD` violation details.
    #[must_use] 
    pub fn parse_sod_details(&self) -> Option<SodViolationDetails> {
        serde_json::from_value(self.details.clone()).ok()
    }

    /// Parse birthright change details.
    #[must_use] 
    pub fn parse_birthright_details(&self) -> Option<BirthrightChangeDetails> {
        serde_json::from_value(self.details.clone()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sod_violation_details_serialization() {
        let details = SodViolationDetails {
            rule_id: Uuid::new_v4(),
            rule_name: "Payment Approval Conflict".to_string(),
            first_entitlement: EntitlementInfo {
                id: Uuid::new_v4(),
                name: "Create Payment".to_string(),
            },
            second_entitlement: EntitlementInfo {
                id: Uuid::new_v4(),
                name: "Approve Payment".to_string(),
            },
            current_assignments: vec!["Finance Role".to_string()],
        };

        let json = serde_json::to_string(&details).unwrap();
        assert!(json.contains("Payment Approval Conflict"));
        assert!(json.contains("Create Payment"));
        assert!(json.contains("Finance Role"));
    }

    #[test]
    fn test_birthright_change_details_serialization() {
        let details = BirthrightChangeDetails {
            policy_id: Uuid::new_v4(),
            policy_name: "Engineering Access".to_string(),
            matched_conditions: vec![ConditionMatch {
                attribute: "department".to_string(),
                operator: "equals".to_string(),
                value: serde_json::json!("Engineering"),
            }],
            entitlements_affected: vec![EntitlementChange {
                id: Uuid::new_v4(),
                name: "GitHub Access".to_string(),
                action: "grant".to_string(),
            }],
        };

        let json = serde_json::to_string(&details).unwrap();
        assert!(json.contains("Engineering Access"));
        assert!(json.contains("department"));
        assert!(json.contains("GitHub Access"));
    }

    #[test]
    fn test_result_filter_default() {
        let filter = PolicySimulationResultFilter::default();
        assert!(filter.impact_type.is_none());
        assert!(filter.severity.is_none());
        assert!(filter.user_id.is_none());
    }
}
