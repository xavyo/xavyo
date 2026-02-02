//! Role Assignment Parameter model (F057).
//!
//! Represents parameter values stored with a role assignment.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A parameter value stored with an assignment.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovRoleAssignmentParameter {
    /// Unique identifier for the assignment parameter.
    pub id: Uuid,

    /// The tenant this assignment parameter belongs to.
    pub tenant_id: Uuid,

    /// The assignment this parameter value belongs to.
    pub assignment_id: Uuid,

    /// The parameter definition this value is for.
    pub parameter_id: Uuid,

    /// The actual parameter value (JSONB).
    pub value: serde_json::Value,

    /// When the parameter value was created.
    pub created_at: DateTime<Utc>,

    /// When the parameter value was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to set/create an assignment parameter value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetGovAssignmentParameter {
    pub parameter_id: Uuid,
    pub value: serde_json::Value,
}

/// Bulk parameter values for creating a parametric assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkParameterValues {
    pub parameters: Vec<SetGovAssignmentParameter>,
}

impl GovRoleAssignmentParameter {
    /// Find an assignment parameter by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_role_assignment_parameters
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a specific parameter value for an assignment.
    pub async fn find_by_assignment_and_parameter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
        parameter_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_role_assignment_parameters
            WHERE tenant_id = $1 AND assignment_id = $2 AND parameter_id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(assignment_id)
        .bind(parameter_id)
        .fetch_optional(pool)
        .await
    }

    /// List all parameter values for an assignment.
    pub async fn list_by_assignment(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_role_assignment_parameters
            WHERE tenant_id = $1 AND assignment_id = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(assignment_id)
        .fetch_all(pool)
        .await
    }

    /// Get parameter values as a map (parameter_id -> value).
    pub async fn get_values_map(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<std::collections::HashMap<Uuid, serde_json::Value>, sqlx::Error> {
        let params = Self::list_by_assignment(pool, tenant_id, assignment_id).await?;
        Ok(params
            .into_iter()
            .map(|p| (p.parameter_id, p.value))
            .collect())
    }

    /// Create a new assignment parameter value.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
        parameter_id: Uuid,
        value: serde_json::Value,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_role_assignment_parameters (
                tenant_id, assignment_id, parameter_id, value
            )
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(assignment_id)
        .bind(parameter_id)
        .bind(&value)
        .fetch_one(pool)
        .await
    }

    /// Create multiple parameter values in bulk.
    pub async fn create_bulk(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
        values: &[SetGovAssignmentParameter],
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut results = Vec::with_capacity(values.len());
        for param in values {
            let result = Self::create(
                pool,
                tenant_id,
                assignment_id,
                param.parameter_id,
                param.value.clone(),
            )
            .await?;
            results.push(result);
        }
        Ok(results)
    }

    /// Update an assignment parameter value.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        value: serde_json::Value,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_role_assignment_parameters
            SET value = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&value)
        .fetch_optional(pool)
        .await
    }

    /// Update a parameter value by assignment and parameter IDs.
    pub async fn update_by_assignment_and_parameter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
        parameter_id: Uuid,
        value: serde_json::Value,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_role_assignment_parameters
            SET value = $4, updated_at = NOW()
            WHERE tenant_id = $1 AND assignment_id = $2 AND parameter_id = $3
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(assignment_id)
        .bind(parameter_id)
        .bind(&value)
        .fetch_optional(pool)
        .await
    }

    /// Delete an assignment parameter value.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_role_assignment_parameters
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all parameter values for an assignment.
    pub async fn delete_by_assignment(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_role_assignment_parameters
            WHERE tenant_id = $1 AND assignment_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(assignment_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count how many assignments use a specific parameter definition.
    pub async fn count_by_parameter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        parameter_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_role_assignment_parameters
            WHERE tenant_id = $1 AND parameter_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(parameter_id)
        .fetch_one(pool)
        .await
    }

    /// Check if an assignment has any parameter values.
    pub async fn assignment_has_parameters(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_role_assignment_parameters
            WHERE tenant_id = $1 AND assignment_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(assignment_id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }
}

/// Extended assignment parameter with parameter definition details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignmentParameterWithDefinition {
    pub id: Uuid,
    pub parameter_id: Uuid,
    pub parameter_name: String,
    pub parameter_display_name: Option<String>,
    pub parameter_type: String,
    pub value: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AssignmentParameterWithDefinition {
    /// List all parameter values for an assignment with their definitions.
    pub async fn list_by_assignment(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<
            _,
            (
                Uuid,
                Uuid,
                String,
                Option<String>,
                String,
                serde_json::Value,
                DateTime<Utc>,
                DateTime<Utc>,
            ),
        >(
            r#"
            SELECT
                ap.id,
                ap.parameter_id,
                p.name AS parameter_name,
                p.display_name AS parameter_display_name,
                p.parameter_type::text AS parameter_type,
                ap.value,
                ap.created_at,
                ap.updated_at
            FROM gov_role_assignment_parameters ap
            JOIN gov_role_parameters p ON ap.parameter_id = p.id
            WHERE ap.tenant_id = $1 AND ap.assignment_id = $2
            ORDER BY p.display_order ASC, p.name ASC
            "#,
        )
        .bind(tenant_id)
        .bind(assignment_id)
        .fetch_all(pool)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(
                    |(
                        id,
                        parameter_id,
                        parameter_name,
                        parameter_display_name,
                        parameter_type,
                        value,
                        created_at,
                        updated_at,
                    )| {
                        Self {
                            id,
                            parameter_id,
                            parameter_name,
                            parameter_display_name,
                            parameter_type,
                            value,
                            created_at,
                            updated_at,
                        }
                    },
                )
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_parameter() {
        let param = SetGovAssignmentParameter {
            parameter_id: Uuid::new_v4(),
            value: serde_json::json!("production_db"),
        };

        assert!(param.value.is_string());
        assert_eq!(param.value.as_str(), Some("production_db"));
    }

    #[test]
    fn test_bulk_parameter_values() {
        let bulk = BulkParameterValues {
            parameters: vec![
                SetGovAssignmentParameter {
                    parameter_id: Uuid::new_v4(),
                    value: serde_json::json!("value1"),
                },
                SetGovAssignmentParameter {
                    parameter_id: Uuid::new_v4(),
                    value: serde_json::json!(42),
                },
            ],
        };

        assert_eq!(bulk.parameters.len(), 2);
    }

    #[test]
    fn test_value_types() {
        // String value
        let string_val = serde_json::json!("test");
        assert!(string_val.is_string());

        // Integer value
        let int_val = serde_json::json!(42);
        assert!(int_val.is_i64());

        // Boolean value
        let bool_val = serde_json::json!(true);
        assert!(bool_val.is_boolean());

        // Date value (stored as string)
        let date_val = serde_json::json!("2026-01-26");
        assert!(date_val.is_string());
    }
}
