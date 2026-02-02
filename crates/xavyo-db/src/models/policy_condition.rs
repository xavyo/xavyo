//! Policy Condition model (F083).
//!
//! Represents conditions attached to authorization policies (AND-combined).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A policy condition record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct PolicyConditionRecord {
    /// Unique identifier for the condition.
    pub id: Uuid,

    /// The tenant this condition belongs to.
    pub tenant_id: Uuid,

    /// The policy this condition belongs to.
    pub policy_id: Uuid,

    /// Condition type: "time_window", "user_attribute", "entitlement_check".
    pub condition_type: String,

    /// Attribute path for user_attribute conditions (e.g., "department").
    pub attribute_path: Option<String>,

    /// Comparison operator for user_attribute conditions.
    pub operator: Option<String>,

    /// Condition value (JSON).
    pub value: serde_json::Value,

    /// When the condition was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a policy condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePolicyCondition {
    pub condition_type: String,
    pub attribute_path: Option<String>,
    pub operator: Option<String>,
    pub value: serde_json::Value,
}

impl PolicyConditionRecord {
    /// Find all conditions for a policy.
    pub async fn find_by_policy_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM policy_conditions
            WHERE tenant_id = $1 AND policy_id = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(policy_id)
        .fetch_all(pool)
        .await
    }

    /// Find a condition by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM policy_conditions
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Create a new policy condition.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        policy_id: Uuid,
        input: CreatePolicyCondition,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO policy_conditions (
                tenant_id, policy_id, condition_type,
                attribute_path, operator, value
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(policy_id)
        .bind(&input.condition_type)
        .bind(&input.attribute_path)
        .bind(&input.operator)
        .bind(&input.value)
        .fetch_one(pool)
        .await
    }

    /// Delete a policy condition.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM policy_conditions
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all conditions for a policy.
    pub async fn delete_by_policy(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM policy_conditions
            WHERE tenant_id = $1 AND policy_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(policy_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_condition_request() {
        let request = CreatePolicyCondition {
            condition_type: "time_window".to_string(),
            attribute_path: None,
            operator: None,
            value: serde_json::json!({
                "start_time": "09:00",
                "end_time": "17:00",
                "timezone": "UTC"
            }),
        };

        assert_eq!(request.condition_type, "time_window");
    }

    #[test]
    fn test_user_attribute_condition() {
        let request = CreatePolicyCondition {
            condition_type: "user_attribute".to_string(),
            attribute_path: Some("department".to_string()),
            operator: Some("equals".to_string()),
            value: serde_json::json!("engineering"),
        };

        assert_eq!(request.attribute_path, Some("department".to_string()));
        assert_eq!(request.operator, Some("equals".to_string()));
    }
}
