//! Governance Meta-role Criteria model (F056).
//!
//! Represents matching conditions that determine which roles inherit from a meta-role.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::CriteriaOperator;

/// A matching criterion for a meta-role.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovMetaRoleCriteria {
    /// Unique identifier for the criteria.
    pub id: Uuid,

    /// The tenant this criteria belongs to.
    pub tenant_id: Uuid,

    /// The meta-role this criteria belongs to.
    pub meta_role_id: Uuid,

    /// The field to match (`risk_level`, `application_id`, etc.).
    pub field: String,

    /// The comparison operator.
    pub operator: CriteriaOperator,

    /// The value(s) to compare (JSON format).
    pub value: serde_json::Value,

    /// When the criteria was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new criteria.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovMetaRoleCriteria {
    pub field: String,
    pub operator: CriteriaOperator,
    pub value: serde_json::Value,
}

impl GovMetaRoleCriteria {
    /// Find a criteria by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_meta_role_criteria
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List all criteria for a meta-role.
    pub async fn list_by_meta_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_meta_role_criteria
            WHERE tenant_id = $1 AND meta_role_id = $2
            ORDER BY created_at ASC
            ",
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .fetch_all(pool)
        .await
    }

    /// Create a new criteria.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        input: CreateGovMetaRoleCriteria,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_meta_role_criteria (
                tenant_id, meta_role_id, field, operator, value
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .bind(&input.field)
        .bind(input.operator)
        .bind(&input.value)
        .fetch_one(pool)
        .await
    }

    /// Delete a criteria.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_meta_role_criteria
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all criteria for a meta-role.
    pub async fn delete_by_meta_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_meta_role_criteria
            WHERE tenant_id = $1 AND meta_role_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_criteria() {
        let input = CreateGovMetaRoleCriteria {
            field: "risk_level".to_string(),
            operator: CriteriaOperator::Eq,
            value: serde_json::json!("critical"),
        };

        assert_eq!(input.field, "risk_level");
        assert_eq!(input.operator, CriteriaOperator::Eq);
    }

    #[test]
    fn test_create_criteria_in_list() {
        let input = CreateGovMetaRoleCriteria {
            field: "application_id".to_string(),
            operator: CriteriaOperator::In,
            value: serde_json::json!(["uuid1", "uuid2", "uuid3"]),
        };

        assert_eq!(input.field, "application_id");
        assert_eq!(input.operator, CriteriaOperator::In);
        assert!(input.value.is_array());
    }
}
