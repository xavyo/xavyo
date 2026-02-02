//! Governance Meta-role Constraint model (F056).
//!
//! Represents policy constraints inherited by roles matching the meta-role criteria.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A constraint inherited from a meta-role.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovMetaRoleConstraint {
    /// Unique identifier.
    pub id: Uuid,

    /// The tenant this belongs to.
    pub tenant_id: Uuid,

    /// The parent meta-role.
    pub meta_role_id: Uuid,

    /// Type of constraint (max_session_duration, require_mfa, etc.).
    pub constraint_type: String,

    /// Constraint configuration (JSON format).
    pub constraint_value: serde_json::Value,

    /// When this was created.
    pub created_at: DateTime<Utc>,
}

/// Request to add a constraint to a meta-role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovMetaRoleConstraint {
    pub constraint_type: String,
    pub constraint_value: serde_json::Value,
}

impl GovMetaRoleConstraint {
    /// Find by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_meta_role_constraints
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find by meta-role and constraint type.
    pub async fn find_by_meta_role_and_type(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        constraint_type: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_meta_role_constraints
            WHERE tenant_id = $1 AND meta_role_id = $2 AND constraint_type = $3
            "#,
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .bind(constraint_type)
        .fetch_optional(pool)
        .await
    }

    /// List all constraints for a meta-role.
    pub async fn list_by_meta_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_meta_role_constraints
            WHERE tenant_id = $1 AND meta_role_id = $2
            ORDER BY constraint_type ASC
            "#,
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .fetch_all(pool)
        .await
    }

    /// Create a new meta-role constraint.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        input: CreateGovMetaRoleConstraint,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_meta_role_constraints (
                tenant_id, meta_role_id, constraint_type, constraint_value
            )
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .bind(&input.constraint_type)
        .bind(&input.constraint_value)
        .fetch_one(pool)
        .await
    }

    /// Update a constraint value.
    pub async fn update_value(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        constraint_value: serde_json::Value,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_meta_role_constraints
            SET constraint_value = $3
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&constraint_value)
        .fetch_optional(pool)
        .await
    }

    /// Delete a constraint.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_meta_role_constraints
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all constraints for a meta-role.
    pub async fn delete_by_meta_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_meta_role_constraints
            WHERE tenant_id = $1 AND meta_role_id = $2
            "#,
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
    fn test_create_constraint_mfa() {
        let input = CreateGovMetaRoleConstraint {
            constraint_type: "require_mfa".to_string(),
            constraint_value: serde_json::json!({ "enabled": true }),
        };

        assert_eq!(input.constraint_type, "require_mfa");
        assert_eq!(input.constraint_value["enabled"], true);
    }

    #[test]
    fn test_create_constraint_session_duration() {
        let input = CreateGovMetaRoleConstraint {
            constraint_type: "max_session_duration".to_string(),
            constraint_value: serde_json::json!({ "hours": 4 }),
        };

        assert_eq!(input.constraint_type, "max_session_duration");
        assert_eq!(input.constraint_value["hours"], 4);
    }

    #[test]
    fn test_create_constraint_ip_whitelist() {
        let input = CreateGovMetaRoleConstraint {
            constraint_type: "ip_whitelist".to_string(),
            constraint_value: serde_json::json!({ "cidrs": ["10.0.0.0/8", "192.168.0.0/16"] }),
        };

        assert_eq!(input.constraint_type, "ip_whitelist");
        assert!(input.constraint_value["cidrs"].is_array());
    }
}
