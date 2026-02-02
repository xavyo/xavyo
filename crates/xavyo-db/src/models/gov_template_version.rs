//! Governance Template Version model (F058).
//!
//! Immutable version snapshots for template audit trail and rollback support.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// An immutable version snapshot of a template.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovTemplateVersion {
    /// Unique identifier for the version.
    pub id: Uuid,

    /// The tenant this version belongs to.
    pub tenant_id: Uuid,

    /// The template this version belongs to.
    pub template_id: Uuid,

    /// Sequential version number (1, 2, 3...).
    pub version_number: i32,

    /// Full rule definitions at this version.
    pub rules_snapshot: serde_json::Value,

    /// Full scope definitions at this version.
    pub scopes_snapshot: serde_json::Value,

    /// User who created this version.
    pub created_by: Uuid,

    /// When the version was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new template version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovTemplateVersion {
    pub version_number: i32,
    pub rules_snapshot: serde_json::Value,
    pub scopes_snapshot: serde_json::Value,
}

impl GovTemplateVersion {
    /// Find a version by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_versions
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a specific version number for a template.
    pub async fn find_by_version_number(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        version_number: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_versions
            WHERE tenant_id = $1 AND template_id = $2 AND version_number = $3
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .bind(version_number)
        .fetch_optional(pool)
        .await
    }

    /// Get the latest version for a template.
    pub async fn find_latest(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_versions
            WHERE tenant_id = $1 AND template_id = $2
            ORDER BY version_number DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_optional(pool)
        .await
    }

    /// List all versions for a template ordered by version number (descending).
    pub async fn list_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_versions
            WHERE tenant_id = $1 AND template_id = $2
            ORDER BY version_number DESC
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_all(pool)
        .await
    }

    /// List versions with pagination.
    pub async fn list_by_template_paginated(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_versions
            WHERE tenant_id = $1 AND template_id = $2
            ORDER BY version_number DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Get the next version number for a template.
    pub async fn get_next_version_number(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<i32, sqlx::Error> {
        let max_version: Option<i32> = sqlx::query_scalar(
            r#"
            SELECT MAX(version_number) FROM gov_template_versions
            WHERE tenant_id = $1 AND template_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_one(pool)
        .await?;

        Ok(max_version.unwrap_or(0) + 1)
    }

    /// Create a new template version.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        created_by: Uuid,
        input: CreateGovTemplateVersion,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_template_versions (
                tenant_id, template_id, version_number, rules_snapshot,
                scopes_snapshot, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .bind(input.version_number)
        .bind(&input.rules_snapshot)
        .bind(&input.scopes_snapshot)
        .bind(created_by)
        .fetch_one(pool)
        .await
    }

    /// Create a new version with auto-incremented version number.
    pub async fn create_next_version(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        created_by: Uuid,
        rules_snapshot: serde_json::Value,
        scopes_snapshot: serde_json::Value,
    ) -> Result<Self, sqlx::Error> {
        let version_number = Self::get_next_version_number(pool, tenant_id, template_id).await?;

        let input = CreateGovTemplateVersion {
            version_number,
            rules_snapshot,
            scopes_snapshot,
        };

        Self::create(pool, tenant_id, template_id, created_by, input).await
    }

    /// Count versions for a template.
    pub async fn count_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_template_versions
            WHERE tenant_id = $1 AND template_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_one(pool)
        .await
    }

    /// Delete old versions, keeping only the most recent N versions.
    pub async fn prune_old_versions(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        keep_count: i32,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_template_versions
            WHERE tenant_id = $1 AND template_id = $2
              AND version_number NOT IN (
                SELECT version_number FROM gov_template_versions
                WHERE tenant_id = $1 AND template_id = $2
                ORDER BY version_number DESC
                LIMIT $3
              )
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .bind(keep_count)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_version() {
        let input = CreateGovTemplateVersion {
            version_number: 1,
            rules_snapshot: serde_json::json!([]),
            scopes_snapshot: serde_json::json!([]),
        };

        assert_eq!(input.version_number, 1);
    }

    #[test]
    fn test_version_snapshots() {
        let rules = serde_json::json!([
            {"rule_type": "default", "target_attribute": "department", "expression": "Unassigned"}
        ]);
        let scopes = serde_json::json!([
            {"scope_type": "global"}
        ]);

        let input = CreateGovTemplateVersion {
            version_number: 1,
            rules_snapshot: rules.clone(),
            scopes_snapshot: scopes.clone(),
        };

        assert_eq!(input.rules_snapshot, rules);
        assert_eq!(input.scopes_snapshot, scopes);
    }
}
