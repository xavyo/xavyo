//! Governance Template Exclusion model (F058).
//!
//! Tracks rules excluded from inherited parent templates in child templates.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// An exclusion that removes a parent's rule from a child template.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovTemplateExclusion {
    /// Unique identifier for the exclusion.
    pub id: Uuid,

    /// The tenant this exclusion belongs to.
    pub tenant_id: Uuid,

    /// The child template that defines this exclusion.
    pub template_id: Uuid,

    /// ID of the parent's rule to exclude.
    pub excluded_rule_id: Uuid,

    /// When the exclusion was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new template exclusion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovTemplateExclusion {
    pub excluded_rule_id: Uuid,
}

impl GovTemplateExclusion {
    /// Find an exclusion by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_exclusions
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find an exclusion by template and rule.
    pub async fn find_by_rule(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        excluded_rule_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_exclusions
            WHERE tenant_id = $1 AND template_id = $2 AND excluded_rule_id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .bind(excluded_rule_id)
        .fetch_optional(pool)
        .await
    }

    /// List all exclusions for a template.
    pub async fn list_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_exclusions
            WHERE tenant_id = $1 AND template_id = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_all(pool)
        .await
    }

    /// Get all excluded rule IDs for a template.
    pub async fn get_excluded_rule_ids(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT excluded_rule_id FROM gov_template_exclusions
            WHERE tenant_id = $1 AND template_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_all(pool)
        .await
    }

    /// Check if a rule is excluded from a template.
    pub async fn is_rule_excluded(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        rule_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_template_exclusions
            WHERE tenant_id = $1 AND template_id = $2 AND excluded_rule_id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .bind(rule_id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// Create a new exclusion.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        input: CreateGovTemplateExclusion,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_template_exclusions (
                tenant_id, template_id, excluded_rule_id
            )
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .bind(input.excluded_rule_id)
        .fetch_one(pool)
        .await
    }

    /// Delete an exclusion by ID.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_template_exclusions
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete an exclusion by template and rule.
    pub async fn delete_by_rule(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        excluded_rule_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_template_exclusions
            WHERE tenant_id = $1 AND template_id = $2 AND excluded_rule_id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .bind(excluded_rule_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all exclusions for a template.
    pub async fn delete_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_template_exclusions
            WHERE tenant_id = $1 AND template_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count exclusions for a template.
    pub async fn count_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_template_exclusions
            WHERE tenant_id = $1 AND template_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_one(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_exclusion() {
        let rule_id = Uuid::new_v4();
        let input = CreateGovTemplateExclusion {
            excluded_rule_id: rule_id,
        };

        assert_eq!(input.excluded_rule_id, rule_id);
    }
}
