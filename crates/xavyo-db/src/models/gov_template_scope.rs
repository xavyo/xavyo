//! Governance Template Scope model (F058).
//!
//! Defines where a template applies (global, organization, category, condition).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::TemplateScopeType;

/// A scope that defines where a template applies.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovTemplateScope {
    /// Unique identifier for the scope.
    pub id: Uuid,

    /// The tenant this scope belongs to.
    pub tenant_id: Uuid,

    /// The template this scope belongs to.
    pub template_id: Uuid,

    /// Type of scope (global, organization, category, condition).
    pub scope_type: TemplateScopeType,

    /// Optional scope value (org ID, category name, etc.).
    pub scope_value: Option<String>,

    /// Optional condition expression for condition-based scopes.
    pub condition: Option<String>,

    /// When the scope was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new template scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovTemplateScope {
    pub scope_type: TemplateScopeType,
    pub scope_value: Option<String>,
    pub condition: Option<String>,
}

impl GovTemplateScope {
    /// Find a scope by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_scopes
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List all scopes for a template.
    pub async fn list_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_scopes
            WHERE tenant_id = $1 AND template_id = $2
            ORDER BY scope_type ASC, scope_value ASC
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_all(pool)
        .await
    }

    /// List scopes by type for a template.
    pub async fn list_by_type(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        scope_type: TemplateScopeType,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_scopes
            WHERE tenant_id = $1 AND template_id = $2 AND scope_type = $3
            ORDER BY scope_value ASC
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .bind(scope_type)
        .fetch_all(pool)
        .await
    }

    /// Find templates with global scope for an object type.
    pub async fn find_global_templates(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT DISTINCT template_id FROM gov_template_scopes
            WHERE tenant_id = $1 AND scope_type = 'global'
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Find templates scoped to a specific organization.
    pub async fn find_templates_for_organization(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        organization_id: &str,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT DISTINCT template_id FROM gov_template_scopes
            WHERE tenant_id = $1
              AND scope_type = 'organization'
              AND scope_value = $2
            "#,
        )
        .bind(tenant_id)
        .bind(organization_id)
        .fetch_all(pool)
        .await
    }

    /// Find templates scoped to a specific category.
    pub async fn find_templates_for_category(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        category: &str,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT DISTINCT template_id FROM gov_template_scopes
            WHERE tenant_id = $1
              AND scope_type = 'category'
              AND scope_value = $2
            "#,
        )
        .bind(tenant_id)
        .bind(category)
        .fetch_all(pool)
        .await
    }

    /// Find all templates with condition-based scopes.
    pub async fn find_conditional_templates(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_scopes
            WHERE tenant_id = $1 AND scope_type = 'condition'
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Create a new template scope.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        input: CreateGovTemplateScope,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_template_scopes (
                tenant_id, template_id, scope_type, scope_value, condition
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .bind(input.scope_type)
        .bind(&input.scope_value)
        .bind(&input.condition)
        .fetch_one(pool)
        .await
    }

    /// Delete a template scope.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_template_scopes
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all scopes for a template.
    pub async fn delete_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_template_scopes
            WHERE tenant_id = $1 AND template_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count scopes for a template.
    pub async fn count_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_template_scopes
            WHERE tenant_id = $1 AND template_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_one(pool)
        .await
    }

    /// Check if scope is global.
    pub fn is_global(&self) -> bool {
        self.scope_type == TemplateScopeType::Global
    }

    /// Check if scope is organization-based.
    pub fn is_organization(&self) -> bool {
        self.scope_type == TemplateScopeType::Organization
    }

    /// Check if scope is category-based.
    pub fn is_category(&self) -> bool {
        self.scope_type == TemplateScopeType::Category
    }

    /// Check if scope is condition-based.
    pub fn is_condition(&self) -> bool {
        self.scope_type == TemplateScopeType::Condition
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_global_scope() {
        let input = CreateGovTemplateScope {
            scope_type: TemplateScopeType::Global,
            scope_value: None,
            condition: None,
        };

        assert_eq!(input.scope_type, TemplateScopeType::Global);
        assert!(input.scope_value.is_none());
        assert!(input.condition.is_none());
    }

    #[test]
    fn test_create_organization_scope() {
        let input = CreateGovTemplateScope {
            scope_type: TemplateScopeType::Organization,
            scope_value: Some("org-123".to_string()),
            condition: None,
        };

        assert_eq!(input.scope_type, TemplateScopeType::Organization);
        assert_eq!(input.scope_value, Some("org-123".to_string()));
    }

    #[test]
    fn test_create_condition_scope() {
        let input = CreateGovTemplateScope {
            scope_type: TemplateScopeType::Condition,
            scope_value: None,
            condition: Some("${department} == \"Engineering\"".to_string()),
        };

        assert_eq!(input.scope_type, TemplateScopeType::Condition);
        assert!(input.condition.is_some());
    }
}
