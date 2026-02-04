//! Script Template model (F066).
//! Pre-built and tenant-created reusable script patterns.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_script_types::TemplateCategory;

/// A reusable script template that can be used to bootstrap new provisioning scripts.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovScriptTemplate {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this template belongs to.
    pub tenant_id: Uuid,

    /// Template display name.
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// Template category (`attribute_mapping`, `value_generation`, etc.).
    pub category: TemplateCategory,

    /// The template script body with placeholder tokens.
    pub template_body: String,

    /// JSON annotations describing each placeholder in the template body.
    pub placeholder_annotations: Option<serde_json::Value>,

    /// Whether this is a system-provided template.
    pub is_system: bool,

    /// Who created this template.
    pub created_by: Uuid,

    /// When the template was created.
    pub created_at: DateTime<Utc>,

    /// When the template was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new script template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScriptTemplate {
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub category: TemplateCategory,
    pub template_body: String,
    pub placeholder_annotations: Option<serde_json::Value>,
    pub is_system: bool,
    pub created_by: Uuid,
}

/// Request to update an existing script template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateScriptTemplate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub category: Option<TemplateCategory>,
    pub template_body: Option<String>,
    pub placeholder_annotations: Option<serde_json::Value>,
}

/// Filter options for listing script templates.
#[derive(Debug, Clone, Default)]
pub struct TemplateFilter {
    pub category: Option<TemplateCategory>,
    pub is_system: Option<bool>,
    pub search: Option<String>,
}

impl GovScriptTemplate {
    /// Create a new script template.
    pub async fn create(
        pool: &sqlx::PgPool,
        params: CreateScriptTemplate,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_script_templates (
                tenant_id, name, description, category, template_body,
                placeholder_annotations, is_system, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(params.tenant_id)
        .bind(&params.name)
        .bind(&params.description)
        .bind(params.category)
        .bind(&params.template_body)
        .bind(&params.placeholder_annotations)
        .bind(params.is_system)
        .bind(params.created_by)
        .fetch_one(pool)
        .await
    }

    /// Find a template by ID within a tenant.
    pub async fn get_by_id(
        pool: &sqlx::PgPool,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_script_templates
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List templates for a tenant with optional filtering and pagination.
    ///
    /// Returns a tuple of (templates, `total_count`) for pagination support.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &TemplateFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Self>, i64), sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_script_templates
            WHERE tenant_id = $1
            ",
        );
        let mut count_query = String::from(
            r"
            SELECT COUNT(*) FROM gov_script_templates
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.category.is_some() {
            param_count += 1;
            let clause = format!(" AND category = ${param_count}");
            query.push_str(&clause);
            count_query.push_str(&clause);
        }
        if filter.is_system.is_some() {
            param_count += 1;
            let clause = format!(" AND is_system = ${param_count}");
            query.push_str(&clause);
            count_query.push_str(&clause);
        }
        if filter.search.is_some() {
            param_count += 1;
            let clause = format!(" AND name ILIKE ${param_count}");
            query.push_str(&clause);
            count_query.push_str(&clause);
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovScriptTemplate>(&query).bind(tenant_id);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);

        if let Some(category) = filter.category {
            q = q.bind(category);
            cq = cq.bind(category);
        }
        if let Some(is_system) = filter.is_system {
            q = q.bind(is_system);
            cq = cq.bind(is_system);
        }
        if let Some(ref search) = filter.search {
            let pattern = format!("%{search}%");
            q = q.bind(pattern.clone());
            cq = cq.bind(pattern);
        }

        let rows = q.bind(limit).bind(offset).fetch_all(pool).await?;
        let total = cq.fetch_one(pool).await?;

        Ok((rows, total))
    }

    /// List all templates in a specific category for a tenant.
    pub async fn list_by_category(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        category: TemplateCategory,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_script_templates
            WHERE tenant_id = $1 AND category = $2
            ORDER BY name
            ",
        )
        .bind(tenant_id)
        .bind(category)
        .fetch_all(pool)
        .await
    }

    /// Update template fields (partial update).
    pub async fn update(
        pool: &sqlx::PgPool,
        id: Uuid,
        tenant_id: Uuid,
        params: UpdateScriptTemplate,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_script_templates
            SET
                name = COALESCE($3, name),
                description = COALESCE($4, description),
                category = COALESCE($5, category),
                template_body = COALESCE($6, template_body),
                placeholder_annotations = COALESCE($7, placeholder_annotations),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&params.name)
        .bind(&params.description)
        .bind(params.category)
        .bind(&params.template_body)
        .bind(&params.placeholder_annotations)
        .fetch_optional(pool)
        .await
    }

    /// Delete a script template. Returns true if a row was deleted.
    pub async fn delete(
        pool: &sqlx::PgPool,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_script_templates
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_params() {
        let params = CreateScriptTemplate {
            tenant_id: Uuid::new_v4(),
            name: "Email Username Generator".to_string(),
            description: Some("Generates email-based usernames".to_string()),
            category: TemplateCategory::ValueGeneration,
            template_body: "function generate(input) { return input.email.split('@')[0]; }"
                .to_string(),
            placeholder_annotations: None,
            is_system: false,
            created_by: Uuid::new_v4(),
        };

        assert_eq!(params.name, "Email Username Generator");
        assert_eq!(params.category, TemplateCategory::ValueGeneration);
        assert!(!params.is_system);
    }

    #[test]
    fn test_update_params() {
        let params = UpdateScriptTemplate {
            name: Some("Updated Template".to_string()),
            description: None,
            category: Some(TemplateCategory::AttributeMapping),
            template_body: None,
            placeholder_annotations: None,
        };

        assert!(params.name.is_some());
        assert!(params.description.is_none());
        assert_eq!(params.category, Some(TemplateCategory::AttributeMapping));
    }

    #[test]
    fn test_template_filter_default() {
        let filter = TemplateFilter::default();

        assert!(filter.category.is_none());
        assert!(filter.is_system.is_none());
        assert!(filter.search.is_none());
    }

    #[test]
    fn test_template_filter_with_values() {
        let filter = TemplateFilter {
            category: Some(TemplateCategory::ConditionalLogic),
            is_system: Some(true),
            search: Some("email".to_string()),
        };

        assert_eq!(filter.category, Some(TemplateCategory::ConditionalLogic));
        assert_eq!(filter.is_system, Some(true));
        assert_eq!(filter.search, Some("email".to_string()));
    }

    #[test]
    fn test_script_template_struct() {
        let now = Utc::now();
        let template = GovScriptTemplate {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Attribute Mapper".to_string(),
            description: Some("Maps source attributes to target".to_string()),
            category: TemplateCategory::AttributeMapping,
            template_body: "function map(src) { return { target: src.value }; }".to_string(),
            placeholder_annotations: Some(serde_json::json!({
                "source_attr": { "type": "string", "description": "Source attribute name" }
            })),
            is_system: true,
            created_by: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
        };

        assert_eq!(template.name, "Attribute Mapper");
        assert_eq!(template.category, TemplateCategory::AttributeMapping);
        assert!(template.is_system);
        assert!(template.placeholder_annotations.is_some());
    }
}
