//! Governance Object Template model (F058).
//!
//! Represents a template that automatically applies to objects based on scopes
//! with rules for defaults, computed values, validation, and normalization.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::{ObjectTemplateStatus, TemplateObjectType};

/// An object template that applies rules to matching objects.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovObjectTemplate {
    /// Unique identifier for the template.
    pub id: Uuid,

    /// The tenant this template belongs to.
    pub tenant_id: Uuid,

    /// Display name for the template.
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// Type of object this template targets.
    pub object_type: TemplateObjectType,

    /// Current status (draft, active, disabled).
    pub status: ObjectTemplateStatus,

    /// Priority for template ordering (lower = higher precedence).
    pub priority: i32,

    /// Optional parent template for inheritance.
    pub parent_template_id: Option<Uuid>,

    /// User who created this template.
    pub created_by: Uuid,

    /// When the template was created.
    pub created_at: DateTime<Utc>,

    /// When the template was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new object template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovObjectTemplate {
    pub name: String,
    pub description: Option<String>,
    pub object_type: TemplateObjectType,
    pub priority: Option<i32>,
    pub parent_template_id: Option<Uuid>,
}

/// Request to update an object template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovObjectTemplate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub priority: Option<i32>,
    pub parent_template_id: Option<Uuid>,
}

/// Filter options for listing object templates.
#[derive(Debug, Clone, Default)]
pub struct ObjectTemplateFilter {
    pub status: Option<ObjectTemplateStatus>,
    pub object_type: Option<TemplateObjectType>,
    pub name_contains: Option<String>,
    pub priority_min: Option<i32>,
    pub priority_max: Option<i32>,
    pub parent_template_id: Option<Uuid>,
    pub include_orphans: Option<bool>,
}

/// Default priority for object templates.
pub const DEFAULT_TEMPLATE_PRIORITY: i32 = 100;

/// Minimum priority value for object templates.
pub const MIN_TEMPLATE_PRIORITY: i32 = 1;

/// Maximum priority value for object templates.
pub const MAX_TEMPLATE_PRIORITY: i32 = 1000;

impl GovObjectTemplate {
    /// Find a template by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_object_templates
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a template by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_object_templates
            WHERE tenant_id = $1 AND name = $2
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List all active templates for a tenant and object type, ordered by priority.
    pub async fn list_active_by_type(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        object_type: TemplateObjectType,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_object_templates
            WHERE tenant_id = $1 AND status = 'active' AND object_type = $2
            ORDER BY priority ASC, name ASC
            ",
        )
        .bind(tenant_id)
        .bind(object_type)
        .fetch_all(pool)
        .await
    }

    /// List templates with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ObjectTemplateFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_object_templates WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.object_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND object_type = ${param_count}"));
        }
        if filter.name_contains.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE ${param_count}"));
        }
        if filter.priority_min.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND priority >= ${param_count}"));
        }
        if filter.priority_max.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND priority <= ${param_count}"));
        }
        if filter.parent_template_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND parent_template_id = ${param_count}"));
        }
        if let Some(include_orphans) = filter.include_orphans {
            if !include_orphans {
                query.push_str(" AND parent_template_id IS NOT NULL");
            }
        }

        query.push_str(&format!(
            " ORDER BY priority ASC, name ASC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(object_type) = filter.object_type {
            q = q.bind(object_type);
        }
        if let Some(ref name_contains) = filter.name_contains {
            q = q.bind(format!("%{name_contains}%"));
        }
        if let Some(priority_min) = filter.priority_min {
            q = q.bind(priority_min);
        }
        if let Some(priority_max) = filter.priority_max {
            q = q.bind(priority_max);
        }
        if let Some(parent_template_id) = filter.parent_template_id {
            q = q.bind(parent_template_id);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count templates with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ObjectTemplateFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from("SELECT COUNT(*) FROM gov_object_templates WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.object_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND object_type = ${param_count}"));
        }
        if filter.name_contains.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE ${param_count}"));
        }
        if filter.priority_min.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND priority >= ${param_count}"));
        }
        if filter.priority_max.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND priority <= ${param_count}"));
        }
        if filter.parent_template_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND parent_template_id = ${param_count}"));
        }
        if let Some(include_orphans) = filter.include_orphans {
            if !include_orphans {
                query.push_str(" AND parent_template_id IS NOT NULL");
            }
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(object_type) = filter.object_type {
            q = q.bind(object_type);
        }
        if let Some(ref name_contains) = filter.name_contains {
            q = q.bind(format!("%{name_contains}%"));
        }
        if let Some(priority_min) = filter.priority_min {
            q = q.bind(priority_min);
        }
        if let Some(priority_max) = filter.priority_max {
            q = q.bind(priority_max);
        }
        if let Some(parent_template_id) = filter.parent_template_id {
            q = q.bind(parent_template_id);
        }

        q.fetch_one(pool).await
    }

    /// Create a new object template.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        created_by: Uuid,
        input: CreateGovObjectTemplate,
    ) -> Result<Self, sqlx::Error> {
        let priority = input.priority.unwrap_or(DEFAULT_TEMPLATE_PRIORITY);

        sqlx::query_as(
            r"
            INSERT INTO gov_object_templates (
                tenant_id, name, description, object_type, priority,
                parent_template_id, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.object_type)
        .bind(priority)
        .bind(input.parent_template_id)
        .bind(created_by)
        .fetch_one(pool)
        .await
    }

    /// Update a template.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovObjectTemplate,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = Vec::new();
        let mut param_count = 2; // $1 = id, $2 = tenant_id

        if input.name.is_some() {
            param_count += 1;
            updates.push(format!("name = ${param_count}"));
        }
        if input.description.is_some() {
            param_count += 1;
            updates.push(format!("description = ${param_count}"));
        }
        if input.priority.is_some() {
            param_count += 1;
            updates.push(format!("priority = ${param_count}"));
        }
        if input.parent_template_id.is_some() {
            param_count += 1;
            updates.push(format!("parent_template_id = ${param_count}"));
        }

        if updates.is_empty() {
            return Self::find_by_id(pool, tenant_id, id).await;
        }

        updates.push("updated_at = NOW()".to_string());
        let query = format!(
            "UPDATE gov_object_templates SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, Self>(&query).bind(id).bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(priority) = input.priority {
            q = q.bind(priority);
        }
        if let Some(parent_template_id) = input.parent_template_id {
            q = q.bind(parent_template_id);
        }

        q.fetch_optional(pool).await
    }

    /// Activate a template (draft -> active).
    pub async fn activate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_object_templates
            SET status = 'active', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'draft'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Disable a template (active -> disabled).
    pub async fn disable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_object_templates
            SET status = 'disabled', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Re-enable a template (disabled -> active).
    pub async fn enable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_object_templates
            SET status = 'active', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'disabled'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a template.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_object_templates
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Find all child templates of a parent.
    pub async fn find_children(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        parent_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_object_templates
            WHERE tenant_id = $1 AND parent_template_id = $2
            ORDER BY priority ASC, name ASC
            ",
        )
        .bind(tenant_id)
        .bind(parent_id)
        .fetch_all(pool)
        .await
    }

    /// Check if a template has any children.
    pub async fn has_children(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_object_templates
            WHERE tenant_id = $1 AND parent_template_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// Get the ancestor chain (parent, grandparent, etc.).
    pub async fn get_ancestor_chain(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            WITH RECURSIVE ancestors AS (
                SELECT * FROM gov_object_templates
                WHERE id = $1 AND tenant_id = $2
                UNION ALL
                SELECT t.* FROM gov_object_templates t
                JOIN ancestors a ON t.id = a.parent_template_id
                WHERE t.tenant_id = $2
            )
            SELECT * FROM ancestors WHERE id != $1
            ORDER BY id
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Check if template is active.
    #[must_use] 
    pub fn is_active(&self) -> bool {
        self.status == ObjectTemplateStatus::Active
    }

    /// Check if template is draft.
    #[must_use] 
    pub fn is_draft(&self) -> bool {
        self.status == ObjectTemplateStatus::Draft
    }

    /// Check if template is disabled.
    #[must_use] 
    pub fn is_disabled(&self) -> bool {
        self.status == ObjectTemplateStatus::Disabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_template_defaults() {
        let input = CreateGovObjectTemplate {
            name: "Test Template".to_string(),
            description: None,
            object_type: TemplateObjectType::User,
            priority: None,
            parent_template_id: None,
        };

        assert_eq!(input.name, "Test Template");
        assert!(input.description.is_none());
        assert_eq!(input.object_type, TemplateObjectType::User);
        assert!(input.priority.is_none());
    }

    #[test]
    fn test_priority_constants() {
        assert_eq!(DEFAULT_TEMPLATE_PRIORITY, 100);
        assert_eq!(MIN_TEMPLATE_PRIORITY, 1);
        assert_eq!(MAX_TEMPLATE_PRIORITY, 1000);
        assert!(MIN_TEMPLATE_PRIORITY < DEFAULT_TEMPLATE_PRIORITY);
        assert!(DEFAULT_TEMPLATE_PRIORITY < MAX_TEMPLATE_PRIORITY);
    }

    #[test]
    fn test_filter_default() {
        let filter = ObjectTemplateFilter::default();
        assert!(filter.status.is_none());
        assert!(filter.object_type.is_none());
        assert!(filter.name_contains.is_none());
        assert!(filter.priority_min.is_none());
        assert!(filter.priority_max.is_none());
        assert!(filter.parent_template_id.is_none());
    }
}
