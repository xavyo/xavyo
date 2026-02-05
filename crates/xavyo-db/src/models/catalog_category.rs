//! Catalog Category model for Self-Service Request Catalog (F-062).
//!
//! Hierarchical organization for catalog items.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A catalog category for organizing requestable items.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CatalogCategory {
    /// Unique identifier for the category.
    pub id: Uuid,

    /// The tenant this category belongs to.
    pub tenant_id: Uuid,

    /// Category display name.
    pub name: String,

    /// Category description.
    pub description: Option<String>,

    /// Parent category ID for hierarchy.
    pub parent_id: Option<Uuid>,

    /// Icon identifier for UI display.
    pub icon: Option<String>,

    /// Sort order within parent.
    pub display_order: i32,

    /// When the category was created.
    pub created_at: DateTime<Utc>,

    /// When the category was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new catalog category.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateCatalogCategory {
    /// Category display name.
    pub name: String,

    /// Category description.
    pub description: Option<String>,

    /// Parent category ID for hierarchy.
    pub parent_id: Option<Uuid>,

    /// Icon identifier for UI display.
    pub icon: Option<String>,

    /// Sort order within parent. Defaults to 0.
    #[serde(default)]
    pub display_order: i32,
}

/// Request to update a catalog category.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateCatalogCategory {
    /// New name for the category.
    pub name: Option<String>,

    /// New description for the category.
    pub description: Option<String>,

    /// New parent category ID.
    pub parent_id: Option<Uuid>,

    /// New icon identifier.
    pub icon: Option<String>,

    /// New display order.
    pub display_order: Option<i32>,
}

/// Filter options for listing categories.
#[derive(Debug, Clone, Default)]
pub struct CatalogCategoryFilter {
    /// Filter by parent category (None = root categories).
    pub parent_id: Option<Option<Uuid>>,
}

impl CatalogCategory {
    /// Find a category by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM catalog_categories
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a category by name within a tenant at the same hierarchy level.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
        parent_id: Option<Uuid>,
    ) -> Result<Option<Self>, sqlx::Error> {
        if let Some(pid) = parent_id {
            sqlx::query_as(
                r"
                SELECT * FROM catalog_categories
                WHERE tenant_id = $1 AND name = $2 AND parent_id = $3
                ",
            )
            .bind(tenant_id)
            .bind(name)
            .bind(pid)
            .fetch_optional(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT * FROM catalog_categories
                WHERE tenant_id = $1 AND name = $2 AND parent_id IS NULL
                ",
            )
            .bind(tenant_id)
            .bind(name)
            .fetch_optional(pool)
            .await
        }
    }

    /// List categories for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CatalogCategoryFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        // Handle parent_id filter: Some(Some(uuid)) = specific parent, Some(None) = root only, None = all
        match filter.parent_id {
            Some(Some(parent)) => {
                sqlx::query_as(
                    r"
                    SELECT * FROM catalog_categories
                    WHERE tenant_id = $1 AND parent_id = $2
                    ORDER BY display_order, name
                    LIMIT $3 OFFSET $4
                    ",
                )
                .bind(tenant_id)
                .bind(parent)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await
            }
            Some(None) => {
                sqlx::query_as(
                    r"
                    SELECT * FROM catalog_categories
                    WHERE tenant_id = $1 AND parent_id IS NULL
                    ORDER BY display_order, name
                    LIMIT $2 OFFSET $3
                    ",
                )
                .bind(tenant_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await
            }
            None => {
                sqlx::query_as(
                    r"
                    SELECT * FROM catalog_categories
                    WHERE tenant_id = $1
                    ORDER BY display_order, name
                    LIMIT $2 OFFSET $3
                    ",
                )
                .bind(tenant_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await
            }
        }
    }

    /// Count categories in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CatalogCategoryFilter,
    ) -> Result<i64, sqlx::Error> {
        match filter.parent_id {
            Some(Some(parent)) => {
                sqlx::query_scalar(
                    r"
                    SELECT COUNT(*) FROM catalog_categories
                    WHERE tenant_id = $1 AND parent_id = $2
                    ",
                )
                .bind(tenant_id)
                .bind(parent)
                .fetch_one(pool)
                .await
            }
            Some(None) => {
                sqlx::query_scalar(
                    r"
                    SELECT COUNT(*) FROM catalog_categories
                    WHERE tenant_id = $1 AND parent_id IS NULL
                    ",
                )
                .bind(tenant_id)
                .fetch_one(pool)
                .await
            }
            None => {
                sqlx::query_scalar(
                    r"
                    SELECT COUNT(*) FROM catalog_categories
                    WHERE tenant_id = $1
                    ",
                )
                .bind(tenant_id)
                .fetch_one(pool)
                .await
            }
        }
    }

    /// Create a new catalog category.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateCatalogCategory,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO catalog_categories (tenant_id, name, description, parent_id, icon, display_order)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.parent_id)
        .bind(&input.icon)
        .bind(input.display_order)
        .fetch_one(pool)
        .await
    }

    /// Update a catalog category.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateCatalogCategory,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${param_idx}"));
            param_idx += 1;
        }
        if input.parent_id.is_some() {
            updates.push(format!("parent_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.icon.is_some() {
            updates.push(format!("icon = ${param_idx}"));
            param_idx += 1;
        }
        if input.display_order.is_some() {
            updates.push(format!("display_order = ${param_idx}"));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE catalog_categories SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, CatalogCategory>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(parent_id) = input.parent_id {
            q = q.bind(parent_id);
        }
        if let Some(ref icon) = input.icon {
            q = q.bind(icon);
        }
        if let Some(display_order) = input.display_order {
            q = q.bind(display_order);
        }

        q.fetch_optional(pool).await
    }

    /// Delete a catalog category.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM catalog_categories
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// List children of a category.
    pub async fn list_children(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        parent_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM catalog_categories
            WHERE tenant_id = $1 AND parent_id = $2
            ORDER BY display_order, name
            ",
        )
        .bind(tenant_id)
        .bind(parent_id)
        .fetch_all(pool)
        .await
    }

    /// List root categories (no parent).
    pub async fn list_root(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM catalog_categories
            WHERE tenant_id = $1 AND parent_id IS NULL
            ORDER BY display_order, name
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Count items in this category.
    pub async fn count_items(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        category_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM catalog_items
            WHERE tenant_id = $1 AND category_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(category_id)
        .fetch_one(pool)
        .await
    }

    /// Check if category has children.
    pub async fn has_children(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM catalog_categories
            WHERE tenant_id = $1 AND parent_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_category_request() {
        let request = CreateCatalogCategory {
            name: "Developer Tools".to_string(),
            description: Some("Access to development resources".to_string()),
            parent_id: None,
            icon: Some("tools".to_string()),
            display_order: 1,
        };

        assert_eq!(request.name, "Developer Tools");
        assert!(request.parent_id.is_none());
        assert_eq!(request.display_order, 1);
    }

    #[test]
    fn test_category_serialization() {
        let category = CatalogCategory {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test Category".to_string(),
            description: None,
            parent_id: None,
            icon: None,
            display_order: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&category).unwrap();
        assert!(json.contains("Test Category"));
    }

    #[test]
    fn test_category_filter_default() {
        let filter = CatalogCategoryFilter::default();
        assert!(filter.parent_id.is_none());
    }
}
