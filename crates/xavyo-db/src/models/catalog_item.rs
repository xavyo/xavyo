//! Catalog Item model for Self-Service Request Catalog (F-062).
//!
//! Represents a requestable item in the catalog (role, entitlement, or resource).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Type of catalog item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "catalog_item_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum CatalogItemType {
    /// Role-based access item.
    Role,
    /// Entitlement-based access item.
    Entitlement,
    /// Generic resource access item.
    Resource,
}

/// Requestability rules for who can request an item.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RequestabilityRules {
    /// Whether users can request this for themselves.
    #[serde(default = "default_true")]
    pub self_request: bool,

    /// Whether managers can request this for direct reports.
    #[serde(default = "default_true")]
    pub manager_request: bool,

    /// Department restrictions (empty = no restriction).
    #[serde(default)]
    pub department_restriction: Vec<String>,

    /// Prerequisite roles that must be held before requesting.
    #[serde(default)]
    pub prerequisite_roles: Vec<Uuid>,

    /// Prerequisite entitlements that must be held before requesting.
    #[serde(default)]
    pub prerequisite_entitlements: Vec<Uuid>,

    /// Archetype restrictions (empty = no restriction).
    #[serde(default)]
    pub archetype_restriction: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// Form field definition for catalog items.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FormField {
    /// Field name (key).
    pub name: String,

    /// Field type (text, textarea, select, checkbox, etc.).
    #[serde(rename = "type")]
    pub field_type: String,

    /// Display label.
    pub label: String,

    /// Whether field is required.
    #[serde(default)]
    pub required: bool,

    /// Options for select fields.
    #[serde(default)]
    pub options: Vec<String>,

    /// Default value.
    pub default: Option<String>,
}

/// A catalog item representing a requestable access right.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CatalogItem {
    /// Unique identifier for the item.
    pub id: Uuid,

    /// The tenant this item belongs to.
    pub tenant_id: Uuid,

    /// Category for organization.
    pub category_id: Option<Uuid>,

    /// Type of item (role, entitlement, resource).
    pub item_type: CatalogItemType,

    /// Item display name.
    pub name: String,

    /// Item description.
    pub description: Option<String>,

    /// Reference to the underlying role or entitlement.
    pub reference_id: Option<Uuid>,

    /// Requestability rules (JSONB).
    #[sqlx(json)]
    pub requestability_rules: serde_json::Value,

    /// Form field definitions (JSONB array).
    #[sqlx(json)]
    pub form_fields: serde_json::Value,

    /// Searchable tags.
    pub tags: Vec<String>,

    /// Icon identifier for UI display.
    pub icon: Option<String>,

    /// Whether item is enabled and visible.
    pub enabled: bool,

    /// Version number for audit.
    pub version: i32,

    /// When the item was created.
    pub created_at: DateTime<Utc>,

    /// When the item was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new catalog item.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateCatalogItem {
    /// Category for organization.
    pub category_id: Option<Uuid>,

    /// Type of item.
    pub item_type: CatalogItemType,

    /// Item display name.
    pub name: String,

    /// Item description.
    pub description: Option<String>,

    /// Reference to the underlying role or entitlement.
    pub reference_id: Option<Uuid>,

    /// Requestability rules.
    #[serde(default)]
    pub requestability_rules: RequestabilityRules,

    /// Form field definitions.
    #[serde(default)]
    pub form_fields: Vec<FormField>,

    /// Searchable tags.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Icon identifier for UI display.
    pub icon: Option<String>,
}

/// Request to update a catalog item.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateCatalogItem {
    /// New category ID.
    pub category_id: Option<Uuid>,

    /// New name.
    pub name: Option<String>,

    /// New description.
    pub description: Option<String>,

    /// New requestability rules.
    pub requestability_rules: Option<RequestabilityRules>,

    /// New form field definitions.
    pub form_fields: Option<Vec<FormField>>,

    /// New tags.
    pub tags: Option<Vec<String>>,

    /// New icon.
    pub icon: Option<String>,
}

/// Filter options for listing catalog items.
#[derive(Debug, Clone, Default)]
pub struct CatalogItemFilter {
    /// Filter by category.
    pub category_id: Option<Uuid>,

    /// Filter by item type.
    pub item_type: Option<CatalogItemType>,

    /// Filter by enabled status.
    pub enabled: Option<bool>,

    /// Full-text search query.
    pub search: Option<String>,

    /// Filter by tag.
    pub tag: Option<String>,
}

impl CatalogItem {
    /// Find an item by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM catalog_items
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find an item by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM catalog_items
            WHERE tenant_id = $1 AND name = $2
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// Find an item by reference ID (the underlying role/entitlement).
    pub async fn find_by_reference(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        reference_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM catalog_items
            WHERE tenant_id = $1 AND reference_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(reference_id)
        .fetch_optional(pool)
        .await
    }

    /// List catalog items for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CatalogItemFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM catalog_items
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.category_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND category_id = ${param_count}"));
        }
        if filter.item_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND item_type = ${param_count}"));
        }
        if filter.enabled.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND enabled = ${param_count}"));
        }
        if filter.search.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND to_tsvector('english', name || ' ' || COALESCE(description, '') || ' ' || array_to_string(tags, ' ')) @@ plainto_tsquery('english', ${param_count})"
            ));
        }
        if filter.tag.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND ${param_count} = ANY(tags)"));
        }

        query.push_str(&format!(
            " ORDER BY name LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, CatalogItem>(&query).bind(tenant_id);

        if let Some(category_id) = filter.category_id {
            q = q.bind(category_id);
        }
        if let Some(item_type) = filter.item_type {
            q = q.bind(item_type);
        }
        if let Some(enabled) = filter.enabled {
            q = q.bind(enabled);
        }
        if let Some(ref search) = filter.search {
            q = q.bind(search);
        }
        if let Some(ref tag) = filter.tag {
            q = q.bind(tag);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count catalog items in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CatalogItemFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM catalog_items
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.category_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND category_id = ${param_count}"));
        }
        if filter.item_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND item_type = ${param_count}"));
        }
        if filter.enabled.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND enabled = ${param_count}"));
        }
        if filter.search.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND to_tsvector('english', name || ' ' || COALESCE(description, '') || ' ' || array_to_string(tags, ' ')) @@ plainto_tsquery('english', ${param_count})"
            ));
        }
        if filter.tag.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND ${param_count} = ANY(tags)"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(category_id) = filter.category_id {
            q = q.bind(category_id);
        }
        if let Some(item_type) = filter.item_type {
            q = q.bind(item_type);
        }
        if let Some(enabled) = filter.enabled {
            q = q.bind(enabled);
        }
        if let Some(ref search) = filter.search {
            q = q.bind(search);
        }
        if let Some(ref tag) = filter.tag {
            q = q.bind(tag);
        }

        q.fetch_one(pool).await
    }

    /// Create a new catalog item.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateCatalogItem,
    ) -> Result<Self, sqlx::Error> {
        let rules_json = serde_json::to_value(&input.requestability_rules)
            .unwrap_or_else(|_| serde_json::json!({}));
        let fields_json =
            serde_json::to_value(&input.form_fields).unwrap_or_else(|_| serde_json::json!([]));

        sqlx::query_as(
            r"
            INSERT INTO catalog_items (tenant_id, category_id, item_type, name, description, reference_id, requestability_rules, form_fields, tags, icon)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.category_id)
        .bind(input.item_type)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.reference_id)
        .bind(&rules_json)
        .bind(&fields_json)
        .bind(&input.tags)
        .bind(&input.icon)
        .fetch_one(pool)
        .await
    }

    /// Update a catalog item.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateCatalogItem,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec![
            "updated_at = NOW()".to_string(),
            "version = version + 1".to_string(),
        ];
        let mut param_idx = 3;

        if input.category_id.is_some() {
            updates.push(format!("category_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${param_idx}"));
            param_idx += 1;
        }
        if input.requestability_rules.is_some() {
            updates.push(format!("requestability_rules = ${param_idx}"));
            param_idx += 1;
        }
        if input.form_fields.is_some() {
            updates.push(format!("form_fields = ${param_idx}"));
            param_idx += 1;
        }
        if input.tags.is_some() {
            updates.push(format!("tags = ${param_idx}"));
            param_idx += 1;
        }
        if input.icon.is_some() {
            updates.push(format!("icon = ${param_idx}"));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE catalog_items SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, CatalogItem>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(category_id) = input.category_id {
            q = q.bind(category_id);
        }
        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(ref rules) = input.requestability_rules {
            let rules_json = serde_json::to_value(rules).unwrap_or_else(|_| serde_json::json!({}));
            q = q.bind(rules_json);
        }
        if let Some(ref fields) = input.form_fields {
            let fields_json =
                serde_json::to_value(fields).unwrap_or_else(|_| serde_json::json!([]));
            q = q.bind(fields_json);
        }
        if let Some(ref tags) = input.tags {
            q = q.bind(tags);
        }
        if let Some(ref icon) = input.icon {
            q = q.bind(icon);
        }

        q.fetch_optional(pool).await
    }

    /// Delete a catalog item.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM catalog_items
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Enable a catalog item.
    pub async fn enable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE catalog_items
            SET enabled = true, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Disable a catalog item.
    pub async fn disable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE catalog_items
            SET enabled = false, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Check if the item is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Parse requestability rules from JSONB.
    #[must_use]
    pub fn get_requestability_rules(&self) -> RequestabilityRules {
        serde_json::from_value(self.requestability_rules.clone()).unwrap_or_default()
    }

    /// Parse form fields from JSONB.
    #[must_use]
    pub fn get_form_fields(&self) -> Vec<FormField> {
        serde_json::from_value(self.form_fields.clone()).unwrap_or_default()
    }

    /// List all enabled items for browsing.
    pub async fn list_enabled(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM catalog_items
            WHERE tenant_id = $1 AND enabled = true
            ORDER BY name
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catalog_item_type_serialization() {
        let role = CatalogItemType::Role;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"role\"");

        let entitlement = CatalogItemType::Entitlement;
        let json = serde_json::to_string(&entitlement).unwrap();
        assert_eq!(json, "\"entitlement\"");
    }

    #[test]
    fn test_requestability_rules_default() {
        let rules = RequestabilityRules::default();
        // Default values based on default_true function
        assert!(!rules.self_request); // default() doesn't call default_true
        assert!(!rules.manager_request);
        assert!(rules.department_restriction.is_empty());
        assert!(rules.prerequisite_roles.is_empty());
    }

    #[test]
    fn test_requestability_rules_serialization() {
        let rules = RequestabilityRules {
            self_request: true,
            manager_request: true,
            department_restriction: vec!["engineering".to_string()],
            prerequisite_roles: vec![],
            prerequisite_entitlements: vec![],
            archetype_restriction: vec![],
        };

        let json = serde_json::to_string(&rules).unwrap();
        assert!(json.contains("engineering"));
    }

    #[test]
    fn test_form_field_serialization() {
        let field = FormField {
            name: "justification".to_string(),
            field_type: "textarea".to_string(),
            label: "Business Justification".to_string(),
            required: true,
            options: vec![],
            default: None,
        };

        let json = serde_json::to_string(&field).unwrap();
        assert!(json.contains("justification"));
        assert!(json.contains("textarea"));
    }

    #[test]
    fn test_create_catalog_item_request() {
        let request = CreateCatalogItem {
            category_id: None,
            item_type: CatalogItemType::Role,
            name: "Developer Access".to_string(),
            description: Some("Standard developer role".to_string()),
            reference_id: Some(Uuid::new_v4()),
            requestability_rules: RequestabilityRules::default(),
            form_fields: vec![],
            tags: vec!["developer".to_string()],
            icon: None,
        };

        assert_eq!(request.name, "Developer Access");
        assert_eq!(request.item_type, CatalogItemType::Role);
    }
}
