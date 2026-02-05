//! Request Cart Item model for Self-Service Request Catalog (F-062).
//!
//! Individual item in a request cart.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// An individual item in a request cart.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RequestCartItem {
    /// Unique identifier for the cart item.
    pub id: Uuid,

    /// The tenant this item belongs to.
    pub tenant_id: Uuid,

    /// The cart this item belongs to.
    pub cart_id: Uuid,

    /// The catalog item being requested.
    pub catalog_item_id: Uuid,

    /// Parameters for parametric roles (JSONB).
    #[sqlx(json)]
    pub parameters: serde_json::Value,

    /// Form field values filled by requester (JSONB).
    #[sqlx(json)]
    pub form_values: serde_json::Value,

    /// When the item was added to cart.
    pub added_at: DateTime<Utc>,
}

/// Request to add an item to a cart.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AddCartItem {
    /// The catalog item to add.
    pub catalog_item_id: Uuid,

    /// Parameters for parametric roles.
    #[serde(default)]
    pub parameters: serde_json::Value,

    /// Form field values.
    #[serde(default)]
    pub form_values: serde_json::Value,
}

/// Request to update a cart item.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateCartItem {
    /// New parameters.
    pub parameters: Option<serde_json::Value>,

    /// New form field values.
    pub form_values: Option<serde_json::Value>,
}

/// Cart item with catalog item details joined.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CartItemWithDetails {
    /// Cart item ID.
    pub id: Uuid,

    /// Cart ID.
    pub cart_id: Uuid,

    /// Catalog item ID.
    pub catalog_item_id: Uuid,

    /// Parameters (JSONB).
    #[sqlx(json)]
    pub parameters: serde_json::Value,

    /// Form values (JSONB).
    #[sqlx(json)]
    pub form_values: serde_json::Value,

    /// When added to cart.
    pub added_at: DateTime<Utc>,

    /// Catalog item name.
    pub item_name: String,

    /// Catalog item description.
    pub item_description: Option<String>,

    /// Catalog item type.
    pub item_type: String,

    /// Whether the catalog item is still enabled.
    pub item_enabled: bool,
}

impl RequestCartItem {
    /// Find a cart item by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM request_cart_items
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a cart item by cart and catalog item (with same parameters).
    pub async fn find_duplicate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        cart_id: Uuid,
        catalog_item_id: Uuid,
        parameters: &serde_json::Value,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM request_cart_items
            WHERE tenant_id = $1 AND cart_id = $2 AND catalog_item_id = $3 AND parameters = $4
            ",
        )
        .bind(tenant_id)
        .bind(cart_id)
        .bind(catalog_item_id)
        .bind(parameters)
        .fetch_optional(pool)
        .await
    }

    /// List all items in a cart.
    pub async fn list_by_cart(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        cart_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM request_cart_items
            WHERE tenant_id = $1 AND cart_id = $2
            ORDER BY added_at
            ",
        )
        .bind(tenant_id)
        .bind(cart_id)
        .fetch_all(pool)
        .await
    }

    /// List items in a cart with catalog item details.
    pub async fn list_by_cart_with_details(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        cart_id: Uuid,
    ) -> Result<Vec<CartItemWithDetails>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT
                rci.id,
                rci.cart_id,
                rci.catalog_item_id,
                rci.parameters,
                rci.form_values,
                rci.added_at,
                ci.name AS item_name,
                ci.description AS item_description,
                ci.item_type::text AS item_type,
                ci.enabled AS item_enabled
            FROM request_cart_items rci
            JOIN catalog_items ci ON ci.id = rci.catalog_item_id AND ci.tenant_id = rci.tenant_id
            WHERE rci.tenant_id = $1 AND rci.cart_id = $2
            ORDER BY rci.added_at
            ",
        )
        .bind(tenant_id)
        .bind(cart_id)
        .fetch_all(pool)
        .await
    }

    /// Add an item to a cart.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        cart_id: Uuid,
        input: AddCartItem,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO request_cart_items (tenant_id, cart_id, catalog_item_id, parameters, form_values)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(cart_id)
        .bind(input.catalog_item_id)
        .bind(&input.parameters)
        .bind(&input.form_values)
        .fetch_one(pool)
        .await
    }

    /// Update a cart item.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateCartItem,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = Vec::new();
        let mut param_idx = 3;

        if input.parameters.is_some() {
            updates.push(format!("parameters = ${param_idx}"));
            param_idx += 1;
        }
        if input.form_values.is_some() {
            updates.push(format!("form_values = ${param_idx}"));
            // param_idx += 1;
        }

        if updates.is_empty() {
            // Nothing to update, return current state
            return Self::find_by_id(pool, tenant_id, id).await;
        }

        let query = format!(
            "UPDATE request_cart_items SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, RequestCartItem>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref parameters) = input.parameters {
            q = q.bind(parameters);
        }
        if let Some(ref form_values) = input.form_values {
            q = q.bind(form_values);
        }

        q.fetch_optional(pool).await
    }

    /// Delete a cart item.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM request_cart_items
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete a cart item by cart and catalog item.
    pub async fn delete_by_catalog_item(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        cart_id: Uuid,
        catalog_item_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM request_cart_items
            WHERE tenant_id = $1 AND cart_id = $2 AND catalog_item_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(cart_id)
        .bind(catalog_item_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Count items in a cart.
    pub async fn count_by_cart(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        cart_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM request_cart_items
            WHERE tenant_id = $1 AND cart_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(cart_id)
        .fetch_one(pool)
        .await
    }

    /// Check if a specific catalog item is in the cart.
    pub async fn exists_in_cart(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        cart_id: Uuid,
        catalog_item_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM request_cart_items
            WHERE tenant_id = $1 AND cart_id = $2 AND catalog_item_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(cart_id)
        .bind(catalog_item_id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// Get parameters as a typed value.
    pub fn get_parameters<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_value(self.parameters.clone())
    }

    /// Get form values as a typed value.
    pub fn get_form_values<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_value(self.form_values.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_cart_item_request() {
        let request = AddCartItem {
            catalog_item_id: Uuid::new_v4(),
            parameters: serde_json::json!({"project_id": "abc-123"}),
            form_values: serde_json::json!({"justification": "Need access for project"}),
        };

        assert!(!request.catalog_item_id.is_nil());
    }

    #[test]
    fn test_cart_item_serialization() {
        let item = RequestCartItem {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            cart_id: Uuid::new_v4(),
            catalog_item_id: Uuid::new_v4(),
            parameters: serde_json::json!({}),
            form_values: serde_json::json!({}),
            added_at: Utc::now(),
        };

        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("catalog_item_id"));
    }

    #[test]
    fn test_update_cart_item_request() {
        let request = UpdateCartItem {
            parameters: Some(serde_json::json!({"new_param": "value"})),
            form_values: None,
        };

        assert!(request.parameters.is_some());
        assert!(request.form_values.is_none());
    }

    #[test]
    fn test_get_parameters() {
        let item = RequestCartItem {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            cart_id: Uuid::new_v4(),
            catalog_item_id: Uuid::new_v4(),
            parameters: serde_json::json!({"key": "value"}),
            form_values: serde_json::json!({}),
            added_at: Utc::now(),
        };

        let params: serde_json::Value = item.get_parameters().unwrap();
        assert_eq!(params["key"], "value");
    }
}
