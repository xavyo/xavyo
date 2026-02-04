//! Tenant attribute definition model (F070).
//!
//! Defines the custom attributes schema for a tenant.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// A custom attribute definition for a tenant.
///
/// Tenants define which custom attributes their users can have,
/// including the data type, whether the attribute is required,
/// and any validation rules.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TenantAttributeDefinition {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this definition belongs to.
    pub tenant_id: Uuid,

    /// Attribute name (lowercase, alphanumeric + underscore, 1-64 chars).
    pub name: String,

    /// Human-readable display label.
    pub display_label: String,

    /// Data type: string, number, boolean, date, json.
    pub data_type: String,

    /// Whether this attribute is required on user creation/update.
    pub required: bool,

    /// Type-specific validation constraints (JSONB).
    pub validation_rules: Option<serde_json::Value>,

    /// Default value when attribute not provided (JSONB).
    pub default_value: Option<serde_json::Value>,

    /// Display ordering.
    pub sort_order: i32,

    /// Soft-delete flag (false = inactive/hidden).
    pub is_active: bool,

    /// Whether this attribute was seeded from the well-known catalog (F081).
    pub is_well_known: bool,

    /// Original well-known catalog slug for cross-tenant interoperability (F081).
    pub well_known_slug: Option<String>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl TenantAttributeDefinition {
    /// Create a new attribute definition.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        name: &str,
        display_label: &str,
        data_type: &str,
        required: bool,
        validation_rules: Option<serde_json::Value>,
        default_value: Option<serde_json::Value>,
        sort_order: i32,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO tenant_attribute_definitions
                (tenant_id, name, display_label, data_type, required, validation_rules, default_value, sort_order)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .bind(display_label)
        .bind(data_type)
        .bind(required)
        .bind(&validation_rules)
        .bind(&default_value)
        .bind(sort_order)
        .fetch_one(pool)
        .await
    }

    /// Create a well-known attribute definition (F081).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_well_known(
        pool: &PgPool,
        tenant_id: Uuid,
        name: &str,
        display_label: &str,
        data_type: &str,
        required: bool,
        validation_rules: Option<serde_json::Value>,
        default_value: Option<serde_json::Value>,
        sort_order: i32,
        well_known_slug: &str,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO tenant_attribute_definitions
                (tenant_id, name, display_label, data_type, required, validation_rules,
                 default_value, sort_order, is_well_known, well_known_slug)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, $9)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .bind(display_label)
        .bind(data_type)
        .bind(required)
        .bind(&validation_rules)
        .bind(&default_value)
        .bind(sort_order)
        .bind(well_known_slug)
        .fetch_one(pool)
        .await
    }

    /// Get an attribute definition by ID within a tenant.
    pub async fn get_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM tenant_attribute_definitions
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Get an attribute definition by name within a tenant.
    pub async fn get_by_name(
        pool: &PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM tenant_attribute_definitions
            WHERE tenant_id = $1 AND name = $2
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List attribute definitions for a tenant with optional filters.
    pub async fn list_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        is_active: Option<bool>,
        data_type: Option<&str>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        // Build query dynamically based on filters
        match (is_active, data_type) {
            (Some(active), Some(dt)) => {
                sqlx::query_as(
                    r"
                    SELECT * FROM tenant_attribute_definitions
                    WHERE tenant_id = $1 AND is_active = $2 AND data_type = $3
                    ORDER BY sort_order ASC, name ASC
                    ",
                )
                .bind(tenant_id)
                .bind(active)
                .bind(dt)
                .fetch_all(pool)
                .await
            }
            (Some(active), None) => {
                sqlx::query_as(
                    r"
                    SELECT * FROM tenant_attribute_definitions
                    WHERE tenant_id = $1 AND is_active = $2
                    ORDER BY sort_order ASC, name ASC
                    ",
                )
                .bind(tenant_id)
                .bind(active)
                .fetch_all(pool)
                .await
            }
            (None, Some(dt)) => {
                sqlx::query_as(
                    r"
                    SELECT * FROM tenant_attribute_definitions
                    WHERE tenant_id = $1 AND data_type = $2
                    ORDER BY sort_order ASC, name ASC
                    ",
                )
                .bind(tenant_id)
                .bind(dt)
                .fetch_all(pool)
                .await
            }
            (None, None) => {
                sqlx::query_as(
                    r"
                    SELECT * FROM tenant_attribute_definitions
                    WHERE tenant_id = $1
                    ORDER BY sort_order ASC, name ASC
                    ",
                )
                .bind(tenant_id)
                .fetch_all(pool)
                .await
            }
        }
    }

    /// Count attribute definitions for a tenant (for limit enforcement).
    pub async fn count_by_tenant(pool: &PgPool, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM tenant_attribute_definitions
            WHERE tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// List all required active attribute definitions for a tenant (for audit).
    pub async fn list_required_active(
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM tenant_attribute_definitions
            WHERE tenant_id = $1 AND required = true AND is_active = true
            ORDER BY sort_order ASC, name ASC
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Update an attribute definition.
    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        display_label: Option<&str>,
        required: Option<bool>,
        validation_rules: Option<serde_json::Value>,
        default_value: Option<serde_json::Value>,
        sort_order: Option<i32>,
        is_active: Option<bool>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE tenant_attribute_definitions
            SET display_label = COALESCE($3, display_label),
                required = COALESCE($4, required),
                validation_rules = CASE WHEN $5::boolean THEN $6 ELSE validation_rules END,
                default_value = CASE WHEN $7::boolean THEN $8 ELSE default_value END,
                sort_order = COALESCE($9, sort_order),
                is_active = COALESCE($10, is_active),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(display_label)
        .bind(required)
        .bind(validation_rules.is_some()) // $5: flag for whether to update validation_rules
        .bind(&validation_rules) // $6: new validation_rules value
        .bind(default_value.is_some()) // $7: flag for whether to update default_value
        .bind(&default_value) // $8: new default_value value
        .bind(sort_order)
        .bind(is_active)
        .fetch_optional(pool)
        .await
    }

    /// Delete an attribute definition (hard delete).
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM tenant_attribute_definitions
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if any users in the tenant have a value for a specific attribute.
    pub async fn has_user_data(
        pool: &PgPool,
        tenant_id: Uuid,
        attribute_name: &str,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM users
            WHERE tenant_id = $1 AND custom_attributes ? $2
            ",
        )
        .bind(tenant_id)
        .bind(attribute_name)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }
}
