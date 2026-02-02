//! Governance Lifecycle Configuration model.
//!
//! Represents configurable lifecycle state machines for object types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Object types that can have lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_lifecycle_object_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum LifecycleObjectType {
    /// User identity object.
    User,
    /// Entitlement/access right object.
    Entitlement,
    /// Role object.
    Role,
}

/// A governance lifecycle configuration.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovLifecycleConfig {
    /// Unique identifier for the configuration.
    pub id: Uuid,

    /// The tenant this configuration belongs to.
    pub tenant_id: Uuid,

    /// Configuration display name.
    pub name: String,

    /// Object type this configuration applies to.
    pub object_type: LifecycleObjectType,

    /// Configuration description.
    pub description: Option<String>,

    /// Whether the configuration is active.
    pub is_active: bool,

    /// When the configuration was created.
    pub created_at: DateTime<Utc>,

    /// When the configuration was last updated.
    pub updated_at: DateTime<Utc>,

    /// Whether to auto-assign initial state to new objects.
    #[sqlx(default)]
    pub auto_assign_initial_state: bool,
}

/// Request to create a new lifecycle configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovLifecycleConfig {
    pub name: String,
    pub object_type: LifecycleObjectType,
    pub description: Option<String>,
    #[serde(default = "default_auto_assign")]
    pub auto_assign_initial_state: bool,
}

fn default_auto_assign() -> bool {
    true
}

/// Request to update a lifecycle configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovLifecycleConfig {
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_active: Option<bool>,
    pub auto_assign_initial_state: Option<bool>,
}

/// Filter options for listing lifecycle configurations.
#[derive(Debug, Clone, Default)]
pub struct LifecycleConfigFilter {
    pub object_type: Option<LifecycleObjectType>,
    pub is_active: Option<bool>,
}

impl GovLifecycleConfig {
    /// Find a configuration by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_lifecycle_configs
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a configuration by object type within a tenant.
    pub async fn find_by_object_type(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        object_type: LifecycleObjectType,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_lifecycle_configs
            WHERE tenant_id = $1 AND object_type = $2
            "#,
        )
        .bind(tenant_id)
        .bind(object_type)
        .fetch_optional(pool)
        .await
    }

    /// List configurations for a tenant with optional filters.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &LifecycleConfigFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_lifecycle_configs
            WHERE tenant_id = $1
            "#,
        );

        let mut param_num = 2;

        if filter.object_type.is_some() {
            query.push_str(&format!(" AND object_type = ${}", param_num));
            param_num += 1;
        }

        if filter.is_active.is_some() {
            query.push_str(&format!(" AND is_active = ${}", param_num));
            param_num += 1;
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_num,
            param_num + 1
        ));

        let mut db_query = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(object_type) = &filter.object_type {
            db_query = db_query.bind(object_type);
        }

        if let Some(is_active) = filter.is_active {
            db_query = db_query.bind(is_active);
        }

        db_query.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count configurations for a tenant with optional filters.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &LifecycleConfigFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_lifecycle_configs
            WHERE tenant_id = $1
            "#,
        );

        let mut param_num = 2;

        if filter.object_type.is_some() {
            query.push_str(&format!(" AND object_type = ${}", param_num));
            param_num += 1;
        }

        if filter.is_active.is_some() {
            query.push_str(&format!(" AND is_active = ${}", param_num));
        }

        let mut db_query = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(object_type) = &filter.object_type {
            db_query = db_query.bind(object_type);
        }

        if let Some(is_active) = filter.is_active {
            db_query = db_query.bind(is_active);
        }

        db_query.fetch_one(pool).await
    }

    /// Create a new lifecycle configuration.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: &CreateGovLifecycleConfig,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_lifecycle_configs (tenant_id, name, object_type, description)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(input.object_type)
        .bind(&input.description)
        .fetch_one(pool)
        .await
    }

    /// Update a lifecycle configuration.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: &UpdateGovLifecycleConfig,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_lifecycle_configs
            SET
                name = COALESCE($3, name),
                description = COALESCE($4, description),
                is_active = COALESCE($5, is_active),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.is_active)
        .fetch_optional(pool)
        .await
    }

    /// Delete a lifecycle configuration.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_lifecycle_configs
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}
