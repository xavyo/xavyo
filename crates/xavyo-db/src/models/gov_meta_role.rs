//! Governance Meta-role model (F056).
//!
//! Represents a meta-role that automatically applies to other roles based on matching criteria.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::{CriteriaLogic, MetaRoleStatus};

/// A meta-role that applies to other roles based on matching criteria.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovMetaRole {
    /// Unique identifier for the meta-role.
    pub id: Uuid,

    /// The tenant this meta-role belongs to.
    pub tenant_id: Uuid,

    /// Display name for the meta-role.
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// Priority for conflict resolution (lower = higher precedence).
    pub priority: i32,

    /// Current status (active or disabled).
    pub status: MetaRoleStatus,

    /// Logic for combining criteria (AND or OR).
    pub criteria_logic: CriteriaLogic,

    /// User who created this meta-role.
    pub created_by: Uuid,

    /// When the meta-role was created.
    pub created_at: DateTime<Utc>,

    /// When the meta-role was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new meta-role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovMetaRole {
    pub name: String,
    pub description: Option<String>,
    pub priority: Option<i32>,
    pub criteria_logic: Option<CriteriaLogic>,
}

/// Request to update a meta-role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovMetaRole {
    pub name: Option<String>,
    pub description: Option<String>,
    pub priority: Option<i32>,
    pub criteria_logic: Option<CriteriaLogic>,
}

/// Filter options for listing meta-roles.
#[derive(Debug, Clone, Default)]
pub struct MetaRoleFilter {
    pub status: Option<MetaRoleStatus>,
    pub name_contains: Option<String>,
    pub priority_min: Option<i32>,
    pub priority_max: Option<i32>,
}

/// Default priority for meta-roles.
pub const DEFAULT_PRIORITY: i32 = 100;

/// Minimum priority value.
pub const MIN_PRIORITY: i32 = 1;

/// Maximum priority value.
pub const MAX_PRIORITY: i32 = 1000;

impl GovMetaRole {
    /// Find a meta-role by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_meta_roles
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a meta-role by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_meta_roles
            WHERE tenant_id = $1 AND name = $2
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List all active meta-roles for a tenant ordered by priority.
    pub async fn list_active(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_meta_roles
            WHERE tenant_id = $1 AND status = 'active'
            ORDER BY priority ASC, name ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List meta-roles with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &MetaRoleFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_meta_roles WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.name_contains.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE ${}", param_count));
        }
        if filter.priority_min.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND priority >= ${}", param_count));
        }
        if filter.priority_max.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND priority <= ${}", param_count));
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
        if let Some(ref name_contains) = filter.name_contains {
            q = q.bind(format!("%{}%", name_contains));
        }
        if let Some(priority_min) = filter.priority_min {
            q = q.bind(priority_min);
        }
        if let Some(priority_max) = filter.priority_max {
            q = q.bind(priority_max);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count meta-roles with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &MetaRoleFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from("SELECT COUNT(*) FROM gov_meta_roles WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.name_contains.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE ${}", param_count));
        }
        if filter.priority_min.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND priority >= ${}", param_count));
        }
        if filter.priority_max.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND priority <= ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(ref name_contains) = filter.name_contains {
            q = q.bind(format!("%{}%", name_contains));
        }
        if let Some(priority_min) = filter.priority_min {
            q = q.bind(priority_min);
        }
        if let Some(priority_max) = filter.priority_max {
            q = q.bind(priority_max);
        }

        q.fetch_one(pool).await
    }

    /// Create a new meta-role.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        created_by: Uuid,
        input: CreateGovMetaRole,
    ) -> Result<Self, sqlx::Error> {
        let priority = input.priority.unwrap_or(DEFAULT_PRIORITY);
        let criteria_logic = input.criteria_logic.unwrap_or_default();

        sqlx::query_as(
            r#"
            INSERT INTO gov_meta_roles (
                tenant_id, name, description, priority, criteria_logic, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(priority)
        .bind(criteria_logic)
        .bind(created_by)
        .fetch_one(pool)
        .await
    }

    /// Update a meta-role.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovMetaRole,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Build dynamic update query
        let mut updates = Vec::new();
        let mut param_count = 2; // $1 = id, $2 = tenant_id

        if input.name.is_some() {
            param_count += 1;
            updates.push(format!("name = ${}", param_count));
        }
        if input.description.is_some() {
            param_count += 1;
            updates.push(format!("description = ${}", param_count));
        }
        if input.priority.is_some() {
            param_count += 1;
            updates.push(format!("priority = ${}", param_count));
        }
        if input.criteria_logic.is_some() {
            param_count += 1;
            updates.push(format!("criteria_logic = ${}", param_count));
        }

        if updates.is_empty() {
            return Self::find_by_id(pool, tenant_id, id).await;
        }

        updates.push("updated_at = NOW()".to_string());
        let query = format!(
            "UPDATE gov_meta_roles SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
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
        if let Some(criteria_logic) = input.criteria_logic {
            q = q.bind(criteria_logic);
        }

        q.fetch_optional(pool).await
    }

    /// Disable a meta-role.
    pub async fn disable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_meta_roles
            SET status = 'disabled', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Enable a meta-role.
    pub async fn enable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_meta_roles
            SET status = 'active', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'disabled'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a meta-role.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_meta_roles
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if meta-role is active.
    pub fn is_active(&self) -> bool {
        self.status == MetaRoleStatus::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_meta_role_defaults() {
        let input = CreateGovMetaRole {
            name: "Test Meta-Role".to_string(),
            description: None,
            priority: None,
            criteria_logic: None,
        };

        assert_eq!(input.name, "Test Meta-Role");
        assert!(input.description.is_none());
        assert!(input.priority.is_none());
    }

    #[test]
    fn test_priority_constants() {
        assert_eq!(DEFAULT_PRIORITY, 100);
        assert_eq!(MIN_PRIORITY, 1);
        assert_eq!(MAX_PRIORITY, 1000);
        assert!(MIN_PRIORITY < DEFAULT_PRIORITY);
        assert!(DEFAULT_PRIORITY < MAX_PRIORITY);
    }

    #[test]
    fn test_filter_default() {
        let filter = MetaRoleFilter::default();
        assert!(filter.status.is_none());
        assert!(filter.name_contains.is_none());
        assert!(filter.priority_min.is_none());
        assert!(filter.priority_max.is_none());
    }
}
