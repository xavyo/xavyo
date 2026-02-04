//! Admin role template model for delegated administration.
//!
//! Represents a named collection of permissions that can be assigned to users.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

use super::AdminPermission;

/// Admin role template entity.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminRoleTemplate {
    /// Unique identifier.
    pub id: Uuid,
    /// Tenant ID (NULL for system templates).
    pub tenant_id: Option<Uuid>,
    /// Template name.
    pub name: String,
    /// Template description.
    pub description: Option<String>,
    /// Whether this is a system template (immutable).
    pub is_system: bool,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Input for creating a new role template.
#[derive(Debug, Clone)]
pub struct CreateRoleTemplate {
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
}

/// Input for updating a role template.
#[derive(Debug, Clone)]
pub struct UpdateRoleTemplate {
    pub name: Option<String>,
    pub description: Option<String>,
}

impl AdminRoleTemplate {
    /// Create a new custom role template.
    pub async fn create<'e, E>(executor: E, input: CreateRoleTemplate) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r"
            INSERT INTO admin_role_templates (tenant_id, name, description, is_system)
            VALUES ($1, $2, $3, false)
            RETURNING id, tenant_id, name, description, is_system, created_at, updated_at
            ",
        )
        .bind(input.tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .fetch_one(executor)
        .await
    }

    /// Get a role template by ID.
    /// Returns system templates regardless of tenant, or tenant-specific templates.
    pub async fn get_by_id<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, name, description, is_system, created_at, updated_at
            FROM admin_role_templates
            WHERE id = $1 AND (tenant_id IS NULL OR tenant_id = $2)
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(executor)
        .await
    }

    /// Get a role template by ID without tenant check (for internal use).
    pub async fn get_by_id_any<'e, E>(executor: E, id: Uuid) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, name, description, is_system, created_at, updated_at
            FROM admin_role_templates
            WHERE id = $1
            ",
        )
        .bind(id)
        .fetch_optional(executor)
        .await
    }

    /// List all role templates for a tenant (includes system templates).
    pub async fn list<'e, E>(
        executor: E,
        tenant_id: Uuid,
        include_system: bool,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        if include_system {
            sqlx::query_as::<_, Self>(
                r"
                SELECT id, tenant_id, name, description, is_system, created_at, updated_at
                FROM admin_role_templates
                WHERE tenant_id IS NULL OR tenant_id = $1
                ORDER BY is_system DESC, name
                ",
            )
            .bind(tenant_id)
            .fetch_all(executor)
            .await
        } else {
            sqlx::query_as::<_, Self>(
                r"
                SELECT id, tenant_id, name, description, is_system, created_at, updated_at
                FROM admin_role_templates
                WHERE tenant_id = $1
                ORDER BY name
                ",
            )
            .bind(tenant_id)
            .fetch_all(executor)
            .await
        }
    }

    /// Update a custom role template.
    pub async fn update<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateRoleTemplate,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r"
            UPDATE admin_role_templates
            SET name = COALESCE($3, name),
                description = COALESCE($4, description),
                updated_at = now()
            WHERE id = $1 AND tenant_id = $2 AND is_system = false
            RETURNING id, tenant_id, name, description, is_system, created_at, updated_at
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .fetch_optional(executor)
        .await
    }

    /// Delete a custom role template.
    /// Returns true if deleted, false if not found or is a system template.
    pub async fn delete<'e, E>(executor: E, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query(
            r"
            DELETE FROM admin_role_templates
            WHERE id = $1 AND tenant_id = $2 AND is_system = false
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(executor)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if a template name exists for a tenant.
    pub async fn name_exists<'e, E>(
        executor: E,
        tenant_id: Uuid,
        name: &str,
        exclude_id: Option<Uuid>,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let row: (bool,) = if let Some(id) = exclude_id {
            sqlx::query_as(
                r"
                SELECT EXISTS(
                    SELECT 1 FROM admin_role_templates
                    WHERE (tenant_id IS NULL OR tenant_id = $1)
                    AND name = $2 AND id != $3
                )
                ",
            )
            .bind(tenant_id)
            .bind(name)
            .bind(id)
            .fetch_one(executor)
            .await?
        } else {
            sqlx::query_as(
                r"
                SELECT EXISTS(
                    SELECT 1 FROM admin_role_templates
                    WHERE (tenant_id IS NULL OR tenant_id = $1) AND name = $2
                )
                ",
            )
            .bind(tenant_id)
            .bind(name)
            .fetch_one(executor)
            .await?
        };

        Ok(row.0)
    }

    /// Get permissions for a template.
    pub async fn get_permissions<'e, E>(
        executor: E,
        template_id: Uuid,
    ) -> Result<Vec<AdminPermission>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, AdminPermission>(
            r"
            SELECT p.id, p.code, p.name, p.description, p.category, p.created_at
            FROM admin_permissions p
            JOIN admin_role_template_permissions tp ON tp.permission_id = p.id
            WHERE tp.template_id = $1
            ORDER BY p.category, p.code
            ",
        )
        .bind(template_id)
        .fetch_all(executor)
        .await
    }

    /// Set permissions for a template (replaces existing).
    /// Note: Uses a transaction internally, requires a pool or connection.
    pub async fn set_permissions(
        pool: &sqlx::PgPool,
        template_id: Uuid,
        permission_ids: &[Uuid],
    ) -> Result<(), sqlx::Error> {
        // Delete existing permissions
        sqlx::query(
            r"
            DELETE FROM admin_role_template_permissions
            WHERE template_id = $1
            ",
        )
        .bind(template_id)
        .execute(pool)
        .await?;

        // Insert new permissions
        for permission_id in permission_ids {
            sqlx::query(
                r"
                INSERT INTO admin_role_template_permissions (template_id, permission_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
                ",
            )
            .bind(template_id)
            .bind(permission_id)
            .execute(pool)
            .await?;
        }

        Ok(())
    }

    /// Add permissions to a template.
    /// Note: Uses a pool to allow multiple executions.
    pub async fn add_permissions(
        pool: &sqlx::PgPool,
        template_id: Uuid,
        permission_ids: &[Uuid],
    ) -> Result<(), sqlx::Error> {
        for permission_id in permission_ids {
            sqlx::query(
                r"
                INSERT INTO admin_role_template_permissions (template_id, permission_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
                ",
            )
            .bind(template_id)
            .bind(permission_id)
            .execute(pool)
            .await?;
        }

        Ok(())
    }

    /// Count templates for a tenant.
    pub async fn count<'e, E>(executor: E, tenant_id: Uuid) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let row: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM admin_role_templates
            WHERE tenant_id IS NULL OR tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_role_template_input() {
        let input = CreateRoleTemplate {
            tenant_id: Uuid::new_v4(),
            name: "Test Template".to_string(),
            description: Some("A test template".to_string()),
        };

        assert_eq!(input.name, "Test Template");
        assert!(input.description.is_some());
    }

    #[test]
    fn test_update_role_template_input() {
        let input = UpdateRoleTemplate {
            name: Some("Updated Name".to_string()),
            description: None,
        };

        assert!(input.name.is_some());
        assert!(input.description.is_none());
    }
}
