//! Admin role template permission model for delegated administration.
//!
//! Represents the many-to-many relationship between role templates and permissions.

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// Admin role template permission link entity.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminRoleTemplatePermission {
    /// Template ID.
    pub template_id: Uuid,
    /// Permission ID.
    pub permission_id: Uuid,
}

impl AdminRoleTemplatePermission {
    /// Create a new template-permission link.
    pub async fn create<'e, E>(
        executor: E,
        template_id: Uuid,
        permission_id: Uuid,
    ) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r"
            INSERT INTO admin_role_template_permissions (template_id, permission_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            RETURNING template_id, permission_id
            ",
        )
        .bind(template_id)
        .bind(permission_id)
        .fetch_one(executor)
        .await
    }

    /// Delete a template-permission link.
    pub async fn delete<'e, E>(
        executor: E,
        template_id: Uuid,
        permission_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query(
            r"
            DELETE FROM admin_role_template_permissions
            WHERE template_id = $1 AND permission_id = $2
            ",
        )
        .bind(template_id)
        .bind(permission_id)
        .execute(executor)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get all permission IDs for a template.
    pub async fn get_permission_ids_for_template<'e, E>(
        executor: E,
        template_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            r"
            SELECT permission_id FROM admin_role_template_permissions
            WHERE template_id = $1
            ",
        )
        .bind(template_id)
        .fetch_all(executor)
        .await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Get all template IDs that have a specific permission.
    pub async fn get_template_ids_for_permission<'e, E>(
        executor: E,
        permission_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            r"
            SELECT template_id FROM admin_role_template_permissions
            WHERE permission_id = $1
            ",
        )
        .bind(permission_id)
        .fetch_all(executor)
        .await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Delete all permission links for a template.
    pub async fn delete_all_for_template<'e, E>(
        executor: E,
        template_id: Uuid,
    ) -> Result<u64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query(
            r"
            DELETE FROM admin_role_template_permissions
            WHERE template_id = $1
            ",
        )
        .bind(template_id)
        .execute(executor)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count permissions for a template.
    pub async fn count_for_template<'e, E>(
        executor: E,
        template_id: Uuid,
    ) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let row: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM admin_role_template_permissions
            WHERE template_id = $1
            ",
        )
        .bind(template_id)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_role_template_permission_struct() {
        let link = AdminRoleTemplatePermission {
            template_id: Uuid::new_v4(),
            permission_id: Uuid::new_v4(),
        };

        assert_ne!(link.template_id, link.permission_id);
    }
}
