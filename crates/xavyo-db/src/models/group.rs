//! Group entity model.
//!
//! User groups for role-based access control.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A user group for RBAC.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Group {
    /// Unique identifier for the group.
    pub id: Uuid,

    /// The tenant this group belongs to.
    pub tenant_id: Uuid,

    /// Group display name.
    pub display_name: String,

    /// External system ID (e.g., Azure AD object ID).
    pub external_id: Option<String>,

    /// Group description.
    pub description: Option<String>,

    /// Parent group ID for hierarchy (NULL = root group).
    pub parent_id: Option<Uuid>,

    /// Group type classification (`organizational_unit`, department, team, `security_group`, `distribution_list`, custom).
    pub group_type: String,

    /// When the group was created.
    pub created_at: DateTime<Utc>,

    /// When the group was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGroup {
    pub display_name: String,
    pub external_id: Option<String>,
    pub description: Option<String>,
    pub parent_id: Option<Uuid>,
    pub group_type: Option<String>,
    pub members: Option<Vec<Uuid>>,
}

/// Request to update a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGroup {
    pub display_name: Option<String>,
    pub external_id: Option<String>,
    pub description: Option<String>,
    /// Use Some(Some(uuid)) to set parent, Some(None) to clear parent, None to leave unchanged.
    pub parent_id: Option<Option<Uuid>>,
    pub group_type: Option<String>,
}

impl Group {
    /// Find a group by ID (without tenant filter — for internal lookups).
    pub async fn find_by_id_only(
        pool: &sqlx::PgPool,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM groups
            WHERE id = $1
            ",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Find a group by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM groups
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a group by display name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        display_name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM groups
            WHERE tenant_id = $1 AND display_name = $2
            ",
        )
        .bind(tenant_id)
        .bind(display_name)
        .fetch_optional(pool)
        .await
    }

    /// Find a group by external ID within a tenant.
    pub async fn find_by_external_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        external_id: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM groups
            WHERE tenant_id = $1 AND external_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(external_id)
        .fetch_optional(pool)
        .await
    }

    /// List all groups for a tenant with pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM groups
            WHERE tenant_id = $1
            ORDER BY display_name
            LIMIT $2 OFFSET $3
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Count groups in a tenant.
    pub async fn count_by_tenant(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
        let result: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM groups
            WHERE tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(result.0)
    }

    /// Create a new group.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        display_name: &str,
        external_id: Option<&str>,
        description: Option<&str>,
        parent_id: Option<Uuid>,
        group_type: Option<&str>,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO groups (tenant_id, display_name, external_id, description, parent_id, group_type)
            VALUES ($1, $2, $3, $4, $5, COALESCE($6, 'security_group'))
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(display_name)
        .bind(external_id)
        .bind(description)
        .bind(parent_id)
        .bind(group_type)
        .fetch_one(pool)
        .await
    }

    /// Update a group.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        update: UpdateGroup,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Build dynamic update query
        let mut query = String::from("UPDATE groups SET updated_at = NOW()");
        let mut param_count = 2; // $1 = id, $2 = tenant_id

        if update.display_name.is_some() {
            param_count += 1;
            query.push_str(&format!(", display_name = ${param_count}"));
        }
        if update.external_id.is_some() {
            param_count += 1;
            query.push_str(&format!(", external_id = ${param_count}"));
        }
        if update.description.is_some() {
            param_count += 1;
            query.push_str(&format!(", description = ${param_count}"));
        }
        if update.parent_id.is_some() {
            param_count += 1;
            query.push_str(&format!(", parent_id = ${param_count}"));
        }
        if update.group_type.is_some() {
            param_count += 1;
            query.push_str(&format!(", group_type = ${param_count}"));
        }

        query.push_str(" WHERE id = $1 AND tenant_id = $2 RETURNING *");

        let mut q = sqlx::query_as::<_, Group>(&query).bind(id).bind(tenant_id);

        if let Some(ref display_name) = update.display_name {
            q = q.bind(display_name);
        }
        if let Some(ref external_id) = update.external_id {
            q = q.bind(external_id);
        }
        if let Some(ref description) = update.description {
            q = q.bind(description);
        }
        if let Some(ref parent_id) = update.parent_id {
            q = q.bind(*parent_id);
        }
        if let Some(ref group_type) = update.group_type {
            q = q.bind(group_type);
        }

        q.fetch_optional(pool).await
    }

    /// Replace a group (full update).
    #[allow(clippy::too_many_arguments)]
    pub async fn replace(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        display_name: &str,
        external_id: Option<&str>,
        description: Option<&str>,
        parent_id: Option<Uuid>,
        group_type: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE groups SET
                display_name = $3,
                external_id = $4,
                description = $5,
                parent_id = $6,
                group_type = $7,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(display_name)
        .bind(external_id)
        .bind(description)
        .bind(parent_id)
        .bind(group_type)
        .fetch_optional(pool)
        .await
    }

    /// Delete a group.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM groups
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
    fn test_create_group_request() {
        let request = CreateGroup {
            display_name: "Engineering".to_string(),
            external_id: Some("azure-12345".to_string()),
            description: Some("Engineering team".to_string()),
            parent_id: None,
            group_type: Some("department".to_string()),
            members: Some(vec![Uuid::new_v4()]),
        };

        assert_eq!(request.display_name, "Engineering");
        assert!(request.members.is_some());
        assert_eq!(request.group_type.as_deref(), Some("department"));
        assert!(request.parent_id.is_none());
    }
}
