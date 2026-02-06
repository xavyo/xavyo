//! Role Inducement model for role-to-role construction inheritance.
//!
//! Represents an inducement relationship where one role (inducing) automatically
//! includes the constructions of another role (induced). Implements the MidPoint-style
//! inducement pattern for role hierarchy and construction inheritance (F-063).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A role inducement defining role-to-role construction inheritance.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RoleInducement {
    /// Unique identifier for the inducement.
    pub id: Uuid,

    /// The tenant this inducement belongs to.
    pub tenant_id: Uuid,

    /// The parent role that induces (includes constructions from induced role).
    pub inducing_role_id: Uuid,

    /// The child role whose constructions are included.
    pub induced_role_id: Uuid,

    /// Whether this inducement is enabled.
    #[serde(default = "default_true")]
    pub is_enabled: bool,

    /// Optional description.
    pub description: Option<String>,

    /// User who created this inducement.
    pub created_by: Uuid,

    /// When the inducement was created.
    pub created_at: DateTime<Utc>,

    /// When the inducement was last updated.
    pub updated_at: DateTime<Utc>,
}

fn default_true() -> bool {
    true
}

/// Inducement with role names for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RoleInducementWithNames {
    /// The inducement.
    #[serde(flatten)]
    pub inducement: RoleInducement,

    /// Inducing role name.
    pub inducing_role_name: Option<String>,

    /// Induced role name.
    pub induced_role_name: Option<String>,
}

/// Request to create a new role inducement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateRoleInducement {
    /// The role to be induced (child role).
    pub induced_role_id: Uuid,

    /// Optional description.
    pub description: Option<String>,
}

/// Filter options for listing inducements.
#[derive(Debug, Clone, Default)]
pub struct RoleInducementFilter {
    /// Filter by enabled status.
    pub enabled_only: bool,
}

/// Induced role info for traversal.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct InducedRoleInfo {
    /// Role ID.
    pub role_id: Uuid,
    /// Role name.
    pub role_name: String,
    /// Depth in inducement chain (0 = direct inducement).
    pub depth: i32,
}

impl RoleInducement {
    /// Find an inducement by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM role_inducements
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find an inducement by ID and inducing role ID.
    pub async fn find_by_id_and_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        inducing_role_id: Uuid,
        inducement_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM role_inducements
            WHERE id = $1 AND inducing_role_id = $2 AND tenant_id = $3
            ",
        )
        .bind(inducement_id)
        .bind(inducing_role_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List inducements for a role (roles this role induces).
    pub async fn list_by_inducing_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        inducing_role_id: Uuid,
        filter: &RoleInducementFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        if filter.enabled_only {
            sqlx::query_as(
                r"
                SELECT * FROM role_inducements
                WHERE tenant_id = $1 AND inducing_role_id = $2 AND is_enabled = true
                ORDER BY created_at ASC
                LIMIT $3 OFFSET $4
                ",
            )
            .bind(tenant_id)
            .bind(inducing_role_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT * FROM role_inducements
                WHERE tenant_id = $1 AND inducing_role_id = $2
                ORDER BY created_at ASC
                LIMIT $3 OFFSET $4
                ",
            )
            .bind(tenant_id)
            .bind(inducing_role_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        }
    }

    /// Count inducements for a role.
    pub async fn count_by_inducing_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        inducing_role_id: Uuid,
        filter: &RoleInducementFilter,
    ) -> Result<i64, sqlx::Error> {
        if filter.enabled_only {
            sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM role_inducements
                WHERE tenant_id = $1 AND inducing_role_id = $2 AND is_enabled = true
                ",
            )
            .bind(tenant_id)
            .bind(inducing_role_id)
            .fetch_one(pool)
            .await
        } else {
            sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM role_inducements
                WHERE tenant_id = $1 AND inducing_role_id = $2
                ",
            )
            .bind(tenant_id)
            .bind(inducing_role_id)
            .fetch_one(pool)
            .await
        }
    }

    /// List inducements with role names.
    pub async fn list_with_names(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        inducing_role_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<RoleInducementWithNames>, sqlx::Error> {
        // First get the inducements
        let inducements = Self::list_by_inducing_role(
            pool,
            tenant_id,
            inducing_role_id,
            &RoleInducementFilter::default(),
            limit,
            offset,
        )
        .await?;

        // Then fetch role names in a separate query
        let role_ids: Vec<Uuid> = inducements
            .iter()
            .flat_map(|i| vec![i.inducing_role_id, i.induced_role_id])
            .collect();

        let role_names: Vec<(Uuid, String)> =
            sqlx::query_as(r"SELECT id, name FROM gov_roles WHERE tenant_id = $1 AND id = ANY($2)")
                .bind(tenant_id)
                .bind(&role_ids)
                .fetch_all(pool)
                .await?;

        let name_map: std::collections::HashMap<Uuid, String> = role_names.into_iter().collect();

        Ok(inducements
            .into_iter()
            .map(|inducement| RoleInducementWithNames {
                inducing_role_name: name_map.get(&inducement.inducing_role_id).cloned(),
                induced_role_name: name_map.get(&inducement.induced_role_id).cloned(),
                inducement,
            })
            .collect())
    }

    /// Check if creating an inducement would create a cycle.
    /// Uses the database function check_inducement_cycle.
    pub async fn would_create_cycle(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        inducing_role_id: Uuid,
        induced_role_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        // Direct self-reference check
        if inducing_role_id == induced_role_id {
            return Ok(true);
        }

        // Check via database function
        let has_cycle: bool = sqlx::query_scalar(r"SELECT check_inducement_cycle($1, $2, $3)")
            .bind(tenant_id)
            .bind(inducing_role_id)
            .bind(induced_role_id)
            .fetch_one(pool)
            .await?;

        Ok(has_cycle)
    }

    /// Create a new inducement.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        inducing_role_id: Uuid,
        input: &CreateRoleInducement,
        created_by: Uuid,
    ) -> Result<Self, sqlx::Error> {
        let id = Uuid::new_v4();

        sqlx::query_as(
            r"
            INSERT INTO role_inducements (
                id, tenant_id, inducing_role_id, induced_role_id,
                description, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(inducing_role_id)
        .bind(input.induced_role_id)
        .bind(&input.description)
        .bind(created_by)
        .fetch_one(pool)
        .await
    }

    /// Delete an inducement.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM role_inducements
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Enable an inducement.
    pub async fn enable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE role_inducements
            SET is_enabled = true, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Disable an inducement.
    pub async fn disable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE role_inducements
            SET is_enabled = false, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Check if an inducement already exists.
    pub async fn exists(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        inducing_role_id: Uuid,
        induced_role_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM role_inducements
            WHERE tenant_id = $1 AND inducing_role_id = $2 AND induced_role_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(inducing_role_id)
        .bind(induced_role_id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// Get all induced role IDs for a role (recursive traversal).
    /// Returns all roles that are directly or transitively induced.
    pub async fn get_all_induced_role_ids(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        let ids: Vec<(Uuid,)> = sqlx::query_as(
            r"
            WITH RECURSIVE induced_roles AS (
                -- Base case: directly induced roles
                SELECT induced_role_id, 1 as depth
                FROM role_inducements
                WHERE tenant_id = $1 AND inducing_role_id = $2 AND is_enabled = true

                UNION

                -- Recursive case: roles induced by induced roles
                SELECT ri.induced_role_id, ir.depth + 1
                FROM role_inducements ri
                INNER JOIN induced_roles ir ON ri.inducing_role_id = ir.induced_role_id
                WHERE ri.tenant_id = $1 AND ri.is_enabled = true AND ir.depth < 20
            )
            SELECT DISTINCT induced_role_id FROM induced_roles
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_all(pool)
        .await?;

        Ok(ids.into_iter().map(|(id,)| id).collect())
    }

    /// Get all induced roles with their names and depths.
    pub async fn get_all_induced_roles(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<InducedRoleInfo>, sqlx::Error> {
        sqlx::query_as(
            r"
            WITH RECURSIVE induced_roles AS (
                -- Base case: directly induced roles
                SELECT induced_role_id as role_id, 0 as depth
                FROM role_inducements
                WHERE tenant_id = $1 AND inducing_role_id = $2 AND is_enabled = true

                UNION

                -- Recursive case: roles induced by induced roles
                SELECT ri.induced_role_id, ir.depth + 1
                FROM role_inducements ri
                INNER JOIN induced_roles ir ON ri.inducing_role_id = ir.role_id
                WHERE ri.tenant_id = $1 AND ri.is_enabled = true AND ir.depth < 20
            )
            SELECT ir.role_id, gr.name as role_name, MIN(ir.depth) as depth
            FROM induced_roles ir
            INNER JOIN gov_roles gr ON ir.role_id = gr.id AND gr.tenant_id = $1
            GROUP BY ir.role_id, gr.name
            ORDER BY depth ASC, role_name ASC
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_all(pool)
        .await
    }

    /// Get the inducement path that leads to a cycle (for error messages).
    pub async fn get_cycle_path(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        inducing_role_id: Uuid,
        induced_role_id: Uuid,
    ) -> Result<Vec<String>, sqlx::Error> {
        // Get the path from induced_role back to inducing_role
        let path: Vec<(String,)> = sqlx::query_as(
            r"
            WITH RECURSIVE inducement_path AS (
                -- Start from the proposed induced role
                SELECT induced_role_id, gr.name as role_name, ARRAY[gr.name] as path, 1 as depth
                FROM role_inducements ri
                INNER JOIN gov_roles gr ON ri.induced_role_id = gr.id AND ri.tenant_id = gr.tenant_id
                WHERE ri.tenant_id = $1 AND ri.inducing_role_id = $2 AND ri.is_enabled = true

                UNION ALL

                -- Follow the inducement chain
                SELECT ri.induced_role_id, gr.name, ip.path || gr.name, ip.depth + 1
                FROM role_inducements ri
                INNER JOIN inducement_path ip ON ri.inducing_role_id = ip.induced_role_id
                INNER JOIN gov_roles gr ON ri.induced_role_id = gr.id AND ri.tenant_id = gr.tenant_id
                WHERE ri.tenant_id = $1 AND ri.is_enabled = true AND ip.depth < 20
                    AND ri.induced_role_id = $3
            )
            SELECT unnest(path) as role_name FROM inducement_path
            WHERE induced_role_id = $3
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(induced_role_id) // Start from the proposed induced role
        .bind(inducing_role_id) // Looking for a path back to inducing role
        .fetch_all(pool)
        .await?;

        Ok(path.into_iter().map(|(name,)| name).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_inducement_serialization() {
        let input = CreateRoleInducement {
            induced_role_id: Uuid::new_v4(),
            description: Some("Test inducement".to_string()),
        };

        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("induced_role_id"));
        assert!(json.contains("Test inducement"));
    }

    #[test]
    fn test_inducement_filter_default() {
        let filter = RoleInducementFilter::default();
        assert!(!filter.enabled_only);
    }
}
