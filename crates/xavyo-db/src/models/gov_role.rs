//! Governance Role model for business role hierarchy.
//!
//! Represents a named business role that can participate in a parent-child hierarchy
//! with entitlement inheritance.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Maximum allowed hierarchy depth (configurable per tenant, default enforced here).
pub const DEFAULT_MAX_HIERARCHY_DEPTH: i32 = 10;

/// A governance role in the business role hierarchy.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GovRole {
    /// Unique identifier for the role.
    pub id: Uuid,

    /// The tenant this role belongs to.
    pub tenant_id: Uuid,

    /// Role display name.
    pub name: String,

    /// Optional role description.
    pub description: Option<String>,

    /// Parent role ID (NULL = root role).
    pub parent_role_id: Option<Uuid>,

    /// If true, cannot be directly assigned to users.
    pub is_abstract: bool,

    /// Computed depth from root (0 = root role).
    pub hierarchy_depth: i32,

    /// Optimistic concurrency version.
    pub version: i32,

    /// User who created this role.
    pub created_by: Uuid,

    /// When the role was created.
    pub created_at: DateTime<Utc>,

    /// When the role was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new governance role.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateGovRole {
    /// Role display name (unique per tenant).
    pub name: String,

    /// Optional role description.
    pub description: Option<String>,

    /// Parent role ID (NULL for root role).
    pub parent_role_id: Option<Uuid>,

    /// If true, cannot be directly assigned to users.
    #[serde(default)]
    pub is_abstract: bool,
}

/// Request to update a governance role.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateGovRole {
    /// Updated role name.
    pub name: Option<String>,

    /// Updated description.
    pub description: Option<String>,

    /// Updated parent role ID.
    pub parent_role_id: Option<Option<Uuid>>,

    /// Updated abstract flag.
    pub is_abstract: Option<bool>,

    /// Version for optimistic concurrency check.
    pub version: i32,
}

/// Filter options for listing governance roles.
#[derive(Debug, Clone, Default)]
pub struct GovRoleFilter {
    /// Filter by parent role ID (use Some(None) to get root roles only).
    pub parent_role_id: Option<Option<Uuid>>,

    /// Filter by abstract flag.
    pub is_abstract: Option<bool>,

    /// Search by name prefix.
    pub name_prefix: Option<String>,
}

/// Tree node for hierarchy visualization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GovRoleTreeNode {
    /// Role ID.
    pub id: Uuid,

    /// Role name.
    pub name: String,

    /// Hierarchy depth.
    pub depth: i32,

    /// Whether this is an abstract role.
    pub is_abstract: bool,

    /// Count of direct entitlements.
    pub direct_entitlement_count: i64,

    /// Count of effective entitlements (direct + inherited).
    pub effective_entitlement_count: i64,

    /// Count of users directly assigned this role.
    pub assigned_user_count: i64,

    /// Child roles.
    pub children: Vec<GovRoleTreeNode>,
}

/// Impact analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GovRoleImpactAnalysis {
    /// Role ID.
    pub role_id: Uuid,

    /// Role name.
    pub role_name: String,

    /// Number of descendant roles.
    pub descendant_count: i64,

    /// Total affected users across all descendants.
    pub total_affected_users: i64,

    /// Descendant role details.
    pub descendants: Vec<GovRoleDescendant>,
}

/// Descendant role info for impact analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GovRoleDescendant {
    /// Role ID.
    pub id: Uuid,

    /// Role name.
    pub name: String,

    /// Hierarchy depth.
    pub depth: i32,

    /// Users assigned to this role.
    pub assigned_user_count: i64,
}

/// Move role result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GovRoleMoveResult {
    /// The moved role.
    pub role: GovRole,

    /// Number of roles affected (including moved role and descendants).
    pub affected_roles_count: i64,

    /// Whether effective entitlements were recomputed.
    pub recomputed: bool,
}

impl GovRole {
    /// Find a role by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_roles
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a role by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_roles
            WHERE tenant_id = $1 AND name = $2
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List roles for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &GovRoleFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_roles
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        // Handle parent_role_id filter (Some(None) = root roles only)
        if let Some(parent_opt) = &filter.parent_role_id {
            if parent_opt.is_none() {
                query.push_str(" AND parent_role_id IS NULL");
            } else {
                param_count += 1;
                query.push_str(&format!(" AND parent_role_id = ${}", param_count));
            }
        }

        if filter.is_abstract.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_abstract = ${}", param_count));
        }

        if filter.name_prefix.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE ${} || '%'", param_count));
        }

        query.push_str(&format!(
            " ORDER BY name LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovRole>(&query).bind(tenant_id);

        if let Some(Some(parent_id)) = &filter.parent_role_id {
            q = q.bind(*parent_id);
        }
        if let Some(is_abstract) = filter.is_abstract {
            q = q.bind(is_abstract);
        }
        if let Some(ref prefix) = filter.name_prefix {
            q = q.bind(prefix);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count roles in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &GovRoleFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_roles
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if let Some(parent_opt) = &filter.parent_role_id {
            if parent_opt.is_none() {
                query.push_str(" AND parent_role_id IS NULL");
            } else {
                param_count += 1;
                query.push_str(&format!(" AND parent_role_id = ${}", param_count));
            }
        }

        if filter.is_abstract.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_abstract = ${}", param_count));
        }

        if filter.name_prefix.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE ${} || '%'", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(Some(parent_id)) = &filter.parent_role_id {
            q = q.bind(*parent_id);
        }
        if let Some(is_abstract) = filter.is_abstract {
            q = q.bind(is_abstract);
        }
        if let Some(ref prefix) = filter.name_prefix {
            q = q.bind(prefix);
        }

        q.fetch_one(pool).await
    }

    /// Create a new governance role.
    /// Computes hierarchy_depth based on parent and validates constraints.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        created_by: Uuid,
        input: CreateGovRole,
        max_depth: i32,
    ) -> Result<Self, sqlx::Error> {
        // Compute depth based on parent
        let depth = if let Some(parent_id) = input.parent_role_id {
            let parent_depth: i32 = sqlx::query_scalar(
                r#"
                SELECT hierarchy_depth FROM gov_roles
                WHERE id = $1 AND tenant_id = $2
                "#,
            )
            .bind(parent_id)
            .bind(tenant_id)
            .fetch_one(pool)
            .await?;

            let new_depth = parent_depth + 1;
            if new_depth > max_depth {
                return Err(sqlx::Error::Protocol(format!(
                    "Maximum hierarchy depth of {} exceeded",
                    max_depth
                )));
            }
            new_depth
        } else {
            0 // Root role
        };

        sqlx::query_as(
            r#"
            INSERT INTO gov_roles (tenant_id, name, description, parent_role_id, is_abstract, hierarchy_depth, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.parent_role_id)
        .bind(input.is_abstract)
        .bind(depth)
        .bind(created_by)
        .fetch_one(pool)
        .await
    }

    /// Update a governance role with optimistic concurrency check.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovRole,
        max_depth: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        // First verify version
        let current: Option<GovRole> = sqlx::query_as(
            r#"
            SELECT * FROM gov_roles
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;

        let current = match current {
            Some(r) if r.version == input.version => r,
            Some(_) => {
                return Err(sqlx::Error::Protocol(
                    "Version conflict: role was modified by another process".to_string(),
                ))
            }
            None => return Ok(None),
        };

        // Compute new depth if parent is changing
        let new_depth = if let Some(new_parent_opt) = &input.parent_role_id {
            if *new_parent_opt != current.parent_role_id {
                if let Some(new_parent_id) = new_parent_opt {
                    // Check for cycle
                    if Self::would_create_cycle(pool, tenant_id, id, *new_parent_id).await? {
                        return Err(sqlx::Error::Protocol(
                            "Circular reference detected: setting this parent would create a cycle"
                                .to_string(),
                        ));
                    }

                    let parent_depth: i32 = sqlx::query_scalar(
                        r#"
                        SELECT hierarchy_depth FROM gov_roles
                        WHERE id = $1 AND tenant_id = $2
                        "#,
                    )
                    .bind(new_parent_id)
                    .bind(tenant_id)
                    .fetch_one(pool)
                    .await?;

                    let depth = parent_depth + 1;
                    if depth > max_depth {
                        return Err(sqlx::Error::Protocol(format!(
                            "Maximum hierarchy depth of {} exceeded",
                            max_depth
                        )));
                    }
                    Some(depth)
                } else {
                    Some(0) // Becoming a root role
                }
            } else {
                None
            }
        } else {
            None
        };

        // Build dynamic update
        let mut updates = vec![
            "updated_at = NOW()".to_string(),
            "version = version + 1".to_string(),
        ];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${}", param_idx));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${}", param_idx));
            param_idx += 1;
        }
        if input.parent_role_id.is_some() {
            updates.push(format!("parent_role_id = ${}", param_idx));
            param_idx += 1;
        }
        if input.is_abstract.is_some() {
            updates.push(format!("is_abstract = ${}", param_idx));
            param_idx += 1;
        }
        if new_depth.is_some() {
            updates.push(format!("hierarchy_depth = ${}", param_idx));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE gov_roles SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, GovRole>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(ref parent_opt) = input.parent_role_id {
            q = q.bind(*parent_opt);
        }
        if let Some(is_abstract) = input.is_abstract {
            q = q.bind(is_abstract);
        }
        if let Some(depth) = new_depth {
            q = q.bind(depth);
        }

        q.fetch_optional(pool).await
    }

    /// Delete a governance role. Children are promoted to root roles.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        // First promote children to root roles (parent_role_id = NULL, depth = 0)
        // This happens automatically via ON DELETE SET NULL, but we need to fix depths
        let children: Vec<Uuid> = sqlx::query_scalar(
            r#"
            SELECT id FROM gov_roles
            WHERE parent_role_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;

        // Delete the role (CASCADE will handle effective entitlements and blocks)
        let result = sqlx::query(
            r#"
            DELETE FROM gov_roles
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        if result.rows_affected() > 0 {
            // Update orphaned children to be root roles with depth 0
            for child_id in children {
                Self::update_subtree_depths(pool, tenant_id, child_id, 0).await?;
            }
        }

        Ok(result.rows_affected() > 0)
    }

    /// Get all ancestors of a role using recursive CTE.
    pub async fn get_ancestors(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            WITH RECURSIVE ancestors AS (
                -- Base case: the direct parent
                SELECT r.* FROM gov_roles r
                WHERE r.id = (SELECT parent_role_id FROM gov_roles WHERE id = $1 AND tenant_id = $2)
                  AND r.tenant_id = $2

                UNION ALL

                -- Recursive case: parents of parents
                SELECT r.* FROM gov_roles r
                INNER JOIN ancestors a ON r.id = a.parent_role_id
                WHERE r.tenant_id = $2
            )
            SELECT * FROM ancestors
            ORDER BY hierarchy_depth DESC
            "#,
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Get all descendants of a role using recursive CTE.
    pub async fn get_descendants(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            WITH RECURSIVE descendants AS (
                -- Base case: direct children
                SELECT r.* FROM gov_roles r
                WHERE r.parent_role_id = $1 AND r.tenant_id = $2

                UNION ALL

                -- Recursive case: children of children
                SELECT r.* FROM gov_roles r
                INNER JOIN descendants d ON r.parent_role_id = d.id
                WHERE r.tenant_id = $2
            )
            SELECT * FROM descendants
            ORDER BY hierarchy_depth ASC
            "#,
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Check if setting `new_parent_id` as parent of `role_id` would create a cycle.
    pub async fn would_create_cycle(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        new_parent_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        // A cycle would be created if new_parent_id is a descendant of role_id
        // (or if new_parent_id == role_id)
        if role_id == new_parent_id {
            return Ok(true);
        }

        let is_descendant: bool = sqlx::query_scalar(
            r#"
            WITH RECURSIVE descendants AS (
                SELECT id FROM gov_roles WHERE parent_role_id = $1 AND tenant_id = $3

                UNION ALL

                SELECT r.id FROM gov_roles r
                INNER JOIN descendants d ON r.parent_role_id = d.id
                WHERE r.tenant_id = $3
            )
            SELECT EXISTS(SELECT 1 FROM descendants WHERE id = $2)
            "#,
        )
        .bind(role_id)
        .bind(new_parent_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(is_descendant)
    }

    /// Update depths for a subtree after a move operation.
    async fn update_subtree_depths(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        root_id: Uuid,
        new_root_depth: i32,
    ) -> Result<(), sqlx::Error> {
        // Update root role's depth
        sqlx::query(
            r#"
            UPDATE gov_roles SET hierarchy_depth = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(root_id)
        .bind(tenant_id)
        .bind(new_root_depth)
        .execute(pool)
        .await?;

        // Update all descendants using recursive CTE
        sqlx::query(
            r#"
            WITH RECURSIVE subtree AS (
                SELECT id, hierarchy_depth, 1 as relative_depth
                FROM gov_roles WHERE parent_role_id = $1 AND tenant_id = $2

                UNION ALL

                SELECT r.id, r.hierarchy_depth, s.relative_depth + 1
                FROM gov_roles r
                INNER JOIN subtree s ON r.parent_role_id = s.id
                WHERE r.tenant_id = $2
            )
            UPDATE gov_roles SET
                hierarchy_depth = $3 + subtree.relative_depth,
                updated_at = NOW()
            FROM subtree
            WHERE gov_roles.id = subtree.id AND gov_roles.tenant_id = $2
            "#,
        )
        .bind(root_id)
        .bind(tenant_id)
        .bind(new_root_depth)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Move a role (and its subtree) to a new parent.
    pub async fn move_to_parent(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        new_parent_id: Option<Uuid>,
        expected_version: i32,
        max_depth: i32,
    ) -> Result<(Self, i64), sqlx::Error> {
        // Verify version
        let current: GovRole = sqlx::query_as(
            r#"
            SELECT * FROM gov_roles
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| sqlx::Error::RowNotFound)?;

        if current.version != expected_version {
            return Err(sqlx::Error::Protocol(
                "Version conflict: role was modified by another process".to_string(),
            ));
        }

        // Check for cycles
        if let Some(parent_id) = new_parent_id {
            if Self::would_create_cycle(pool, tenant_id, role_id, parent_id).await? {
                return Err(sqlx::Error::Protocol(
                    "Circular reference detected: setting this parent would create a cycle"
                        .to_string(),
                ));
            }
        }

        // Compute new depth
        let new_depth = if let Some(parent_id) = new_parent_id {
            let parent_depth: i32 = sqlx::query_scalar(
                r#"
                SELECT hierarchy_depth FROM gov_roles
                WHERE id = $1 AND tenant_id = $2
                "#,
            )
            .bind(parent_id)
            .bind(tenant_id)
            .fetch_one(pool)
            .await?;

            parent_depth + 1
        } else {
            0
        };

        // Get max descendant depth to validate
        let max_descendant_depth: Option<i32> = sqlx::query_scalar(
            r#"
            WITH RECURSIVE descendants AS (
                SELECT id, hierarchy_depth FROM gov_roles
                WHERE parent_role_id = $1 AND tenant_id = $2

                UNION ALL

                SELECT r.id, r.hierarchy_depth FROM gov_roles r
                INNER JOIN descendants d ON r.parent_role_id = d.id
                WHERE r.tenant_id = $2
            )
            SELECT MAX(hierarchy_depth) FROM descendants
            "#,
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        if let Some(max_desc_depth) = max_descendant_depth {
            let depth_delta = new_depth - current.hierarchy_depth;
            let new_max = max_desc_depth + depth_delta;
            if new_max > max_depth {
                return Err(sqlx::Error::Protocol(format!(
                    "Move would cause descendants to exceed maximum hierarchy depth of {}",
                    max_depth
                )));
            }
        }

        // Update the role's parent
        let updated: GovRole = sqlx::query_as(
            r#"
            UPDATE gov_roles SET
                parent_role_id = $3,
                hierarchy_depth = $4,
                version = version + 1,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(role_id)
        .bind(tenant_id)
        .bind(new_parent_id)
        .bind(new_depth)
        .fetch_one(pool)
        .await?;

        // Update descendant depths
        Self::update_subtree_depths(pool, tenant_id, role_id, new_depth).await?;

        // Count affected roles
        let descendants = Self::get_descendants(pool, tenant_id, role_id).await?;
        let affected_count = (descendants.len() + 1) as i64;

        Ok((updated, affected_count))
    }

    /// Get root roles for a tenant.
    pub async fn get_root_roles(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_roles
            WHERE tenant_id = $1 AND parent_role_id IS NULL
            ORDER BY name
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Get children of a role.
    pub async fn get_children(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        parent_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_roles
            WHERE tenant_id = $1 AND parent_role_id = $2
            ORDER BY name
            "#,
        )
        .bind(tenant_id)
        .bind(parent_id)
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_gov_role_request() {
        let request = CreateGovRole {
            name: "Engineering".to_string(),
            description: Some("Engineering department role".to_string()),
            parent_role_id: None,
            is_abstract: true,
        };

        assert_eq!(request.name, "Engineering");
        assert!(request.is_abstract);
        assert!(request.parent_role_id.is_none());
    }

    #[test]
    fn test_update_gov_role_request() {
        let request = UpdateGovRole {
            name: Some("Senior Developer".to_string()),
            description: None,
            parent_role_id: Some(Some(Uuid::new_v4())),
            is_abstract: Some(false),
            version: 1,
        };

        assert_eq!(request.version, 1);
    }

    #[test]
    fn test_gov_role_serialization() {
        let role = GovRole {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Developer".to_string(),
            description: Some("Developer role".to_string()),
            parent_role_id: None,
            is_abstract: false,
            hierarchy_depth: 0,
            version: 1,
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&role).unwrap();
        assert!(json.contains("Developer"));
    }
}
