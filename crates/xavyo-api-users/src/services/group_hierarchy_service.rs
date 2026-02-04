//! Group hierarchy service for managing parent-child relationships and tree traversal.
//!
//! Provides cycle detection, depth validation, and recursive CTE queries for
//! the organization & department hierarchy feature (F071).

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::Group;

use crate::error::ApiUsersError;

/// Maximum allowed hierarchy depth (10 levels).
const MAX_DEPTH: i32 = 10;

/// Allowed `group_type` values.
const ALLOWED_GROUP_TYPES: &[&str] = &[
    "organizational_unit",
    "department",
    "team",
    "security_group",
    "distribution_list",
    "custom",
];

/// Service for group hierarchy operations.
#[derive(Clone)]
pub struct GroupHierarchyService {
    pool: PgPool,
}

impl GroupHierarchyService {
    /// Create a new hierarchy service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Validate that a `group_type` value is one of the allowed types.
    pub fn validate_group_type(group_type: &str) -> Result<(), ApiUsersError> {
        if ALLOWED_GROUP_TYPES.contains(&group_type) {
            Ok(())
        } else {
            Err(ApiUsersError::Validation(format!(
                "Invalid group_type '{}'. Allowed values: {}",
                group_type,
                ALLOWED_GROUP_TYPES.join(", ")
            )))
        }
    }

    /// Get the depth of a group in the hierarchy (1 = root, 2 = child of root, etc.).
    pub async fn get_group_depth(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> Result<i32, ApiUsersError> {
        let result: Option<(Option<i64>,)> = sqlx::query_as(
            r"
            WITH RECURSIVE depth_calc AS (
                SELECT id, parent_id, 1 AS depth
                FROM groups
                WHERE id = $2 AND tenant_id = $1

                UNION ALL

                SELECT g.id, g.parent_id, d.depth + 1
                FROM groups g
                JOIN depth_calc d ON g.id = d.parent_id
                WHERE g.tenant_id = $1
            )
            SELECT MAX(depth) AS group_depth FROM depth_calc
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some((Some(depth),)) => Ok(depth as i32),
            _ => Err(ApiUsersError::GroupNotFound),
        }
    }

    /// Check if setting `new_parent_id` as the parent of `group_id` would create a cycle.
    ///
    /// A cycle would occur if `group_id` is an ancestor of `new_parent_id` (i.e., `new_parent_id`
    /// is already a descendant of `group_id`).
    pub async fn would_create_cycle(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        new_parent_id: Uuid,
    ) -> Result<bool, ApiUsersError> {
        let result: (bool,) = sqlx::query_as(
            r"
            WITH RECURSIVE ancestors_of_new_parent AS (
                SELECT id, parent_id
                FROM groups
                WHERE id = $3 AND tenant_id = $1

                UNION ALL

                SELECT g.id, g.parent_id
                FROM groups g
                JOIN ancestors_of_new_parent a ON g.id = a.parent_id
                WHERE g.tenant_id = $1
            )
            SELECT EXISTS (
                SELECT 1 FROM ancestors_of_new_parent WHERE id = $2
            ) AS would_create_cycle
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(new_parent_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(result.0)
    }

    /// Calculate what the depth of `group_id` would be if moved under `new_parent_id`.
    /// Returns the depth of the deepest descendant of `group_id` in the new position.
    async fn calculate_new_subtree_depth(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        new_parent_id: Uuid,
    ) -> Result<i32, ApiUsersError> {
        // Get depth of the new parent
        let parent_depth = self.get_group_depth(tenant_id, new_parent_id).await?;

        // Get the maximum depth within the subtree rooted at group_id (relative)
        let result: (Option<i64>,) = sqlx::query_as(
            r"
            WITH RECURSIVE subtree AS (
                SELECT id, parent_id, 0 AS relative_depth
                FROM groups
                WHERE id = $2 AND tenant_id = $1

                UNION ALL

                SELECT g.id, g.parent_id, s.relative_depth + 1
                FROM groups g
                JOIN subtree s ON g.parent_id = s.id
                WHERE g.tenant_id = $1
            )
            SELECT MAX(relative_depth) AS max_relative_depth FROM subtree
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_one(&self.pool)
        .await?;

        let max_relative_depth = result.0.unwrap_or(0) as i32;

        // New deepest depth = parent_depth + 1 (for group_id itself) + max_relative_depth
        Ok(parent_depth + 1 + max_relative_depth)
    }

    /// Validate that setting a parent is allowed: parent exists, same tenant, no cycle, depth OK.
    pub async fn validate_parent(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        parent_id: Option<Uuid>,
    ) -> Result<(), ApiUsersError> {
        let new_parent_id = match parent_id {
            None => return Ok(()), // Setting to root is always valid
            Some(pid) => pid,
        };

        // Check parent exists in the same tenant
        let parent = Group::find_by_id(&self.pool, tenant_id, new_parent_id).await?;
        if parent.is_none() {
            return Err(ApiUsersError::ParentNotFound);
        }

        // Check for cycle: group_id must not be an ancestor of new_parent_id
        if self
            .would_create_cycle(tenant_id, group_id, new_parent_id)
            .await?
        {
            return Err(ApiUsersError::CycleDetected);
        }

        // Check depth: the deepest node in group_id's subtree must not exceed MAX_DEPTH
        let new_max_depth = self
            .calculate_new_subtree_depth(tenant_id, group_id, new_parent_id)
            .await?;
        if new_max_depth > MAX_DEPTH {
            return Err(ApiUsersError::MaxDepthExceeded);
        }

        Ok(())
    }

    /// Check if a group has any children.
    pub async fn has_children(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> Result<bool, ApiUsersError> {
        let result: (bool,) = sqlx::query_as(
            r"
            SELECT EXISTS(
                SELECT 1 FROM groups WHERE tenant_id = $1 AND parent_id = $2
            )
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(result.0)
    }

    /// Move a group to a new parent (or make it a root group).
    pub async fn move_group(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        new_parent_id: Option<Uuid>,
    ) -> Result<Group, ApiUsersError> {
        // Verify group exists
        let group = Group::find_by_id(&self.pool, tenant_id, group_id).await?;
        if group.is_none() {
            return Err(ApiUsersError::GroupNotFound);
        }

        // Validate the new parent
        self.validate_parent(tenant_id, group_id, new_parent_id)
            .await?;

        // Update parent_id
        let update = xavyo_db::models::UpdateGroup {
            display_name: None,
            external_id: None,
            description: None,
            parent_id: Some(new_parent_id),
            group_type: None,
        };

        Group::update(&self.pool, tenant_id, group_id, update)
            .await?
            .ok_or(ApiUsersError::GroupNotFound)
    }

    /// Get direct children of a group with pagination.
    pub async fn get_children(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Group>, bool), ApiUsersError> {
        // Verify group exists
        let group = Group::find_by_id(&self.pool, tenant_id, group_id).await?;
        if group.is_none() {
            return Err(ApiUsersError::GroupNotFound);
        }

        let children: Vec<Group> = sqlx::query_as(
            r"
            SELECT * FROM groups
            WHERE tenant_id = $1 AND parent_id = $2
            ORDER BY display_name
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(limit + 1) // fetch one extra to detect has_more
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let has_more = children.len() as i64 > limit;
        let children = if has_more {
            children.into_iter().take(limit as usize).collect()
        } else {
            children
        };

        Ok((children, has_more))
    }

    /// Get ancestor path from root to the group's immediate parent.
    pub async fn get_ancestors(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> Result<Vec<AncestorRow>, ApiUsersError> {
        // Verify group exists
        let group = Group::find_by_id(&self.pool, tenant_id, group_id).await?;
        if group.is_none() {
            return Err(ApiUsersError::GroupNotFound);
        }

        let ancestors: Vec<AncestorRow> = sqlx::query_as(
            r"
            WITH RECURSIVE ancestors AS (
                SELECT id, parent_id, display_name, group_type, 0 AS depth
                FROM groups
                WHERE id = $2 AND tenant_id = $1

                UNION ALL

                SELECT g.id, g.parent_id, g.display_name, g.group_type, a.depth + 1
                FROM groups g
                JOIN ancestors a ON g.id = a.parent_id
                WHERE g.tenant_id = $1
            )
            SELECT id, display_name, group_type, depth
            FROM ancestors
            WHERE id != $2
            ORDER BY depth DESC
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(ancestors)
    }

    /// Get ancestor `display_name` path from root to the group's immediate parent.
    pub async fn get_ancestor_path_names(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> Result<Vec<String>, ApiUsersError> {
        let ancestors = self.get_ancestors(tenant_id, group_id).await?;
        Ok(ancestors.into_iter().map(|a| a.display_name).collect())
    }

    /// Get full subtree (all descendants) with relative depth and pagination.
    pub async fn get_subtree(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<SubtreeRow>, bool), ApiUsersError> {
        // Verify group exists
        let group = Group::find_by_id(&self.pool, tenant_id, group_id).await?;
        if group.is_none() {
            return Err(ApiUsersError::GroupNotFound);
        }

        let descendants: Vec<SubtreeRow> = sqlx::query_as(
            r"
            WITH RECURSIVE subtree AS (
                SELECT id, parent_id, display_name, group_type, 0 AS relative_depth
                FROM groups
                WHERE id = $2 AND tenant_id = $1

                UNION ALL

                SELECT g.id, g.parent_id, g.display_name, g.group_type, s.relative_depth + 1
                FROM groups g
                JOIN subtree s ON g.parent_id = s.id
                WHERE g.tenant_id = $1
            )
            SELECT id, parent_id, display_name, group_type, relative_depth
            FROM subtree
            WHERE id != $2
            ORDER BY relative_depth, display_name
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(limit + 1)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let has_more = descendants.len() as i64 > limit;
        let descendants = if has_more {
            descendants.into_iter().take(limit as usize).collect()
        } else {
            descendants
        };

        Ok((descendants, has_more))
    }

    /// Get root groups (no parent) with pagination.
    pub async fn get_roots(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Group>, bool), ApiUsersError> {
        let roots: Vec<Group> = sqlx::query_as(
            r"
            SELECT * FROM groups
            WHERE tenant_id = $1 AND parent_id IS NULL
            ORDER BY display_name
            LIMIT $2 OFFSET $3
            ",
        )
        .bind(tenant_id)
        .bind(limit + 1)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let has_more = roots.len() as i64 > limit;
        let roots = if has_more {
            roots.into_iter().take(limit as usize).collect()
        } else {
            roots
        };

        Ok((roots, has_more))
    }

    /// Get all members in a group and all its descendant groups, with pagination.
    pub async fn get_subtree_members(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<SubtreeMemberRow>, i64), ApiUsersError> {
        // Verify group exists
        let group = Group::find_by_id(&self.pool, tenant_id, group_id).await?;
        if group.is_none() {
            return Err(ApiUsersError::GroupNotFound);
        }

        // Get total count
        let count_result: (i64,) = sqlx::query_as(
            r"
            WITH RECURSIVE subtree AS (
                SELECT id FROM groups
                WHERE id = $2 AND tenant_id = $1

                UNION ALL

                SELECT g.id
                FROM groups g
                JOIN subtree s ON g.parent_id = s.id
                WHERE g.tenant_id = $1
            )
            SELECT COUNT(DISTINCT u.id)
            FROM subtree s
            JOIN group_memberships gm ON gm.group_id = s.id AND gm.tenant_id = $1
            JOIN users u ON u.id = gm.user_id AND u.tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_one(&self.pool)
        .await?;

        let total_count = count_result.0;

        // Get paginated members
        let members: Vec<SubtreeMemberRow> = sqlx::query_as(
            r"
            WITH RECURSIVE subtree AS (
                SELECT id FROM groups
                WHERE id = $2 AND tenant_id = $1

                UNION ALL

                SELECT g.id
                FROM groups g
                JOIN subtree s ON g.parent_id = s.id
                WHERE g.tenant_id = $1
            )
            SELECT DISTINCT u.id AS user_id, u.email, u.display_name
            FROM subtree s
            JOIN group_memberships gm ON gm.group_id = s.id AND gm.tenant_id = $1
            JOIN users u ON u.id = gm.user_id AND u.tenant_id = $1
            ORDER BY u.email
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((members, total_count))
    }

    /// List groups filtered by type with pagination.
    pub async fn list_by_tenant_filtered(
        &self,
        tenant_id: Uuid,
        group_type: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Group>, bool), ApiUsersError> {
        let groups = match group_type {
            Some(gt) => {
                sqlx::query_as::<_, Group>(
                    r"
                    SELECT * FROM groups
                    WHERE tenant_id = $1 AND group_type = $2
                    ORDER BY display_name
                    LIMIT $3 OFFSET $4
                    ",
                )
                .bind(tenant_id)
                .bind(gt)
                .bind(limit + 1)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, Group>(
                    r"
                    SELECT * FROM groups
                    WHERE tenant_id = $1
                    ORDER BY display_name
                    LIMIT $2 OFFSET $3
                    ",
                )
                .bind(tenant_id)
                .bind(limit + 1)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
            }
        };

        let has_more = groups.len() as i64 > limit;
        let groups = if has_more {
            groups.into_iter().take(limit as usize).collect()
        } else {
            groups
        };

        Ok((groups, has_more))
    }
}

/// Row type for ancestor queries.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct AncestorRow {
    pub id: Uuid,
    pub display_name: String,
    pub group_type: String,
    pub depth: i32,
}

/// Row type for subtree queries.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct SubtreeRow {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub display_name: String,
    pub group_type: String,
    pub relative_depth: i32,
}

/// Row type for subtree membership queries.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct SubtreeMemberRow {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_group_type_allowed() {
        assert!(GroupHierarchyService::validate_group_type("organizational_unit").is_ok());
        assert!(GroupHierarchyService::validate_group_type("department").is_ok());
        assert!(GroupHierarchyService::validate_group_type("team").is_ok());
        assert!(GroupHierarchyService::validate_group_type("security_group").is_ok());
        assert!(GroupHierarchyService::validate_group_type("distribution_list").is_ok());
        assert!(GroupHierarchyService::validate_group_type("custom").is_ok());
    }

    #[test]
    fn test_validate_group_type_rejected() {
        assert!(GroupHierarchyService::validate_group_type("invalid").is_err());
        assert!(GroupHierarchyService::validate_group_type("").is_err());
        assert!(GroupHierarchyService::validate_group_type("DEPARTMENT").is_err());
    }

    #[test]
    fn test_max_depth_constant() {
        assert_eq!(MAX_DEPTH, 10);
    }

    #[test]
    fn test_allowed_group_types() {
        assert_eq!(ALLOWED_GROUP_TYPES.len(), 6);
    }
}
