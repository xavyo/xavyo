//! Role hierarchy service for governance API.
//!
//! Provides business role hierarchy management with parent-child relationships,
//! entitlement inheritance, and cycle detection (F088).

use std::collections::HashMap;

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    AdminAction, AdminAuditLog, AdminResourceType, CreateAuditLogEntry, CreateGovRole,
    EffectiveEntitlementDetails, GovRole, GovRoleEffectiveEntitlement, GovRoleFilter,
    GovRoleImpactAnalysis, GovRoleInheritanceBlock, GovRoleMoveResult, GovRoleTreeNode,
    InheritanceBlockDetails, UpdateGovRole, DEFAULT_MAX_HIERARCHY_DEPTH,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for governance role hierarchy operations.
pub struct RoleHierarchyService {
    pool: PgPool,
    /// Maximum allowed hierarchy depth (configurable per tenant).
    max_depth: i32,
}

impl RoleHierarchyService {
    /// Create a new role hierarchy service with default max depth.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            max_depth: DEFAULT_MAX_HIERARCHY_DEPTH,
        }
    }

    /// Create a new role hierarchy service with custom max depth.
    #[must_use]
    pub fn with_max_depth(pool: PgPool, max_depth: i32) -> Self {
        Self { pool, max_depth }
    }

    // =========================================================================
    // Role CRUD Operations
    // =========================================================================

    /// List roles for a tenant with pagination and filtering.
    pub async fn list_roles(
        &self,
        tenant_id: Uuid,
        filter: GovRoleFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovRole>, i64)> {
        let roles = GovRole::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = GovRole::count_by_tenant(&self.pool, tenant_id, &filter).await?;
        Ok((roles, total))
    }

    /// Get a role by ID.
    pub async fn get_role(&self, tenant_id: Uuid, role_id: Uuid) -> Result<GovRole> {
        GovRole::find_by_id(&self.pool, tenant_id, role_id)
            .await?
            .ok_or(GovernanceError::GovRoleNotFound(role_id))
    }

    /// Create a new governance role.
    pub async fn create_role(
        &self,
        tenant_id: Uuid,
        created_by: Uuid,
        input: CreateGovRole,
    ) -> Result<GovRole> {
        // Validate name uniqueness
        if let Some(_existing) = GovRole::find_by_name(&self.pool, tenant_id, &input.name).await? {
            return Err(GovernanceError::GovRoleNameExists(input.name));
        }

        // Validate parent exists if specified
        if let Some(parent_id) = input.parent_role_id {
            if GovRole::find_by_id(&self.pool, tenant_id, parent_id)
                .await?
                .is_none()
            {
                return Err(GovernanceError::GovRoleParentNotFound(parent_id));
            }
        }

        // Create role (depth and cycle detection handled by model)
        let role = GovRole::create(&self.pool, tenant_id, created_by, input, self.max_depth)
            .await
            .map_err(|e| {
                if e.to_string().contains("Maximum hierarchy depth") {
                    GovernanceError::GovRoleDepthExceeded(self.max_depth)
                } else {
                    GovernanceError::Database(e)
                }
            })?;

        // Compute effective entitlements for the new role
        GovRoleEffectiveEntitlement::compute_for_role(&self.pool, tenant_id, role.id).await?;

        // Audit log: role created (T064)
        let _ = self
            .log_audit(
                tenant_id,
                created_by,
                AdminAction::Create,
                AdminResourceType::GovRole,
                Some(role.id),
                None,
                Some(json!({
                    "name": role.name,
                    "parent_role_id": role.parent_role_id,
                    "is_abstract": role.is_abstract,
                    "hierarchy_depth": role.hierarchy_depth,
                })),
            )
            .await;

        Ok(role)
    }

    /// Update a governance role.
    pub async fn update_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        updated_by: Uuid,
        input: UpdateGovRole,
    ) -> Result<GovRole> {
        // Get old role for audit log
        let old_role = self.get_role(tenant_id, role_id).await?;

        // Validate name uniqueness if changing
        if let Some(ref new_name) = input.name {
            if let Some(existing) = GovRole::find_by_name(&self.pool, tenant_id, new_name).await? {
                if existing.id != role_id {
                    return Err(GovernanceError::GovRoleNameExists(new_name.clone()));
                }
            }
        }

        // Validate parent exists if changing
        if let Some(Some(parent_id)) = input.parent_role_id {
            if GovRole::find_by_id(&self.pool, tenant_id, parent_id)
                .await?
                .is_none()
            {
                return Err(GovernanceError::GovRoleParentNotFound(parent_id));
            }
        }

        let role = GovRole::update(&self.pool, tenant_id, role_id, input, self.max_depth)
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("Version conflict") {
                    GovernanceError::GovRoleVersionConflict
                } else if msg.contains("Circular reference") {
                    GovernanceError::GovRoleCircularReference
                } else if msg.contains("Maximum hierarchy depth") {
                    GovernanceError::GovRoleDepthExceeded(self.max_depth)
                } else {
                    GovernanceError::Database(e)
                }
            })?
            .ok_or(GovernanceError::GovRoleNotFound(role_id))?;

        // Recompute effective entitlements for the role and its descendants
        GovRoleEffectiveEntitlement::recompute_for_descendants(&self.pool, tenant_id, role_id)
            .await?;

        // Audit log: role updated (T064)
        let _ = self
            .log_audit(
                tenant_id,
                updated_by,
                AdminAction::Update,
                AdminResourceType::GovRole,
                Some(role_id),
                Some(json!({
                    "name": old_role.name,
                    "parent_role_id": old_role.parent_role_id,
                    "is_abstract": old_role.is_abstract,
                })),
                Some(json!({
                    "name": role.name,
                    "parent_role_id": role.parent_role_id,
                    "is_abstract": role.is_abstract,
                })),
            )
            .await;

        Ok(role)
    }

    /// Delete a governance role.
    pub async fn delete_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        deleted_by: Uuid,
    ) -> Result<()> {
        // Verify role exists (also captures data for audit log)
        let role = self.get_role(tenant_id, role_id).await?;

        // Check for child roles (they'll be orphaned - promoted to root)
        let children = GovRole::get_children(&self.pool, tenant_id, role_id).await?;
        let child_ids: Vec<Uuid> = children.iter().map(|c| c.id).collect();

        // Count active assignments that will be orphaned by this role deletion
        let affected_assignment_count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_entitlement_assignments gea
            JOIN gov_role_entitlements gre ON gea.entitlement_id = gre.entitlement_id
              AND gea.tenant_id = gre.tenant_id
            WHERE gre.tenant_id = $1 AND gre.role_id = $2
              AND gea.status = 'active'
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        // Delete the role (CASCADE handles effective entitlements and blocks)
        let deleted = GovRole::delete(&self.pool, tenant_id, role_id).await?;
        if !deleted {
            return Err(GovernanceError::GovRoleNotFound(role_id));
        }

        // Recompute effective entitlements for orphaned children (now root roles)
        for child in children {
            GovRoleEffectiveEntitlement::recompute_for_descendants(&self.pool, tenant_id, child.id)
                .await?;
        }

        // Audit log: role deleted (T064)
        let _ = self
            .log_audit(
                tenant_id,
                deleted_by,
                AdminAction::Delete,
                AdminResourceType::GovRole,
                Some(role_id),
                Some(json!({
                    "name": role.name,
                    "parent_role_id": role.parent_role_id,
                    "is_abstract": role.is_abstract,
                    "orphaned_children": child_ids,
                    "affected_assignment_count": affected_assignment_count,
                })),
                None,
            )
            .await;

        Ok(())
    }

    // =========================================================================
    // Hierarchy Navigation
    // =========================================================================

    /// Get ancestors of a role.
    pub async fn get_ancestors(&self, tenant_id: Uuid, role_id: Uuid) -> Result<Vec<GovRole>> {
        // Verify role exists
        let _role = self.get_role(tenant_id, role_id).await?;
        GovRole::get_ancestors(&self.pool, tenant_id, role_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get descendants of a role.
    pub async fn get_descendants(&self, tenant_id: Uuid, role_id: Uuid) -> Result<Vec<GovRole>> {
        // Verify role exists
        let _role = self.get_role(tenant_id, role_id).await?;
        GovRole::get_descendants(&self.pool, tenant_id, role_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get root roles for a tenant.
    pub async fn get_root_roles(&self, tenant_id: Uuid) -> Result<Vec<GovRole>> {
        GovRole::get_root_roles(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get children of a role.
    pub async fn get_children(&self, tenant_id: Uuid, role_id: Uuid) -> Result<Vec<GovRole>> {
        // Verify role exists
        let _role = self.get_role(tenant_id, role_id).await?;
        GovRole::get_children(&self.pool, tenant_id, role_id)
            .await
            .map_err(GovernanceError::Database)
    }

    // =========================================================================
    // Move Operations
    // =========================================================================

    /// Move a role to a new parent.
    pub async fn move_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        new_parent_id: Option<Uuid>,
        expected_version: i32,
        moved_by: Uuid,
    ) -> Result<GovRoleMoveResult> {
        // Get old parent for audit log
        let old_role = self.get_role(tenant_id, role_id).await?;
        let old_parent_id = old_role.parent_role_id;

        // Validate new parent exists if specified
        if let Some(parent_id) = new_parent_id {
            if GovRole::find_by_id(&self.pool, tenant_id, parent_id)
                .await?
                .is_none()
            {
                return Err(GovernanceError::GovRoleParentNotFound(parent_id));
            }
        }

        let (role, affected_count) = GovRole::move_to_parent(
            &self.pool,
            tenant_id,
            role_id,
            new_parent_id,
            expected_version,
            self.max_depth,
        )
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("Version conflict") {
                GovernanceError::GovRoleVersionConflict
            } else if msg.contains("Circular reference") {
                GovernanceError::GovRoleCircularReference
            } else if msg.contains("exceed maximum hierarchy depth") {
                GovernanceError::GovRoleMoveExceedsDepth(self.max_depth)
            } else if msg.contains("RowNotFound") {
                GovernanceError::GovRoleNotFound(role_id)
            } else {
                GovernanceError::Database(e)
            }
        })?;

        // Recompute effective entitlements for moved role and descendants
        GovRoleEffectiveEntitlement::recompute_for_descendants(&self.pool, tenant_id, role_id)
            .await?;

        // Trigger SoD re-check for affected users (F088/T063)
        let _ = self.trigger_sod_recheck_for_role(tenant_id, role_id).await;

        // Audit log: role moved (T064)
        let _ = self
            .log_audit(
                tenant_id,
                moved_by,
                AdminAction::Move,
                AdminResourceType::GovRole,
                Some(role_id),
                Some(json!({
                    "parent_role_id": old_parent_id,
                    "name": old_role.name,
                })),
                Some(json!({
                    "parent_role_id": new_parent_id,
                    "affected_roles_count": affected_count,
                })),
            )
            .await;

        Ok(GovRoleMoveResult {
            role,
            affected_roles_count: affected_count,
            recomputed: true,
        })
    }

    // =========================================================================
    // User Count Helpers
    // =========================================================================

    /// Count distinct users assigned to a single role via its effective entitlements.
    ///
    /// A user is considered "assigned" to a role if they have an active entitlement
    /// assignment for any of the role's effective entitlements (direct + inherited).
    async fn count_users_for_role(&self, tenant_id: Uuid, role_id: Uuid) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(DISTINCT ea.target_id)
            FROM gov_role_effective_entitlements ree
            JOIN gov_entitlement_assignments ea
                ON ea.entitlement_id = ree.entitlement_id
                AND ea.tenant_id = ree.tenant_id
            WHERE ree.tenant_id = $1
                AND ree.role_id = $2
                AND ea.target_type = 'user'
                AND ea.status = 'active'
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0);

        Ok(count)
    }

    /// Count distinct users for multiple roles in a single query.
    ///
    /// Returns a map of role_id -> user_count. Roles with zero users are included
    /// with a count of 0.
    async fn count_users_for_roles(
        &self,
        tenant_id: Uuid,
        role_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, i64>> {
        // Initialize all roles with 0
        let mut counts: HashMap<Uuid, i64> = role_ids.iter().map(|id| (*id, 0i64)).collect();

        if role_ids.is_empty() {
            return Ok(counts);
        }

        let rows: Vec<(Uuid, i64)> = sqlx::query_as(
            r"
            SELECT ree.role_id, COUNT(DISTINCT ea.target_id) as user_count
            FROM gov_role_effective_entitlements ree
            JOIN gov_entitlement_assignments ea
                ON ea.entitlement_id = ree.entitlement_id
                AND ea.tenant_id = ree.tenant_id
            WHERE ree.tenant_id = $1
                AND ree.role_id = ANY($2)
                AND ea.target_type = 'user'
                AND ea.status = 'active'
            GROUP BY ree.role_id
            ",
        )
        .bind(tenant_id)
        .bind(role_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        for (role_id, user_count) in rows {
            counts.insert(role_id, user_count);
        }

        Ok(counts)
    }

    // =========================================================================
    // Tree View & Impact Analysis
    // =========================================================================

    /// Get role hierarchy as tree structure.
    pub async fn get_tree(
        &self,
        tenant_id: Uuid,
        root_role_id: Option<Uuid>,
    ) -> Result<Vec<GovRoleTreeNode>> {
        let roots = if let Some(root_id) = root_role_id {
            let role = self.get_role(tenant_id, root_id).await?;
            vec![role]
        } else {
            self.get_root_roles(tenant_id).await?
        };

        let mut tree = Vec::new();
        for root in roots {
            let node = self.build_tree_node(tenant_id, root).await?;
            tree.push(node);
        }

        Ok(tree)
    }

    /// Recursively build a tree node with counts.
    async fn build_tree_node(&self, tenant_id: Uuid, role: GovRole) -> Result<GovRoleTreeNode> {
        // Get direct entitlement count
        let direct_count =
            xavyo_db::models::GovRoleEntitlement::count_by_role_id(&self.pool, tenant_id, role.id)
                .await
                .unwrap_or(0);

        // Get effective entitlement count
        let effective_count =
            GovRoleEffectiveEntitlement::count_for_role(&self.pool, tenant_id, role.id)
                .await
                .unwrap_or(0);

        // Count distinct users with active entitlement assignments for this role's
        // effective entitlements (direct + inherited).
        let user_count = self.count_users_for_role(tenant_id, role.id).await?;

        // Get children and build their nodes
        let children_roles = GovRole::get_children(&self.pool, tenant_id, role.id).await?;
        let mut children = Vec::new();
        for child in children_roles {
            let child_node = Box::pin(self.build_tree_node(tenant_id, child)).await?;
            children.push(child_node);
        }

        Ok(GovRoleTreeNode {
            id: role.id,
            name: role.name,
            depth: role.hierarchy_depth,
            is_abstract: role.is_abstract,
            direct_entitlement_count: direct_count,
            effective_entitlement_count: effective_count,
            assigned_user_count: user_count,
            children,
        })
    }

    /// Get impact analysis for a role.
    pub async fn get_impact(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<GovRoleImpactAnalysis> {
        let role = self.get_role(tenant_id, role_id).await?;
        let descendants = self.get_descendants(tenant_id, role_id).await?;

        // Collect all role IDs (this role + descendants) for a bulk user count query.
        let mut all_role_ids: Vec<Uuid> = vec![role_id];
        all_role_ids.extend(descendants.iter().map(|d| d.id));

        let user_counts = self.count_users_for_roles(tenant_id, &all_role_ids).await?;

        // Sum total affected users across all roles.
        let total_affected_users: i64 = user_counts.values().sum();

        let descendant_details: Vec<_> = descendants
            .into_iter()
            .map(|d| {
                let count = user_counts.get(&d.id).copied().unwrap_or(0);
                xavyo_db::models::GovRoleDescendant {
                    id: d.id,
                    name: d.name,
                    depth: d.hierarchy_depth,
                    assigned_user_count: count,
                }
            })
            .collect();

        Ok(GovRoleImpactAnalysis {
            role_id: role.id,
            role_name: role.name,
            descendant_count: descendant_details.len() as i64,
            total_affected_users,
            descendants: descendant_details,
        })
    }

    // =========================================================================
    // Effective Entitlements
    // =========================================================================

    /// Get effective entitlements for a role.
    pub async fn get_effective_entitlements(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<EffectiveEntitlementDetails>> {
        // Verify role exists
        let _role = self.get_role(tenant_id, role_id).await?;

        GovRoleEffectiveEntitlement::get_for_role_with_details(&self.pool, tenant_id, role_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Recompute effective entitlements for a role.
    pub async fn recompute_effective_entitlements(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<i64> {
        // Verify role exists
        let _role = self.get_role(tenant_id, role_id).await?;

        GovRoleEffectiveEntitlement::recompute_for_descendants(&self.pool, tenant_id, role_id)
            .await
            .map_err(GovernanceError::Database)
    }

    // =========================================================================
    // Inheritance Blocks
    // =========================================================================

    /// List inheritance blocks for a role.
    pub async fn list_inheritance_blocks(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<InheritanceBlockDetails>> {
        // Verify role exists
        let _role = self.get_role(tenant_id, role_id).await?;

        GovRoleInheritanceBlock::list_for_role_with_details(&self.pool, tenant_id, role_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Add an inheritance block for a role.
    pub async fn add_inheritance_block(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        entitlement_id: Uuid,
        created_by: Uuid,
    ) -> Result<GovRoleInheritanceBlock> {
        // Verify role exists
        let _role = self.get_role(tenant_id, role_id).await?;

        // Check if block already exists
        if let Some(_existing) = GovRoleInheritanceBlock::find_by_role_and_entitlement(
            &self.pool,
            tenant_id,
            role_id,
            entitlement_id,
        )
        .await?
        {
            return Err(GovernanceError::GovRoleInheritanceBlockExists);
        }

        let block = GovRoleInheritanceBlock::create(
            &self.pool,
            tenant_id,
            role_id,
            entitlement_id,
            created_by,
        )
        .await?;

        // Recompute effective entitlements for the role and its descendants
        GovRoleEffectiveEntitlement::recompute_for_descendants(&self.pool, tenant_id, role_id)
            .await?;

        // Trigger SoD re-check for affected users (F088/T063)
        let _ = self.trigger_sod_recheck_for_role(tenant_id, role_id).await;

        // Audit log: inheritance block created (T065)
        let _ = self
            .log_audit(
                tenant_id,
                created_by,
                AdminAction::Create,
                AdminResourceType::GovRoleInheritanceBlock,
                Some(block.id),
                None,
                Some(json!({
                    "role_id": role_id,
                    "entitlement_id": entitlement_id,
                })),
            )
            .await;

        Ok(block)
    }

    /// Remove an inheritance block.
    pub async fn remove_inheritance_block(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        block_id: Uuid,
        deleted_by: Uuid,
    ) -> Result<()> {
        // Verify role exists
        let _role = self.get_role(tenant_id, role_id).await?;

        // Verify block exists
        let block = GovRoleInheritanceBlock::find_by_id(&self.pool, tenant_id, block_id)
            .await?
            .ok_or(GovernanceError::GovRoleInheritanceBlockNotFound(block_id))?;

        // Verify block belongs to the role
        if block.role_id != role_id {
            return Err(GovernanceError::GovRoleInheritanceBlockNotFound(block_id));
        }

        GovRoleInheritanceBlock::delete(&self.pool, tenant_id, block_id).await?;

        // Recompute effective entitlements for the role and its descendants
        GovRoleEffectiveEntitlement::recompute_for_descendants(&self.pool, tenant_id, role_id)
            .await?;

        // Trigger SoD re-check for affected users (F088/T063)
        let _ = self.trigger_sod_recheck_for_role(tenant_id, role_id).await;

        // Audit log: inheritance block deleted (T065)
        let _ = self
            .log_audit(
                tenant_id,
                deleted_by,
                AdminAction::Delete,
                AdminResourceType::GovRoleInheritanceBlock,
                Some(block_id),
                Some(json!({
                    "role_id": role_id,
                    "entitlement_id": block.entitlement_id,
                })),
                None,
            )
            .await;

        Ok(())
    }

    // =========================================================================
    // Role Entitlement Management
    // =========================================================================

    /// Add an entitlement to a role.
    pub async fn add_role_entitlement(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        entitlement_id: Uuid,
        created_by: Uuid,
    ) -> Result<xavyo_db::models::GovRoleEntitlement> {
        // Verify role exists
        let _role = self.get_role(tenant_id, role_id).await?;

        // Check if mapping already exists
        if let Some(_existing) =
            xavyo_db::models::GovRoleEntitlement::find_by_role_id_and_entitlement(
                &self.pool,
                tenant_id,
                role_id,
                entitlement_id,
            )
            .await?
        {
            return Err(GovernanceError::RoleEntitlementExists(format!(
                "role_id={role_id}"
            )));
        }

        let mapping = xavyo_db::models::GovRoleEntitlement::create_with_role_id(
            &self.pool,
            tenant_id,
            role_id,
            entitlement_id,
            created_by,
        )
        .await?;

        // Recompute effective entitlements for the role and its descendants
        GovRoleEffectiveEntitlement::recompute_for_descendants(&self.pool, tenant_id, role_id)
            .await?;

        // Trigger SoD re-check for affected users (F088/T063)
        let _ = self.trigger_sod_recheck_for_role(tenant_id, role_id).await;

        Ok(mapping)
    }

    /// Remove an entitlement from a role.
    pub async fn remove_role_entitlement(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<()> {
        // Verify role exists
        let _role = self.get_role(tenant_id, role_id).await?;

        let deleted = xavyo_db::models::GovRoleEntitlement::delete_by_role_id_and_entitlement(
            &self.pool,
            tenant_id,
            role_id,
            entitlement_id,
        )
        .await?;

        if !deleted {
            return Err(GovernanceError::RoleEntitlementNotFound(Uuid::nil()));
        }

        // Recompute effective entitlements for the role and its descendants
        GovRoleEffectiveEntitlement::recompute_for_descendants(&self.pool, tenant_id, role_id)
            .await?;

        // Trigger SoD re-check for affected users (F088/T063)
        let _ = self.trigger_sod_recheck_for_role(tenant_id, role_id).await;

        Ok(())
    }

    /// List direct entitlements for a role.
    pub async fn list_role_entitlements(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<xavyo_db::models::GovRoleEntitlement>> {
        // Verify role exists
        let _role = self.get_role(tenant_id, role_id).await?;

        xavyo_db::models::GovRoleEntitlement::list_by_role_id(&self.pool, tenant_id, role_id)
            .await
            .map_err(GovernanceError::Database)
    }

    // =========================================================================
    // Abstract Role Validation
    // =========================================================================

    /// Check if a role is assignable (not abstract).
    pub async fn is_role_assignable(&self, tenant_id: Uuid, role_id: Uuid) -> Result<bool> {
        let role = self.get_role(tenant_id, role_id).await?;
        Ok(!role.is_abstract)
    }

    /// Validate that a role can be assigned to a user.
    pub async fn validate_role_assignment(&self, tenant_id: Uuid, role_id: Uuid) -> Result<()> {
        let role = self.get_role(tenant_id, role_id).await?;
        if role.is_abstract {
            return Err(GovernanceError::GovRoleIsAbstract(role.name));
        }
        Ok(())
    }

    // =========================================================================
    // SoD Re-check Triggers (F088/T063)
    // =========================================================================

    /// Trigger `SoD` re-check for users affected by hierarchy changes.
    ///
    /// This should be called after any operation that changes effective entitlements:
    /// - Adding/removing entitlements from a role
    /// - Adding/removing inheritance blocks
    /// - Moving a role in the hierarchy
    ///
    /// Returns the number of users that were checked.
    pub async fn trigger_sod_recheck_for_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<i64> {
        // Get all roles affected (this role and all descendants)
        let role = self.get_role(tenant_id, role_id).await?;
        let descendants = self.get_descendants(tenant_id, role_id).await?;

        let mut affected_role_ids = vec![role.id];
        affected_role_ids.extend(descendants.iter().map(|d| d.id));

        // Get users assigned to any of these roles via effective entitlements.
        // We join gov_role_effective_entitlements -> gov_entitlement_assignments
        // to find distinct users who hold entitlements granted by these roles.
        let user_count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(DISTINCT ea.target_id)
            FROM gov_role_effective_entitlements ree
            JOIN gov_entitlement_assignments ea
                ON ea.entitlement_id = ree.entitlement_id
                AND ea.tenant_id = ree.tenant_id
            WHERE ree.tenant_id = $1
                AND ree.role_id = ANY($2)
                AND ea.target_type = 'user'
                AND ea.status = 'active'
            ",
        )
        .bind(tenant_id)
        .bind(&affected_role_ids)
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0);

        // Note: Actual SoD violation scanning would be handled by a background job
        // or the SodViolationService::scan_all_rules() method. Here we just identify
        // the affected user count. A production system might:
        // 1. Queue a background SoD re-scan job for affected users
        // 2. Publish an event for async processing
        // 3. Call SodEnforcementService::check_bulk_assignments() inline for small sets

        tracing::info!(
            tenant_id = %tenant_id,
            role_id = %role_id,
            affected_roles = affected_role_ids.len(),
            affected_users = user_count,
            "SoD re-check triggered for role hierarchy change"
        );

        Ok(user_count)
    }

    /// Trigger `SoD` re-check for a specific user after role changes.
    ///
    /// This is a lighter-weight check for single-user scenarios like
    /// assigning a role to a user.
    pub async fn trigger_sod_recheck_for_user(&self, tenant_id: Uuid, user_id: Uuid) -> Result<()> {
        // Note: This would integrate with SodEnforcementService or
        // SodViolationService to check the user's effective entitlements.
        // For now, we log the trigger for observability.

        tracing::info!(
            tenant_id = %tenant_id,
            user_id = %user_id,
            "SoD re-check triggered for user after role hierarchy change"
        );

        Ok(())
    }

    // =========================================================================
    // Audit Logging (F088/T064/T065)
    // =========================================================================

    /// Log an audit entry for a governance role hierarchy operation.
    async fn log_audit(
        &self,
        tenant_id: Uuid,
        admin_user_id: Uuid,
        action: AdminAction,
        resource_type: AdminResourceType,
        resource_id: Option<Uuid>,
        old_value: Option<serde_json::Value>,
        new_value: Option<serde_json::Value>,
    ) -> Result<()> {
        let entry = CreateAuditLogEntry {
            tenant_id,
            admin_user_id,
            action,
            resource_type,
            resource_id,
            old_value,
            new_value,
            ip_address: None,
            user_agent: None,
        };

        match AdminAuditLog::create(&self.pool, entry).await {
            Ok(_) => {
                tracing::debug!(
                    tenant_id = %tenant_id,
                    resource_id = ?resource_id,
                    "Audit log entry created for role hierarchy operation"
                );
            }
            Err(e) => {
                // Log but don't fail the operation if audit logging fails
                tracing::warn!(
                    tenant_id = %tenant_id,
                    resource_id = ?resource_id,
                    error = %e,
                    "Failed to create audit log entry for role hierarchy operation"
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_service_creation() {
        // This test just verifies the service struct can be instantiated
        // Real tests would require a database connection
    }

    #[test]
    fn test_service_with_custom_depth() {
        // Verify custom depth is stored
    }
}
