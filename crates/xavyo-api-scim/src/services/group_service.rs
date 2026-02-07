//! SCIM group provisioning service.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{Group, GroupMembership};

use crate::error::{ScimError, ScimResult};
use crate::models::{
    CreateScimGroupRequest, ReplaceScimGroupRequest, ScimGroup, ScimGroupListResponse,
    ScimGroupMember, ScimMeta, ScimPagination, ScimPatchOp, ScimPatchRequest, XavyoGroupExtension,
};
use crate::services::filter_parser::{parse_filter, AttributeMapper};

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

/// Service for SCIM group operations.
pub struct GroupService {
    pool: PgPool,
    base_url: String,
}

impl GroupService {
    /// Create a new group service.
    pub fn new(pool: PgPool, base_url: impl Into<String>) -> Self {
        Self {
            pool,
            base_url: base_url.into(),
        }
    }

    /// Validate `group_type` is one of the allowed values (F071).
    fn validate_group_type(group_type: &str) -> ScimResult<()> {
        if ALLOWED_GROUP_TYPES.contains(&group_type) {
            Ok(())
        } else {
            Err(ScimError::Validation(format!(
                "Invalid group_type '{}'. Allowed values: {}",
                group_type,
                ALLOWED_GROUP_TYPES.join(", ")
            )))
        }
    }

    /// Validate that setting a parent would not create a cycle or exceed max depth (F071).
    ///
    /// For new groups (`group_id` = None), only checks parent depth.
    /// For existing groups, also checks that the parent is not a descendant.
    async fn validate_hierarchy(
        &self,
        tenant_id: Uuid,
        group_id: Option<Uuid>,
        parent_id: Uuid,
    ) -> ScimResult<()> {
        // Check parent exists and is in the same tenant
        let parent = Group::find_by_id(&self.pool, tenant_id, parent_id)
            .await?
            .ok_or_else(|| ScimError::Validation(format!("Parent group {parent_id} not found")))?;

        // Ensure parent is in the same tenant (defense-in-depth)
        if parent.tenant_id != tenant_id {
            return Err(ScimError::Validation(
                "Parent group belongs to a different tenant".to_string(),
            ));
        }

        // Check depth: parent's depth + 1 must not exceed MAX_DEPTH
        let parent_depth: Option<(Option<i64>,)> = sqlx::query_as(
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
            SELECT MAX(depth) FROM depth_calc
            ",
        )
        .bind(tenant_id)
        .bind(parent_id)
        .fetch_optional(&self.pool)
        .await?;

        let parent_depth = parent_depth.and_then(|(d,)| d).unwrap_or(1) as i32;

        if parent_depth + 1 > MAX_DEPTH {
            return Err(ScimError::Validation(format!(
                "Maximum hierarchy depth of {MAX_DEPTH} levels exceeded"
            )));
        }

        // For existing groups, check that the parent is not a descendant (cycle detection)
        if let Some(gid) = group_id {
            let would_cycle: (bool,) = sqlx::query_as(
                r"
                WITH RECURSIVE ancestors AS (
                    SELECT id, parent_id
                    FROM groups
                    WHERE id = $2 AND tenant_id = $1

                    UNION ALL

                    SELECT g.id, g.parent_id
                    FROM groups g
                    JOIN ancestors a ON g.id = a.parent_id
                    WHERE g.tenant_id = $1
                )
                SELECT EXISTS(SELECT 1 FROM ancestors WHERE id = $3)
                ",
            )
            .bind(tenant_id)
            .bind(parent_id)
            .bind(gid)
            .fetch_one(&self.pool)
            .await?;

            if would_cycle.0 {
                return Err(ScimError::Validation(
                    "Setting this parent would create a cycle in the hierarchy".to_string(),
                ));
            }

            // Also check the subtree depth of the group being moved
            let subtree_depth: Option<(Option<i64>,)> = sqlx::query_as(
                r"
                WITH RECURSIVE subtree AS (
                    SELECT id, 0 AS relative_depth
                    FROM groups
                    WHERE id = $2 AND tenant_id = $1

                    UNION ALL

                    SELECT g.id, s.relative_depth + 1
                    FROM groups g
                    JOIN subtree s ON g.parent_id = s.id
                    WHERE g.tenant_id = $1
                )
                SELECT MAX(relative_depth) FROM subtree
                ",
            )
            .bind(tenant_id)
            .bind(gid)
            .fetch_optional(&self.pool)
            .await?;

            let subtree_max = subtree_depth.and_then(|(d,)| d).unwrap_or(0) as i32;
            if parent_depth + 1 + subtree_max > MAX_DEPTH {
                return Err(ScimError::Validation(format!(
                    "Moving this group would exceed maximum hierarchy depth of {MAX_DEPTH} levels"
                )));
            }
        }

        Ok(())
    }

    /// Convert a Group to SCIM format.
    async fn to_scim_group(&self, tenant_id: Uuid, group: &Group) -> ScimResult<ScimGroup> {
        let members = self.get_group_members(tenant_id, group.id).await?;

        let mut scim_group = ScimGroup::new(&group.display_name);
        scim_group.id = Some(group.id);
        scim_group.external_id = group.external_id.clone();
        scim_group.members = members;
        scim_group.meta = Some(ScimMeta {
            resource_type: "Group".to_string(),
            created: group.created_at,
            last_modified: group.updated_at,
            location: Some(format!("{}/scim/v2/Groups/{}", self.base_url, group.id)),
            version: None,
        });

        // Include hierarchy extension attributes (F071)
        let parent_external_id = if let Some(pid) = group.parent_id {
            Group::find_by_id(&self.pool, tenant_id, pid)
                .await?
                .and_then(|p| p.external_id)
        } else {
            None
        };

        scim_group
            .schemas
            .push(ScimGroup::XAVYO_EXTENSION_SCHEMA.to_string());
        scim_group.xavyo_extension = Some(XavyoGroupExtension {
            group_type: Some(group.group_type.clone()),
            parent_external_id,
        });

        Ok(scim_group)
    }

    /// Get members of a group as SCIM format.
    async fn get_group_members(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> ScimResult<Vec<ScimGroupMember>> {
        let members = GroupMembership::get_group_members(&self.pool, tenant_id, group_id).await?;

        Ok(members
            .into_iter()
            .map(|m| ScimGroupMember {
                value: m.user_id,
                display: m.display_name.or(Some(m.email)),
                member_type: Some("User".to_string()),
                ref_uri: Some(format!("{}/scim/v2/Users/{}", self.base_url, m.user_id)),
            })
            .collect())
    }

    /// Create a new group.
    pub async fn create_group(
        &self,
        tenant_id: Uuid,
        request: CreateScimGroupRequest,
    ) -> ScimResult<ScimGroup> {
        // Check for existing group with same name
        let existing = Group::find_by_name(&self.pool, tenant_id, &request.display_name).await?;
        if existing.is_some() {
            return Err(ScimError::Conflict {
                resource_type: "group".to_string(),
                field: "displayName".to_string(),
                value: request.display_name.clone(),
            });
        }

        // Extract hierarchy extension attributes (F071)
        let (parent_id, group_type) = if let Some(ref ext) = request.xavyo_extension {
            // Validate group_type if provided
            if let Some(ref gt) = ext.group_type {
                Self::validate_group_type(gt)?;
            }

            // Resolve parent by external_id if provided
            let parent_id = if let Some(ref parent_ext_id) = ext.parent_external_id {
                if let Some(parent) =
                    Group::find_by_external_id(&self.pool, tenant_id, parent_ext_id).await?
                {
                    Some(parent.id)
                } else {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        parent_external_id = %parent_ext_id,
                        "Parent group not found by external_id, creating as root"
                    );
                    None
                }
            } else {
                None
            };

            // Validate hierarchy constraints if parent is being set
            if let Some(pid) = parent_id {
                self.validate_hierarchy(tenant_id, None, pid).await?;
            }

            (parent_id, ext.group_type.as_deref())
        } else {
            (None, None)
        };

        // Create group
        let group = Group::create(
            &self.pool,
            tenant_id,
            &request.display_name,
            request.external_id.as_deref(),
            None, // description
            parent_id,
            group_type,
        )
        .await?;

        // Add members if provided
        if !request.members.is_empty() {
            let member_ids: Vec<Uuid> = request.members.iter().map(|m| m.value).collect();
            GroupMembership::set_members(&self.pool, tenant_id, group.id, &member_ids).await?;
        }

        self.to_scim_group(tenant_id, &group).await
    }

    /// Get a group by ID.
    pub async fn get_group(&self, tenant_id: Uuid, group_id: Uuid) -> ScimResult<ScimGroup> {
        let group = self.find_group(tenant_id, group_id).await?;
        self.to_scim_group(tenant_id, &group).await
    }

    /// Find a group by ID, returning error if not found.
    async fn find_group(&self, tenant_id: Uuid, group_id: Uuid) -> ScimResult<Group> {
        Group::find_by_id(&self.pool, tenant_id, group_id)
            .await?
            .ok_or_else(|| ScimError::NotFound(format!("Group {group_id} not found")))
    }

    /// List groups with optional filtering and pagination.
    pub async fn list_groups(
        &self,
        tenant_id: Uuid,
        filter: Option<&str>,
        pagination: ScimPagination,
    ) -> ScimResult<ScimGroupListResponse> {
        let filter_mapper = AttributeMapper::for_groups();

        // Build query
        let mut base_query = String::from("SELECT * FROM groups WHERE tenant_id = $1");
        let mut count_query = String::from("SELECT COUNT(*) FROM groups WHERE tenant_id = $1");
        let mut params: Vec<String> = vec![];

        // Apply filter
        if let Some(filter_str) = filter {
            let sql_filter = parse_filter(filter_str, &filter_mapper, 2)?;
            base_query.push_str(&format!(" AND {}", sql_filter.clause));
            count_query.push_str(&format!(" AND {}", sql_filter.clause));
            params = sql_filter.params;
        }

        // Apply sorting
        base_query.push_str(" ORDER BY display_name ASC");

        // Apply pagination
        let param_offset = params.len() + 2;
        base_query.push_str(&format!(
            " LIMIT ${} OFFSET ${}",
            param_offset,
            param_offset + 1
        ));

        // Execute count query
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        for param in &params {
            count_q = count_q.bind(param);
        }
        let total_results = count_q.fetch_one(&self.pool).await?;

        // Execute main query
        let mut main_q = sqlx::query_as::<_, Group>(&base_query).bind(tenant_id);
        for param in &params {
            main_q = main_q.bind(param);
        }
        main_q = main_q.bind(pagination.limit()).bind(pagination.offset());
        let groups = main_q.fetch_all(&self.pool).await?;

        // Convert to SCIM format
        let mut resources = Vec::with_capacity(groups.len());
        for group in groups {
            resources.push(self.to_scim_group(tenant_id, &group).await?);
        }

        Ok(ScimGroupListResponse::new(
            resources,
            total_results,
            pagination.start_index,
            pagination.count,
        ))
    }

    /// Replace a group (full update).
    pub async fn replace_group(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        request: ReplaceScimGroupRequest,
    ) -> ScimResult<ScimGroup> {
        // Verify group exists
        let _ = self.find_group(tenant_id, group_id).await?;

        // Check for name conflicts with other groups
        let existing = Group::find_by_name(&self.pool, tenant_id, &request.display_name).await?;
        if let Some(ex) = existing {
            if ex.id != group_id {
                return Err(ScimError::Conflict {
                    resource_type: "group".to_string(),
                    field: "displayName".to_string(),
                    value: request.display_name.clone(),
                });
            }
        }

        // Get existing group to preserve hierarchy fields unless overridden
        let existing = self.find_group(tenant_id, group_id).await?;

        // Extract hierarchy extension attributes (F071)
        let (parent_id, group_type) = if let Some(ref ext) = request.xavyo_extension {
            // Validate group_type if provided
            if let Some(ref gt) = ext.group_type {
                Self::validate_group_type(gt)?;
            }

            let parent_id = if let Some(ref parent_ext_id) = ext.parent_external_id {
                if let Some(parent) =
                    Group::find_by_external_id(&self.pool, tenant_id, parent_ext_id).await?
                {
                    Some(parent.id)
                } else {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        parent_external_id = %parent_ext_id,
                        "Parent group not found by external_id, keeping current parent"
                    );
                    existing.parent_id
                }
            } else {
                None // Explicitly set to root if no parentExternalId in extension
            };

            // Validate hierarchy constraints if parent is changing
            if let Some(pid) = parent_id {
                if Some(pid) != existing.parent_id {
                    self.validate_hierarchy(tenant_id, Some(group_id), pid)
                        .await?;
                }
            }

            let gt = ext.group_type.as_deref().unwrap_or(&existing.group_type);
            (parent_id, gt.to_string())
        } else {
            (existing.parent_id, existing.group_type.clone())
        };

        // Update group
        let group = Group::replace(
            &self.pool,
            tenant_id,
            group_id,
            &request.display_name,
            request.external_id.as_deref(),
            None,
            parent_id,
            &group_type,
        )
        .await?
        .ok_or_else(|| ScimError::NotFound(format!("Group {group_id} not found")))?;

        // Replace members
        let member_ids: Vec<Uuid> = request.members.iter().map(|m| m.value).collect();
        GroupMembership::set_members(&self.pool, tenant_id, group_id, &member_ids).await?;

        self.to_scim_group(tenant_id, &group).await
    }

    /// Patch a group (partial update).
    pub async fn patch_group(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        request: ScimPatchRequest,
    ) -> ScimResult<ScimGroup> {
        // Validate patch request
        request.validate().map_err(ScimError::InvalidPatchOp)?;

        // Get current group
        let original_name = {
            let g = self.find_group(tenant_id, group_id).await?;
            g.display_name.clone()
        };
        let mut group = self.find_group(tenant_id, group_id).await?;

        // Apply each operation
        for op in &request.operations {
            self.apply_patch_op(tenant_id, group_id, &mut group, op)
                .await?;
        }

        // Check for displayName conflicts if it was changed
        if group.display_name != original_name {
            let existing =
                Group::find_by_name(&self.pool, tenant_id, &group.display_name).await?;
            if let Some(ex) = existing {
                if ex.id != group_id {
                    return Err(ScimError::Conflict {
                        resource_type: "group".to_string(),
                        field: "displayName".to_string(),
                        value: group.display_name.clone(),
                    });
                }
            }
        }

        // Update group attributes if changed
        let _ = Group::replace(
            &self.pool,
            tenant_id,
            group_id,
            &group.display_name,
            group.external_id.as_deref(),
            group.description.as_deref(),
            group.parent_id,
            &group.group_type,
        )
        .await?;

        // Reload and return
        let updated = self.find_group(tenant_id, group_id).await?;
        self.to_scim_group(tenant_id, &updated).await
    }

    /// Apply a single patch operation to a group.
    async fn apply_patch_op(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        group: &mut Group,
        op: &ScimPatchOp,
    ) -> ScimResult<()> {
        let op_type = op.op.to_lowercase();
        let path = op.path.as_deref().unwrap_or("");

        match op_type.as_str() {
            "replace" => {
                let value = op.value.as_ref().ok_or_else(|| {
                    ScimError::InvalidPatchOp("Value required for replace".to_string())
                })?;

                match path {
                    "displayName" | "displayname" => {
                        if let Some(name) = value.as_str() {
                            group.display_name = name.to_string();
                        }
                    }
                    "externalId" | "externalid" => {
                        group.external_id = value.as_str().map(std::string::ToString::to_string);
                    }
                    "members" => {
                        // Replace all members
                        if let Some(members) = value.as_array() {
                            let member_ids: Vec<Uuid> = members
                                .iter()
                                .filter_map(|m| {
                                    m.get("value")
                                        .and_then(|v| v.as_str())
                                        .and_then(|s| s.parse().ok())
                                })
                                .collect();
                            GroupMembership::set_members(
                                &self.pool,
                                tenant_id,
                                group_id,
                                &member_ids,
                            )
                            .await?;
                        }
                    }
                    // F071: Hierarchy extension paths
                    p if p.starts_with(
                        "urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group:groupType",
                    ) || p == "groupType" =>
                    {
                        if let Some(gt) = value.as_str() {
                            Self::validate_group_type(gt)?;
                            group.group_type = gt.to_string();
                        }
                    }
                    p if p.starts_with(
                        "urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group:parentExternalId",
                    ) || p == "parentExternalId" =>
                    {
                        if let Some(ext_id) = value.as_str() {
                            if let Some(parent) =
                                Group::find_by_external_id(&self.pool, tenant_id, ext_id).await?
                            {
                                // Validate hierarchy before applying
                                self.validate_hierarchy(tenant_id, Some(group_id), parent.id)
                                    .await?;
                                group.parent_id = Some(parent.id);
                            } else {
                                tracing::warn!(
                                    parent_external_id = %ext_id,
                                    "Parent not found by external_id in patch"
                                );
                            }
                        } else if value.is_null() {
                            group.parent_id = None;
                        }
                    }
                    _ => {
                        tracing::warn!("Unknown patch path: {}", path);
                    }
                }
            }
            "add" => {
                if path.starts_with("members") || path.is_empty() {
                    // Add members
                    if let Some(value) = &op.value {
                        let members = if let Some(arr) = value.as_array() {
                            arr.clone()
                        } else {
                            vec![value.clone()]
                        };

                        for member in members {
                            if let Some(user_id) = member
                                .get("value")
                                .and_then(|v| v.as_str())
                                .and_then(|s| s.parse::<Uuid>().ok())
                            {
                                let _ = GroupMembership::add_member(
                                    &self.pool, tenant_id, group_id, user_id,
                                )
                                .await;
                            }
                        }
                    }
                } else {
                    // Handle other add operations
                    tracing::warn!("Add operation on path {} not supported", path);
                }
            }
            "remove" => {
                if path.starts_with("members") {
                    // Parse member filter from path: members[value eq "uuid"]
                    if let Some(user_id) = self.parse_member_filter(path) {
                        GroupMembership::remove_member(&self.pool, tenant_id, group_id, user_id)
                            .await?;
                    }
                } else {
                    tracing::warn!("Cannot remove path: {}", path);
                }
            }
            _ => {
                return Err(ScimError::InvalidPatchOp(format!(
                    "Unknown operation: {}",
                    op.op
                )));
            }
        }

        Ok(())
    }

    /// Parse member ID from path like `members[value eq "uuid"]`.
    fn parse_member_filter(&self, path: &str) -> Option<Uuid> {
        parse_member_filter_path(path)
    }
}

/// Parse member ID from path like `members[value eq "uuid"]`.
/// This is a standalone function for easier testing.
fn parse_member_filter_path(path: &str) -> Option<Uuid> {
    // Simple parser for members[value eq "uuid"]
    if !path.starts_with("members[") {
        return None;
    }

    let inner = path.strip_prefix("members[")?.strip_suffix("]")?;

    // Parse: value eq "uuid"
    let parts: Vec<&str> = inner.splitn(3, ' ').collect();
    if parts.len() != 3 || parts[0] != "value" || parts[1] != "eq" {
        return None;
    }

    let uuid_str = parts[2].trim_matches('"');
    uuid_str.parse().ok()
}

impl GroupService {
    /// Delete a group.
    ///
    /// Returns error if the group has child groups (ON DELETE RESTRICT also enforces at DB level).
    pub async fn delete_group(&self, tenant_id: Uuid, group_id: Uuid) -> ScimResult<()> {
        // Check for child groups (F071) — prevent deletion if children exist
        let has_children: (bool,) = sqlx::query_as(
            r"SELECT EXISTS(SELECT 1 FROM groups WHERE tenant_id = $1 AND parent_id = $2)",
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_one(&self.pool)
        .await?;

        if has_children.0 {
            return Err(ScimError::Conflict {
                resource_type: "group".to_string(),
                field: "children".to_string(),
                value: format!(
                    "Group {group_id} has child groups. Remove or reassign children first."
                ),
            });
        }

        // Remove all members first
        GroupMembership::remove_all_members(&self.pool, tenant_id, group_id).await?;

        // Delete the group
        let deleted = Group::delete(&self.pool, tenant_id, group_id).await?;

        if !deleted {
            return Err(ScimError::NotFound(format!("Group {group_id} not found")));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_member_filter() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

        // Test using the standalone function
        let result =
            parse_member_filter_path(r#"members[value eq "550e8400-e29b-41d4-a716-446655440000"]"#);
        assert_eq!(result, Some(uuid));

        let invalid = parse_member_filter_path("members");
        assert_eq!(invalid, None);
    }
}
