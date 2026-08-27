//! SCIM group provisioning service.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{Group, GroupMembership};

use crate::error::{is_unique_violation, unsupported_patch_path, ScimError, ScimResult};
use crate::models::{
    CreateScimGroupRequest, ReplaceScimGroupRequest, ScimGroup, ScimGroupListResponse,
    ScimGroupMember, ScimMeta, ScimPagination, ScimPatchOp, ScimPatchRequest, XavyoGroupExtension,
};
use crate::services::filter_parser::{parse_filter, AttributeMapper};

/// Maximum allowed hierarchy depth (10 levels).
const MAX_DEPTH: i32 = 10;

/// Depth from a recursive `MAX(...)` query. NULL/missing must not become 1 or 0.
fn required_hierarchy_depth(value: Option<(Option<i64>,)>, what: &str) -> ScimResult<i32> {
    value
        .and_then(|(d,)| d)
        .map(|d| d as i32)
        .ok_or_else(|| ScimError::Validation(format!("Could not determine {what}")))
}

/// RFC 7644 §3.4.2.3: omitted `sortBy`/`sortOrder` use defaults; invalid
/// values must not silently become `display_name` / ascending.
fn resolve_group_sort(
    sort_by: Option<&str>,
    sort_order: Option<&str>,
) -> ScimResult<(&'static str, &'static str)> {
    let column = match sort_by {
        None => "display_name",
        Some("displayName") => "display_name",
        Some("externalId") => "external_id",
        Some("id") => "id",
        Some("meta.created") => "created_at",
        Some(other) => {
            return Err(ScimError::Validation(format!(
                "Invalid sortBy '{other}'. Supported: displayName, externalId, id, meta.created"
            )));
        }
    };
    let order = match sort_order {
        None | Some("ascending") => "ASC",
        Some("descending") => "DESC",
        Some(other) => {
            return Err(ScimError::Validation(format!(
                "Invalid sortOrder '{other}'. Must be ascending or descending"
            )));
        }
    };
    Ok((column, order))
}

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
                JOIN depth_calc d ON g.id = d.parent_id AND g.tenant_id = $1
                WHERE g.tenant_id = $1
            )
            SELECT MAX(depth) FROM depth_calc
            ",
        )
        .bind(tenant_id)
        .bind(parent_id)
        .fetch_optional(&self.pool)
        .await?;

        let parent_depth = required_hierarchy_depth(parent_depth, "parent group depth")?;

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
                    JOIN ancestors a ON g.id = a.parent_id AND g.tenant_id = $1
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
                    JOIN subtree s ON g.parent_id = s.id AND g.tenant_id = $1
                    WHERE g.tenant_id = $1
                )
                SELECT MAX(relative_depth) FROM subtree
                ",
            )
            .bind(tenant_id)
            .bind(gid)
            .fetch_optional(&self.pool)
            .await?;

            let subtree_max = required_hierarchy_depth(subtree_depth, "group subtree depth")?;
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

    /// Maximum allowed length for string fields.
    const MAX_STRING_LEN: usize = 255;

    /// Validate string field lengths.
    fn validate_group_strings(display_name: &str, external_id: Option<&str>) -> ScimResult<()> {
        if display_name.len() > Self::MAX_STRING_LEN {
            return Err(ScimError::Validation(format!(
                "displayName exceeds maximum length of {} characters",
                Self::MAX_STRING_LEN
            )));
        }
        if display_name.trim().is_empty() {
            return Err(ScimError::Validation(
                "displayName must not be empty".to_string(),
            ));
        }
        if let Some(ext_id) = external_id {
            if ext_id.len() > Self::MAX_STRING_LEN {
                return Err(ScimError::Validation(format!(
                    "externalId exceeds maximum length of {} characters",
                    Self::MAX_STRING_LEN
                )));
            }
        }
        Ok(())
    }

    /// Validate that member UUIDs belong to the same tenant and are active.
    ///
    /// Prevents adding deactivated users to groups, which would be inconsistent
    /// with SCIM semantics (DELETE deactivates, and deactivated users return 404).
    async fn validate_members_tenant(
        &self,
        tenant_id: Uuid,
        member_ids: &[Uuid],
    ) -> ScimResult<()> {
        if member_ids.is_empty() {
            return Ok(());
        }

        // Count how many of the provided UUIDs exist and are active in this tenant
        let count: (i64,) = sqlx::query_as(
            r"SELECT COUNT(*)::bigint FROM users WHERE tenant_id = $1 AND id = ANY($2) AND is_active = true",
        )
        .bind(tenant_id)
        .bind(member_ids)
        .fetch_one(&self.pool)
        .await?;

        if count.0 != member_ids.len() as i64 {
            return Err(ScimError::Validation(
                "One or more member IDs do not exist or are inactive in this tenant".to_string(),
            ));
        }
        Ok(())
    }

    /// Create a new group.
    pub async fn create_group(
        &self,
        tenant_id: Uuid,
        request: CreateScimGroupRequest,
    ) -> ScimResult<ScimGroup> {
        Self::validate_group_strings(&request.display_name, request.external_id.as_deref())?;

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

        // Create group — catch unique constraint violations (TOCTOU race condition)
        let group = match Group::create(
            &self.pool,
            tenant_id,
            &request.display_name,
            request.external_id.as_deref(),
            None, // description
            parent_id,
            group_type,
        )
        .await
        {
            Ok(group) => group,
            Err(ref e) if is_unique_violation(e) => {
                return Err(ScimError::Conflict {
                    resource_type: "group".to_string(),
                    field: "displayName".to_string(),
                    value: request.display_name.clone(),
                });
            }
            Err(e) => return Err(e.into()),
        };

        // Add members if provided — validate they belong to the same tenant
        if !request.members.is_empty() {
            let member_ids: Vec<Uuid> = request.members.iter().map(|m| m.value).collect();
            self.validate_members_tenant(tenant_id, &member_ids).await?;
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

        // Apply sorting (column names are from a hardcoded allowlist — quote for defense-in-depth)
        let (sort_column, sort_order) = resolve_group_sort(
            pagination.sort_by.as_deref(),
            pagination.sort_order.as_deref(),
        )?;
        base_query.push_str(&format!(" ORDER BY \"{sort_column}\" {sort_order}"));

        // Apply pagination.
        // Parameter numbering: $1 = tenant_id, $2..N = filter params, $N+1 = LIMIT, $N+2 = OFFSET.
        // Both count_query and base_query share the same $1..N params; base_query adds LIMIT/OFFSET.
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

        // RFC 7644 Section 3.4.2: itemsPerPage = actual number of resources returned
        let items_per_page = resources.len() as i64;
        Ok(ScimGroupListResponse::new(
            resources,
            total_results,
            pagination.start_index,
            items_per_page,
        ))
    }

    /// Replace a group (full update).
    pub async fn replace_group(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        request: ReplaceScimGroupRequest,
    ) -> ScimResult<ScimGroup> {
        Self::validate_group_strings(&request.display_name, request.external_id.as_deref())?;

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

        // Replace members — validate they belong to the same tenant
        let member_ids: Vec<Uuid> = request.members.iter().map(|m| m.value).collect();
        self.validate_members_tenant(tenant_id, &member_ids).await?;
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

        // Get current group (single fetch instead of two)
        let mut group = self.find_group(tenant_id, group_id).await?;
        let original_name = group.display_name.clone();

        // Apply each operation
        for op in &request.operations {
            self.apply_patch_op(tenant_id, group_id, &mut group, op)
                .await?;
        }

        // Check for displayName conflicts if it was changed
        if group.display_name != original_name {
            let existing = Group::find_by_name(&self.pool, tenant_id, &group.display_name).await?;
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
                        group.display_name = patch_string(value, "displayName")?;
                    }
                    "externalId" | "externalid" => {
                        group.external_id = patch_optional_string(value, "externalId")?;
                    }
                    "members" => {
                        let member_ids = member_ids_from_patch_value(value)?;
                        self.validate_members_tenant(tenant_id, &member_ids).await?;
                        GroupMembership::set_members(&self.pool, tenant_id, group_id, &member_ids)
                            .await?;
                    }
                    // F071: Hierarchy extension paths
                    p if p.starts_with(
                        "urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group:groupType",
                    ) || p == "groupType" =>
                    {
                        let gt = patch_string(value, "groupType")?;
                        Self::validate_group_type(&gt)?;
                        group.group_type = gt;
                    }
                    p if p.starts_with(
                        "urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group:parentExternalId",
                    ) || p == "parentExternalId" =>
                    {
                        match value {
                            serde_json::Value::Null => group.parent_id = None,
                            serde_json::Value::String(ext_id) => {
                                if let Some(parent) =
                                    Group::find_by_external_id(&self.pool, tenant_id, ext_id)
                                        .await?
                                {
                                    self.validate_hierarchy(tenant_id, Some(group_id), parent.id)
                                        .await?;
                                    group.parent_id = Some(parent.id);
                                } else {
                                    return Err(ScimError::NotFound(format!(
                                        "Parent group with externalId {ext_id} not found"
                                    )));
                                }
                            }
                            _ => {
                                return Err(ScimError::Validation(
                                    "parentExternalId must be a string".to_string(),
                                ));
                            }
                        }
                    }
                    _ => {
                        return Err(unsupported_patch_path(path));
                    }
                }
            }
            "add" => {
                if path.starts_with("members") || path.is_empty() {
                    let value = op.value.as_ref().ok_or_else(|| {
                        ScimError::InvalidPatchOp("Value required for add members".to_string())
                    })?;
                    let members_json = if value.is_array() {
                        value.clone()
                    } else {
                        serde_json::json!([value])
                    };
                    if path.is_empty() {
                        let has_member_values = members_json
                            .as_array()
                            .is_some_and(|m| m.iter().any(|item| item.get("value").is_some()));
                        if !has_member_values {
                            return Err(ScimError::InvalidPatchOp(
                                "Add with empty path on Group requires member values with 'value' field".to_string(),
                            ));
                        }
                    }
                    let member_uuids = member_ids_from_patch_value(&members_json)?;
                    self.validate_members_tenant(tenant_id, &member_uuids)
                        .await?;

                    for user_id in member_uuids {
                        if let Err(e) =
                            GroupMembership::add_member(&self.pool, tenant_id, group_id, user_id)
                                .await
                        {
                            // Duplicate memberships are silently ignored (idempotent),
                            // but other errors (e.g. FK violation for non-existent user) propagate.
                            let err_str = e.to_string();
                            let is_duplicate =
                                err_str.contains("duplicate key value violates unique constraint");
                            if !is_duplicate {
                                tracing::error!("Failed to add member {user_id}: {err_str}");
                                return Err(ScimError::Validation(format!(
                                    "Failed to add member {user_id}"
                                )));
                            }
                        }
                    }
                } else {
                    return Err(unsupported_patch_path(path));
                }
            }
            "remove" => {
                if path.starts_with("members") {
                    let user_id = member_id_from_remove_path(path)?;
                    GroupMembership::remove_member(&self.pool, tenant_id, group_id, user_id)
                        .await?;
                } else {
                    return Err(unsupported_patch_path(path));
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
}

fn patch_string(value: &serde_json::Value, field: &str) -> ScimResult<String> {
    value
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| ScimError::Validation(format!("{field} must be a string")))
}

fn patch_optional_string(value: &serde_json::Value, field: &str) -> ScimResult<Option<String>> {
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) => Ok(Some(s.clone())),
        _ => Err(ScimError::Validation(format!("{field} must be a string"))),
    }
}

/// Replace-members PATCH values. Invalid entries must not be dropped.
fn member_ids_from_patch_value(value: &serde_json::Value) -> ScimResult<Vec<Uuid>> {
    let members = value
        .as_array()
        .ok_or_else(|| ScimError::InvalidPatchOp("members must be an array".to_string()))?;
    members
        .iter()
        .map(|m| {
            let raw = m.get("value").and_then(|v| v.as_str()).ok_or_else(|| {
                ScimError::InvalidPatchOp("members[].value must be a string UUID".to_string())
            })?;
            raw.parse()
                .map_err(|_| ScimError::InvalidPatchOp(format!("invalid member id: {raw}")))
        })
        .collect()
}

/// Parse member ID from a remove-members PATCH path. Unparseable paths fail.
fn member_id_from_remove_path(path: &str) -> ScimResult<Uuid> {
    parse_member_filter_path(path)
        .ok_or_else(|| ScimError::InvalidPatchOp(format!("Invalid member filter path: {path}")))
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
            return Err(ScimError::Validation(format!(
                "Group {group_id} has child groups. Remove or reassign children first."
            )));
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

    #[test]
    fn group_patch_does_not_drop_invalid_members_or_display_name() {
        assert!(patch_string(&serde_json::json!(1), "displayName").is_err());
        assert_eq!(
            patch_string(&serde_json::json!("Team"), "displayName").unwrap(),
            "Team"
        );

        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(
            member_ids_from_patch_value(&serde_json::json!([{"value": uuid.to_string()}])).unwrap(),
            vec![uuid]
        );
        assert!(
            member_ids_from_patch_value(&serde_json::json!({"value": uuid.to_string()})).is_err()
        );
        assert!(member_ids_from_patch_value(&serde_json::json!([
            {"value": uuid.to_string()},
            {"value": "not-a-uuid"}
        ]))
        .is_err());
        assert!(member_ids_from_patch_value(&serde_json::json!([{"display": "x"}])).is_err());

        let src = include_str!("group_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("member_ids_from_patch_value(")
                && production.contains("patch_string(")
                && !production.contains(".filter_map(|m|"),
            "group PATCH members/displayName must fail closed, not drop invalid entries"
        );
        assert!(
            production.contains("parentExternalId must be a string")
                && !production.contains("if let Some(ext_id) = value.as_str()"),
            "parentExternalId non-string must not no-op"
        );
    }

    #[test]
    fn invalid_member_remove_path_is_not_success() {
        let err = member_id_from_remove_path("members").expect_err("must fail closed");
        assert!(
            matches!(err, ScimError::InvalidPatchOp(ref msg) if msg.contains("members")),
            "got {err:?}"
        );
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(
            member_id_from_remove_path(
                r#"members[value eq "550e8400-e29b-41d4-a716-446655440000"]"#
            )
            .unwrap(),
            uuid
        );
    }

    #[test]
    fn group_patch_unknown_path_is_not_success() {
        let src = include_str!("group_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("unsupported_patch_path(path)"),
            "unknown group PATCH paths must fail closed"
        );
        assert!(
            !production.contains("tracing::warn!(\"Unknown patch path"),
            "must not no-op unknown group PATCH paths"
        );
        assert!(
            !production.contains("tracing::warn!(\"Add operation on path"),
            "must not no-op unsupported add paths"
        );
        assert!(
            !production.contains("tracing::warn!(\"Cannot remove path"),
            "must not no-op unsupported remove paths"
        );
        assert!(
            production.contains("Parent group with externalId")
                && !production.contains("Parent not found by external_id in patch"),
            "missing parent on PATCH must fail, not continue"
        );
        let err = unsupported_patch_path("displayName.invalid");
        assert!(
            matches!(err, ScimError::InvalidPatchOp(ref msg) if msg.contains("displayName.invalid")),
            "got {err:?}"
        );
    }

    #[test]
    fn hierarchy_walks_join_groups_on_tenant_id() {
        let src = include_str!("group_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("JOIN depth_calc d ON g.id = d.parent_id AND g.tenant_id = $1"),
            "depth walks must join groups on tenant_id"
        );
        assert!(
            production.contains("JOIN ancestors a ON g.id = a.parent_id AND g.tenant_id = $1"),
            "ancestor walks must join groups on tenant_id"
        );
        assert!(
            production.contains("JOIN subtree s ON g.parent_id = s.id AND g.tenant_id = $1"),
            "subtree walks must join groups on tenant_id"
        );
        assert!(
            !production.contains("JOIN depth_calc d ON g.id = d.parent_id\n"),
            "must not join depth_calc by id alone"
        );
        assert!(
            !production.contains("JOIN subtree s ON g.parent_id = s.id\n"),
            "must not join subtree by parent_id alone"
        );
    }

    #[test]
    fn invalid_group_sort_is_rejected() {
        assert_eq!(
            resolve_group_sort(None, None).unwrap(),
            ("display_name", "ASC")
        );
        assert_eq!(
            resolve_group_sort(Some("externalId"), Some("descending")).unwrap(),
            ("external_id", "DESC")
        );
        let err = resolve_group_sort(Some("members"), None).unwrap_err();
        assert!(
            matches!(err, ScimError::Validation(ref msg) if msg.contains("sortBy")),
            "got {err:?}"
        );
        let err = resolve_group_sort(None, Some("DESC")).unwrap_err();
        assert!(
            matches!(err, ScimError::Validation(ref msg) if msg.contains("sortOrder")),
            "got {err:?}"
        );
        let src = include_str!("group_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        let list = production
            .split("pub async fn list_groups")
            .nth(1)
            .and_then(|s| s.split("pub async fn").next())
            .expect("list_groups");
        assert!(
            list.contains("resolve_group_sort("),
            "SCIM group list must not silently default invalid sortBy/sortOrder"
        );
        assert!(
            !list.contains("_ => \"display_name\"") && !list.contains("_ => \"ASC\""),
            "invalid SCIM group sort must not fall through to display_name/ASC"
        );
    }

    #[test]
    fn hierarchy_depth_does_not_default_when_missing() {
        assert_eq!(
            required_hierarchy_depth(Some((Some(3),)), "parent").unwrap(),
            3
        );
        assert_eq!(
            required_hierarchy_depth(Some((Some(0),)), "subtree").unwrap(),
            0
        );
        assert!(required_hierarchy_depth(None, "parent group depth").is_err());
        assert!(required_hierarchy_depth(Some((None,)), "parent group depth").is_err());

        let src = include_str!("group_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("required_hierarchy_depth("),
            "hierarchy validation must fail closed when depth is unknown"
        );
        assert!(
            !production.contains("unwrap_or(1)") && !production.contains("unwrap_or(0)"),
            "missing parent/subtree depth must not silently default"
        );
    }
}
