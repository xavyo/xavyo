//! SCIM user provisioning service.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{GroupMembership, ScimAttributeMapping, User};

use crate::error::{is_unique_violation, ScimError, ScimResult};
use crate::models::{
    CreateScimUserRequest, ReplaceScimUserRequest, ScimPagination, ScimPatchOp, ScimPatchRequest,
    ScimUser, ScimUserGroup, ScimUserListResponse,
};
use crate::services::attribute_mapper::{AttributeMapperService, ExtractedUserData};
use crate::services::filter_parser::{parse_filter, AttributeMapper};

/// Service for SCIM user operations.
pub struct UserService {
    pool: PgPool,
    base_url: String,
}

impl UserService {
    /// Create a new user service.
    pub fn new(pool: PgPool, base_url: impl Into<String>) -> Self {
        Self {
            pool,
            base_url: base_url.into(),
        }
    }

    /// Get attribute mapper for tenant.
    async fn get_mapper(&self, tenant_id: Uuid) -> ScimResult<AttributeMapperService> {
        let mappings = ScimAttributeMapping::list_by_tenant(&self.pool, tenant_id).await?;
        if mappings.is_empty() {
            Ok(AttributeMapperService::with_defaults())
        } else {
            Ok(AttributeMapperService::new(mappings))
        }
    }

    /// Get user groups as SCIM format.
    async fn get_user_groups(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> ScimResult<Vec<ScimUserGroup>> {
        let groups = GroupMembership::get_user_groups(&self.pool, tenant_id, user_id).await?;
        Ok(groups
            .into_iter()
            .map(|g| ScimUserGroup {
                value: g.group_id,
                display: Some(g.display_name),
                ref_uri: Some(format!("{}/scim/v2/Groups/{}", self.base_url, g.group_id)),
            })
            .collect())
    }

    /// Maximum allowed length for string fields.
    const MAX_STRING_LEN: usize = 255;

    /// Validate string field lengths to prevent oversized values.
    fn validate_string_lengths(data: &ExtractedUserData) -> ScimResult<()> {
        if data.email.len() > Self::MAX_STRING_LEN {
            return Err(ScimError::Validation(format!(
                "userName exceeds maximum length of {} characters",
                Self::MAX_STRING_LEN
            )));
        }
        if let Some(ref name) = data.display_name {
            if name.len() > Self::MAX_STRING_LEN {
                return Err(ScimError::Validation(format!(
                    "displayName exceeds maximum length of {} characters",
                    Self::MAX_STRING_LEN
                )));
            }
        }
        if let Some(ref ext_id) = data.external_id {
            if ext_id.len() > Self::MAX_STRING_LEN {
                return Err(ScimError::Validation(format!(
                    "externalId exceeds maximum length of {} characters",
                    Self::MAX_STRING_LEN
                )));
            }
        }
        if let Some(ref first) = data.first_name {
            if first.len() > Self::MAX_STRING_LEN {
                return Err(ScimError::Validation(format!(
                    "name.givenName exceeds maximum length of {} characters",
                    Self::MAX_STRING_LEN
                )));
            }
        }
        if let Some(ref last) = data.last_name {
            if last.len() > Self::MAX_STRING_LEN {
                return Err(ScimError::Validation(format!(
                    "name.familyName exceeds maximum length of {} characters",
                    Self::MAX_STRING_LEN
                )));
            }
        }
        Ok(())
    }

    /// Create a new user.
    pub async fn create_user(
        &self,
        tenant_id: Uuid,
        request: CreateScimUserRequest,
    ) -> ScimResult<ScimUser> {
        let mapper = self.get_mapper(tenant_id).await?;
        let data = mapper.extract_user_data(&request)?;
        Self::validate_string_lengths(&data)?;

        // Check for existing user with same email
        let existing = User::find_by_email(&self.pool, tenant_id, &data.email).await?;
        if existing.is_some() {
            return Err(ScimError::Conflict {
                resource_type: "user".to_string(),
                field: "userName".to_string(),
                value: data.email.clone(),
            });
        }

        // Create user — catch unique constraint violations (TOCTOU race condition)
        let user = match self.insert_user(tenant_id, &data).await {
            Ok(user) => user,
            Err(ScimError::Database(ref e)) if is_unique_violation(e) => {
                return Err(ScimError::Conflict {
                    resource_type: "user".to_string(),
                    field: "userName".to_string(),
                    value: data.email.clone(),
                });
            }
            Err(e) => return Err(e),
        };

        // Get groups and convert to SCIM
        let groups = self.get_user_groups(tenant_id, user.id).await?;
        Ok(mapper.to_scim_user(&user, groups, &self.base_url))
    }

    /// Insert a new user into the database.
    async fn insert_user(&self, tenant_id: Uuid, data: &ExtractedUserData) -> ScimResult<User> {
        // Build custom_attributes JSONB from extracted SCIM extension data (F070)
        let custom_attrs = serde_json::Value::Object(data.custom_attributes.clone());

        let user: User = sqlx::query_as(
            r"
            INSERT INTO users (
                tenant_id, email, password_hash, display_name, is_active,
                email_verified, external_id, first_name, last_name,
                scim_provisioned, scim_last_sync, custom_attributes
            )
            VALUES ($1, $2, '', $3, $4, true, $5, $6, $7, true, NOW(), $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&data.email)
        .bind(&data.display_name)
        .bind(data.is_active)
        .bind(&data.external_id)
        .bind(&data.first_name)
        .bind(&data.last_name)
        .bind(&custom_attrs)
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    /// Get a user by ID.
    pub async fn get_user(&self, tenant_id: Uuid, user_id: Uuid) -> ScimResult<ScimUser> {
        let user = self.find_user(tenant_id, user_id).await?;
        let mapper = self.get_mapper(tenant_id).await?;
        let groups = self.get_user_groups(tenant_id, user.id).await?;
        Ok(mapper.to_scim_user(&user, groups, &self.base_url))
    }

    /// Find an active user by ID, returning error if not found or deactivated.
    ///
    /// SCIM DELETE deactivates users (sets is_active=false). Per RFC 7644 Section 3.6,
    /// subsequent GET on a deleted resource should return 404.
    async fn find_user(&self, tenant_id: Uuid, user_id: Uuid) -> ScimResult<User> {
        let user: Option<User> = sqlx::query_as(
            r"
            SELECT * FROM users
            WHERE id = $1 AND tenant_id = $2 AND is_active = true
            ",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        user.ok_or_else(|| ScimError::NotFound(format!("User {user_id} not found")))
    }

    /// List users with optional filtering and pagination.
    pub async fn list_users(
        &self,
        tenant_id: Uuid,
        filter: Option<&str>,
        pagination: ScimPagination,
    ) -> ScimResult<ScimUserListResponse> {
        let mapper = self.get_mapper(tenant_id).await?;
        let filter_mapper = AttributeMapper::for_users();

        // Build query — only return active users (SCIM DELETE deactivates, per RFC 7644 Section 3.6)
        let mut base_query =
            String::from("SELECT * FROM users WHERE tenant_id = $1 AND is_active = true");
        let mut count_query =
            String::from("SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND is_active = true");
        let mut params: Vec<String> = vec![];

        // Apply filter
        if let Some(filter_str) = filter {
            let sql_filter = parse_filter(filter_str, &filter_mapper, 2)?;
            base_query.push_str(&format!(" AND {}", sql_filter.clause));
            count_query.push_str(&format!(" AND {}", sql_filter.clause));
            params = sql_filter.params;
        }

        // Apply sorting (column names are from a hardcoded allowlist — quote for defense-in-depth)
        let sort_column = match pagination.sort_by.as_deref() {
            Some("userName") => "email",
            Some("displayName") => "display_name",
            Some("name.givenName") => "first_name",
            Some("name.familyName") => "last_name",
            _ => "created_at",
        };
        let sort_order = match pagination.sort_order.as_deref() {
            Some("descending") => "DESC",
            _ => "ASC",
        };
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
        let total_results = self
            .execute_count_query(&count_query, tenant_id, &params)
            .await?;

        // Execute main query
        let users = self
            .execute_list_query(&base_query, tenant_id, &params, &pagination)
            .await?;

        // Convert to SCIM format
        let mut resources = Vec::with_capacity(users.len());
        for user in users {
            let groups = self.get_user_groups(tenant_id, user.id).await?;
            resources.push(mapper.to_scim_user(&user, groups, &self.base_url));
        }

        // RFC 7644 Section 3.4.2: itemsPerPage = actual number of resources returned
        let items_per_page = resources.len() as i64;
        Ok(ScimUserListResponse::new(
            resources,
            total_results,
            pagination.start_index,
            items_per_page,
        ))
    }

    async fn execute_count_query(
        &self,
        query: &str,
        tenant_id: Uuid,
        params: &[String],
    ) -> ScimResult<i64> {
        // Build dynamic query with params
        let mut q = sqlx::query_scalar::<_, i64>(query).bind(tenant_id);
        for param in params {
            q = q.bind(param);
        }
        let count = q.fetch_one(&self.pool).await?;
        Ok(count)
    }

    async fn execute_list_query(
        &self,
        query: &str,
        tenant_id: Uuid,
        params: &[String],
        pagination: &ScimPagination,
    ) -> ScimResult<Vec<User>> {
        let mut q = sqlx::query_as::<_, User>(query).bind(tenant_id);
        for param in params {
            q = q.bind(param);
        }
        q = q.bind(pagination.limit()).bind(pagination.offset());
        let users = q.fetch_all(&self.pool).await?;
        Ok(users)
    }

    /// Replace a user (full update).
    pub async fn replace_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        request: ReplaceScimUserRequest,
    ) -> ScimResult<ScimUser> {
        // Verify user exists
        let _ = self.find_user(tenant_id, user_id).await?;

        let mapper = self.get_mapper(tenant_id).await?;
        let data = mapper.extract_user_data(&request)?;
        Self::validate_string_lengths(&data)?;

        // Check for email conflicts with other users
        let existing = User::find_by_email(&self.pool, tenant_id, &data.email).await?;
        if let Some(ex) = existing {
            if ex.id != user_id {
                return Err(ScimError::Conflict {
                    resource_type: "user".to_string(),
                    field: "userName".to_string(),
                    value: data.email.clone(),
                });
            }
        }

        // Build custom_attributes JSONB from extracted SCIM extension data (F070)
        let custom_attrs = serde_json::Value::Object(data.custom_attributes.clone());

        // Update user — catch unique constraint violations (TOCTOU race condition)
        let user: User = match sqlx::query_as(
            r"
            UPDATE users SET
                email = $3,
                display_name = $4,
                is_active = $5,
                external_id = $6,
                first_name = $7,
                last_name = $8,
                custom_attributes = $9,
                scim_last_sync = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(&data.email)
        .bind(&data.display_name)
        .bind(data.is_active)
        .bind(&data.external_id)
        .bind(&data.first_name)
        .bind(&data.last_name)
        .bind(&custom_attrs)
        .fetch_one(&self.pool)
        .await
        {
            Ok(user) => user,
            Err(ref e) if is_unique_violation(e) => {
                return Err(ScimError::Conflict {
                    resource_type: "user".to_string(),
                    field: "userName".to_string(),
                    value: data.email.clone(),
                });
            }
            Err(e) => return Err(e.into()),
        };

        let groups = self.get_user_groups(tenant_id, user.id).await?;
        Ok(mapper.to_scim_user(&user, groups, &self.base_url))
    }

    /// Patch a user (partial update).
    pub async fn patch_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        request: ScimPatchRequest,
    ) -> ScimResult<ScimUser> {
        // Validate patch request
        request.validate().map_err(ScimError::InvalidPatchOp)?;

        // Get current user
        let mut user = self.find_user(tenant_id, user_id).await?;
        let original_email = user.email.clone();

        // Apply each operation
        for op in &request.operations {
            self.apply_patch_op(&mut user, op)?;
        }

        // Check for email conflicts if userName was changed
        if user.email != original_email {
            let existing = User::find_by_email(&self.pool, tenant_id, &user.email).await?;
            if let Some(ex) = existing {
                if ex.id != user_id {
                    return Err(ScimError::Conflict {
                        resource_type: "user".to_string(),
                        field: "userName".to_string(),
                        value: user.email.clone(),
                    });
                }
            }
        }

        // Update in database (includes custom_attributes for enterprise extension patches — F081)
        // Catch unique constraint violations (TOCTOU race condition)
        let updated: User = match sqlx::query_as(
            r"
            UPDATE users SET
                email = $3,
                display_name = $4,
                is_active = $5,
                external_id = $6,
                first_name = $7,
                last_name = $8,
                custom_attributes = $9,
                scim_last_sync = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(&user.email)
        .bind(&user.display_name)
        .bind(user.is_active)
        .bind(&user.external_id)
        .bind(&user.first_name)
        .bind(&user.last_name)
        .bind(&user.custom_attributes)
        .fetch_one(&self.pool)
        .await
        {
            Ok(user) => user,
            Err(ref e) if is_unique_violation(e) => {
                return Err(ScimError::Conflict {
                    resource_type: "user".to_string(),
                    field: "userName".to_string(),
                    value: user.email.clone(),
                });
            }
            Err(e) => return Err(e.into()),
        };

        let mapper = self.get_mapper(tenant_id).await?;
        let groups = self.get_user_groups(tenant_id, updated.id).await?;
        Ok(mapper.to_scim_user(&updated, groups, &self.base_url))
    }

    /// Apply a single patch operation to a user.
    fn apply_patch_op(&self, user: &mut User, op: &ScimPatchOp) -> ScimResult<()> {
        let op_type = op.op.to_lowercase();
        let path = op.path.as_deref().unwrap_or("");

        match op_type.as_str() {
            "replace" | "add" => {
                let value = op.value.as_ref().ok_or_else(|| {
                    ScimError::InvalidPatchOp("Value required for replace/add".to_string())
                })?;

                match path {
                    "displayName" | "displayname" => {
                        user.display_name = value.as_str().map(std::string::ToString::to_string);
                    }
                    "active" => {
                        user.is_active = value.as_bool().ok_or_else(|| {
                            ScimError::Validation("active must be a boolean value".to_string())
                        })?;
                    }
                    "externalId" | "externalid" => {
                        user.external_id = value.as_str().map(std::string::ToString::to_string);
                    }
                    "name.givenName" | "name.givenname" => {
                        user.first_name = value.as_str().map(std::string::ToString::to_string);
                    }
                    "name.familyName" | "name.familyname" => {
                        user.last_name = value.as_str().map(std::string::ToString::to_string);
                    }
                    "userName" | "username" => {
                        if let Some(email) = value.as_str() {
                            // Basic email format validation
                            if !email.contains('@') || !email.contains('.') {
                                return Err(ScimError::Validation(
                                    "userName must be a valid email address".to_string(),
                                ));
                            }
                            user.email = email.to_string();
                        }
                    }
                    "" => {
                        // No path means the value is an object with multiple attributes
                        if let Some(obj) = value.as_object() {
                            if let Some(active) = obj.get("active") {
                                user.is_active = active.as_bool().ok_or_else(|| {
                                    ScimError::Validation(
                                        "active must be a boolean value".to_string(),
                                    )
                                })?;
                            }
                            if let Some(display_name) = obj.get("displayName") {
                                user.display_name =
                                    display_name.as_str().map(std::string::ToString::to_string);
                            }
                            // Handle enterprise extension attributes in bulk patch (F081)
                            let enterprise_uri =
                                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
                            if let Some(ext_obj) =
                                obj.get(enterprise_uri).and_then(|v| v.as_object())
                            {
                                if let Some(ca_obj) = user.custom_attributes.as_object_mut() {
                                    for (field, val) in ext_obj {
                                        let key = match field.as_str() {
                                            "costCenter" => "cost_center".to_string(),
                                            "employeeNumber" => "employee_id".to_string(),
                                            "manager" => {
                                                if let Some(mgr_val) =
                                                    val.as_object().and_then(|m| m.get("value"))
                                                {
                                                    ca_obj.insert(
                                                        "manager_id".to_string(),
                                                        mgr_val.clone(),
                                                    );
                                                }
                                                continue;
                                            }
                                            other => other.to_string(),
                                        };
                                        ca_obj.insert(key, val.clone());
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        // Handle enterprise extension attribute paths (F081)
                        // Path format: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:field"
                        if let Some(custom_key) = Self::resolve_enterprise_extension_path(path) {
                            if let Some(obj) = user.custom_attributes.as_object_mut() {
                                obj.insert(custom_key, value.clone());
                            }
                        } else {
                            tracing::warn!("Unknown patch path: {}", path);
                        }
                    }
                }
            }
            "remove" => match path {
                "displayName" | "displayname" => {
                    user.display_name = None;
                }
                "externalId" | "externalid" => {
                    user.external_id = None;
                }
                "name.givenName" | "name.givenname" => {
                    user.first_name = None;
                }
                "name.familyName" | "name.familyname" => {
                    user.last_name = None;
                }
                _ => {
                    // Handle enterprise extension attribute removal (F081)
                    if let Some(custom_key) = Self::resolve_enterprise_extension_path(path) {
                        if let Some(obj) = user.custom_attributes.as_object_mut() {
                            obj.remove(&custom_key);
                        }
                    } else {
                        tracing::warn!("Cannot remove path: {}", path);
                    }
                }
            },
            _ => {
                return Err(ScimError::InvalidPatchOp(format!(
                    "Unknown operation: {}",
                    op.op
                )));
            }
        }

        Ok(())
    }

    /// Resolve a SCIM enterprise extension path to a custom attribute key (F081).
    ///
    /// Handles paths like:
    /// - `"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"` → `"department"`
    /// - `"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:costCenter"` → `"cost_center"`
    ///
    /// Returns `None` if the path doesn't match the enterprise extension pattern.
    fn resolve_enterprise_extension_path(path: &str) -> Option<String> {
        const ENTERPRISE_PREFIX: &str =
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:";

        let field = path.strip_prefix(ENTERPRISE_PREFIX)?;
        if field.is_empty() {
            return None;
        }

        // Map standard SCIM enterprise field names to custom attribute slugs
        let mapped = match field {
            "costCenter" => "cost_center",
            "employeeNumber" => "employee_id",
            "manager" | "manager.value" => "manager_id",
            // Fields that already match the slug (department, division, organization)
            other => other,
        };

        Some(mapped.to_string())
    }

    /// Delete (deactivate) a user.
    ///
    /// Only deactivates active users. Returns 404 if the user is already
    /// deactivated or doesn't exist (idempotent per RFC 7644 Section 3.6).
    pub async fn delete_user(&self, tenant_id: Uuid, user_id: Uuid) -> ScimResult<()> {
        let result = sqlx::query(
            r"
            UPDATE users SET
                is_active = false,
                scim_last_sync = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND is_active = true
            ",
        )
        .bind(user_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(ScimError::NotFound(format!("User {user_id} not found")));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to test patch operation logic without needing a pool
    fn apply_test_patch_op(user: &mut User, op: &ScimPatchOp) -> ScimResult<()> {
        let op_lower = op.op.to_lowercase();
        let path = op.path.as_deref().unwrap_or("");
        let value = op.value.as_ref();

        match op_lower.as_str() {
            "replace" | "add" => {
                let value = value.ok_or_else(|| {
                    ScimError::InvalidPatchOp("Value required for replace/add".to_string())
                })?;

                match path {
                    "active" => {
                        user.is_active = value.as_bool().unwrap_or(true);
                    }
                    "displayName" | "displayname" => {
                        user.display_name = value.as_str().map(|s| s.to_string());
                    }
                    "externalId" | "externalid" => {
                        user.external_id = value.as_str().map(|s| s.to_string());
                    }
                    "userName" | "username" => {
                        if let Some(email) = value.as_str() {
                            if !email.contains('@') || !email.contains('.') {
                                return Err(ScimError::Validation(
                                    "userName must be a valid email address".to_string(),
                                ));
                            }
                            user.email = email.to_string();
                        }
                    }
                    "name.givenName" | "name.givenname" => {
                        user.first_name = value.as_str().map(|s| s.to_string());
                    }
                    "name.familyName" | "name.familyname" => {
                        user.last_name = value.as_str().map(|s| s.to_string());
                    }
                    _ => {}
                }
            }
            "remove" => match path {
                "displayName" | "displayname" => user.display_name = None,
                "externalId" | "externalid" => user.external_id = None,
                "name.givenName" | "name.givenname" => user.first_name = None,
                "name.familyName" | "name.familyname" => user.last_name = None,
                _ => {}
            },
            _ => return Err(ScimError::InvalidPatchOp(format!("Unknown op: {}", op.op))),
        }
        Ok(())
    }

    #[test]
    fn test_patch_op_replace_active() {
        use chrono::Utc;

        let mut user = User {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            password_hash: "".to_string(),
            display_name: None,
            is_active: true,
            email_verified: true,
            email_verified_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            external_id: None,
            first_name: None,
            last_name: None,
            scim_provisioned: true,
            scim_last_sync: Some(Utc::now()),
            // Lockout tracking fields (F024)
            failed_login_count: 0,
            last_failed_login_at: None,
            locked_at: None,
            locked_until: None,
            lockout_reason: None,
            // Password expiration tracking fields (F024)
            password_changed_at: None,
            password_expires_at: None,
            must_change_password: false,
            // Self-service profile fields (F027)
            avatar_url: None,
            // Object Lifecycle States (F052)
            lifecycle_state_id: None,
            // Manager hierarchy (F054)
            manager_id: None,
            // Custom attributes (F070)
            custom_attributes: serde_json::json!({}),
            // Archetype fields (F058)
            archetype_id: None,
            archetype_custom_attrs: serde_json::json!({}),
        };

        let op = ScimPatchOp {
            op: "replace".to_string(),
            path: Some("active".to_string()),
            value: Some(serde_json::json!(false)),
        };

        apply_test_patch_op(&mut user, &op).unwrap();
        assert!(!user.is_active);
    }
}
