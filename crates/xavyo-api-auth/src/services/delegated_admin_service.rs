//! Delegated administration service for managing permissions, templates, and assignments.
//!
//! Provides enterprise-grade RBAC with support for:
//! - Permission management (view system-defined permissions)
//! - Role template management (create, update, delete custom templates)
//! - User-role assignments with optional scope restrictions
//! - Permission caching for performance (<50ms checks)
//! - Comprehensive audit logging

use crate::error::ApiAuthError;
use crate::models::{
    AssignmentResponse, AuditLogEntryResponse, EffectivePermissions, PermissionResponse,
    RoleTemplateDetailResponse, RoleTemplateResponse, ScopeAssignment,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde_json::json;
use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use tracing::info;
use uuid::Uuid;
use xavyo_db::{
    set_tenant_context, AdminAction, AdminAuditLog, AdminPermission, AdminResourceType,
    AdminRoleTemplate, AssignmentFilter, AuditLogFilter, CategorySummary, CreateAssignment,
    CreateAuditLogEntry, CreateRoleTemplate, UpdateRoleTemplate, UserAdminAssignment,
};

/// Cache TTL for permission checks (5 minutes).
const PERMISSION_CACHE_TTL_SECS: u64 = 300;

/// Cached permission entry.
#[derive(Debug, Clone)]
struct CachedPermissions {
    effective: EffectivePermissions,
    cached_at: Instant,
}

/// Delegated administration service.
#[derive(Clone)]
pub struct DelegatedAdminService {
    pool: PgPool,
    /// Permission cache: (tenant_id, user_id) -> CachedPermissions
    cache: Arc<DashMap<(Uuid, Uuid), CachedPermissions>>,
}

impl DelegatedAdminService {
    /// Create a new delegated admin service.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            cache: Arc::new(DashMap::new()),
        }
    }

    // ========================================================================
    // Permission methods (US3)
    // ========================================================================

    /// List all system-defined permissions.
    pub async fn list_permissions(&self) -> Result<Vec<PermissionResponse>, ApiAuthError> {
        let permissions = AdminPermission::get_all(&self.pool)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok(permissions
            .into_iter()
            .map(|p| PermissionResponse {
                id: p.id,
                code: p.code,
                name: p.name,
                description: p.description,
                category: p.category,
            })
            .collect())
    }

    /// Get permission category summaries.
    pub async fn get_category_summaries(&self) -> Result<Vec<CategorySummary>, ApiAuthError> {
        AdminPermission::get_category_summaries(&self.pool)
            .await
            .map_err(ApiAuthError::Database)
    }

    /// Get permissions for a specific category.
    pub async fn get_permissions_by_category(
        &self,
        category: &str,
    ) -> Result<Vec<PermissionResponse>, ApiAuthError> {
        let permissions = AdminPermission::get_by_category(&self.pool, category)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok(permissions
            .into_iter()
            .map(|p| PermissionResponse {
                id: p.id,
                code: p.code,
                name: p.name,
                description: p.description,
                category: p.category,
            })
            .collect())
    }

    /// Expand wildcard permissions to actual permission codes.
    pub async fn expand_wildcard_permissions(
        &self,
        patterns: &[String],
    ) -> Result<Vec<String>, ApiAuthError> {
        AdminPermission::expand_wildcards(&self.pool, patterns)
            .await
            .map_err(ApiAuthError::Database)
    }

    /// Validate permission codes exist.
    pub async fn validate_permission_codes(
        &self,
        codes: &[String],
    ) -> Result<Vec<Uuid>, ApiAuthError> {
        // Expand wildcards first
        let expanded = self.expand_wildcard_permissions(codes).await?;

        // Get all matching permissions
        let permissions = AdminPermission::get_by_codes(&self.pool, &expanded)
            .await
            .map_err(ApiAuthError::Database)?;

        // Check all codes exist
        let found_codes: HashSet<_> = permissions.iter().map(|p| p.code.clone()).collect();
        for code in &expanded {
            if !found_codes.contains(code) {
                return Err(ApiAuthError::InvalidPermission(format!(
                    "Permission '{}' does not exist",
                    code
                )));
            }
        }

        Ok(permissions.into_iter().map(|p| p.id).collect())
    }

    // ========================================================================
    // Role template methods (US2)
    // ========================================================================

    /// Create a new custom role template.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_role_template(
        &self,
        tenant_id: Uuid,
        admin_user_id: Uuid,
        name: String,
        description: Option<String>,
        permission_codes: Vec<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<RoleTemplateResponse, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Check name doesn't already exist
        if AdminRoleTemplate::name_exists(&mut *conn, tenant_id, &name, None)
            .await
            .map_err(ApiAuthError::Database)?
        {
            return Err(ApiAuthError::TemplateNameExists);
        }

        // Validate and get permission IDs
        let permission_ids = self.validate_permission_codes(&permission_codes).await?;

        // Create the template
        let template = AdminRoleTemplate::create(
            &mut *conn,
            CreateRoleTemplate {
                tenant_id,
                name: name.clone(),
                description: description.clone(),
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        // Add permissions
        AdminRoleTemplate::set_permissions(&self.pool, template.id, &permission_ids)
            .await
            .map_err(ApiAuthError::Database)?;

        // Log the action
        self.log_admin_action(
            tenant_id,
            admin_user_id,
            AdminAction::Create,
            AdminResourceType::Template,
            Some(template.id),
            None,
            Some(json!({
                "name": name,
                "description": description,
                "permissions": permission_codes
            })),
            ip_address,
            user_agent,
        )
        .await?;

        info!(
            tenant_id = %tenant_id,
            template_id = %template.id,
            name = %template.name,
            "Created role template"
        );

        Ok(RoleTemplateResponse {
            id: template.id,
            name: template.name,
            description: template.description,
            is_system: template.is_system,
            created_at: template.created_at,
            updated_at: template.updated_at,
        })
    }

    /// Get a role template by ID.
    pub async fn get_role_template(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<RoleTemplateDetailResponse, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let template = AdminRoleTemplate::get_by_id(&mut *conn, tenant_id, id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::TemplateNotFound)?;

        let permissions = AdminRoleTemplate::get_permissions(&mut *conn, id)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok(RoleTemplateDetailResponse {
            id: template.id,
            name: template.name,
            description: template.description,
            is_system: template.is_system,
            created_at: template.created_at,
            updated_at: template.updated_at,
            permissions: permissions
                .into_iter()
                .map(|p| PermissionResponse {
                    id: p.id,
                    code: p.code,
                    name: p.name,
                    description: p.description,
                    category: p.category,
                })
                .collect(),
        })
    }

    /// List role templates.
    pub async fn list_role_templates(
        &self,
        tenant_id: Uuid,
        include_system: bool,
    ) -> Result<(Vec<RoleTemplateResponse>, i64), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let templates = AdminRoleTemplate::list(&mut *conn, tenant_id, include_system)
            .await
            .map_err(ApiAuthError::Database)?;

        let total = AdminRoleTemplate::count(&mut *conn, tenant_id)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok((
            templates
                .into_iter()
                .map(|t| RoleTemplateResponse {
                    id: t.id,
                    name: t.name,
                    description: t.description,
                    is_system: t.is_system,
                    created_at: t.created_at,
                    updated_at: t.updated_at,
                })
                .collect(),
            total,
        ))
    }

    /// Update a custom role template.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_role_template(
        &self,
        tenant_id: Uuid,
        admin_user_id: Uuid,
        id: Uuid,
        name: Option<String>,
        description: Option<String>,
        permission_codes: Option<Vec<String>>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<RoleTemplateResponse, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get existing template
        let old_template = AdminRoleTemplate::get_by_id(&mut *conn, tenant_id, id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::TemplateNotFound)?;

        // Cannot modify system templates
        if old_template.is_system {
            return Err(ApiAuthError::CannotDeleteSystemTemplate);
        }

        // Check name uniqueness if changing
        if let Some(ref new_name) = name {
            if AdminRoleTemplate::name_exists(&mut *conn, tenant_id, new_name, Some(id))
                .await
                .map_err(ApiAuthError::Database)?
            {
                return Err(ApiAuthError::TemplateNameExists);
            }
        }

        // Get old permissions for audit
        let old_permissions = AdminRoleTemplate::get_permissions(&mut *conn, id)
            .await
            .map_err(ApiAuthError::Database)?;
        let old_permission_codes: Vec<String> =
            old_permissions.iter().map(|p| p.code.clone()).collect();

        // Update template
        let template = AdminRoleTemplate::update(
            &mut *conn,
            tenant_id,
            id,
            UpdateRoleTemplate {
                name: name.clone(),
                description: description.clone(),
            },
        )
        .await
        .map_err(ApiAuthError::Database)?
        .ok_or(ApiAuthError::TemplateNotFound)?;

        // Update permissions if provided
        if let Some(ref codes) = permission_codes {
            let permission_ids = self.validate_permission_codes(codes).await?;
            AdminRoleTemplate::set_permissions(&self.pool, id, &permission_ids)
                .await
                .map_err(ApiAuthError::Database)?;

            // Invalidate cache for all users with this template
            self.invalidate_cache_for_template(tenant_id, id).await;
        }

        // Log the action
        self.log_admin_action(
            tenant_id,
            admin_user_id,
            AdminAction::Update,
            AdminResourceType::Template,
            Some(id),
            Some(json!({
                "name": old_template.name,
                "description": old_template.description,
                "permissions": old_permission_codes
            })),
            Some(json!({
                "name": name.as_ref().unwrap_or(&old_template.name),
                "description": description.as_ref().or(old_template.description.as_ref()),
                "permissions": permission_codes.as_ref().unwrap_or(&old_permission_codes)
            })),
            ip_address,
            user_agent,
        )
        .await?;

        info!(
            tenant_id = %tenant_id,
            template_id = %id,
            "Updated role template"
        );

        Ok(RoleTemplateResponse {
            id: template.id,
            name: template.name,
            description: template.description,
            is_system: template.is_system,
            created_at: template.created_at,
            updated_at: template.updated_at,
        })
    }

    /// Delete a custom role template.
    pub async fn delete_role_template(
        &self,
        tenant_id: Uuid,
        admin_user_id: Uuid,
        id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get existing template
        let template = AdminRoleTemplate::get_by_id(&mut *conn, tenant_id, id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::TemplateNotFound)?;

        // Cannot delete system templates
        if template.is_system {
            return Err(ApiAuthError::CannotDeleteSystemTemplate);
        }

        // Revoke all assignments using this template
        let revoked_count = UserAdminAssignment::revoke_all_for_template(&mut *conn, tenant_id, id)
            .await
            .map_err(ApiAuthError::Database)?;

        if revoked_count > 0 {
            info!(
                tenant_id = %tenant_id,
                template_id = %id,
                revoked_count = revoked_count,
                "Revoked assignments for deleted template"
            );
        }

        // Delete the template
        let deleted = AdminRoleTemplate::delete(&mut *conn, tenant_id, id)
            .await
            .map_err(ApiAuthError::Database)?;

        if !deleted {
            return Err(ApiAuthError::TemplateNotFound);
        }

        // Invalidate cache for all users with this template
        self.invalidate_cache_for_template(tenant_id, id).await;

        // Log the action
        self.log_admin_action(
            tenant_id,
            admin_user_id,
            AdminAction::Delete,
            AdminResourceType::Template,
            Some(id),
            Some(json!({
                "name": template.name,
                "description": template.description,
                "revoked_assignments": revoked_count
            })),
            None,
            ip_address,
            user_agent,
        )
        .await?;

        info!(
            tenant_id = %tenant_id,
            template_id = %id,
            name = %template.name,
            "Deleted role template"
        );

        Ok(())
    }

    // ========================================================================
    // Assignment methods (US1, US5)
    // ========================================================================

    /// Create a new assignment.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_assignment(
        &self,
        tenant_id: Uuid,
        admin_user_id: Uuid,
        user_id: Uuid,
        template_id: Uuid,
        scope_type: Option<String>,
        scope_value: Option<Vec<String>>,
        expires_at: Option<DateTime<Utc>>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<AssignmentResponse, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Verify template exists and is accessible
        let template = AdminRoleTemplate::get_by_id(&mut *conn, tenant_id, template_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::TemplateNotFound)?;

        // Validate scope consistency
        if scope_type.is_some() != scope_value.is_some() {
            return Err(ApiAuthError::Validation(
                "scope_type and scope_value must both be provided or both be null".to_string(),
            ));
        }

        // Create the assignment
        let assignment = UserAdminAssignment::create(
            &mut *conn,
            CreateAssignment {
                tenant_id,
                user_id,
                template_id,
                scope_type: scope_type.clone(),
                scope_value: scope_value.clone(),
                assigned_by: admin_user_id,
                expires_at,
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        // Invalidate user's permission cache
        self.invalidate_user_permission_cache(tenant_id, user_id);

        // Log the action
        self.log_admin_action(
            tenant_id,
            admin_user_id,
            AdminAction::Assign,
            AdminResourceType::Assignment,
            Some(assignment.id),
            None,
            Some(json!({
                "user_id": user_id,
                "template_id": template_id,
                "template_name": template.name,
                "scope_type": scope_type,
                "scope_value": scope_value,
                "expires_at": expires_at
            })),
            ip_address,
            user_agent,
        )
        .await?;

        info!(
            tenant_id = %tenant_id,
            assignment_id = %assignment.id,
            user_id = %user_id,
            template_id = %template_id,
            "Created assignment"
        );

        Ok(AssignmentResponse {
            id: assignment.id,
            user_id: assignment.user_id,
            user_email: None,
            user_name: None,
            template_id: assignment.template_id,
            template_name: Some(template.name),
            scope_type: assignment.scope_type,
            scope_value: assignment.scope_value,
            assigned_by: assignment.assigned_by,
            assigned_by_name: None,
            assigned_at: assignment.assigned_at,
            expires_at: assignment.expires_at,
            revoked_at: assignment.revoked_at,
        })
    }

    /// Get an assignment by ID.
    pub async fn get_assignment(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<AssignmentResponse, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let assignment = UserAdminAssignment::get_by_id(&mut *conn, tenant_id, id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::AssignmentNotFound)?;

        // Get template name
        let template = AdminRoleTemplate::get_by_id_any(&mut *conn, assignment.template_id)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok(AssignmentResponse {
            id: assignment.id,
            user_id: assignment.user_id,
            user_email: None,
            user_name: None,
            template_id: assignment.template_id,
            template_name: template.map(|t| t.name),
            scope_type: assignment.scope_type,
            scope_value: assignment.scope_value,
            assigned_by: assignment.assigned_by,
            assigned_by_name: None,
            assigned_at: assignment.assigned_at,
            expires_at: assignment.expires_at,
            revoked_at: assignment.revoked_at,
        })
    }

    /// List assignments with optional filters.
    pub async fn list_assignments(
        &self,
        tenant_id: Uuid,
        filter: AssignmentFilter,
        cursor: Option<DateTime<Utc>>,
        limit: i32,
    ) -> Result<(Vec<AssignmentResponse>, i64), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let assignments = UserAdminAssignment::list(&mut *conn, tenant_id, &filter, cursor, limit)
            .await
            .map_err(ApiAuthError::Database)?;

        let total = if filter.include_revoked {
            UserAdminAssignment::count_all(&mut *conn, tenant_id)
                .await
                .map_err(ApiAuthError::Database)?
        } else {
            UserAdminAssignment::count_active(&mut *conn, tenant_id)
                .await
                .map_err(ApiAuthError::Database)?
        };

        // Get template names for all assignments
        let mut responses = Vec::with_capacity(assignments.len());
        for a in assignments {
            let template = AdminRoleTemplate::get_by_id_any(&mut *conn, a.template_id)
                .await
                .map_err(ApiAuthError::Database)?;

            responses.push(AssignmentResponse {
                id: a.id,
                user_id: a.user_id,
                user_email: None,
                user_name: None,
                template_id: a.template_id,
                template_name: template.map(|t| t.name),
                scope_type: a.scope_type,
                scope_value: a.scope_value,
                assigned_by: a.assigned_by,
                assigned_by_name: None,
                assigned_at: a.assigned_at,
                expires_at: a.expires_at,
                revoked_at: a.revoked_at,
            });
        }

        Ok((responses, total))
    }

    /// Revoke an assignment.
    pub async fn revoke_assignment(
        &self,
        tenant_id: Uuid,
        admin_user_id: Uuid,
        id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get existing assignment for audit
        let assignment = UserAdminAssignment::get_by_id(&mut *conn, tenant_id, id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::AssignmentNotFound)?;

        // Revoke the assignment
        let revoked = UserAdminAssignment::revoke(&mut *conn, tenant_id, id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::AssignmentNotFound)?;

        // Invalidate user's permission cache
        self.invalidate_user_permission_cache(tenant_id, assignment.user_id);

        // Log the action
        self.log_admin_action(
            tenant_id,
            admin_user_id,
            AdminAction::Revoke,
            AdminResourceType::Assignment,
            Some(id),
            Some(json!({
                "user_id": assignment.user_id,
                "template_id": assignment.template_id,
                "scope_type": assignment.scope_type,
                "scope_value": assignment.scope_value
            })),
            None,
            ip_address,
            user_agent,
        )
        .await?;

        info!(
            tenant_id = %tenant_id,
            assignment_id = %id,
            user_id = %revoked.user_id,
            "Revoked assignment"
        );

        Ok(())
    }

    // ========================================================================
    // Permission checking methods (US6)
    // ========================================================================

    /// Get effective permissions for a user (with caching).
    pub async fn get_user_effective_permissions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<EffectivePermissions, ApiAuthError> {
        let cache_key = (tenant_id, user_id);

        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key) {
            if cached.cached_at.elapsed().as_secs() < PERMISSION_CACHE_TTL_SECS {
                return Ok(cached.effective.clone());
            }
            // Cache expired, remove it
            drop(cached);
            self.cache.remove(&cache_key);
        }

        // Fetch from database
        let effective = self
            .fetch_user_effective_permissions(tenant_id, user_id)
            .await?;

        // Cache the result
        self.cache.insert(
            cache_key,
            CachedPermissions {
                effective: effective.clone(),
                cached_at: Instant::now(),
            },
        );

        Ok(effective)
    }

    /// Fetch effective permissions from database (internal).
    async fn fetch_user_effective_permissions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<EffectivePermissions, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get active assignments
        let assignments = UserAdminAssignment::get_active_for_user(&mut *conn, tenant_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        let mut permissions = HashSet::new();
        let mut scopes = Vec::new();

        for assignment in assignments {
            // Get permissions for this template
            let template_permissions =
                AdminRoleTemplate::get_permissions(&mut *conn, assignment.template_id)
                    .await
                    .map_err(ApiAuthError::Database)?;

            for p in template_permissions {
                permissions.insert(p.code);
            }

            // Collect scopes
            if let (Some(scope_type), Some(scope_value)) =
                (assignment.scope_type, assignment.scope_value)
            {
                scopes.push(ScopeAssignment {
                    scope_type,
                    scope_value,
                });
            }
        }

        Ok(EffectivePermissions {
            permissions,
            scopes,
        })
    }

    /// Invalidate permission cache for a specific user.
    pub fn invalidate_user_permission_cache(&self, tenant_id: Uuid, user_id: Uuid) {
        self.cache.remove(&(tenant_id, user_id));
    }

    /// Invalidate cache for all users with a specific template.
    async fn invalidate_cache_for_template(&self, tenant_id: Uuid, template_id: Uuid) {
        // Get all users with this template
        if let Ok(mut conn) = self.pool.acquire().await {
            if let Ok(()) =
                set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id)).await
            {
                if let Ok(assignments) = UserAdminAssignment::list(
                    &mut *conn,
                    tenant_id,
                    &AssignmentFilter {
                        template_id: Some(template_id),
                        ..Default::default()
                    },
                    None,
                    1000,
                )
                .await
                {
                    for assignment in assignments {
                        self.cache.remove(&(tenant_id, assignment.user_id));
                    }
                }
            }
        }
    }

    /// Check if a user has a specific permission.
    pub async fn has_permission(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        required_permission: &str,
    ) -> Result<bool, ApiAuthError> {
        let effective = self
            .get_user_effective_permissions(tenant_id, user_id)
            .await?;
        Ok(effective.has_permission(required_permission))
    }

    /// Check if a resource is within user's scope.
    pub async fn check_scope(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        scope_type: &str,
        resource_scope: &str,
    ) -> Result<bool, ApiAuthError> {
        let effective = self
            .get_user_effective_permissions(tenant_id, user_id)
            .await?;
        Ok(effective.is_in_scope(scope_type, resource_scope))
    }

    // ========================================================================
    // Audit log methods (US4)
    // ========================================================================

    /// Log an administrative action.
    #[allow(clippy::too_many_arguments)]
    pub async fn log_admin_action(
        &self,
        tenant_id: Uuid,
        admin_user_id: Uuid,
        action: AdminAction,
        resource_type: AdminResourceType,
        resource_id: Option<Uuid>,
        old_value: Option<serde_json::Value>,
        new_value: Option<serde_json::Value>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        AdminAuditLog::create(
            &mut *conn,
            CreateAuditLogEntry {
                tenant_id,
                admin_user_id,
                action,
                resource_type,
                resource_id,
                old_value,
                new_value,
                ip_address,
                user_agent,
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        Ok(())
    }

    /// Get audit log entries with optional filters.
    pub async fn get_audit_log(
        &self,
        tenant_id: Uuid,
        filter: AuditLogFilter,
        cursor: Option<DateTime<Utc>>,
        limit: i32,
    ) -> Result<(Vec<AuditLogEntryResponse>, i64), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let entries = AdminAuditLog::list(&mut *conn, tenant_id, &filter, cursor, limit)
            .await
            .map_err(ApiAuthError::Database)?;

        let total = AdminAuditLog::count(&mut *conn, tenant_id, &filter)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok((
            entries
                .into_iter()
                .map(|e| AuditLogEntryResponse {
                    id: e.id,
                    admin_user_id: e.admin_user_id,
                    admin_user_email: None,
                    admin_user_name: None,
                    action: e.action,
                    resource_type: e.resource_type,
                    resource_id: e.resource_id,
                    old_value: e.old_value,
                    new_value: e.new_value,
                    ip_address: e.ip_address,
                    user_agent: e.user_agent,
                    created_at: e.created_at,
                })
                .collect(),
            total,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effective_permissions_has_permission_direct() {
        let mut permissions = HashSet::new();
        permissions.insert("users:read".to_string());
        permissions.insert("users:update".to_string());

        let effective = EffectivePermissions {
            permissions,
            scopes: vec![],
        };

        assert!(effective.has_permission("users:read"));
        assert!(effective.has_permission("users:update"));
        assert!(!effective.has_permission("users:delete"));
    }

    #[test]
    fn test_effective_permissions_has_permission_wildcard() {
        let mut permissions = HashSet::new();
        permissions.insert("users:*".to_string());

        let effective = EffectivePermissions {
            permissions,
            scopes: vec![],
        };

        assert!(effective.has_permission("users:read"));
        assert!(effective.has_permission("users:update"));
        assert!(effective.has_permission("users:delete"));
        assert!(!effective.has_permission("groups:read"));
    }

    #[test]
    fn test_effective_permissions_scope_global() {
        let effective = EffectivePermissions {
            permissions: HashSet::new(),
            scopes: vec![],
        };

        // No scopes means global access
        assert!(effective.is_in_scope("group", "any-group"));
    }

    #[test]
    fn test_effective_permissions_scope_restricted() {
        let effective = EffectivePermissions {
            permissions: HashSet::new(),
            scopes: vec![ScopeAssignment {
                scope_type: "group".to_string(),
                scope_value: vec!["sales".to_string(), "marketing".to_string()],
            }],
        };

        assert!(effective.is_in_scope("group", "sales"));
        assert!(effective.is_in_scope("group", "marketing"));
        assert!(!effective.is_in_scope("group", "engineering"));
        assert!(!effective.is_in_scope("department", "sales"));
    }
}
