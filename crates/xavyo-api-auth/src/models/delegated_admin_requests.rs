//! Request and response types for delegated administration API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

// ============================================================================
// Permission types
// ============================================================================

/// Permission response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PermissionResponse {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub category: String,
}

/// Category summary.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CategorySummaryResponse {
    pub name: String,
    pub permission_count: i64,
}

/// List permissions response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PermissionListResponse {
    pub permissions: Vec<PermissionResponse>,
    pub categories: Vec<CategorySummaryResponse>,
}

// ============================================================================
// Role template types
// ============================================================================

/// Role template response (summary).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoleTemplateResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Role template detail response (with permissions).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoleTemplateDetailResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub permissions: Vec<PermissionResponse>,
}

/// List role templates response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoleTemplateListResponse {
    pub templates: Vec<RoleTemplateResponse>,
    pub total: i64,
}

/// Create role template request.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateRoleTemplateRequest {
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: String,
    #[validate(length(max = 500, message = "Description must be at most 500 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[validate(length(min = 1, message = "At least one permission is required"))]
    pub permissions: Vec<String>,
}

/// Update role template request.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateRoleTemplateRequest {
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[validate(length(max = 500, message = "Description must be at most 500 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
}

/// Query params for listing templates.
#[derive(Debug, Clone, Serialize, Deserialize, IntoParams)]
pub struct ListTemplatesQuery {
    #[serde(default = "default_true")]
    pub include_system: bool,
}

fn default_true() -> bool {
    true
}

// ============================================================================
// Assignment types
// ============================================================================

/// Assignment response (summary).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AssignmentResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    pub template_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_value: Option<Vec<String>>,
    pub assigned_by: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_by_name: Option<String>,
    pub assigned_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Assignment detail response (with template details).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AssignmentDetailResponse {
    #[serde(flatten)]
    pub assignment: AssignmentResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<RoleTemplateDetailResponse>,
}

/// List assignments response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AssignmentListResponse {
    pub assignments: Vec<AssignmentResponse>,
    pub total: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<DateTime<Utc>>,
}

/// Create assignment request.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateAssignmentRequest {
    pub user_id: Uuid,
    pub template_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_value: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Maximum allowed limit for pagination.
const MAX_LIMIT: i32 = 100;

/// Query params for listing assignments.
#[derive(Debug, Clone, Serialize, Deserialize, Default, IntoParams)]
pub struct ListAssignmentsQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_id: Option<Uuid>,
    #[serde(default)]
    pub include_expired: bool,
    #[serde(default)]
    pub include_revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<DateTime<Utc>>,
    #[serde(default = "default_limit")]
    pub limit: i32,
}

impl ListAssignmentsQuery {
    /// Validate and clamp pagination values.
    ///
    /// SECURITY: Prevents `DoS` via unbounded pagination.
    #[must_use]
    pub fn validated(self) -> Self {
        Self {
            limit: self.limit.clamp(1, MAX_LIMIT),
            ..self
        }
    }
}

fn default_limit() -> i32 {
    50
}

// ============================================================================
// Audit log types
// ============================================================================

/// Audit log entry response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditLogEntryResponse {
    pub id: Uuid,
    pub admin_user_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_user_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_user_name: Option<String>,
    pub action: String,
    pub resource_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Audit log list response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditLogResponse {
    pub entries: Vec<AuditLogEntryResponse>,
    pub total: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<DateTime<Utc>>,
}

/// Query params for audit log.
#[derive(Debug, Clone, Serialize, Deserialize, Default, IntoParams)]
pub struct AuditLogQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_date: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_date: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<DateTime<Utc>>,
    #[serde(default = "default_limit")]
    pub limit: i32,
}

impl AuditLogQuery {
    /// Validate and clamp pagination values.
    ///
    /// SECURITY: Prevents `DoS` via unbounded pagination.
    #[must_use]
    pub fn validated(self) -> Self {
        Self {
            limit: self.limit.clamp(1, MAX_LIMIT),
            ..self
        }
    }
}

// ============================================================================
// Effective permissions (internal use)
// ============================================================================

/// User's effective permissions after aggregating all assignments.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct EffectivePermissions {
    /// Set of permission codes (e.g., "users:read", "users:*").
    pub permissions: std::collections::HashSet<String>,
    /// List of scopes from all active assignments.
    pub scopes: Vec<ScopeAssignment>,
}

/// A single scope assignment.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScopeAssignment {
    pub scope_type: String,
    pub scope_value: Vec<String>,
}

impl EffectivePermissions {
    /// Check if user has a specific permission (with wildcard support).
    #[must_use]
    pub fn has_permission(&self, required: &str) -> bool {
        // Direct match
        if self.permissions.contains(required) {
            return true;
        }

        // Wildcard match (e.g., user has "users:*" and required is "users:read")
        if let Some(category) = required.split(':').next() {
            let wildcard = format!("{category}:*");
            if self.permissions.contains(&wildcard) {
                return true;
            }
        }

        false
    }

    /// Check if a resource is within any of the user's scopes.
    /// If user has no scopes, they have global access for their permissions.
    #[must_use]
    pub fn is_in_scope(&self, scope_type: &str, resource_scope: &str) -> bool {
        // If no scopes defined, user has global access
        if self.scopes.is_empty() {
            return true;
        }

        // Check if resource is in any of the user's scopes
        for scope in &self.scopes {
            if scope.scope_type == scope_type
                && scope.scope_value.contains(&resource_scope.to_string())
            {
                return true;
            }
        }

        false
    }
}
