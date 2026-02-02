//! Role entitlement request/response models for governance API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use xavyo_db::models::GovRoleEntitlement;

/// Request to create a new role-entitlement mapping.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateRoleEntitlementRequest {
    /// The entitlement to map to the role.
    pub entitlement_id: Uuid,

    /// The role name (e.g., "admin", "viewer").
    #[validate(length(
        min = 1,
        max = 100,
        message = "Role name must be between 1 and 100 characters"
    ))]
    pub role_name: String,
}

/// Query parameters for listing role entitlements.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListRoleEntitlementsQuery {
    /// Filter by entitlement ID.
    pub entitlement_id: Option<Uuid>,

    /// Filter by role name.
    pub role_name: Option<String>,

    /// Maximum number of results to return.
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Number of results to skip.
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// Role entitlement response model.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoleEntitlementResponse {
    /// Unique identifier for the mapping.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// The entitlement being mapped.
    pub entitlement_id: Uuid,

    /// The role name being mapped.
    pub role_name: String,

    /// When the mapping was created.
    pub created_at: DateTime<Utc>,

    /// Who created this mapping.
    pub created_by: Uuid,
}

impl From<GovRoleEntitlement> for RoleEntitlementResponse {
    fn from(re: GovRoleEntitlement) -> Self {
        Self {
            id: re.id,
            tenant_id: re.tenant_id,
            entitlement_id: re.entitlement_id,
            role_name: re.role_name,
            created_at: re.created_at,
            created_by: re.created_by,
        }
    }
}

/// Paginated list of role entitlements.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoleEntitlementListResponse {
    /// List of role-entitlement mappings.
    pub items: Vec<RoleEntitlementResponse>,

    /// Total count of matching mappings.
    pub total: i64,

    /// Maximum number of results returned.
    pub limit: i64,

    /// Number of results skipped.
    pub offset: i64,
}

/// Response containing all distinct roles.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DistinctRolesResponse {
    /// List of distinct role names.
    pub roles: Vec<String>,
}
