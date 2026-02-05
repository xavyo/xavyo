//! Role inducement request/response models for governance API.
//!
//! DTOs for the role inducement endpoints (F-063).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use xavyo_db::RoleInducement;

/// Query parameters for listing role inducements.
#[derive(Debug, Clone, Deserialize, IntoParams, Default)]
pub struct ListInducementsQuery {
    /// Only return enabled inducements.
    #[serde(default)]
    pub enabled_only: bool,

    /// Maximum number of results to return.
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Number of results to skip.
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

/// Request to create a new role inducement.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateInducementRequest {
    /// The role to be induced (child role whose constructions are inherited).
    pub induced_role_id: Uuid,

    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 2000, message = "Description must be at most 2000 characters"))]
    pub description: Option<String>,
}

/// Role inducement response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InducementResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Inducing role ID (the parent role).
    pub inducing_role_id: Uuid,

    /// Inducing role name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inducing_role_name: Option<String>,

    /// Induced role ID (the child role).
    pub induced_role_id: Uuid,

    /// Induced role name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub induced_role_name: Option<String>,

    /// Whether enabled.
    pub is_enabled: bool,

    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Creator user ID.
    pub created_by: Uuid,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl InducementResponse {
    /// Create response from database model with role names.
    pub fn from_model(
        inducement: RoleInducement,
        inducing_role_name: Option<String>,
        induced_role_name: Option<String>,
    ) -> Self {
        Self {
            id: inducement.id,
            tenant_id: inducement.tenant_id,
            inducing_role_id: inducement.inducing_role_id,
            inducing_role_name,
            induced_role_id: inducement.induced_role_id,
            induced_role_name,
            is_enabled: inducement.is_enabled,
            description: inducement.description,
            created_by: inducement.created_by,
            created_at: inducement.created_at,
            updated_at: inducement.updated_at,
        }
    }
}

impl From<RoleInducement> for InducementResponse {
    fn from(inducement: RoleInducement) -> Self {
        Self::from_model(inducement, None, None)
    }
}

/// List inducements response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InducementListResponse {
    /// List of inducements.
    pub items: Vec<InducementResponse>,

    /// Total count.
    pub total: i64,
}

/// Cycle detection error details.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CycleDetectedError {
    /// Error code.
    pub error: String,

    /// Human-readable message.
    pub message: String,

    /// Path of roles that would form the cycle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycle_path: Option<Vec<String>>,
}

impl CycleDetectedError {
    /// Create a new cycle detected error.
    pub fn new(cycle_path: Vec<String>) -> Self {
        let message = if cycle_path.is_empty() {
            "Creating this inducement would create a circular reference".to_string()
        } else {
            format!(
                "Creating this inducement would create a circular reference: {}",
                cycle_path.join(" → ")
            )
        };

        Self {
            error: "CYCLE_DETECTED".to_string(),
            message,
            cycle_path: if cycle_path.is_empty() {
                None
            } else {
                Some(cycle_path)
            },
        }
    }
}

/// Induced role info for traversal.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InducedRoleInfoResponse {
    /// Role ID.
    pub role_id: Uuid,

    /// Role name.
    pub role_name: String,

    /// Depth in inducement chain (0 = direct inducement).
    pub depth: i32,
}
