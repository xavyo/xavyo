//! Request/response DTOs for entitlement-action mappings (F083).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use xavyo_db::models::EntitlementActionMapping;

/// Request to create a new entitlement-action mapping.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateMappingRequest {
    /// The entitlement to map.
    pub entitlement_id: Uuid,

    /// The action this entitlement grants (e.g., "read", "write", "delete", "*").
    pub action: String,

    /// The resource type this mapping applies to (e.g., "report", "user", "*").
    pub resource_type: String,
}

/// Response for a single entitlement-action mapping.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MappingResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// The mapped entitlement.
    pub entitlement_id: Uuid,

    /// The granted action.
    pub action: String,

    /// The target resource type.
    pub resource_type: String,

    /// Who created this mapping.
    pub created_by: Option<Uuid>,

    /// When the mapping was created.
    pub created_at: DateTime<Utc>,
}

/// Response for a paginated list of mappings.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MappingListResponse {
    /// The list of mappings.
    pub items: Vec<MappingResponse>,

    /// Total number of mappings matching the filters.
    pub total: i64,

    /// Page size.
    pub limit: i64,

    /// Page offset.
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

fn default_offset() -> i64 {
    0
}

/// Query parameters for listing mappings.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListMappingsQuery {
    /// Filter by entitlement ID.
    pub entitlement_id: Option<Uuid>,

    /// Maximum number of results (default: 50, max: 100).
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Offset for pagination (default: 0).
    #[serde(default = "default_offset")]
    pub offset: i64,
}

impl From<EntitlementActionMapping> for MappingResponse {
    fn from(m: EntitlementActionMapping) -> Self {
        Self {
            id: m.id,
            tenant_id: m.tenant_id,
            entitlement_id: m.entitlement_id,
            action: m.action,
            resource_type: m.resource_type,
            created_by: m.created_by,
            created_at: m.created_at,
        }
    }
}
