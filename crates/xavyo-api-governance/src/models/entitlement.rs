//! Entitlement request/response models for governance API.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use xavyo_db::models::{GovEntitlement, GovEntitlementStatus, GovRiskLevel};

/// Request to create a new entitlement.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateEntitlementRequest {
    /// The application this entitlement belongs to.
    pub application_id: Uuid,

    /// Entitlement display name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Entitlement description.
    #[validate(length(max = 2000, message = "Description cannot exceed 2000 characters"))]
    pub description: Option<String>,

    /// Risk level classification.
    pub risk_level: GovRiskLevel,

    /// Entitlement owner (user ID).
    pub owner_id: Option<Uuid>,

    /// External system reference ID.
    #[validate(length(max = 255, message = "External ID cannot exceed 255 characters"))]
    pub external_id: Option<String>,

    /// Extensible metadata as JSON.
    pub metadata: Option<serde_json::Value>,

    /// Whether this entitlement can be delegated. Defaults to true.
    pub is_delegable: Option<bool>,
}

/// Request to update an entitlement.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateEntitlementRequest {
    /// Entitlement display name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: Option<String>,

    /// Entitlement description.
    #[validate(length(max = 2000, message = "Description cannot exceed 2000 characters"))]
    pub description: Option<String>,

    /// Risk level classification.
    pub risk_level: Option<GovRiskLevel>,

    /// Entitlement status.
    pub status: Option<GovEntitlementStatus>,

    /// Entitlement owner (user ID).
    pub owner_id: Option<Uuid>,

    /// External system reference ID.
    #[validate(length(max = 255, message = "External ID cannot exceed 255 characters"))]
    pub external_id: Option<String>,

    /// Extensible metadata as JSON.
    pub metadata: Option<serde_json::Value>,

    /// Whether this entitlement can be delegated.
    pub is_delegable: Option<bool>,
}

/// Query parameters for listing entitlements.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListEntitlementsQuery {
    /// Filter by application ID.
    pub application_id: Option<Uuid>,

    /// Filter by status.
    pub status: Option<GovEntitlementStatus>,

    /// Filter by risk level.
    pub risk_level: Option<GovRiskLevel>,

    /// Filter by owner ID.
    pub owner_id: Option<Uuid>,

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

/// Entitlement response model.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EntitlementResponse {
    /// Unique identifier for the entitlement.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// The application this entitlement belongs to.
    pub application_id: Uuid,

    /// Entitlement display name.
    pub name: String,

    /// Entitlement description.
    pub description: Option<String>,

    /// Risk level classification.
    pub risk_level: GovRiskLevel,

    /// Entitlement status.
    pub status: GovEntitlementStatus,

    /// Entitlement owner (user ID).
    pub owner_id: Option<Uuid>,

    /// External system reference ID.
    pub external_id: Option<String>,

    /// Extensible metadata as JSON.
    pub metadata: Option<serde_json::Value>,

    /// Whether this entitlement can be delegated.
    pub is_delegable: bool,

    /// When the entitlement was created.
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When the entitlement was last updated.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<GovEntitlement> for EntitlementResponse {
    fn from(ent: GovEntitlement) -> Self {
        Self {
            id: ent.id,
            tenant_id: ent.tenant_id,
            application_id: ent.application_id,
            name: ent.name,
            description: ent.description,
            risk_level: ent.risk_level,
            status: ent.status,
            owner_id: ent.owner_id,
            external_id: ent.external_id,
            metadata: ent.metadata,
            is_delegable: ent.is_delegable,
            created_at: ent.created_at,
            updated_at: ent.updated_at,
        }
    }
}

/// Paginated list of entitlements.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EntitlementListResponse {
    /// List of entitlements.
    pub items: Vec<EntitlementResponse>,

    /// Total count of matching entitlements.
    pub total: i64,

    /// Maximum number of results returned.
    pub limit: i64,

    /// Number of results skipped.
    pub offset: i64,
}

/// Request to set entitlement owner.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SetOwnerRequest {
    /// The user ID to set as owner.
    pub owner_id: Uuid,
}
