//! Application request/response models for governance API.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use xavyo_db::models::{GovAppStatus, GovAppType, GovApplication};

/// Request to create a new application.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateApplicationRequest {
    /// Application display name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Application type (internal or external).
    pub app_type: GovAppType,

    /// Application description.
    #[validate(length(max = 2000, message = "Description cannot exceed 2000 characters"))]
    pub description: Option<String>,

    /// Application owner (user ID).
    pub owner_id: Option<Uuid>,

    /// External system reference ID.
    #[validate(length(max = 255, message = "External ID cannot exceed 255 characters"))]
    pub external_id: Option<String>,

    /// Extensible metadata as JSON.
    pub metadata: Option<serde_json::Value>,

    /// Whether entitlements in this application can be delegated. Defaults to true.
    pub is_delegable: Option<bool>,
}

/// Request to update an application.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateApplicationRequest {
    /// Application display name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: Option<String>,

    /// Application status (active or inactive).
    pub status: Option<GovAppStatus>,

    /// Application description.
    #[validate(length(max = 2000, message = "Description cannot exceed 2000 characters"))]
    pub description: Option<String>,

    /// Application owner (user ID).
    pub owner_id: Option<Uuid>,

    /// External system reference ID.
    #[validate(length(max = 255, message = "External ID cannot exceed 255 characters"))]
    pub external_id: Option<String>,

    /// Extensible metadata as JSON.
    pub metadata: Option<serde_json::Value>,

    /// Whether entitlements in this application can be delegated.
    pub is_delegable: Option<bool>,
}

/// Query parameters for listing applications.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListApplicationsQuery {
    /// Filter by status.
    pub status: Option<GovAppStatus>,

    /// Filter by application type.
    pub app_type: Option<GovAppType>,

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

/// Application response model.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApplicationResponse {
    /// Unique identifier for the application.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Application display name.
    pub name: String,

    /// Application type (internal or external).
    pub app_type: GovAppType,

    /// Application status (active or inactive).
    pub status: GovAppStatus,

    /// Application description.
    pub description: Option<String>,

    /// Application owner (user ID).
    pub owner_id: Option<Uuid>,

    /// External system reference ID.
    pub external_id: Option<String>,

    /// Extensible metadata as JSON.
    pub metadata: Option<serde_json::Value>,

    /// Whether entitlements in this application can be delegated.
    pub is_delegable: bool,

    /// When the application was created.
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When the application was last updated.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<GovApplication> for ApplicationResponse {
    fn from(app: GovApplication) -> Self {
        Self {
            id: app.id,
            tenant_id: app.tenant_id,
            name: app.name,
            app_type: app.app_type,
            status: app.status,
            description: app.description,
            owner_id: app.owner_id,
            external_id: app.external_id,
            metadata: app.metadata,
            is_delegable: app.is_delegable,
            created_at: app.created_at,
            updated_at: app.updated_at,
        }
    }
}

/// Paginated list of applications.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApplicationListResponse {
    /// List of applications.
    pub items: Vec<ApplicationResponse>,

    /// Total count of matching applications.
    pub total: i64,

    /// Maximum number of results returned.
    pub limit: i64,

    /// Number of results skipped.
    pub offset: i64,
}
