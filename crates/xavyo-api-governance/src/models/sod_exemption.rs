//! Request and response models for SoD exemption endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{GovExemptionStatus, GovSodExemption};

/// Request to create a new SoD exemption.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateSodExemptionRequest {
    /// Rule to exempt.
    pub rule_id: Uuid,

    /// User to exempt.
    pub user_id: Uuid,

    /// Business justification (required).
    #[validate(length(
        min = 10,
        max = 2000,
        message = "Justification must be 10-2000 characters"
    ))]
    pub justification: String,

    /// When the exemption expires.
    pub expires_at: DateTime<Utc>,
}

/// Query parameters for listing SoD exemptions.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListSodExemptionsQuery {
    /// Filter by rule ID.
    pub rule_id: Option<Uuid>,

    /// Filter by user ID.
    pub user_id: Option<Uuid>,

    /// Filter by exemption status.
    pub status: Option<GovExemptionStatus>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListSodExemptionsQuery {
    fn default() -> Self {
        Self {
            rule_id: None,
            user_id: None,
            status: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// SoD exemption response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SodExemptionResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Exempted rule ID.
    pub rule_id: Uuid,

    /// Exempted user ID.
    pub user_id: Uuid,

    /// Who approved the exemption.
    pub approver_id: Uuid,

    /// Business justification.
    pub justification: String,

    /// Exemption status.
    pub status: GovExemptionStatus,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Expiration timestamp.
    pub expires_at: DateTime<Utc>,

    /// When the exemption was revoked (if applicable).
    pub revoked_at: Option<DateTime<Utc>>,

    /// Who revoked the exemption (if applicable).
    pub revoked_by: Option<Uuid>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,

    /// Whether the exemption is currently active (status=active and not expired).
    pub is_active: bool,
}

impl From<GovSodExemption> for SodExemptionResponse {
    fn from(exemption: GovSodExemption) -> Self {
        let is_active = exemption.is_active();
        Self {
            id: exemption.id,
            rule_id: exemption.rule_id,
            user_id: exemption.user_id,
            approver_id: exemption.approver_id,
            justification: exemption.justification,
            status: exemption.status,
            created_at: exemption.created_at,
            expires_at: exemption.expires_at,
            revoked_at: exemption.revoked_at,
            revoked_by: exemption.revoked_by,
            updated_at: exemption.updated_at,
            is_active,
        }
    }
}

/// Paginated list of SoD exemptions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SodExemptionListResponse {
    /// List of exemptions.
    pub items: Vec<SodExemptionResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Exemption with enriched information.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SodExemptionDetailResponse {
    /// Exemption details.
    #[serde(flatten)]
    pub exemption: SodExemptionResponse,

    /// Rule name.
    pub rule_name: String,

    /// Rule severity.
    pub rule_severity: String,

    /// Days until expiration (negative if expired).
    pub days_until_expiration: i64,
}

/// Summary of expiring exemptions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExpiringExemptionsResponse {
    /// Exemptions expiring within the specified window.
    pub items: Vec<SodExemptionResponse>,

    /// Number of exemptions expiring.
    pub count: i64,

    /// Time window in hours that was checked.
    pub within_hours: i64,
}
