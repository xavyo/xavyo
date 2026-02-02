//! Request and response models for service account endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{GovServiceAccount, ServiceAccountStatus};

/// Service account response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ServiceAccountResponse {
    /// Service account ID.
    pub id: Uuid,

    /// The user ID this service account is linked to.
    pub user_id: Uuid,

    /// Display name for the service account.
    pub name: String,

    /// Purpose/justification for the service account.
    pub purpose: String,

    /// Owner responsible for this service account.
    pub owner_id: Uuid,

    /// Current status.
    pub status: ServiceAccountStatus,

    /// When this account expires (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Days until expiration (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_until_expiry: Option<i64>,

    /// When ownership was last certified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_certified_at: Option<DateTime<Utc>>,

    /// Who performed the last certification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certified_by: Option<Uuid>,

    /// Whether certification is due (more than 365 days since last cert).
    pub needs_certification: bool,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<GovServiceAccount> for ServiceAccountResponse {
    fn from(account: GovServiceAccount) -> Self {
        let days_until_expiry = account.days_until_expiry();
        let needs_certification = account.needs_certification();

        Self {
            id: account.id,
            user_id: account.user_id,
            name: account.name,
            purpose: account.purpose,
            owner_id: account.owner_id,
            status: account.status,
            expires_at: account.expires_at,
            days_until_expiry,
            last_certified_at: account.last_certified_at,
            certified_by: account.certified_by,
            needs_certification,
            created_at: account.created_at,
            updated_at: account.updated_at,
        }
    }
}

/// Request to register a new service account.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct RegisterServiceAccountRequest {
    /// The user ID to register as a service account.
    pub user_id: Uuid,

    /// Display name for the service account.
    #[validate(length(min = 1, max = 200, message = "Name must be 1-200 characters"))]
    pub name: String,

    /// Purpose/justification for the service account.
    #[validate(length(min = 10, message = "Purpose must be at least 10 characters"))]
    pub purpose: String,

    /// Owner responsible for this service account.
    pub owner_id: Uuid,

    /// When this account expires (optional).
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to update a service account.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateServiceAccountRequest {
    /// New name for the service account.
    #[validate(length(min = 1, max = 200, message = "Name must be 1-200 characters"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// New purpose/justification.
    #[validate(length(min = 10, message = "Purpose must be at least 10 characters"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    /// New owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<Uuid>,

    /// New expiration date.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Query parameters for listing service accounts.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListServiceAccountsQuery {
    /// Filter by status.
    pub status: Option<ServiceAccountStatus>,

    /// Filter by owner.
    pub owner_id: Option<Uuid>,

    /// Filter accounts expiring within this many days.
    #[param(minimum = 1)]
    pub expiring_within_days: Option<i32>,

    /// Filter accounts needing certification.
    pub needs_certification: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListServiceAccountsQuery {
    fn default() -> Self {
        Self {
            status: None,
            owner_id: None,
            expiring_within_days: None,
            needs_certification: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Paginated list of service accounts.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ServiceAccountListResponse {
    /// List of service accounts.
    pub items: Vec<ServiceAccountResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Summary of service accounts.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ServiceAccountSummary {
    /// Total number of service accounts.
    pub total: i64,

    /// Number of active accounts.
    pub active: i64,

    /// Number of expired accounts.
    pub expired: i64,

    /// Number of suspended accounts.
    pub suspended: i64,

    /// Number needing certification.
    pub needs_certification: i64,

    /// Number expiring within 30 days.
    pub expiring_soon: i64,
}

/// Response for certify operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CertifyServiceAccountResponse {
    /// Updated service account.
    pub account: ServiceAccountResponse,

    /// Message.
    pub message: String,
}
