//! Request and response models for Power of Attorney endpoints.
//!
//! F-061: Power of Attorney / Identity Assumption feature.
//! Enables users to grant another user the ability to act on their behalf.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{PoaEventType, PoaStatus, PowerOfAttorney};

/// Request to grant a Power of Attorney.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct GrantPoaRequest {
    /// The user who will receive PoA authority (the attorney).
    pub attorney_id: Uuid,

    /// When the PoA becomes active.
    pub starts_at: DateTime<Utc>,

    /// When the PoA expires (max 90 days from starts_at).
    pub ends_at: DateTime<Utc>,

    /// Optional scope restrictions. If None, full identity assumption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<PoaScopeRequest>,

    /// Reason for granting PoA.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 500))]
    pub reason: Option<String>,
}

/// Scope restrictions for a Power of Attorney.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct PoaScopeRequest {
    /// Applications in scope. Empty = no application restriction.
    #[serde(default)]
    pub application_ids: Vec<Uuid>,

    /// Workflow types in scope. Empty = no type restriction.
    /// Valid values: "access_request", "certification", "state_transition"
    #[serde(default)]
    pub workflow_types: Vec<String>,
}

/// Request to extend a PoA's end date.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ExtendPoaRequest {
    /// New end date (must be after current end date, max 90 days from original start).
    pub new_ends_at: DateTime<Utc>,
}

/// Request to revoke a PoA.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct RevokePoaRequest {
    /// Reason for revocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 500))]
    pub reason: Option<String>,
}

/// Query parameters for listing Power of Attorney grants.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListPoaQuery {
    /// Direction filter: "incoming" (where user is attorney), "outgoing" (where user is donor).
    #[param(inline)]
    pub direction: Option<PoaDirection>,

    /// Filter by status: pending, active, expired, revoked.
    pub status: Option<String>,

    /// Filter to only currently active grants.
    pub active_now: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

/// Direction filter for listing PoA grants.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PoaDirection {
    /// Grants where the user is the attorney (receiving authority).
    Incoming,
    /// Grants where the user is the donor (granting authority).
    Outgoing,
}

impl Default for ListPoaQuery {
    fn default() -> Self {
        Self {
            direction: None,
            status: None,
            active_now: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Power of Attorney response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PoaResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// The user granting PoA (the donor).
    pub donor_id: Uuid,

    /// The user receiving PoA (the attorney).
    pub attorney_id: Uuid,

    /// When the PoA becomes active.
    pub starts_at: DateTime<Utc>,

    /// When the PoA expires.
    pub ends_at: DateTime<Utc>,

    /// Lifecycle status.
    pub status: PoaStatus,

    /// Whether the PoA is currently in effect.
    pub is_currently_active: bool,

    /// Scope ID if scoped PoA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<Uuid>,

    /// Reason for grant/revoke.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// When the PoA was created.
    pub created_at: DateTime<Utc>,

    /// When the PoA was revoked (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,

    /// Who revoked the PoA (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<Uuid>,
}

impl From<PowerOfAttorney> for PoaResponse {
    fn from(poa: PowerOfAttorney) -> Self {
        let now = Utc::now();
        Self {
            id: poa.id,
            donor_id: poa.donor_id,
            attorney_id: poa.attorney_id,
            starts_at: poa.starts_at,
            ends_at: poa.ends_at,
            status: poa.status,
            is_currently_active: poa.is_currently_active(now),
            scope_id: poa.scope_id,
            reason: poa.reason,
            created_at: poa.created_at,
            revoked_at: poa.revoked_at,
            revoked_by: poa.revoked_by,
        }
    }
}

/// Paginated list of PoA grants.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PoaListResponse {
    /// List of PoA grants.
    pub items: Vec<PoaResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Response for assuming an identity.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AssumeIdentityResponse {
    /// New access token with acting_as claims.
    pub access_token: String,

    /// ID of the assumed session.
    pub session_id: Uuid,

    /// ID of the donor whose identity was assumed.
    pub donor_id: Uuid,

    /// Display name of the donor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub donor_name: Option<String>,

    /// Email of the donor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub donor_email: Option<String>,

    /// Scope restrictions (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<PoaScopeResponse>,

    /// Effective roles for the assumed identity session (intersection of donor and attorney roles).
    /// The attorney cannot gain roles they don't already possess.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_roles: Option<Vec<String>>,

    /// True if any donor roles were restricted because the attorney lacks them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles_restricted: Option<bool>,
}

/// Response for dropping an assumed identity.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DropIdentityResponse {
    /// Original access token (attorney's own identity).
    pub access_token: String,
}

/// Current assumption status response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CurrentAssumptionResponse {
    /// Whether the user is currently assuming an identity.
    pub is_assuming: bool,

    /// ID of the PoA grant (if assuming).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poa_id: Option<Uuid>,

    /// ID of the donor (if assuming).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub donor_id: Option<Uuid>,

    /// Display name of the donor (if assuming).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub donor_name: Option<String>,

    /// ID of the assumed session (if assuming).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,

    /// When the identity was assumed (if assuming).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assumed_at: Option<DateTime<Utc>>,

    /// Scope restrictions (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<PoaScopeResponse>,
}

/// Scope response for PoA.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PoaScopeResponse {
    /// Applications in scope.
    pub application_ids: Vec<Uuid>,

    /// Workflow types in scope.
    pub workflow_types: Vec<String>,
}

/// Query parameters for listing audit events.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListPoaAuditQuery {
    /// Filter by event type.
    pub event_type: Option<String>,

    /// Filter by actor ID.
    pub actor_id: Option<Uuid>,

    /// Filter by affected user ID.
    pub affected_user_id: Option<Uuid>,

    /// Filter by events after this time.
    pub after: Option<DateTime<Utc>>,

    /// Filter by events before this time.
    pub before: Option<DateTime<Utc>>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListPoaAuditQuery {
    fn default() -> Self {
        Self {
            event_type: None,
            actor_id: None,
            affected_user_id: None,
            after: None,
            before: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Audit event response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PoaAuditEventResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Event type.
    pub event_type: PoaEventType,

    /// ID of the actor who performed the action.
    pub actor_id: Uuid,

    /// Display name of the actor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_name: Option<String>,

    /// ID of the affected user (if different from actor).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_user_id: Option<Uuid>,

    /// Display name of the affected user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_user_name: Option<String>,

    /// Additional event details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,

    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

/// Paginated list of audit events.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PoaAuditListResponse {
    /// List of audit events.
    pub items: Vec<PoaAuditEventResponse>,

    /// Total count matching the filter.
    pub total: i64,
}

/// Admin query for listing all PoA grants.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct AdminListPoaQuery {
    /// Filter by donor ID.
    pub donor_id: Option<Uuid>,

    /// Filter by attorney ID.
    pub attorney_id: Option<Uuid>,

    /// Filter by status.
    pub status: Option<String>,

    /// Filter to only currently active grants.
    pub active_now: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for AdminListPoaQuery {
    fn default() -> Self {
        Self {
            donor_id: None,
            attorney_id: None,
            status: None,
            active_now: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}
