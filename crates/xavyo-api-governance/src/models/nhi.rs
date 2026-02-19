//! Request and response models for NHI (Non-Human Identity) endpoints.
//!
//! F061 - NHI Lifecycle Management

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{
    GovNhiAuditEvent, GovNhiRequest, GovNhiRiskScore, GovNhiUsageEvent, GovServiceAccount,
    NhiAuditEventType, NhiRequestStatus, NhiSuspensionReason, NhiUsageOutcome, RiskLevel,
    ServiceAccountStatus,
};

// =============================================================================
// NHI Core Models
// =============================================================================

/// NHI (Non-Human Identity) response with full lifecycle details.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiResponse {
    /// NHI ID (same as service account ID).
    pub id: Uuid,

    /// The linked user ID.
    pub user_id: Uuid,

    /// Display name for the NHI.
    pub name: String,

    /// Purpose/justification for the NHI.
    pub purpose: String,

    /// Primary owner responsible for this NHI.
    pub owner_id: Uuid,

    /// Backup owner (secondary contact).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_owner_id: Option<Uuid>,

    /// Current status.
    pub status: ServiceAccountStatus,

    /// When this NHI expires (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Days until expiration (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_until_expiry: Option<i64>,

    // NHI-specific lifecycle fields
    /// Credential rotation interval in days.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_interval_days: Option<i32>,

    /// When credentials were last rotated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_rotation_at: Option<DateTime<Utc>>,

    /// Whether credential rotation is needed.
    pub needs_rotation: bool,

    /// When the NHI was last used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,

    /// Days since last use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_since_last_use: Option<i64>,

    /// Inactivity threshold in days (default: 90).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inactivity_threshold_days: Option<i32>,

    /// Whether the NHI is inactive (beyond threshold).
    pub is_inactive: bool,

    /// When the grace period ends (after inactivity warning).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_period_ends_at: Option<DateTime<Utc>>,

    /// Whether in grace period.
    pub is_in_grace_period: bool,

    /// Reason for suspension (if suspended).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspension_reason: Option<NhiSuspensionReason>,

    // Certification fields
    /// When ownership was last certified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_certified_at: Option<DateTime<Utc>>,

    /// Who performed the last certification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certified_by: Option<Uuid>,

    /// Whether certification is due.
    pub needs_certification: bool,

    // Timestamps
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<GovServiceAccount> for NhiResponse {
    fn from(account: GovServiceAccount) -> Self {
        // Compute derived fields before moving
        let days_until_expiry = account.days_until_expiry();
        let needs_rotation = account.needs_rotation();
        let days_since_last_use = account.days_since_last_use();
        let is_inactive = account.is_inactive();
        let is_in_grace_period = account.is_in_grace_period();
        let needs_certification = account.needs_certification();

        Self {
            id: account.id,
            user_id: account.user_id,
            name: account.name,
            purpose: account.purpose,
            owner_id: account.owner_id,
            backup_owner_id: account.backup_owner_id,
            status: account.status,
            expires_at: account.expires_at,
            days_until_expiry,
            rotation_interval_days: account.rotation_interval_days,
            last_rotation_at: account.last_rotation_at,
            needs_rotation,
            last_used_at: account.last_used_at,
            days_since_last_use,
            inactivity_threshold_days: account.inactivity_threshold_days,
            is_inactive,
            grace_period_ends_at: account.grace_period_ends_at,
            is_in_grace_period,
            suspension_reason: account.suspension_reason,
            last_certified_at: account.last_certified_at,
            certified_by: account.certified_by,
            needs_certification,
            created_at: account.created_at,
            updated_at: account.updated_at,
        }
    }
}

/// Request to create a new NHI.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateNhiRequest {
    /// The user ID to register as an NHI.
    pub user_id: Uuid,

    /// Display name for the NHI.
    #[validate(length(min = 1, max = 200, message = "Name must be 1-200 characters"))]
    pub name: String,

    /// Purpose/justification for the NHI.
    #[validate(length(min = 10, message = "Purpose must be at least 10 characters"))]
    pub purpose: String,

    /// Primary owner responsible for this NHI.
    pub owner_id: Uuid,

    /// Backup owner (secondary contact).
    #[serde(default)]
    pub backup_owner_id: Option<Uuid>,

    /// When this NHI expires (optional).
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,

    /// Credential rotation interval in days (default: 90).
    #[validate(range(min = 1, max = 365, message = "Rotation interval must be 1-365 days"))]
    #[serde(default)]
    pub rotation_interval_days: Option<i32>,

    /// Inactivity threshold in days (default: 90).
    #[validate(range(
        min = 1,
        max = 365,
        message = "Inactivity threshold must be 1-365 days"
    ))]
    #[serde(default)]
    pub inactivity_threshold_days: Option<i32>,
}

/// Request to update an NHI.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateNhiRequest {
    /// New name for the NHI.
    #[validate(length(min = 1, max = 200, message = "Name must be 1-200 characters"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// New purpose/justification.
    #[validate(length(min = 10, message = "Purpose must be at least 10 characters"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    /// New primary owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<Uuid>,

    /// New backup owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_owner_id: Option<Uuid>,

    /// New expiration date.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// New rotation interval in days.
    #[validate(range(min = 1, max = 365, message = "Rotation interval must be 1-365 days"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_interval_days: Option<i32>,

    /// New inactivity threshold in days.
    #[validate(range(
        min = 1,
        max = 365,
        message = "Inactivity threshold must be 1-365 days"
    ))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inactivity_threshold_days: Option<i32>,
}

/// Query parameters for listing NHIs.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListNhisQuery {
    /// Filter by status.
    pub status: Option<ServiceAccountStatus>,

    /// Filter by owner.
    pub owner_id: Option<Uuid>,

    /// Filter NHIs expiring within this many days.
    #[param(minimum = 1)]
    pub expiring_within_days: Option<i32>,

    /// Filter NHIs needing certification.
    pub needs_certification: Option<bool>,

    /// Filter NHIs needing rotation.
    pub needs_rotation: Option<bool>,

    /// Filter inactive NHIs.
    pub inactive_only: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListNhisQuery {
    fn default() -> Self {
        Self {
            status: None,
            owner_id: None,
            expiring_within_days: None,
            needs_certification: None,
            needs_rotation: None,
            inactive_only: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Paginated list of NHIs.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiListResponse {
    /// List of NHIs.
    pub items: Vec<NhiResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Summary of NHIs.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiSummary {
    /// Total number of NHIs.
    pub total: i64,

    /// Number of active NHIs.
    pub active: i64,

    /// Number of expired NHIs.
    pub expired: i64,

    /// Number of suspended NHIs.
    pub suspended: i64,

    /// Number needing certification.
    pub needs_certification: i64,

    /// Number needing credential rotation.
    pub needs_rotation: i64,

    /// Number inactive (beyond threshold).
    pub inactive: i64,

    /// Number expiring within 30 days.
    pub expiring_soon: i64,

    /// Breakdown by risk level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by_risk_level: Option<NhiRiskBreakdown>,
}

/// NHI count breakdown by risk level.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiRiskBreakdown {
    pub low: i64,
    pub medium: i64,
    pub high: i64,
    pub critical: i64,
}

// =============================================================================
// Usage Models
// =============================================================================

/// NHI usage event response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiUsageEventResponse {
    /// Event ID.
    pub id: Uuid,

    /// The NHI that was used.
    pub nhi_id: Uuid,

    /// When the event occurred.
    pub timestamp: DateTime<Utc>,

    /// The resource/service accessed.
    pub target_resource: String,

    /// The action performed.
    pub action: String,

    /// Outcome of the event.
    pub outcome: NhiUsageOutcome,

    /// Source IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,

    /// User agent string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,

    /// Request duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<i32>,
}

impl From<GovNhiUsageEvent> for NhiUsageEventResponse {
    fn from(event: GovNhiUsageEvent) -> Self {
        Self {
            id: event.id,
            nhi_id: event.nhi_id,
            timestamp: event.timestamp,
            target_resource: event.target_resource,
            action: event.action,
            outcome: event.outcome,
            source_ip: event.source_ip,
            user_agent: event.user_agent,
            duration_ms: event.duration_ms,
        }
    }
}

/// Query parameters for listing usage events.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListNhiUsageQuery {
    /// Filter by target resource (partial match).
    pub target_resource: Option<String>,

    /// Filter by outcome.
    pub outcome: Option<NhiUsageOutcome>,

    /// Start date for time range.
    pub start_date: Option<DateTime<Utc>>,

    /// End date for time range.
    pub end_date: Option<DateTime<Utc>>,

    /// Maximum number of results (default: 50, max: 1000).
    #[param(minimum = 1, maximum = 1000)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListNhiUsageQuery {
    fn default() -> Self {
        Self {
            target_resource: None,
            outcome: None,
            start_date: None,
            end_date: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Paginated list of usage events.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiUsageEventListResponse {
    pub items: Vec<NhiUsageEventResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// NHI usage summary.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiUsageSummaryResponse {
    /// The NHI ID.
    pub nhi_id: Uuid,

    /// Period in days covered.
    pub period_days: i32,

    /// Total events in period.
    pub total_events: i64,

    /// Successful events.
    pub successful_events: i64,

    /// Failed events.
    pub failed_events: i64,

    /// Denied events.
    pub denied_events: i64,

    /// Number of unique resources accessed.
    pub unique_resources: i64,

    /// When the NHI was last used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,

    /// Top accessed resources.
    pub top_resources: Vec<ResourceAccessSummary>,
}

/// Resource access summary.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ResourceAccessSummary {
    pub target_resource: String,
    pub access_count: i64,
    pub last_access: DateTime<Utc>,
}

// =============================================================================
// Risk Models
// =============================================================================

/// NHI risk score response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiRiskScoreResponse {
    /// The NHI ID.
    pub nhi_id: Uuid,

    /// Combined risk score (0-100).
    pub total_score: i32,

    /// Risk level based on score.
    pub risk_level: RiskLevel,

    /// Contribution from staleness (days since last use).
    pub staleness_factor: i32,

    /// Contribution from credential age.
    pub credential_age_factor: i32,

    /// Contribution from access scope (entitlement sensitivity).
    pub access_scope_factor: i32,

    /// Detailed breakdown of factor calculations.
    pub factor_breakdown: serde_json::Value,

    /// When the score was calculated.
    pub calculated_at: DateTime<Utc>,

    /// When the next calculation should occur.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_calculation_at: Option<DateTime<Utc>>,
}

impl From<GovNhiRiskScore> for NhiRiskScoreResponse {
    fn from(score: GovNhiRiskScore) -> Self {
        Self {
            nhi_id: score.nhi_id,
            total_score: score.total_score,
            risk_level: score.risk_level,
            staleness_factor: score.staleness_factor,
            credential_age_factor: score.credential_age_factor,
            access_scope_factor: score.access_scope_factor,
            factor_breakdown: score.factor_breakdown,
            calculated_at: score.calculated_at,
            next_calculation_at: score.next_calculation_at,
        }
    }
}

// =============================================================================
// Request Workflow Models
// =============================================================================

/// NHI request response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiRequestResponse {
    /// Request ID.
    pub id: Uuid,

    /// Who submitted the request.
    pub requester_id: Uuid,

    /// Requested NHI name.
    pub requested_name: String,

    /// Purpose/justification for the NHI.
    pub purpose: String,

    /// Requested entitlement IDs.
    pub requested_permissions: Vec<Uuid>,

    /// Requested expiration date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_expiration: Option<DateTime<Utc>>,

    /// Requested rotation interval in days.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_rotation_days: Option<i32>,

    /// Current status.
    pub status: NhiRequestStatus,

    /// Who approved/rejected the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver_id: Option<Uuid>,

    /// When the decision was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_at: Option<DateTime<Utc>>,

    /// Approver comments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_comments: Option<String>,

    /// The created NHI ID (if approved).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_nhi_id: Option<Uuid>,

    /// When this request expires.
    pub expires_at: DateTime<Utc>,

    /// When the request was submitted.
    pub created_at: DateTime<Utc>,
}

impl From<GovNhiRequest> for NhiRequestResponse {
    fn from(req: GovNhiRequest) -> Self {
        Self {
            id: req.id,
            requester_id: req.requester_id,
            requested_name: req.requested_name,
            purpose: req.purpose,
            requested_permissions: req.requested_permissions,
            requested_expiration: req.requested_expiration,
            requested_rotation_days: req.requested_rotation_days,
            status: req.status,
            approver_id: req.approver_id,
            decision_at: req.decision_at,
            decision_comments: req.decision_comments,
            created_nhi_id: req.created_nhi_id,
            expires_at: req.expires_at,
            created_at: req.created_at,
        }
    }
}

/// Request to submit an NHI request.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct SubmitNhiRequestRequest {
    /// Requested NHI name.
    #[validate(length(min = 1, max = 200, message = "Name must be 1-200 characters"))]
    pub name: String,

    /// Purpose/justification for the NHI.
    #[validate(length(min = 10, message = "Purpose must be at least 10 characters"))]
    pub purpose: String,

    /// Requested entitlement IDs.
    #[validate(length(min = 0, max = 50, message = "Maximum 50 permissions"))]
    #[serde(default)]
    pub requested_permissions: Vec<Uuid>,

    /// Requested expiration date.
    #[serde(default)]
    pub requested_expiration: Option<DateTime<Utc>>,

    /// Requested rotation interval in days.
    #[validate(range(min = 1, max = 365, message = "Rotation interval must be 1-365 days"))]
    #[serde(default)]
    pub requested_rotation_days: Option<i32>,
}

/// Request to approve an NHI request.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApproveNhiRequestRequest {
    /// Approver comments.
    #[serde(default)]
    pub comments: Option<String>,
}

/// Request to reject an NHI request.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct RejectNhiRequestRequest {
    /// Reason for rejection.
    #[validate(length(min = 5, message = "Reason must be at least 5 characters"))]
    pub reason: String,
}

/// Query parameters for listing NHI requests.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListNhiRequestsQuery {
    /// Filter by status.
    pub status: Option<NhiRequestStatus>,

    /// Filter by requester.
    pub requester_id: Option<Uuid>,

    /// Filter pending requests only.
    pub pending_only: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListNhiRequestsQuery {
    fn default() -> Self {
        Self {
            status: None,
            requester_id: None,
            pending_only: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Paginated list of NHI requests.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiRequestListResponse {
    pub items: Vec<NhiRequestResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

// =============================================================================
// Audit Models
// =============================================================================

/// NHI audit event response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiAuditEventResponse {
    /// Event ID.
    pub id: Uuid,

    /// The NHI this event is for.
    pub nhi_id: Uuid,

    /// Type of event.
    pub event_type: NhiAuditEventType,

    /// Who performed the action (None for system actions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Uuid>,

    /// When the event occurred.
    pub timestamp: DateTime<Utc>,

    /// Before/after values for changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changes: Option<serde_json::Value>,

    /// Additional context/metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,

    /// IP address of the actor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
}

impl From<GovNhiAuditEvent> for NhiAuditEventResponse {
    fn from(event: GovNhiAuditEvent) -> Self {
        Self {
            id: event.id,
            nhi_id: event.nhi_id,
            event_type: event.event_type,
            actor_id: event.actor_id,
            timestamp: event.timestamp,
            changes: event.changes,
            metadata: event.metadata,
            source_ip: event.source_ip,
        }
    }
}

/// Query parameters for listing audit events.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListNhiAuditQuery {
    /// Filter by event type.
    pub event_type: Option<NhiAuditEventType>,

    /// Filter by actor.
    pub actor_id: Option<Uuid>,

    /// Start date for time range.
    pub start_date: Option<DateTime<Utc>>,

    /// End date for time range.
    pub end_date: Option<DateTime<Utc>>,

    /// Maximum number of results (default: 50, max: 1000).
    #[param(minimum = 1, maximum = 1000)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListNhiAuditQuery {
    fn default() -> Self {
        Self {
            event_type: None,
            actor_id: None,
            start_date: None,
            end_date: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Paginated list of audit events.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiAuditEventListResponse {
    pub items: Vec<NhiAuditEventResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

// =============================================================================
// Action Models
// =============================================================================

/// Request to suspend an NHI.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct SuspendNhiRequest {
    /// Reason for suspension.
    pub reason: NhiSuspensionReason,

    /// Additional details.
    #[validate(length(max = 500, message = "Details must be at most 500 characters"))]
    #[serde(default)]
    pub details: Option<String>,
}

/// Request to reactivate an NHI.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ReactivateNhiRequest {
    /// Reason/justification for reactivation.
    #[validate(length(min = 5, message = "Reason must be at least 5 characters"))]
    pub reason: String,
}

/// Request to transfer NHI ownership.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct TransferOwnershipRequest {
    /// New owner ID.
    pub new_owner_id: Uuid,

    /// Reason for transfer.
    #[validate(length(min = 5, message = "Reason must be at least 5 characters"))]
    pub reason: String,
}

/// Response for certify operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CertifyNhiResponse {
    /// Updated NHI.
    pub nhi: NhiResponse,

    /// Message.
    pub message: String,
}

// =============================================================================
// Usage Service Models
// =============================================================================

/// Request to record a usage event.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct RecordUsageRequest {
    /// The resource/service accessed.
    #[validate(length(min = 1, max = 500, message = "Resource must be 1-500 characters"))]
    pub target_resource: String,

    /// The action performed (e.g., read, write, admin).
    #[validate(length(min = 1, max = 100, message = "Action must be 1-100 characters"))]
    pub action: String,

    /// Outcome of the event.
    pub outcome: NhiUsageOutcome,

    /// Source IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,

    /// User agent string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,

    /// Request duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<i32>,

    /// Additional metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Query parameters for listing usage events (alias for `ListNhiUsageQuery`).
pub type NhiUsageListQuery = ListNhiUsageQuery;

/// Paginated list of usage events (alias for `NhiUsageEventListResponse`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiUsageListResponse {
    pub items: Vec<NhiUsageEventResponse>,
    pub total: i64,
    pub limit: i32,
    pub offset: i32,
}

/// Resource access information for summary.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ResourceAccessInfo {
    /// The resource name.
    pub resource: String,

    /// Number of times accessed.
    pub access_count: i64,

    /// When last accessed.
    pub last_access: DateTime<Utc>,
}

/// Extended NHI usage summary response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiUsageSummaryExtendedResponse {
    /// The NHI ID.
    pub nhi_id: Uuid,

    /// The NHI name.
    pub nhi_name: String,

    /// Period in days covered.
    pub period_days: i32,

    /// Total events in period.
    pub total_events: i64,

    /// Successful events.
    pub successful_events: i64,

    /// Failed events.
    pub failed_events: i64,

    /// Denied events.
    pub denied_events: i64,

    /// Success rate as percentage.
    pub success_rate: f64,

    /// Number of unique resources accessed.
    pub unique_resources: i64,

    /// Top accessed resources.
    pub top_resources: Vec<ResourceAccessInfo>,

    /// When the NHI was last used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Information about a stale NHI.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StaleNhiInfo {
    /// The NHI ID.
    pub nhi_id: Uuid,

    /// The NHI name.
    pub name: String,

    /// The owner responsible.
    pub owner_id: Uuid,

    /// Days since last use.
    pub days_inactive: i32,

    /// When last used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,

    /// Configured inactivity threshold.
    pub inactivity_threshold_days: i32,

    /// Whether NHI is in grace period.
    pub in_grace_period: bool,

    /// When grace period ends.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_period_ends_at: Option<DateTime<Utc>>,
}

/// Staleness report response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StalenessReportResponse {
    /// When the report was generated.
    pub generated_at: DateTime<Utc>,

    /// Minimum inactive days threshold used.
    pub min_inactive_days: i32,

    /// Total stale NHIs.
    pub total_stale: i64,

    /// NHIs stale > 180 days (critical).
    pub critical_count: i64,

    /// NHIs stale 90-180 days (warning).
    pub warning_count: i64,

    /// List of stale NHIs (sorted by `days_inactive` desc).
    pub stale_nhis: Vec<StaleNhiInfo>,
}

// =============================================================================
// Risk Score List Models
// =============================================================================

/// Paginated list of NHI risk scores.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiRiskScoreListResponse {
    pub items: Vec<NhiRiskScoreResponse>,
    pub total: i64,
    pub limit: i32,
    pub offset: i32,
}

/// Summary of NHI risk scores by level.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskLevelSummary {
    /// Total NHIs with risk scores.
    pub total: i64,

    /// NHIs with low risk (0-25).
    pub low: i64,

    /// NHIs with medium risk (26-50).
    pub medium: i64,

    /// NHIs with high risk (51-75).
    pub high: i64,

    /// NHIs with critical risk (76-100).
    pub critical: i64,
}

// =============================================================================
// NHI Certification Models (User Story 5)
// =============================================================================

/// Status of an NHI certification item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NhiCertificationStatus {
    /// Awaiting reviewer decision.
    Pending,
    /// NHI was certified (approved).
    Certified,
    /// NHI was revoked (rejected).
    Revoked,
    /// Certification deadline passed without decision.
    Expired,
}

impl NhiCertificationStatus {
    /// Check if this status represents a final decision.
    #[must_use]
    pub fn is_decided(&self) -> bool {
        !matches!(self, Self::Pending)
    }

    /// Check if this status represents a certified (approved) NHI.
    #[must_use]
    pub fn is_certified(&self) -> bool {
        matches!(self, Self::Certified)
    }
}

/// Decision made on an NHI certification item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NhiCertificationDecision {
    /// Certify the NHI (approve continued use).
    Certify,
    /// Revoke the NHI (suspend and invalidate credentials).
    Revoke,
    /// Delegate decision to another reviewer.
    Delegate,
}

impl NhiCertificationDecision {
    /// Check if this decision is an approval.
    #[must_use]
    pub fn is_approval(&self) -> bool {
        matches!(self, Self::Certify)
    }
}

/// NHI certification item response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiCertificationItemResponse {
    /// Certification item ID.
    pub id: Uuid,

    /// The certification campaign this belongs to.
    pub campaign_id: Uuid,

    /// The NHI being certified.
    pub nhi_id: Uuid,

    /// NHI display name.
    pub nhi_name: String,

    /// NHI purpose.
    pub nhi_purpose: String,

    /// NHI owner responsible.
    pub owner_id: Uuid,

    /// Owner name (if resolved).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_name: Option<String>,

    /// Assigned reviewer.
    pub reviewer_id: Uuid,

    /// Current status.
    pub status: NhiCertificationStatus,

    /// Deadline for decision.
    pub deadline: DateTime<Utc>,

    /// Decision made (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<NhiCertificationDecision>,

    /// Who made the decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<Uuid>,

    /// When the decision was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,

    /// Comment from reviewer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// When the item was created.
    pub created_at: DateTime<Utc>,
}

/// NHI certification campaign summary.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiCertificationSummary {
    /// Total items in campaign.
    pub total: i64,

    /// Pending items awaiting decision.
    pub pending: i64,

    /// Certified (approved) items.
    pub certified: i64,

    /// Revoked items.
    pub revoked: i64,

    /// Expired items (deadline passed).
    pub expired: i64,
}

impl NhiCertificationSummary {
    /// Calculate completion rate as percentage.
    #[must_use]
    pub fn completion_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            ((self.total - self.pending) as f64 / self.total as f64) * 100.0
        }
    }
}

/// Request to create an NHI certification campaign.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateNhiCertificationCampaignRequest {
    /// Campaign name.
    #[validate(length(min = 1, max = 200, message = "Name must be 1-200 characters"))]
    pub name: String,

    /// Campaign description.
    #[serde(default)]
    pub description: Option<String>,

    /// Filter NHIs by owner (optional - certify specific owner's NHIs).
    #[serde(default)]
    pub owner_filter: Option<Uuid>,

    /// Only include NHIs needing certification (> 365 days since last cert).
    #[serde(default = "default_true")]
    pub needs_certification_only: bool,

    /// Reviewer assignment strategy.
    #[serde(default)]
    pub reviewer_type: NhiCertReviewerType,

    /// Specific reviewer IDs (if `reviewer_type` is `SpecificUsers`).
    #[serde(default)]
    pub specific_reviewers: Option<Vec<Uuid>>,

    /// Deadline for the campaign.
    pub deadline: DateTime<Utc>,
}

fn default_true() -> bool {
    true
}

/// Reviewer assignment strategy for NHI certification.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NhiCertReviewerType {
    /// NHI owner certifies their own NHIs (self-attestation).
    #[default]
    Owner,
    /// Backup owner reviews (if no backup, falls back to owner).
    BackupOwner,
    /// Specific users review all NHIs.
    SpecificUsers,
    /// User's manager reviews (requires manager relationship).
    OwnerManager,
}

/// Request to make a decision on an NHI certification item.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct NhiCertificationDecisionRequest {
    /// The decision to make.
    pub decision: NhiCertificationDecision,

    /// Comment explaining the decision.
    #[validate(length(max = 1000, message = "Comment must be at most 1000 characters"))]
    #[serde(default)]
    pub comment: Option<String>,

    /// Delegate to this user (required if decision is Delegate).
    #[serde(default)]
    pub delegate_to: Option<Uuid>,
}

/// Request for bulk certification decision.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct BulkNhiCertificationDecisionRequest {
    /// IDs of certification items to process.
    #[validate(length(min = 1, max = 100, message = "Must provide 1-100 item IDs"))]
    pub item_ids: Vec<Uuid>,

    /// The decision to make for all items.
    pub decision: NhiCertificationDecision,

    /// Comment for all items.
    #[validate(length(max = 500, message = "Comment must be at most 500 characters"))]
    #[serde(default)]
    pub comment: Option<String>,
}

/// Result of bulk certification decision.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkNhiCertificationResult {
    /// IDs that were successfully processed.
    pub succeeded: Vec<Uuid>,

    /// Items that failed with their error messages.
    pub failed: Vec<BulkCertificationError>,
}

/// Error for a single item in bulk operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkCertificationError {
    /// The item ID that failed.
    pub item_id: Uuid,

    /// Error message.
    pub error: String,
}

/// Query parameters for listing NHI certification items.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListNhiCertificationItemsQuery {
    /// Filter by campaign ID.
    pub campaign_id: Option<Uuid>,

    /// Filter by status.
    pub status: Option<NhiCertificationStatus>,

    /// Filter by reviewer.
    pub reviewer_id: Option<Uuid>,

    /// Filter by NHI owner.
    pub owner_id: Option<Uuid>,

    /// Show only my pending items (current user is reviewer).
    pub my_pending: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListNhiCertificationItemsQuery {
    fn default() -> Self {
        Self {
            campaign_id: None,
            status: None,
            reviewer_id: None,
            owner_id: None,
            my_pending: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Paginated list of NHI certification items.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiCertificationItemListResponse {
    pub items: Vec<NhiCertificationItemResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// NHI certification campaign response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiCertificationCampaignResponse {
    /// Campaign ID.
    pub id: Uuid,

    /// Campaign name.
    pub name: String,

    /// Campaign description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Current status.
    pub status: NhiCertCampaignStatus,

    /// Total NHIs included.
    pub total_items: i64,

    /// Pending items.
    pub pending_items: i64,

    /// Certified items.
    pub certified_items: i64,

    /// Revoked items.
    pub revoked_items: i64,

    /// Expired items.
    pub expired_items: i64,

    /// Completion rate as percentage.
    pub completion_rate: f64,

    /// Campaign deadline.
    pub deadline: DateTime<Utc>,

    /// Who created the campaign.
    pub created_by: Uuid,

    /// When the campaign was created.
    pub created_at: DateTime<Utc>,

    /// When the campaign was launched (if launched).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launched_at: Option<DateTime<Utc>>,

    /// When the campaign was completed (if completed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

/// Status of an NHI certification campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NhiCertCampaignStatus {
    /// Campaign is being configured (not yet launched).
    Draft,
    /// Campaign is active and accepting decisions.
    Active,
    /// Campaign is past deadline.
    Overdue,
    /// Campaign is complete (all items decided or expired).
    Completed,
    /// Campaign was cancelled.
    Cancelled,
}

impl NhiCertCampaignStatus {
    /// Check if this campaign can be cancelled.
    #[must_use]
    pub fn can_cancel(&self) -> bool {
        matches!(self, Self::Draft | Self::Active | Self::Overdue)
    }
}

/// Query parameters for listing NHI certification campaigns.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListNhiCertificationCampaignsQuery {
    /// Filter by status.
    pub status: Option<NhiCertCampaignStatus>,

    /// Filter by creator.
    pub created_by: Option<Uuid>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListNhiCertificationCampaignsQuery {
    fn default() -> Self {
        Self {
            status: None,
            created_by: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Paginated list of NHI certification campaigns.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NhiCertificationCampaignListResponse {
    pub items: Vec<NhiCertificationCampaignResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}
