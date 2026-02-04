//! Request and response models for micro-certification endpoints (F055).
//!
//! Micro-certifications are event-triggered single-item certifications that extend
//! the existing certification campaign infrastructure with just-in-time access reviews.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{
    GovMicroCertEvent, GovMicroCertTrigger, GovMicroCertification, MicroCertDecision,
    MicroCertEventStats, MicroCertEventType, MicroCertReviewerType, MicroCertScopeType,
    MicroCertStatus, MicroCertTriggerType, MicroCertificationStats,
};

// ============================================================================
// Trigger Rule Models
// ============================================================================

/// Request to create a new micro-certification trigger rule.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateTriggerRuleRequest {
    /// Display name for the trigger rule (1-255 characters).
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Type of event that triggers the certification.
    pub trigger_type: MicroCertTriggerType,

    /// Scope type for the rule (tenant, application, or entitlement).
    #[serde(default)]
    pub scope_type: Option<MicroCertScopeType>,

    /// Scope ID (application/entitlement ID - required for non-tenant scope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<Uuid>,

    /// How to determine the reviewer.
    #[serde(default)]
    pub reviewer_type: Option<MicroCertReviewerType>,

    /// Specific reviewer user ID (required when `reviewer_type` is `specific_user`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub specific_reviewer_id: Option<Uuid>,

    /// Fallback reviewer user ID for escalation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reviewer_id: Option<Uuid>,

    /// Timeout in seconds (default 86400 = 24 hours).
    #[serde(default)]
    pub timeout_secs: Option<i32>,

    /// Send reminder at this % of deadline (1-99, default: 75).
    #[validate(range(
        min = 1,
        max = 99,
        message = "Reminder threshold must be between 1 and 99"
    ))]
    #[serde(default)]
    pub reminder_threshold_percent: Option<i32>,

    /// Whether to auto-revoke on timeout (default: true).
    #[serde(default)]
    pub auto_revoke: Option<bool>,

    /// For `SoD`: revoke triggering assignment (default: true).
    #[serde(default)]
    pub revoke_triggering_assignment: Option<bool>,

    /// Mark as tenant-wide default for this trigger type (default: false).
    #[serde(default)]
    pub is_default: Option<bool>,

    /// Priority for rule matching (higher = matched first, default: 0).
    #[serde(default)]
    pub priority: Option<i32>,

    /// Extensible metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Request to update an existing trigger rule.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateTriggerRuleRequest {
    /// Updated display name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Updated scope type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_type: Option<MicroCertScopeType>,

    /// Updated scope ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<Uuid>,

    /// Updated reviewer type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_type: Option<MicroCertReviewerType>,

    /// Updated specific reviewer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub specific_reviewer_id: Option<Uuid>,

    /// Updated fallback reviewer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reviewer_id: Option<Uuid>,

    /// Updated timeout in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<i32>,

    /// Updated reminder threshold percent.
    #[validate(range(
        min = 1,
        max = 99,
        message = "Reminder threshold must be between 1 and 99"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reminder_threshold_percent: Option<i32>,

    /// Updated auto-revoke setting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_revoke: Option<bool>,

    /// Updated revoke triggering assignment setting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke_triggering_assignment: Option<bool>,

    /// Whether the rule is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,

    /// Whether this is the default rule for trigger type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,

    /// Updated priority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,

    /// Updated metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Query parameters for listing trigger rules.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListTriggerRulesQuery {
    /// Filter by trigger type.
    pub trigger_type: Option<MicroCertTriggerType>,

    /// Filter by scope type.
    pub scope_type: Option<MicroCertScopeType>,

    /// Filter by scope ID.
    pub scope_id: Option<Uuid>,

    /// Filter by active status.
    pub is_active: Option<bool>,

    /// Filter by default status.
    pub is_default: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListTriggerRulesQuery {
    fn default() -> Self {
        Self {
            trigger_type: None,
            scope_type: None,
            scope_id: None,
            is_active: None,
            is_default: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Trigger rule response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TriggerRuleResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Display name.
    pub name: String,

    /// Trigger type.
    pub trigger_type: MicroCertTriggerType,

    /// Scope type.
    pub scope_type: MicroCertScopeType,

    /// Scope ID (application or entitlement ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<Uuid>,

    /// Reviewer type.
    pub reviewer_type: MicroCertReviewerType,

    /// Specific reviewer ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub specific_reviewer_id: Option<Uuid>,

    /// Fallback reviewer ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reviewer_id: Option<Uuid>,

    /// Timeout in seconds.
    pub timeout_secs: i32,

    /// Reminder threshold percent (1-99).
    pub reminder_threshold_percent: i32,

    /// Whether to auto-revoke on timeout.
    pub auto_revoke: bool,

    /// For `SoD`: revoke triggering assignment.
    pub revoke_triggering_assignment: bool,

    /// Whether the rule is active.
    pub is_active: bool,

    /// Whether this is the default rule for trigger type.
    pub is_default: bool,

    /// Rule priority.
    pub priority: i32,

    /// Extensible metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,

    /// When the rule was created.
    pub created_at: DateTime<Utc>,

    /// When the rule was last updated.
    pub updated_at: DateTime<Utc>,
}

impl From<GovMicroCertTrigger> for TriggerRuleResponse {
    fn from(trigger: GovMicroCertTrigger) -> Self {
        Self {
            id: trigger.id,
            tenant_id: trigger.tenant_id,
            name: trigger.name,
            trigger_type: trigger.trigger_type,
            scope_type: trigger.scope_type,
            scope_id: trigger.scope_id,
            reviewer_type: trigger.reviewer_type,
            specific_reviewer_id: trigger.specific_reviewer_id,
            fallback_reviewer_id: trigger.fallback_reviewer_id,
            timeout_secs: trigger.timeout_secs,
            reminder_threshold_percent: trigger.reminder_threshold_percent,
            auto_revoke: trigger.auto_revoke,
            revoke_triggering_assignment: trigger.revoke_triggering_assignment,
            is_active: trigger.is_active,
            is_default: trigger.is_default,
            priority: trigger.priority,
            metadata: trigger.metadata,
            created_at: trigger.created_at,
            updated_at: trigger.updated_at,
        }
    }
}

/// Paginated list of trigger rules.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TriggerRuleListResponse {
    /// List of trigger rules.
    pub items: Vec<TriggerRuleResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

// ============================================================================
// Micro-certification Models
// ============================================================================

/// Request to create a micro-certification manually.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateMicroCertificationRequest {
    /// The trigger rule to use.
    pub trigger_rule_id: Uuid,

    /// The assignment being certified (optional if assignment was deleted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignment_id: Option<Uuid>,

    /// The user whose access is being certified.
    pub user_id: Uuid,

    /// The entitlement being certified.
    pub entitlement_id: Uuid,

    /// The assigned reviewer.
    pub reviewer_id: Uuid,

    /// Optional backup reviewer for escalation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_reviewer_id: Option<Uuid>,

    /// Event type that triggered this certification.
    #[validate(length(min = 1, max = 255, message = "Event type must be 1-255 characters"))]
    pub triggering_event_type: String,

    /// Event ID for traceability.
    pub triggering_event_id: Uuid,

    /// Snapshot of event payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggering_event_data: Option<serde_json::Value>,

    /// Deadline for the certification.
    pub deadline: DateTime<Utc>,

    /// When to escalate to backup reviewer (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation_deadline: Option<DateTime<Utc>>,
}

/// Request to submit a decision for a micro-certification.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct DecideMicroCertificationRequest {
    /// Decision type (approve, revoke, reduce).
    /// Note: For delegate decision, use `DelegateMicroCertificationRequest` instead.
    pub decision: MicroCertDecision,

    /// Comment/justification (required for revoke/reduce, optional for approve).
    #[validate(length(max = 2000, message = "Comment must not exceed 2000 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Request to delegate a micro-certification to another reviewer.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct DelegateMicroCertificationRequest {
    /// The user ID to delegate the certification to.
    pub delegate_to: Uuid,

    /// Reason for delegating (optional but recommended).
    #[validate(length(max = 2000, message = "Comment must not exceed 2000 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Query parameters for listing micro-certifications.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListMicroCertificationsQuery {
    /// Filter by status.
    pub status: Option<MicroCertStatus>,

    /// Filter by reviewer.
    pub reviewer_id: Option<Uuid>,

    /// Filter by user whose access is being certified.
    pub user_id: Option<Uuid>,

    /// Filter by entitlement.
    pub entitlement_id: Option<Uuid>,

    /// Filter by assignment.
    pub assignment_id: Option<Uuid>,

    /// Filter by trigger rule.
    pub trigger_rule_id: Option<Uuid>,

    /// Filter certifications created after this date.
    pub from_date: Option<DateTime<Utc>>,

    /// Filter certifications created before this date.
    pub to_date: Option<DateTime<Utc>>,

    /// Include escalated certifications only.
    pub escalated: Option<bool>,

    /// Filter certifications past deadline only.
    pub past_deadline: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListMicroCertificationsQuery {
    fn default() -> Self {
        Self {
            status: None,
            reviewer_id: None,
            user_id: None,
            entitlement_id: None,
            assignment_id: None,
            trigger_rule_id: None,
            from_date: None,
            to_date: None,
            escalated: None,
            past_deadline: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Micro-certification response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MicroCertificationResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Trigger rule ID that created this certification.
    pub trigger_rule_id: Uuid,

    /// Assignment ID being certified (NULL if deleted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignment_id: Option<Uuid>,

    /// User whose access is being certified.
    pub user_id: Uuid,

    /// Entitlement being certified.
    pub entitlement_id: Uuid,

    /// Current reviewer.
    pub reviewer_id: Uuid,

    /// Backup reviewer for escalation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_reviewer_id: Option<Uuid>,

    /// Certification status.
    pub status: MicroCertStatus,

    /// Event type that triggered this certification.
    pub triggering_event_type: String,

    /// Event ID for traceability.
    pub triggering_event_id: Uuid,

    /// Snapshot of event payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggering_event_data: Option<serde_json::Value>,

    /// Deadline for certification.
    pub deadline: DateTime<Utc>,

    /// When to escalate to backup reviewer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation_deadline: Option<DateTime<Utc>>,

    /// Whether reminder was sent.
    pub reminder_sent: bool,

    /// Whether escalated to backup.
    pub escalated: bool,

    /// Decision made (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<MicroCertDecision>,

    /// Decision comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_comment: Option<String>,

    /// Who made the decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<Uuid>,

    /// When the decision was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,

    /// Which assignment was revoked (for `SoD` violations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_assignment_id: Option<Uuid>,

    /// User who delegated to current reviewer (for Delegate decision chain).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_by_id: Option<Uuid>,

    /// Original reviewer before any delegation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_reviewer_id: Option<Uuid>,

    /// Comment from delegator explaining why delegated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_comment: Option<String>,

    /// When the certification was created.
    pub created_at: DateTime<Utc>,

    /// When the certification was last updated.
    pub updated_at: DateTime<Utc>,
}

impl From<GovMicroCertification> for MicroCertificationResponse {
    fn from(cert: GovMicroCertification) -> Self {
        Self {
            id: cert.id,
            tenant_id: cert.tenant_id,
            trigger_rule_id: cert.trigger_rule_id,
            assignment_id: cert.assignment_id,
            user_id: cert.user_id,
            entitlement_id: cert.entitlement_id,
            reviewer_id: cert.reviewer_id,
            backup_reviewer_id: cert.backup_reviewer_id,
            status: cert.status,
            triggering_event_type: cert.triggering_event_type,
            triggering_event_id: cert.triggering_event_id,
            triggering_event_data: cert.triggering_event_data,
            deadline: cert.deadline,
            escalation_deadline: cert.escalation_deadline,
            reminder_sent: cert.reminder_sent,
            escalated: cert.escalated,
            decision: cert.decision,
            decision_comment: cert.decision_comment,
            decided_by: cert.decided_by,
            decided_at: cert.decided_at,
            revoked_assignment_id: cert.revoked_assignment_id,
            delegated_by_id: cert.delegated_by_id,
            original_reviewer_id: cert.original_reviewer_id,
            delegation_comment: cert.delegation_comment,
            created_at: cert.created_at,
            updated_at: cert.updated_at,
        }
    }
}

/// Micro-certification response with additional details.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MicroCertificationWithDetailsResponse {
    /// Certification details.
    #[serde(flatten)]
    pub certification: MicroCertificationResponse,

    /// User summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<MicroCertUserSummary>,

    /// Entitlement summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement: Option<MicroCertEntitlementSummary>,

    /// Reviewer summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<MicroCertUserSummary>,

    /// Trigger rule summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger_rule: Option<TriggerRuleSummary>,

    /// Audit trail events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<MicroCertEventResponse>>,
}

/// User summary for micro-certification display.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MicroCertUserSummary {
    /// User ID.
    pub id: Uuid,

    /// User email.
    pub email: String,

    /// User display name.
    pub display_name: String,

    /// User department.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,

    /// User's manager ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager_id: Option<Uuid>,
}

/// Entitlement summary for micro-certification display.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MicroCertEntitlementSummary {
    /// Entitlement ID.
    pub id: Uuid,

    /// Entitlement name.
    pub name: String,

    /// Entitlement description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Application ID.
    pub application_id: Uuid,

    /// Application name.
    pub application_name: String,

    /// Risk level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,

    /// Whether it's a sensitive/high-risk entitlement.
    pub is_sensitive: bool,
}

/// Trigger rule summary for display.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TriggerRuleSummary {
    /// Rule ID.
    pub id: Uuid,

    /// Rule name.
    pub name: String,

    /// Trigger type.
    pub trigger_type: MicroCertTriggerType,
}

/// Paginated list of micro-certifications.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MicroCertificationListResponse {
    /// List of micro-certifications.
    pub items: Vec<MicroCertificationWithDetailsResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Statistics response for micro-certifications.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MicroCertificationStatsResponse {
    /// Total certifications in period.
    pub total: i64,

    /// Pending certifications.
    pub pending: i64,

    /// Approved certifications.
    pub approved: i64,

    /// Revoked certifications (manual).
    pub revoked: i64,

    /// Auto-revoked certifications (timeout with `auto_revoke=true`).
    pub auto_revoked: i64,

    /// Flagged for review certifications (Reduce decision).
    pub flagged_for_review: i64,

    /// Expired certifications.
    pub expired: i64,

    /// Skipped certifications.
    pub skipped: i64,

    /// Certifications that were escalated.
    pub escalated: i64,

    /// Certifications past deadline but still pending.
    pub past_deadline: i64,

    /// Breakdown by trigger type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by_trigger_type: Option<Vec<TriggerTypeStats>>,
}

impl From<MicroCertificationStats> for MicroCertificationStatsResponse {
    fn from(stats: MicroCertificationStats) -> Self {
        Self {
            total: stats.total,
            pending: stats.pending,
            approved: stats.approved,
            revoked: stats.revoked,
            auto_revoked: stats.auto_revoked,
            flagged_for_review: stats.flagged_for_review,
            expired: stats.expired,
            skipped: stats.skipped,
            escalated: stats.escalated,
            past_deadline: stats.past_deadline,
            by_trigger_type: None,
        }
    }
}

/// Statistics breakdown by trigger type.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TriggerTypeStats {
    /// Trigger type.
    pub trigger_type: MicroCertTriggerType,

    /// Count for this trigger type.
    pub count: i64,
}

// ============================================================================
// Event (Audit Trail) Models
// ============================================================================

/// Query parameters for listing micro-certification events.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListMicroCertEventsQuery {
    /// Filter by certification ID.
    pub micro_certification_id: Option<Uuid>,

    /// Filter by event type.
    pub event_type: Option<MicroCertEventType>,

    /// Filter by actor (user who performed action).
    pub actor_id: Option<Uuid>,

    /// Filter events from this date.
    pub from_date: Option<DateTime<Utc>>,

    /// Filter events to this date.
    pub to_date: Option<DateTime<Utc>>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListMicroCertEventsQuery {
    fn default() -> Self {
        Self {
            micro_certification_id: None,
            event_type: None,
            actor_id: None,
            from_date: None,
            to_date: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Micro-certification event response (audit trail).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MicroCertEventResponse {
    /// Unique event identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Parent certification ID.
    pub micro_certification_id: Uuid,

    /// Type of event.
    pub event_type: MicroCertEventType,

    /// Actor who performed action (NULL for system events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Uuid>,

    /// Event-specific details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,

    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

impl From<GovMicroCertEvent> for MicroCertEventResponse {
    fn from(event: GovMicroCertEvent) -> Self {
        Self {
            id: event.id,
            tenant_id: event.tenant_id,
            micro_certification_id: event.micro_certification_id,
            event_type: event.event_type,
            actor_id: event.actor_id,
            details: event.details,
            created_at: event.created_at,
        }
    }
}

/// Paginated list of micro-certification events.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MicroCertEventListResponse {
    /// List of events.
    pub items: Vec<MicroCertEventResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Event statistics response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MicroCertEventStatsResponse {
    /// Total events in period.
    pub total: i64,

    /// Created events.
    pub created: i64,

    /// Reminder sent events.
    pub reminder_sent: i64,

    /// Escalation events.
    pub escalated: i64,

    /// Approval events.
    pub approved: i64,

    /// Rejection events (manual revoke).
    pub rejected: i64,

    /// Flagged for review events (Reduce decision).
    pub flagged_for_review: i64,

    /// Delegation events.
    pub delegated: i64,

    /// Auto-revoke events.
    pub auto_revoked: i64,

    /// Expiration events.
    pub expired: i64,

    /// Skip events.
    pub skipped: i64,
}

impl From<MicroCertEventStats> for MicroCertEventStatsResponse {
    fn from(stats: MicroCertEventStats) -> Self {
        Self {
            total: stats.total,
            created: stats.created,
            reminder_sent: stats.reminder_sent,
            escalated: stats.escalated,
            approved: stats.approved,
            rejected: stats.rejected,
            flagged_for_review: stats.flagged_for_review,
            delegated: stats.delegated,
            auto_revoked: stats.auto_revoked,
            expired: stats.expired,
            skipped: stats.skipped,
        }
    }
}

// ============================================================================
// Reviewer Models
// ============================================================================

/// Query parameters for my-micro-certifications endpoint.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct MyMicroCertificationsQuery {
    /// Filter by status.
    pub status: Option<MicroCertStatus>,

    /// Show escalated items only.
    pub escalated_only: Option<bool>,

    /// Filter by deadline before this date.
    pub deadline_before: Option<DateTime<Utc>>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for MyMicroCertificationsQuery {
    fn default() -> Self {
        Self {
            status: None,
            escalated_only: None,
            deadline_before: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Summary of a reviewer's pending micro-certifications.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReviewerMicroCertSummary {
    /// Total pending certifications.
    pub total_pending: i64,

    /// Overdue certifications.
    pub overdue_count: i64,

    /// Escalated certifications.
    pub escalated_count: i64,

    /// Due within 24 hours.
    pub due_soon_count: i64,

    /// Breakdown by trigger type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by_trigger_type: Option<Vec<TriggerTypeStats>>,
}

// ============================================================================
// Skip/Bulk Operations
// ============================================================================

/// Request to skip a micro-certification.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct SkipMicroCertificationRequest {
    /// Reason for skipping (minimum 10 characters).
    #[validate(length(
        min = 10,
        max = 1000,
        message = "Reason must be between 10 and 1000 characters"
    ))]
    pub reason: String,
}

/// Request for bulk decision on multiple micro-certifications.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct BulkDecisionRequest {
    /// IDs of micro-certifications to decide.
    #[validate(length(min = 1, max = 100, message = "Must include 1-100 certification IDs"))]
    pub certification_ids: Vec<Uuid>,

    /// Decision to apply to all.
    pub decision: MicroCertDecision,

    /// Comment for the bulk decision.
    #[validate(length(max = 2000, message = "Comment must not exceed 2000 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Result of a bulk decision operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkDecisionResponse {
    /// Number of successfully decided certifications.
    pub success_count: i64,

    /// Number of failed certifications.
    pub failure_count: i64,

    /// IDs that were successfully decided.
    pub succeeded: Vec<Uuid>,

    /// Failed IDs with error messages.
    pub failures: Vec<BulkDecisionFailure>,
}

/// Individual failure in bulk decision.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkDecisionFailure {
    /// Certification ID that failed.
    pub certification_id: Uuid,

    /// Error message.
    pub error: String,
}

// ============================================================================
// Manual Trigger Models (T089)
// ============================================================================

/// Request to manually trigger a micro-certification.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ManualTriggerRequest {
    /// The user whose access to certify.
    pub user_id: Uuid,

    /// The entitlement to certify.
    pub entitlement_id: Uuid,

    /// Optional specific trigger rule to use. If not provided, the default rule for Manual trigger type is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger_rule_id: Option<Uuid>,

    /// Optional specific reviewer. If not provided, reviewer is resolved based on trigger rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_id: Option<Uuid>,

    /// Reason for manually triggering certification (minimum 10 characters).
    #[validate(length(
        min = 10,
        max = 1000,
        message = "Reason must be between 10 and 1000 characters"
    ))]
    pub reason: String,
}

/// Response for manual trigger operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ManualTriggerResponse {
    /// The created certification.
    pub certification: MicroCertificationResponse,

    /// Whether a duplicate was detected and skipped.
    pub duplicate_skipped: bool,

    /// Message describing the outcome.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use validator::Validate;

    #[test]
    fn test_create_trigger_rule_validation() {
        let valid = CreateTriggerRuleRequest {
            name: "High Risk Role Assignment".to_string(),
            trigger_type: MicroCertTriggerType::HighRiskAssignment,
            scope_type: Some(MicroCertScopeType::Tenant),
            scope_id: None,
            reviewer_type: Some(MicroCertReviewerType::UserManager),
            specific_reviewer_id: None,
            fallback_reviewer_id: None,
            timeout_secs: Some(86400), // 24 hours
            reminder_threshold_percent: Some(75),
            auto_revoke: Some(true),
            revoke_triggering_assignment: Some(true),
            is_default: Some(true),
            priority: Some(100),
            metadata: None,
        };
        assert!(valid.validate().is_ok());

        // Test invalid reminder threshold
        let invalid_threshold = CreateTriggerRuleRequest {
            reminder_threshold_percent: Some(150), // > 99
            ..valid.clone()
        };
        assert!(invalid_threshold.validate().is_err());

        // Test empty name
        let invalid_name = CreateTriggerRuleRequest {
            name: "".to_string(),
            ..valid.clone()
        };
        assert!(invalid_name.validate().is_err());
    }

    #[test]
    fn test_decide_micro_certification_validation() {
        let valid_approve = DecideMicroCertificationRequest {
            decision: MicroCertDecision::Approve,
            comment: Some("Access verified and justified".to_string()),
        };
        assert!(valid_approve.validate().is_ok());

        let valid_revoke = DecideMicroCertificationRequest {
            decision: MicroCertDecision::Revoke,
            comment: Some("User no longer needs this access".to_string()),
        };
        assert!(valid_revoke.validate().is_ok());

        let valid_reduce = DecideMicroCertificationRequest {
            decision: MicroCertDecision::Reduce,
            comment: Some("Access looks suspicious, flagging for investigation".to_string()),
        };
        assert!(valid_reduce.validate().is_ok());
    }

    #[test]
    fn test_delegate_micro_certification_validation() {
        let valid = DelegateMicroCertificationRequest {
            delegate_to: Uuid::new_v4(),
            comment: Some("Delegating to security team lead for review".to_string()),
        };
        assert!(valid.validate().is_ok());

        let valid_no_comment = DelegateMicroCertificationRequest {
            delegate_to: Uuid::new_v4(),
            comment: None,
        };
        assert!(valid_no_comment.validate().is_ok());
    }

    #[test]
    fn test_skip_micro_certification_validation() {
        let valid = SkipMicroCertificationRequest {
            reason: "User account is being terminated, access will be removed".to_string(),
        };
        assert!(valid.validate().is_ok());

        let invalid_short = SkipMicroCertificationRequest {
            reason: "Skip".to_string(),
        };
        assert!(invalid_short.validate().is_err());
    }

    #[test]
    fn test_bulk_decision_validation() {
        let valid = BulkDecisionRequest {
            certification_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
            decision: MicroCertDecision::Approve,
            comment: Some("Bulk approval after review".to_string()),
        };
        assert!(valid.validate().is_ok());

        let invalid_empty = BulkDecisionRequest {
            certification_ids: vec![],
            decision: MicroCertDecision::Approve,
            comment: None,
        };
        assert!(invalid_empty.validate().is_err());
    }

    #[test]
    fn test_list_queries_defaults() {
        let trigger_query = ListTriggerRulesQuery::default();
        assert_eq!(trigger_query.limit, Some(50));
        assert_eq!(trigger_query.offset, Some(0));

        let cert_query = ListMicroCertificationsQuery::default();
        assert_eq!(cert_query.limit, Some(50));
        assert_eq!(cert_query.offset, Some(0));

        let event_query = ListMicroCertEventsQuery::default();
        assert_eq!(event_query.limit, Some(50));
        assert_eq!(event_query.offset, Some(0));
    }
}
