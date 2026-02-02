//! Lifecycle state events for F052 Object Lifecycle States.
//!
//! Events for tracking state transitions, scheduled transitions,
//! bulk operations, and rollbacks.

use crate::event::Event;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Published when a state transition is requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionRequested {
    /// Transition request ID.
    pub request_id: Uuid,
    /// Object being transitioned.
    pub object_id: Uuid,
    /// Object type (user, entitlement, role).
    pub object_type: String,
    /// Source state name.
    pub from_state: String,
    /// Target state name.
    pub to_state: String,
    /// Transition name.
    pub transition_name: String,
    /// User who requested the transition.
    pub requested_by: Uuid,
    /// Whether approval is required.
    pub requires_approval: bool,
    /// When the request was created.
    pub requested_at: DateTime<Utc>,
}

impl Event for StateTransitionRequested {
    const TOPIC: &'static str = "xavyo.governance.lifecycle.requested";
    const EVENT_TYPE: &'static str = "xavyo.governance.lifecycle.requested";
}

/// Published when a state transition is approved (if approval was required).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionApproved {
    /// Transition request ID.
    pub request_id: Uuid,
    /// Object being transitioned.
    pub object_id: Uuid,
    /// Object type (user, entitlement, role).
    pub object_type: String,
    /// User who approved the transition.
    pub approved_by: Uuid,
    /// Approval comments (if any).
    pub comments: Option<String>,
    /// When the transition was approved.
    pub approved_at: DateTime<Utc>,
}

impl Event for StateTransitionApproved {
    const TOPIC: &'static str = "xavyo.governance.lifecycle.approved";
    const EVENT_TYPE: &'static str = "xavyo.governance.lifecycle.approved";
}

/// Published when a state transition is executed (completed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionExecuted {
    /// Transition request ID.
    pub request_id: Uuid,
    /// Object that was transitioned.
    pub object_id: Uuid,
    /// Object type (user, entitlement, role).
    pub object_type: String,
    /// Previous state name.
    pub from_state: String,
    /// New state name.
    pub to_state: String,
    /// Transition name.
    pub transition_name: String,
    /// User who performed the transition.
    pub actor_id: Uuid,
    /// Whether this transition has a grace period for rollback.
    pub has_grace_period: bool,
    /// When grace period expires (if applicable).
    pub grace_period_ends_at: Option<DateTime<Utc>>,
    /// When the transition was executed.
    pub executed_at: DateTime<Utc>,
}

impl Event for StateTransitionExecuted {
    const TOPIC: &'static str = "xavyo.governance.lifecycle.executed";
    const EVENT_TYPE: &'static str = "xavyo.governance.lifecycle.executed";
}

/// Published when a state transition is rejected (approval denied).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionRejected {
    /// Transition request ID.
    pub request_id: Uuid,
    /// Object that was to be transitioned.
    pub object_id: Uuid,
    /// Object type (user, entitlement, role).
    pub object_type: String,
    /// User who rejected the transition.
    pub rejected_by: Uuid,
    /// Rejection reason.
    pub reason: String,
    /// When the transition was rejected.
    pub rejected_at: DateTime<Utc>,
}

impl Event for StateTransitionRejected {
    const TOPIC: &'static str = "xavyo.governance.lifecycle.rejected";
    const EVENT_TYPE: &'static str = "xavyo.governance.lifecycle.rejected";
}

/// Published when a state transition is rolled back within grace period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionRolledBack {
    /// Transition request ID.
    pub request_id: Uuid,
    /// Object that was rolled back.
    pub object_id: Uuid,
    /// Object type (user, entitlement, role).
    pub object_type: String,
    /// State restored to.
    pub restored_to_state: String,
    /// State that was rolled back from.
    pub rolled_back_from_state: String,
    /// User who performed the rollback.
    pub rolled_back_by: Uuid,
    /// Rollback reason.
    pub reason: Option<String>,
    /// When the rollback was performed.
    pub rolled_back_at: DateTime<Utc>,
}

impl Event for StateTransitionRolledBack {
    const TOPIC: &'static str = "xavyo.governance.lifecycle.rolled_back";
    const EVENT_TYPE: &'static str = "xavyo.governance.lifecycle.rolled_back";
}

/// Published when a bulk state operation is started.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkOperationStarted {
    /// Bulk operation ID.
    pub operation_id: Uuid,
    /// Transition being applied.
    pub transition_name: String,
    /// Total objects to process.
    pub total_count: u32,
    /// User who initiated the operation.
    pub requested_by: Uuid,
    /// When the operation started.
    pub started_at: DateTime<Utc>,
}

impl Event for BulkOperationStarted {
    const TOPIC: &'static str = "xavyo.governance.lifecycle.bulk.started";
    const EVENT_TYPE: &'static str = "xavyo.governance.lifecycle.bulk.started";
}

/// Published periodically during bulk operation to report progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkOperationProgress {
    /// Bulk operation ID.
    pub operation_id: Uuid,
    /// Objects processed so far.
    pub processed_count: u32,
    /// Total objects.
    pub total_count: u32,
    /// Successful transitions.
    pub success_count: u32,
    /// Failed transitions.
    pub failure_count: u32,
    /// Progress percentage (0-100).
    pub progress_percent: u8,
    /// When this progress was reported.
    pub reported_at: DateTime<Utc>,
}

impl Event for BulkOperationProgress {
    const TOPIC: &'static str = "xavyo.governance.lifecycle.bulk.progress";
    const EVENT_TYPE: &'static str = "xavyo.governance.lifecycle.bulk.progress";
}

/// Published when a bulk state operation is completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkOperationCompleted {
    /// Bulk operation ID.
    pub operation_id: Uuid,
    /// Transition that was applied.
    pub transition_name: String,
    /// Total objects processed.
    pub total_count: u32,
    /// Successful transitions.
    pub success_count: u32,
    /// Failed transitions.
    pub failure_count: u32,
    /// Duration in seconds.
    pub duration_seconds: u64,
    /// When the operation completed.
    pub completed_at: DateTime<Utc>,
}

impl Event for BulkOperationCompleted {
    const TOPIC: &'static str = "xavyo.governance.lifecycle.bulk.completed";
    const EVENT_TYPE: &'static str = "xavyo.governance.lifecycle.bulk.completed";
}

/// Published when a bulk state operation fails entirely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkOperationFailed {
    /// Bulk operation ID.
    pub operation_id: Uuid,
    /// Error message.
    pub error: String,
    /// Objects processed before failure.
    pub processed_count: u32,
    /// When the operation failed.
    pub failed_at: DateTime<Utc>,
}

impl Event for BulkOperationFailed {
    const TOPIC: &'static str = "xavyo.governance.lifecycle.bulk.failed";
    const EVENT_TYPE: &'static str = "xavyo.governance.lifecycle.bulk.failed";
}

/// Published when a scheduled transition becomes due.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTransitionDue {
    /// Scheduled transition ID.
    pub schedule_id: Uuid,
    /// Transition request ID.
    pub request_id: Uuid,
    /// Object to be transitioned.
    pub object_id: Uuid,
    /// Object type (user, entitlement, role).
    pub object_type: String,
    /// Target state.
    pub to_state: String,
    /// When the transition was scheduled for.
    pub scheduled_for: DateTime<Utc>,
    /// When this event was fired.
    pub triggered_at: DateTime<Utc>,
}

impl Event for ScheduledTransitionDue {
    const TOPIC: &'static str = "xavyo.governance.lifecycle.scheduled.due";
    const EVENT_TYPE: &'static str = "xavyo.governance.lifecycle.scheduled.due";
}

/// Published when a scheduled transition is cancelled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTransitionCancelled {
    /// Scheduled transition ID.
    pub schedule_id: Uuid,
    /// Transition request ID.
    pub request_id: Uuid,
    /// Object that was scheduled.
    pub object_id: Uuid,
    /// User who cancelled the schedule.
    pub cancelled_by: Uuid,
    /// When the schedule was cancelled.
    pub cancelled_at: DateTime<Utc>,
}

impl Event for ScheduledTransitionCancelled {
    const TOPIC: &'static str = "xavyo.governance.lifecycle.scheduled.cancelled";
    const EVENT_TYPE: &'static str = "xavyo.governance.lifecycle.scheduled.cancelled";
}

/// Published when state-based access rules are applied (entitlements paused/revoked).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateAccessRulesApplied {
    /// Transition request ID that triggered this.
    pub request_id: Uuid,
    /// Object whose entitlements were affected.
    pub object_id: Uuid,
    /// New state that triggered the rules.
    pub state: String,
    /// Action taken (pause, revoke).
    pub action: String,
    /// Number of entitlements affected.
    pub entitlements_affected: u32,
    /// When the rules were applied.
    pub applied_at: DateTime<Utc>,
}

impl Event for StateAccessRulesApplied {
    const TOPIC: &'static str = "xavyo.governance.lifecycle.access_rules.applied";
    const EVENT_TYPE: &'static str = "xavyo.governance.lifecycle.access_rules.applied";
}

/// Published when state-based access rules are reversed (entitlements restored).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateAccessRulesReversed {
    /// Transition request ID that triggered this (the rollback).
    pub request_id: Uuid,
    /// Object whose entitlements were restored.
    pub object_id: Uuid,
    /// State restored to.
    pub restored_to_state: String,
    /// Number of entitlements restored.
    pub entitlements_restored: u32,
    /// When the rules were reversed.
    pub reversed_at: DateTime<Utc>,
}

impl Event for StateAccessRulesReversed {
    const TOPIC: &'static str = "xavyo.governance.lifecycle.access_rules.reversed";
    const EVENT_TYPE: &'static str = "xavyo.governance.lifecycle.access_rules.reversed";
}

/// Published when a grace period expires for a transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GracePeriodExpired {
    /// Transition request ID.
    pub request_id: Uuid,
    /// Object that can no longer be rolled back.
    pub object_id: Uuid,
    /// Current state (now finalized).
    pub state: String,
    /// When the grace period expired.
    pub expired_at: DateTime<Utc>,
}

impl Event for GracePeriodExpired {
    const TOPIC: &'static str = "xavyo.governance.lifecycle.grace_period.expired";
    const EVENT_TYPE: &'static str = "xavyo.governance.lifecycle.grace_period.expired";
}
