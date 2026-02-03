//! Audit logging DTOs for authorization policies (F-020).
//!
//! This module provides data structures for policy audit events and version history.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::PolicyResponse;

/// Action performed on an authorization policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAuditAction {
    /// Policy was created.
    #[default]
    Created,
    /// Policy was updated.
    Updated,
    /// Policy was deleted.
    Deleted,
    /// Condition was added to policy.
    ConditionAdded,
    /// Condition was removed from policy.
    ConditionRemoved,
    /// Policy status was changed.
    StatusChanged,
}

impl std::fmt::Display for PolicyAuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Updated => write!(f, "updated"),
            Self::Deleted => write!(f, "deleted"),
            Self::ConditionAdded => write!(f, "condition_added"),
            Self::ConditionRemoved => write!(f, "condition_removed"),
            Self::StatusChanged => write!(f, "status_changed"),
        }
    }
}

/// A policy audit event capturing a change to a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAuditEvent {
    /// Unique event identifier.
    pub id: Uuid,
    /// Tenant this event belongs to.
    pub tenant_id: Uuid,
    /// The policy that was changed.
    pub policy_id: Uuid,
    /// Action performed.
    pub action: PolicyAuditAction,
    /// User who performed the action.
    pub actor_id: Uuid,
    /// Policy state before the change (None for create).
    pub before_state: Option<serde_json::Value>,
    /// Policy state after the change (None for delete).
    pub after_state: Option<serde_json::Value>,
    /// When the change occurred.
    pub timestamp: DateTime<Utc>,
    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Input for creating a policy audit event.
#[derive(Debug, Clone, Default)]
pub struct PolicyAuditEventInput {
    /// Tenant this event belongs to.
    pub tenant_id: Uuid,
    /// The policy that was changed.
    pub policy_id: Uuid,
    /// Action performed.
    pub action: PolicyAuditAction,
    /// User who performed the action.
    pub actor_id: Uuid,
    /// Policy state before the change.
    pub before_state: Option<serde_json::Value>,
    /// Policy state after the change.
    pub after_state: Option<serde_json::Value>,
    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Filter for querying policy audit events.
#[derive(Debug, Clone, Default)]
pub struct PolicyAuditFilter {
    /// Filter by policy ID.
    pub policy_id: Option<Uuid>,
    /// Filter by actor ID.
    pub actor_id: Option<Uuid>,
    /// Filter by action type.
    pub action: Option<PolicyAuditAction>,
    /// Filter by events after this date.
    pub from_date: Option<DateTime<Utc>>,
    /// Filter by events before this date.
    pub to_date: Option<DateTime<Utc>>,
    /// Maximum number of results.
    pub limit: Option<usize>,
    /// Number of results to skip.
    pub offset: Option<usize>,
}

/// A policy version capturing state at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersion {
    /// Version record identifier.
    pub id: Uuid,
    /// Policy this version belongs to.
    pub policy_id: Uuid,
    /// Tenant isolation.
    pub tenant_id: Uuid,
    /// Sequential version number.
    pub version_number: i32,
    /// Complete policy state at this version.
    pub policy_state: serde_json::Value,
    /// When this version was created.
    pub created_at: DateTime<Utc>,
    /// User who created this version.
    pub created_by: Uuid,
}

/// Input for creating a policy version.
#[derive(Debug, Clone)]
pub struct PolicyVersionInput {
    /// Policy this version belongs to.
    pub policy_id: Uuid,
    /// Tenant isolation.
    pub tenant_id: Uuid,
    /// Complete policy state.
    pub policy_state: serde_json::Value,
    /// User who created this version.
    pub created_by: Uuid,
}

// ============================================================================
// API Response Types
// ============================================================================

/// API response for a policy audit event.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PolicyAuditEventResponse {
    /// Unique event identifier.
    pub id: Uuid,
    /// The policy that was changed.
    pub policy_id: Uuid,
    /// Action performed.
    pub action: PolicyAuditAction,
    /// User who performed the action.
    pub actor_id: Uuid,
    /// Policy state before the change.
    pub before_state: Option<serde_json::Value>,
    /// Policy state after the change.
    pub after_state: Option<serde_json::Value>,
    /// When the change occurred.
    pub timestamp: DateTime<Utc>,
    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,
}

impl From<PolicyAuditEvent> for PolicyAuditEventResponse {
    fn from(event: PolicyAuditEvent) -> Self {
        Self {
            id: event.id,
            policy_id: event.policy_id,
            action: event.action,
            actor_id: event.actor_id,
            before_state: event.before_state,
            after_state: event.after_state,
            timestamp: event.timestamp,
            metadata: event.metadata,
        }
    }
}

/// API response for a list of audit events.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuditEventListResponse {
    /// The list of audit events.
    pub events: Vec<PolicyAuditEventResponse>,
    /// Total number of matching events.
    pub total: i64,
    /// Whether there are more results.
    pub has_more: bool,
}

/// API response for a policy version summary.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PolicyVersionSummary {
    /// Version number.
    pub version_number: i32,
    /// When this version was created.
    pub created_at: DateTime<Utc>,
    /// User who created this version.
    pub created_by: Uuid,
    /// Brief description of what changed.
    pub change_summary: Option<String>,
}

/// API response for a list of policy versions.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PolicyVersionListResponse {
    /// The list of versions.
    pub versions: Vec<PolicyVersionSummary>,
}

/// API response for a specific policy version.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PolicyVersionResponse {
    /// Version number.
    pub version_number: i32,
    /// Complete policy state at this version.
    pub policy_state: PolicyResponse,
    /// When this version was created.
    pub created_at: DateTime<Utc>,
    /// User who created this version.
    pub created_by: Uuid,
}

fn default_limit() -> i64 {
    100
}

fn default_offset() -> i64 {
    0
}

/// Query parameters for listing audit events.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListAuditQuery {
    /// Filter by policy ID.
    pub policy_id: Option<Uuid>,

    /// Filter by actor who made changes.
    pub actor_id: Option<Uuid>,

    /// Filter by action type.
    pub action: Option<String>,

    /// Events after this timestamp (ISO 8601).
    pub from_date: Option<DateTime<Utc>>,

    /// Events before this timestamp (ISO 8601).
    pub to_date: Option<DateTime<Utc>>,

    /// Maximum number of results (default: 100, max: 1000).
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Offset for pagination (default: 0).
    #[serde(default = "default_offset")]
    pub offset: i64,
}

impl From<ListAuditQuery> for PolicyAuditFilter {
    fn from(query: ListAuditQuery) -> Self {
        Self {
            policy_id: query.policy_id,
            actor_id: query.actor_id,
            action: query.action.and_then(|s| match s.as_str() {
                "created" => Some(PolicyAuditAction::Created),
                "updated" => Some(PolicyAuditAction::Updated),
                "deleted" => Some(PolicyAuditAction::Deleted),
                "condition_added" => Some(PolicyAuditAction::ConditionAdded),
                "condition_removed" => Some(PolicyAuditAction::ConditionRemoved),
                "status_changed" => Some(PolicyAuditAction::StatusChanged),
                _ => None,
            }),
            from_date: query.from_date,
            to_date: query.to_date,
            limit: Some(query.limit.min(1000) as usize),
            offset: Some(query.offset as usize),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_audit_action_display() {
        assert_eq!(PolicyAuditAction::Created.to_string(), "created");
        assert_eq!(PolicyAuditAction::Updated.to_string(), "updated");
        assert_eq!(PolicyAuditAction::Deleted.to_string(), "deleted");
        assert_eq!(
            PolicyAuditAction::ConditionAdded.to_string(),
            "condition_added"
        );
        assert_eq!(
            PolicyAuditAction::ConditionRemoved.to_string(),
            "condition_removed"
        );
        assert_eq!(
            PolicyAuditAction::StatusChanged.to_string(),
            "status_changed"
        );
    }

    #[test]
    fn test_policy_audit_action_default() {
        let action = PolicyAuditAction::default();
        assert_eq!(action, PolicyAuditAction::Created);
    }

    #[test]
    fn test_list_audit_query_to_filter() {
        let query = ListAuditQuery {
            policy_id: Some(Uuid::new_v4()),
            actor_id: None,
            action: Some("updated".to_string()),
            from_date: None,
            to_date: None,
            limit: 50,
            offset: 10,
        };

        let filter: PolicyAuditFilter = query.into();
        assert_eq!(filter.action, Some(PolicyAuditAction::Updated));
        assert_eq!(filter.limit, Some(50));
        assert_eq!(filter.offset, Some(10));
    }

    #[test]
    fn test_list_audit_query_limit_capped() {
        let query = ListAuditQuery {
            policy_id: None,
            actor_id: None,
            action: None,
            from_date: None,
            to_date: None,
            limit: 5000, // Over the 1000 max
            offset: 0,
        };

        let filter: PolicyAuditFilter = query.into();
        assert_eq!(filter.limit, Some(1000)); // Capped at 1000
    }
}
