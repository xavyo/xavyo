//! Live synchronization events.
//!
//! Events for tracking inbound change processing, conflicts,
//! and sync cycle status in real-time.

use crate::event::Event;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Published when an inbound change is detected from an external system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundChangeDetected {
    /// Unique ID for this change.
    pub change_id: Uuid,
    /// Connector that detected the change.
    pub connector_id: Uuid,
    /// Type of change (create, update, delete).
    pub change_type: String,
    /// External system's unique identifier for the object.
    pub external_uid: String,
    /// Object class (e.g., "user", "group").
    pub object_class: String,
    /// Sync situation determined (linked, unlinked, unmatched, etc.).
    pub sync_situation: String,
    /// Linked internal identity ID (if determined).
    pub linked_identity_id: Option<Uuid>,
    /// When the change was detected.
    pub detected_at: DateTime<Utc>,
}

impl Event for InboundChangeDetected {
    const TOPIC: &'static str = "xavyo.sync.change.detected";
    const EVENT_TYPE: &'static str = "xavyo.sync.change.detected";
}

/// Published when an inbound change has been successfully processed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundChangeProcessed {
    /// The change that was processed.
    pub change_id: Uuid,
    /// Connector that processed the change.
    pub connector_id: Uuid,
    /// Final sync situation after processing.
    pub sync_situation: String,
    /// Identity ID that was affected (created/updated/deleted).
    pub affected_identity_id: Option<Uuid>,
    /// What action was taken (created, updated, linked, etc.).
    pub action_taken: String,
    /// Processing duration in milliseconds.
    pub duration_ms: i64,
    /// When processing completed.
    pub processed_at: DateTime<Utc>,
}

impl Event for InboundChangeProcessed {
    const TOPIC: &'static str = "xavyo.sync.change.processed";
    const EVENT_TYPE: &'static str = "xavyo.sync.change.processed";
}

/// Published when an inbound change fails to process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundChangeFailed {
    /// The change that failed.
    pub change_id: Uuid,
    /// Connector where failure occurred.
    pub connector_id: Uuid,
    /// Error message.
    pub error_message: String,
    /// Error category (transient, permanent, conflict).
    pub error_category: String,
    /// Number of retry attempts so far.
    pub retry_count: i32,
    /// Whether the change will be retried.
    pub will_retry: bool,
    /// When the failure occurred.
    pub failed_at: DateTime<Utc>,
}

impl Event for InboundChangeFailed {
    const TOPIC: &'static str = "xavyo.sync.change.failed";
    const EVENT_TYPE: &'static str = "xavyo.sync.change.failed";
}

/// Published when a sync conflict is detected between inbound and outbound changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConflictDetected {
    /// Unique ID for this conflict.
    pub conflict_id: Uuid,
    /// Connector where conflict occurred.
    pub connector_id: Uuid,
    /// The inbound change involved.
    pub inbound_change_id: Uuid,
    /// The outbound operation involved (if any).
    pub outbound_operation_id: Option<Uuid>,
    /// Type of conflict (concurrent_update, delete_update, etc.).
    pub conflict_type: String,
    /// Attributes that are in conflict.
    pub affected_attributes: Vec<String>,
    /// Initial resolution strategy assigned.
    pub resolution_strategy: String,
    /// When the conflict was detected.
    pub detected_at: DateTime<Utc>,
}

impl Event for SyncConflictDetected {
    const TOPIC: &'static str = "xavyo.sync.conflict.detected";
    const EVENT_TYPE: &'static str = "xavyo.sync.conflict.detected";
}

/// Published when a sync conflict is resolved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConflictResolved {
    /// The conflict that was resolved.
    pub conflict_id: Uuid,
    /// Connector where conflict was resolved.
    pub connector_id: Uuid,
    /// Final resolution strategy applied.
    pub resolution_strategy: String,
    /// Who resolved the conflict.
    pub resolved_by: Uuid,
    /// Optional notes about the resolution.
    pub resolution_notes: Option<String>,
    /// When the conflict was resolved.
    pub resolved_at: DateTime<Utc>,
}

impl Event for SyncConflictResolved {
    const TOPIC: &'static str = "xavyo.sync.conflict.resolved";
    const EVENT_TYPE: &'static str = "xavyo.sync.conflict.resolved";
}

/// Published when a sync cycle completes (batch of changes processed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCycleCompleted {
    /// Connector that completed the sync cycle.
    pub connector_id: Uuid,
    /// Total changes processed in this cycle.
    pub processed_count: i64,
    /// Successfully processed changes.
    pub succeeded_count: i64,
    /// Failed changes.
    pub failed_count: i64,
    /// Changes that resulted in conflicts.
    pub conflict_count: i64,
    /// Duration of the sync cycle in milliseconds.
    pub duration_ms: i64,
    /// Current sync token value after this cycle.
    pub sync_token: String,
    /// Whether there are more changes to process.
    pub has_more: bool,
    /// When the cycle completed.
    pub completed_at: DateTime<Utc>,
}

impl Event for SyncCycleCompleted {
    const TOPIC: &'static str = "xavyo.sync.cycle.completed";
    const EVENT_TYPE: &'static str = "xavyo.sync.cycle.completed";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inbound_change_detected_serialization() {
        let event = InboundChangeDetected {
            change_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            change_type: "update".to_string(),
            external_uid: "cn=john.doe,ou=users,dc=example,dc=com".to_string(),
            object_class: "user".to_string(),
            sync_situation: "linked".to_string(),
            linked_identity_id: Some(Uuid::new_v4()),
            detected_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: InboundChangeDetected = serde_json::from_str(&json).unwrap();

        assert_eq!(event.change_id, restored.change_id);
        assert_eq!(event.change_type, restored.change_type);
        assert_eq!(event.external_uid, restored.external_uid);
    }

    #[test]
    fn test_inbound_change_detected_topic() {
        assert_eq!(InboundChangeDetected::TOPIC, "xavyo.sync.change.detected");
        assert_eq!(
            InboundChangeDetected::EVENT_TYPE,
            "xavyo.sync.change.detected"
        );
    }

    #[test]
    fn test_inbound_change_processed_serialization() {
        let event = InboundChangeProcessed {
            change_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            sync_situation: "linked".to_string(),
            affected_identity_id: Some(Uuid::new_v4()),
            action_taken: "updated".to_string(),
            duration_ms: 42,
            processed_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("action_taken"));
    }

    #[test]
    fn test_inbound_change_failed_serialization() {
        let event = InboundChangeFailed {
            change_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            error_message: "Connection timeout".to_string(),
            error_category: "transient".to_string(),
            retry_count: 2,
            will_retry: true,
            failed_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: InboundChangeFailed = serde_json::from_str(&json).unwrap();

        assert_eq!(event.error_message, restored.error_message);
        assert!(restored.will_retry);
    }

    #[test]
    fn test_sync_conflict_detected_serialization() {
        let event = SyncConflictDetected {
            conflict_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            inbound_change_id: Uuid::new_v4(),
            outbound_operation_id: Some(Uuid::new_v4()),
            conflict_type: "concurrent_update".to_string(),
            affected_attributes: vec!["email".to_string(), "displayName".to_string()],
            resolution_strategy: "manual".to_string(),
            detected_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("affected_attributes"));
        assert!(json.contains("email"));
    }

    #[test]
    fn test_sync_conflict_resolved_serialization() {
        let event = SyncConflictResolved {
            conflict_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            resolution_strategy: "inbound_wins".to_string(),
            resolved_by: Uuid::new_v4(),
            resolution_notes: Some("Approved by admin".to_string()),
            resolved_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("resolution_notes"));
    }

    #[test]
    fn test_sync_cycle_completed_serialization() {
        let event = SyncCycleCompleted {
            connector_id: Uuid::new_v4(),
            processed_count: 100,
            succeeded_count: 95,
            failed_count: 3,
            conflict_count: 2,
            duration_ms: 5432,
            sync_token: "cookie=abc123".to_string(),
            has_more: false,
            completed_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: SyncCycleCompleted = serde_json::from_str(&json).unwrap();

        assert_eq!(event.processed_count, restored.processed_count);
        assert_eq!(event.succeeded_count, restored.succeeded_count);
        assert_eq!(event.has_more, restored.has_more);
    }

    #[test]
    fn test_all_sync_events_have_topics() {
        assert!(!InboundChangeDetected::TOPIC.is_empty());
        assert!(!InboundChangeProcessed::TOPIC.is_empty());
        assert!(!InboundChangeFailed::TOPIC.is_empty());
        assert!(!SyncConflictDetected::TOPIC.is_empty());
        assert!(!SyncConflictResolved::TOPIC.is_empty());
        assert!(!SyncCycleCompleted::TOPIC.is_empty());
    }

    #[test]
    fn test_all_sync_topics_follow_convention() {
        assert!(InboundChangeDetected::TOPIC.starts_with("xavyo."));
        assert!(InboundChangeProcessed::TOPIC.starts_with("xavyo."));
        assert!(InboundChangeFailed::TOPIC.starts_with("xavyo."));
        assert!(SyncConflictDetected::TOPIC.starts_with("xavyo."));
        assert!(SyncConflictResolved::TOPIC.starts_with("xavyo."));
        assert!(SyncCycleCompleted::TOPIC.starts_with("xavyo."));
    }
}
