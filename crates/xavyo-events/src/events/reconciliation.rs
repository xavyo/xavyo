//! Reconciliation events for F049 Reconciliation Engine.
//!
//! Events for tracking reconciliation runs, discrepancies,
//! and remediation actions.

use crate::event::Event;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Published when a reconciliation run is started.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationStarted {
    /// Reconciliation run ID.
    pub run_id: Uuid,
    /// Connector being reconciled.
    pub connector_id: Uuid,
    /// Reconciliation mode (full, delta).
    pub mode: String,
    /// User who triggered the run (if any).
    pub triggered_by: Option<Uuid>,
    /// Whether this is a dry run.
    pub dry_run: bool,
    /// When the run started.
    pub started_at: DateTime<Utc>,
}

impl Event for ReconciliationStarted {
    const TOPIC: &'static str = "xavyo.reconciliation.run.started";
    const EVENT_TYPE: &'static str = "xavyo.reconciliation.run.started";
}

/// Published when a reconciliation run completes successfully.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationCompleted {
    /// Reconciliation run ID.
    pub run_id: Uuid,
    /// Connector that was reconciled.
    pub connector_id: Uuid,
    /// Total accounts processed.
    pub accounts_processed: u32,
    /// Total discrepancies found.
    pub discrepancies_found: u32,
    /// Discrepancies by type.
    pub discrepancies_by_type: HashMap<String, u32>,
    /// Duration in seconds.
    pub duration_seconds: u64,
    /// When the run completed.
    pub completed_at: DateTime<Utc>,
}

impl Event for ReconciliationCompleted {
    const TOPIC: &'static str = "xavyo.reconciliation.run.completed";
    const EVENT_TYPE: &'static str = "xavyo.reconciliation.run.completed";
}

/// Published when a reconciliation run fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationFailed {
    /// Reconciliation run ID.
    pub run_id: Uuid,
    /// Connector that was being reconciled.
    pub connector_id: Uuid,
    /// Error message.
    pub error_message: String,
    /// Accounts processed before failure.
    pub accounts_processed: u32,
    /// Discrepancies found before failure.
    pub discrepancies_found: u32,
    /// Whether the run can be resumed.
    pub can_resume: bool,
    /// When the failure occurred.
    pub failed_at: DateTime<Utc>,
}

impl Event for ReconciliationFailed {
    const TOPIC: &'static str = "xavyo.reconciliation.run.failed";
    const EVENT_TYPE: &'static str = "xavyo.reconciliation.run.failed";
}

/// Published when a reconciliation run is cancelled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationCancelled {
    /// Reconciliation run ID.
    pub run_id: Uuid,
    /// Connector that was being reconciled.
    pub connector_id: Uuid,
    /// User who cancelled the run (if any).
    pub cancelled_by: Option<Uuid>,
    /// Accounts processed before cancellation.
    pub accounts_processed: u32,
    /// Whether the run can be resumed.
    pub can_resume: bool,
    /// When the cancellation occurred.
    pub cancelled_at: DateTime<Utc>,
}

impl Event for ReconciliationCancelled {
    const TOPIC: &'static str = "xavyo.reconciliation.run.cancelled";
    const EVENT_TYPE: &'static str = "xavyo.reconciliation.run.cancelled";
}

/// Published when a discrepancy is detected during reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscrepancyDetected {
    /// Discrepancy ID.
    pub discrepancy_id: Uuid,
    /// Reconciliation run ID.
    pub run_id: Uuid,
    /// Connector ID.
    pub connector_id: Uuid,
    /// Type of discrepancy (missing, orphan, mismatch, collision, unlinked, deleted).
    pub discrepancy_type: String,
    /// Associated identity ID (if known).
    pub identity_id: Option<Uuid>,
    /// External account UID.
    pub external_uid: String,
    /// Suggested remediation actions.
    pub suggested_actions: Vec<String>,
    /// When the discrepancy was detected.
    pub detected_at: DateTime<Utc>,
}

impl Event for DiscrepancyDetected {
    const TOPIC: &'static str = "xavyo.reconciliation.discrepancy.detected";
    const EVENT_TYPE: &'static str = "xavyo.reconciliation.discrepancy.detected";
}

/// Published when a remediation action is executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationExecuted {
    /// Action ID.
    pub action_id: Uuid,
    /// Discrepancy that was remediated.
    pub discrepancy_id: Uuid,
    /// Connector ID.
    pub connector_id: Uuid,
    /// Action type (create, update, delete, link, unlink, inactivate_identity).
    pub action_type: String,
    /// Result of the action (success, failure).
    pub result: String,
    /// Error message if failed.
    pub error_message: Option<String>,
    /// User who executed the action.
    pub executed_by: Uuid,
    /// Whether this was a dry run.
    pub dry_run: bool,
    /// When the action was executed.
    pub executed_at: DateTime<Utc>,
}

impl Event for RemediationExecuted {
    const TOPIC: &'static str = "xavyo.reconciliation.remediation.executed";
    const EVENT_TYPE: &'static str = "xavyo.reconciliation.remediation.executed";
}

/// Published when a discrepancy is ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscrepancyIgnored {
    /// Discrepancy ID.
    pub discrepancy_id: Uuid,
    /// Connector ID.
    pub connector_id: Uuid,
    /// User who ignored the discrepancy.
    pub ignored_by: Uuid,
    /// Reason for ignoring (if provided).
    pub reason: Option<String>,
    /// When the discrepancy was ignored.
    pub ignored_at: DateTime<Utc>,
}

impl Event for DiscrepancyIgnored {
    const TOPIC: &'static str = "xavyo.reconciliation.discrepancy.ignored";
    const EVENT_TYPE: &'static str = "xavyo.reconciliation.discrepancy.ignored";
}

/// Published when a scheduled reconciliation is triggered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledReconciliationTriggered {
    /// Schedule ID.
    pub schedule_id: Uuid,
    /// Connector ID.
    pub connector_id: Uuid,
    /// Run ID that was created.
    pub run_id: Uuid,
    /// Reconciliation mode.
    pub mode: String,
    /// Schedule frequency.
    pub frequency: String,
    /// When the scheduled run was triggered.
    pub triggered_at: DateTime<Utc>,
}

impl Event for ScheduledReconciliationTriggered {
    const TOPIC: &'static str = "xavyo.reconciliation.schedule.triggered";
    const EVENT_TYPE: &'static str = "xavyo.reconciliation.schedule.triggered";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reconciliation_started_serialization() {
        let event = ReconciliationStarted {
            run_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            mode: "full".to_string(),
            triggered_by: Some(Uuid::new_v4()),
            dry_run: false,
            started_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: ReconciliationStarted = serde_json::from_str(&json).unwrap();

        assert_eq!(event.run_id, restored.run_id);
        assert_eq!(event.mode, restored.mode);
    }

    #[test]
    fn test_reconciliation_completed_serialization() {
        let mut by_type = HashMap::new();
        by_type.insert("orphan".to_string(), 5);
        by_type.insert("mismatch".to_string(), 3);

        let event = ReconciliationCompleted {
            run_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            accounts_processed: 1000,
            discrepancies_found: 8,
            discrepancies_by_type: by_type,
            duration_seconds: 120,
            completed_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: ReconciliationCompleted = serde_json::from_str(&json).unwrap();

        assert_eq!(event.accounts_processed, restored.accounts_processed);
        assert_eq!(event.discrepancies_found, restored.discrepancies_found);
    }

    #[test]
    fn test_reconciliation_failed_serialization() {
        let event = ReconciliationFailed {
            run_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            error_message: "Connection timeout".to_string(),
            accounts_processed: 500,
            discrepancies_found: 4,
            can_resume: true,
            failed_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: ReconciliationFailed = serde_json::from_str(&json).unwrap();

        assert_eq!(event.error_message, restored.error_message);
        assert!(restored.can_resume);
    }

    #[test]
    fn test_discrepancy_detected_serialization() {
        let event = DiscrepancyDetected {
            discrepancy_id: Uuid::new_v4(),
            run_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            discrepancy_type: "orphan".to_string(),
            identity_id: None,
            external_uid: "cn=orphan.user,ou=users,dc=example,dc=com".to_string(),
            suggested_actions: vec!["link".to_string(), "delete".to_string()],
            detected_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: DiscrepancyDetected = serde_json::from_str(&json).unwrap();

        assert_eq!(event.discrepancy_type, restored.discrepancy_type);
        assert_eq!(event.suggested_actions.len(), 2);
    }

    #[test]
    fn test_remediation_executed_serialization() {
        let event = RemediationExecuted {
            action_id: Uuid::new_v4(),
            discrepancy_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            action_type: "create".to_string(),
            result: "success".to_string(),
            error_message: None,
            executed_by: Uuid::new_v4(),
            dry_run: false,
            executed_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: RemediationExecuted = serde_json::from_str(&json).unwrap();

        assert_eq!(event.action_type, restored.action_type);
        assert_eq!(event.result, "success");
    }

    #[test]
    fn test_all_reconciliation_events_have_topics() {
        assert!(!ReconciliationStarted::TOPIC.is_empty());
        assert!(!ReconciliationCompleted::TOPIC.is_empty());
        assert!(!ReconciliationFailed::TOPIC.is_empty());
        assert!(!ReconciliationCancelled::TOPIC.is_empty());
        assert!(!DiscrepancyDetected::TOPIC.is_empty());
        assert!(!RemediationExecuted::TOPIC.is_empty());
        assert!(!DiscrepancyIgnored::TOPIC.is_empty());
        assert!(!ScheduledReconciliationTriggered::TOPIC.is_empty());
    }

    #[test]
    fn test_all_reconciliation_topics_follow_convention() {
        assert!(ReconciliationStarted::TOPIC.starts_with("xavyo."));
        assert!(ReconciliationCompleted::TOPIC.starts_with("xavyo."));
        assert!(ReconciliationFailed::TOPIC.starts_with("xavyo."));
        assert!(ReconciliationCancelled::TOPIC.starts_with("xavyo."));
        assert!(DiscrepancyDetected::TOPIC.starts_with("xavyo."));
        assert!(RemediationExecuted::TOPIC.starts_with("xavyo."));
        assert!(DiscrepancyIgnored::TOPIC.starts_with("xavyo."));
        assert!(ScheduledReconciliationTriggered::TOPIC.starts_with("xavyo."));
    }
}
