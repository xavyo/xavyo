//! Escalation events for F054 Workflow Escalation.
//!
//! Events for escalation lifecycle changes:
//! - Warning (pre-escalation notification)
//! - Occurred (escalation executed)
//! - Cancelled (escalation cancelled by admin)
//! - Reset (escalation reset to original approver)
//! - Exhausted (all escalation levels exhausted)

use crate::event::Event;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Escalation target type for events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationTargetType {
    /// Escalated to a specific user.
    SpecificUser,
    /// Escalated to an approval group.
    ApprovalGroup,
    /// Escalated to the approver's manager.
    Manager,
    /// Escalated up the manager chain.
    ManagerChain,
    /// Escalated to tenant administrators.
    TenantAdmin,
}

/// Reason for escalation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationReason {
    /// Escalated due to timeout.
    Timeout,
    /// Manually escalated by admin.
    ManualEscalation,
    /// Previous target was unavailable.
    TargetUnavailable,
}

/// Final fallback action type for events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalFallbackAction {
    /// Escalate to tenant admin.
    EscalateAdmin,
    /// Automatically approve.
    AutoApprove,
    /// Automatically reject.
    AutoReject,
    /// Keep pending.
    RemainPending,
}

/// Published when an escalation warning is sent (before timeout).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationWarning {
    /// The access request ID.
    pub request_id: Uuid,
    /// The approval step order.
    pub step_order: i32,
    /// The current approver receiving the warning.
    pub approver_id: Uuid,
    /// When the approval will timeout.
    pub deadline: DateTime<Utc>,
    /// Time remaining until escalation in seconds.
    pub seconds_remaining: i64,
    /// Current escalation level (0 = original, 1+ = escalated).
    pub escalation_level: i32,
}

impl Event for EscalationWarning {
    const TOPIC: &'static str = "xavyo.governance.escalation.warning";
    const EVENT_TYPE: &'static str = "xavyo.governance.escalation.warning";
}

/// Published when an escalation occurs (work item reassigned).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationOccurred {
    /// The access request ID.
    pub request_id: Uuid,
    /// The approval step order.
    pub step_order: i32,
    /// The new escalation level (1, 2, 3...).
    pub escalation_level: i32,
    /// The original approver before escalation.
    pub original_approver_id: Option<Uuid>,
    /// Type of escalation target.
    pub target_type: EscalationTargetType,
    /// Resolved target user IDs (can be multiple for groups).
    pub target_ids: Vec<Uuid>,
    /// Reason for escalation.
    pub reason: EscalationReason,
    /// Previous deadline that was exceeded.
    pub previous_deadline: Option<DateTime<Utc>>,
    /// New deadline after escalation.
    pub new_deadline: Option<DateTime<Utc>>,
}

impl Event for EscalationOccurred {
    const TOPIC: &'static str = "xavyo.governance.escalation.occurred";
    const EVENT_TYPE: &'static str = "xavyo.governance.escalation.occurred";
}

/// Published when an escalation is cancelled by an admin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationCancelled {
    /// The access request ID.
    pub request_id: Uuid,
    /// The approval step order.
    pub step_order: i32,
    /// The escalation level that was cancelled.
    pub escalation_level: i32,
    /// User who cancelled the escalation.
    pub cancelled_by: Uuid,
    /// Current assignee (remains unchanged).
    pub current_assignee_id: Uuid,
}

impl Event for EscalationCancelled {
    const TOPIC: &'static str = "xavyo.governance.escalation.cancelled";
    const EVENT_TYPE: &'static str = "xavyo.governance.escalation.cancelled";
}

/// Published when an escalation is reset to the original approver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationReset {
    /// The access request ID.
    pub request_id: Uuid,
    /// The approval step order.
    pub step_order: i32,
    /// The escalation level that was reset from.
    pub previous_escalation_level: i32,
    /// User who reset the escalation.
    pub reset_by: Uuid,
    /// The original approver work item is returned to.
    pub original_approver_id: Uuid,
    /// New deadline after reset.
    pub new_deadline: Option<DateTime<Utc>>,
}

impl Event for EscalationReset {
    const TOPIC: &'static str = "xavyo.governance.escalation.reset";
    const EVENT_TYPE: &'static str = "xavyo.governance.escalation.reset";
}

/// Published when all escalation levels are exhausted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationExhausted {
    /// The access request ID.
    pub request_id: Uuid,
    /// The approval step order.
    pub step_order: i32,
    /// The final escalation level reached.
    pub final_escalation_level: i32,
    /// The final fallback action taken.
    pub fallback_action: FinalFallbackAction,
    /// Result of the fallback action (approved, rejected, pending).
    pub result_status: String,
}

impl Event for EscalationExhausted {
    const TOPIC: &'static str = "xavyo.governance.escalation.exhausted";
    const EVENT_TYPE: &'static str = "xavyo.governance.escalation.exhausted";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escalation_warning_serialization() {
        let event = EscalationWarning {
            request_id: Uuid::new_v4(),
            step_order: 1,
            approver_id: Uuid::new_v4(),
            deadline: Utc::now(),
            seconds_remaining: 14400, // 4 hours
            escalation_level: 0,
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: EscalationWarning = serde_json::from_str(&json).unwrap();
        assert_eq!(event.request_id, restored.request_id);
        assert_eq!(event.seconds_remaining, restored.seconds_remaining);
    }

    #[test]
    fn test_escalation_occurred_serialization() {
        let event = EscalationOccurred {
            request_id: Uuid::new_v4(),
            step_order: 1,
            escalation_level: 1,
            original_approver_id: Some(Uuid::new_v4()),
            target_type: EscalationTargetType::Manager,
            target_ids: vec![Uuid::new_v4()],
            reason: EscalationReason::Timeout,
            previous_deadline: Some(Utc::now()),
            new_deadline: Some(Utc::now()),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: EscalationOccurred = serde_json::from_str(&json).unwrap();
        assert_eq!(event.request_id, restored.request_id);
        assert_eq!(event.escalation_level, restored.escalation_level);
    }

    #[test]
    fn test_escalation_cancelled_serialization() {
        let event = EscalationCancelled {
            request_id: Uuid::new_v4(),
            step_order: 1,
            escalation_level: 2,
            cancelled_by: Uuid::new_v4(),
            current_assignee_id: Uuid::new_v4(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: EscalationCancelled = serde_json::from_str(&json).unwrap();
        assert_eq!(event.request_id, restored.request_id);
    }

    #[test]
    fn test_escalation_reset_serialization() {
        let event = EscalationReset {
            request_id: Uuid::new_v4(),
            step_order: 1,
            previous_escalation_level: 2,
            reset_by: Uuid::new_v4(),
            original_approver_id: Uuid::new_v4(),
            new_deadline: Some(Utc::now()),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: EscalationReset = serde_json::from_str(&json).unwrap();
        assert_eq!(
            event.previous_escalation_level,
            restored.previous_escalation_level
        );
    }

    #[test]
    fn test_escalation_exhausted_serialization() {
        let event = EscalationExhausted {
            request_id: Uuid::new_v4(),
            step_order: 1,
            final_escalation_level: 3,
            fallback_action: FinalFallbackAction::AutoReject,
            result_status: "rejected".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: EscalationExhausted = serde_json::from_str(&json).unwrap();
        assert_eq!(
            event.final_escalation_level,
            restored.final_escalation_level
        );
    }

    #[test]
    fn test_escalation_topics() {
        assert_eq!(
            EscalationWarning::TOPIC,
            "xavyo.governance.escalation.warning"
        );
        assert_eq!(
            EscalationOccurred::TOPIC,
            "xavyo.governance.escalation.occurred"
        );
        assert_eq!(
            EscalationCancelled::TOPIC,
            "xavyo.governance.escalation.cancelled"
        );
        assert_eq!(EscalationReset::TOPIC, "xavyo.governance.escalation.reset");
        assert_eq!(
            EscalationExhausted::TOPIC,
            "xavyo.governance.escalation.exhausted"
        );
    }

    #[test]
    fn test_all_escalation_topics_follow_convention() {
        assert!(EscalationWarning::TOPIC.starts_with("xavyo."));
        assert!(EscalationOccurred::TOPIC.starts_with("xavyo."));
        assert!(EscalationCancelled::TOPIC.starts_with("xavyo."));
        assert!(EscalationReset::TOPIC.starts_with("xavyo."));
        assert!(EscalationExhausted::TOPIC.starts_with("xavyo."));
    }

    #[test]
    fn test_target_type_serialization() {
        let manager = EscalationTargetType::Manager;
        let json = serde_json::to_string(&manager).unwrap();
        assert_eq!(json, "\"manager\"");

        let tenant_admin = EscalationTargetType::TenantAdmin;
        let json = serde_json::to_string(&tenant_admin).unwrap();
        assert_eq!(json, "\"tenant_admin\"");
    }

    #[test]
    fn test_reason_serialization() {
        let timeout = EscalationReason::Timeout;
        let json = serde_json::to_string(&timeout).unwrap();
        assert_eq!(json, "\"timeout\"");

        let manual = EscalationReason::ManualEscalation;
        let json = serde_json::to_string(&manual).unwrap();
        assert_eq!(json, "\"manual_escalation\"");
    }

    #[test]
    fn test_fallback_action_serialization() {
        let auto_reject = FinalFallbackAction::AutoReject;
        let json = serde_json::to_string(&auto_reject).unwrap();
        assert_eq!(json, "\"auto_reject\"");

        let escalate = FinalFallbackAction::EscalateAdmin;
        let json = serde_json::to_string(&escalate).unwrap();
        assert_eq!(json, "\"escalate_admin\"");
    }
}
