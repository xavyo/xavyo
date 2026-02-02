//! Micro-certification events for F055 Micro-certification.
//!
//! Events for micro-certification lifecycle changes:
//! - Created (certification triggered)
//! - Reminder (notification before deadline)
//! - Escalated (escalated to backup reviewer)
//! - Decided (reviewer made decision)
//! - AutoRevoked (system revoked due to timeout)
//! - Expired (deadline passed without auto-revoke)
//! - Skipped (assignment deleted before decision)
//! - AssignmentRevoked (entitlement assignment was revoked)

use crate::event::Event;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Trigger type for micro-certification events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MicroCertTriggerType {
    /// Entitlement with risk_level = high/critical assigned.
    HighRiskAssignment,
    /// SoD rule violation detected.
    SodViolation,
    /// User's manager changed.
    ManagerChange,
    /// Scheduled re-certification.
    PeriodicRecert,
    /// Manually triggered by admin.
    Manual,
}

/// Reviewer type for micro-certification events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MicroCertReviewerType {
    /// User's direct manager.
    UserManager,
    /// Owner of the entitlement.
    EntitlementOwner,
    /// Owner of the application.
    ApplicationOwner,
    /// Specific user from trigger rule.
    SpecificUser,
}

/// Decision type for micro-certification events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MicroCertDecision {
    /// Certify the access.
    Approve,
    /// Reject/revoke the access.
    Revoke,
}

/// Published when a micro-certification is created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroCertificationCreated {
    /// The micro-certification ID.
    pub certification_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The trigger rule ID that created this certification.
    pub trigger_rule_id: Uuid,
    /// The entitlement assignment ID (if exists).
    pub assignment_id: Option<Uuid>,
    /// The user whose access is being certified.
    pub user_id: Uuid,
    /// The entitlement being certified.
    pub entitlement_id: Uuid,
    /// The assigned reviewer.
    pub reviewer_id: Uuid,
    /// The backup reviewer (if configured).
    pub backup_reviewer_id: Option<Uuid>,
    /// Type of event that triggered this certification.
    pub trigger_type: MicroCertTriggerType,
    /// The triggering event ID for traceability.
    pub triggering_event_id: Uuid,
    /// When the certification must be completed.
    pub deadline: DateTime<Utc>,
    /// When to escalate to backup reviewer (if configured).
    pub escalation_deadline: Option<DateTime<Utc>>,
}

impl Event for MicroCertificationCreated {
    const TOPIC: &'static str = "xavyo.governance.micro_certification.created";
    const EVENT_TYPE: &'static str = "xavyo.governance.micro_certification.created";
}

/// Published when a reminder is sent to the reviewer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroCertificationReminder {
    /// The micro-certification ID.
    pub certification_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The reviewer receiving the reminder.
    pub reviewer_id: Uuid,
    /// The user whose access is being certified.
    pub user_id: Uuid,
    /// The entitlement being certified.
    pub entitlement_id: Uuid,
    /// When the certification must be completed.
    pub deadline: DateTime<Utc>,
    /// Time remaining until deadline in seconds.
    pub seconds_remaining: i64,
    /// Whether auto-revoke is enabled.
    pub auto_revoke: bool,
}

impl Event for MicroCertificationReminder {
    const TOPIC: &'static str = "xavyo.governance.micro_certification.reminder";
    const EVENT_TYPE: &'static str = "xavyo.governance.micro_certification.reminder";
}

/// Published when a certification is escalated to backup reviewer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroCertificationEscalated {
    /// The micro-certification ID.
    pub certification_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The original reviewer who didn't respond.
    pub original_reviewer_id: Uuid,
    /// The new backup reviewer.
    pub backup_reviewer_id: Uuid,
    /// The user whose access is being certified.
    pub user_id: Uuid,
    /// The entitlement being certified.
    pub entitlement_id: Uuid,
    /// When the certification must be completed.
    pub deadline: DateTime<Utc>,
    /// Time remaining until deadline in seconds.
    pub seconds_remaining: i64,
}

impl Event for MicroCertificationEscalated {
    const TOPIC: &'static str = "xavyo.governance.micro_certification.escalated";
    const EVENT_TYPE: &'static str = "xavyo.governance.micro_certification.escalated";
}

/// Published when a reviewer makes a decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroCertificationDecided {
    /// The micro-certification ID.
    pub certification_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The user whose access was certified.
    pub user_id: Uuid,
    /// The entitlement that was certified.
    pub entitlement_id: Uuid,
    /// The entitlement assignment ID (if exists).
    pub assignment_id: Option<Uuid>,
    /// The reviewer who made the decision.
    pub decided_by: Uuid,
    /// The decision made.
    pub decision: MicroCertDecision,
    /// Optional comment from reviewer.
    pub comment: Option<String>,
    /// For SoD: which assignment was revoked (if any).
    pub revoked_assignment_id: Option<Uuid>,
}

impl Event for MicroCertificationDecided {
    const TOPIC: &'static str = "xavyo.governance.micro_certification.decided";
    const EVENT_TYPE: &'static str = "xavyo.governance.micro_certification.decided";
}

/// Published when a certification is auto-revoked due to timeout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroCertificationAutoRevoked {
    /// The micro-certification ID.
    pub certification_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The user whose access was auto-revoked.
    pub user_id: Uuid,
    /// The entitlement that was auto-revoked.
    pub entitlement_id: Uuid,
    /// The entitlement assignment ID that was revoked.
    pub assignment_id: Option<Uuid>,
    /// The reviewer who didn't respond.
    pub reviewer_id: Uuid,
    /// The backup reviewer who also didn't respond (if escalated).
    pub backup_reviewer_id: Option<Uuid>,
    /// The deadline that was exceeded.
    pub deadline: DateTime<Utc>,
}

impl Event for MicroCertificationAutoRevoked {
    const TOPIC: &'static str = "xavyo.governance.micro_certification.auto_revoked";
    const EVENT_TYPE: &'static str = "xavyo.governance.micro_certification.auto_revoked";
}

/// Published when a certification expires without auto-revoke.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroCertificationExpired {
    /// The micro-certification ID.
    pub certification_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The user whose access remains uncertified.
    pub user_id: Uuid,
    /// The entitlement that remains uncertified.
    pub entitlement_id: Uuid,
    /// The entitlement assignment ID.
    pub assignment_id: Option<Uuid>,
    /// The reviewer who didn't respond.
    pub reviewer_id: Uuid,
    /// The backup reviewer who also didn't respond (if escalated).
    pub backup_reviewer_id: Option<Uuid>,
    /// The deadline that was exceeded.
    pub deadline: DateTime<Utc>,
}

impl Event for MicroCertificationExpired {
    const TOPIC: &'static str = "xavyo.governance.micro_certification.expired";
    const EVENT_TYPE: &'static str = "xavyo.governance.micro_certification.expired";
}

/// Published when a certification is skipped (assignment deleted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroCertificationSkipped {
    /// The micro-certification ID.
    pub certification_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The user whose certification was skipped.
    pub user_id: Uuid,
    /// The entitlement that was skipped.
    pub entitlement_id: Uuid,
    /// Reason for skipping.
    pub reason: String,
}

impl Event for MicroCertificationSkipped {
    const TOPIC: &'static str = "xavyo.governance.micro_certification.skipped";
    const EVENT_TYPE: &'static str = "xavyo.governance.micro_certification.skipped";
}

/// Published when an entitlement assignment is revoked due to micro-certification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroCertAssignmentRevoked {
    /// The micro-certification ID that caused the revocation.
    pub certification_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The entitlement assignment ID that was revoked.
    pub assignment_id: Uuid,
    /// The user who lost the access.
    pub user_id: Uuid,
    /// The entitlement that was revoked.
    pub entitlement_id: Uuid,
    /// Reason for revocation.
    pub reason: String,
    /// Who triggered the revocation (reviewer ID or null for system).
    pub revoked_by: Option<Uuid>,
}

impl Event for MicroCertAssignmentRevoked {
    const TOPIC: &'static str = "xavyo.governance.micro_certification.assignment_revoked";
    const EVENT_TYPE: &'static str = "xavyo.governance.micro_certification.assignment_revoked";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_micro_certification_created_serialization() {
        let event = MicroCertificationCreated {
            certification_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            trigger_rule_id: Uuid::new_v4(),
            assignment_id: Some(Uuid::new_v4()),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: Some(Uuid::new_v4()),
            trigger_type: MicroCertTriggerType::HighRiskAssignment,
            triggering_event_id: Uuid::new_v4(),
            deadline: Utc::now(),
            escalation_deadline: Some(Utc::now()),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: MicroCertificationCreated = serde_json::from_str(&json).unwrap();
        assert_eq!(event.certification_id, restored.certification_id);
    }

    #[test]
    fn test_micro_certification_reminder_serialization() {
        let event = MicroCertificationReminder {
            certification_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            deadline: Utc::now(),
            seconds_remaining: 21600, // 6 hours
            auto_revoke: true,
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: MicroCertificationReminder = serde_json::from_str(&json).unwrap();
        assert_eq!(event.seconds_remaining, restored.seconds_remaining);
    }

    #[test]
    fn test_micro_certification_escalated_serialization() {
        let event = MicroCertificationEscalated {
            certification_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            original_reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            deadline: Utc::now(),
            seconds_remaining: 14400, // 4 hours
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: MicroCertificationEscalated = serde_json::from_str(&json).unwrap();
        assert_eq!(event.certification_id, restored.certification_id);
    }

    #[test]
    fn test_micro_certification_decided_serialization() {
        let event = MicroCertificationDecided {
            certification_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            assignment_id: Some(Uuid::new_v4()),
            decided_by: Uuid::new_v4(),
            decision: MicroCertDecision::Approve,
            comment: Some("Approved for Q1 project".to_string()),
            revoked_assignment_id: None,
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: MicroCertificationDecided = serde_json::from_str(&json).unwrap();
        assert_eq!(event.certification_id, restored.certification_id);
    }

    #[test]
    fn test_micro_certification_auto_revoked_serialization() {
        let event = MicroCertificationAutoRevoked {
            certification_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            assignment_id: Some(Uuid::new_v4()),
            reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: Some(Uuid::new_v4()),
            deadline: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: MicroCertificationAutoRevoked = serde_json::from_str(&json).unwrap();
        assert_eq!(event.certification_id, restored.certification_id);
    }

    #[test]
    fn test_micro_certification_expired_serialization() {
        let event = MicroCertificationExpired {
            certification_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            assignment_id: Some(Uuid::new_v4()),
            reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: None,
            deadline: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: MicroCertificationExpired = serde_json::from_str(&json).unwrap();
        assert_eq!(event.certification_id, restored.certification_id);
    }

    #[test]
    fn test_micro_certification_skipped_serialization() {
        let event = MicroCertificationSkipped {
            certification_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reason: "Assignment deleted".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: MicroCertificationSkipped = serde_json::from_str(&json).unwrap();
        assert_eq!(event.reason, restored.reason);
    }

    #[test]
    fn test_micro_cert_assignment_revoked_serialization() {
        let event = MicroCertAssignmentRevoked {
            certification_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            assignment_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reason: "Certification rejected".to_string(),
            revoked_by: Some(Uuid::new_v4()),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: MicroCertAssignmentRevoked = serde_json::from_str(&json).unwrap();
        assert_eq!(event.reason, restored.reason);
    }

    #[test]
    fn test_micro_certification_topics() {
        assert_eq!(
            MicroCertificationCreated::TOPIC,
            "xavyo.governance.micro_certification.created"
        );
        assert_eq!(
            MicroCertificationReminder::TOPIC,
            "xavyo.governance.micro_certification.reminder"
        );
        assert_eq!(
            MicroCertificationEscalated::TOPIC,
            "xavyo.governance.micro_certification.escalated"
        );
        assert_eq!(
            MicroCertificationDecided::TOPIC,
            "xavyo.governance.micro_certification.decided"
        );
        assert_eq!(
            MicroCertificationAutoRevoked::TOPIC,
            "xavyo.governance.micro_certification.auto_revoked"
        );
        assert_eq!(
            MicroCertificationExpired::TOPIC,
            "xavyo.governance.micro_certification.expired"
        );
        assert_eq!(
            MicroCertificationSkipped::TOPIC,
            "xavyo.governance.micro_certification.skipped"
        );
        assert_eq!(
            MicroCertAssignmentRevoked::TOPIC,
            "xavyo.governance.micro_certification.assignment_revoked"
        );
    }

    #[test]
    fn test_all_topics_follow_convention() {
        assert!(MicroCertificationCreated::TOPIC.starts_with("xavyo."));
        assert!(MicroCertificationReminder::TOPIC.starts_with("xavyo."));
        assert!(MicroCertificationEscalated::TOPIC.starts_with("xavyo."));
        assert!(MicroCertificationDecided::TOPIC.starts_with("xavyo."));
        assert!(MicroCertificationAutoRevoked::TOPIC.starts_with("xavyo."));
        assert!(MicroCertificationExpired::TOPIC.starts_with("xavyo."));
        assert!(MicroCertificationSkipped::TOPIC.starts_with("xavyo."));
        assert!(MicroCertAssignmentRevoked::TOPIC.starts_with("xavyo."));
    }

    #[test]
    fn test_trigger_type_serialization() {
        let high_risk = MicroCertTriggerType::HighRiskAssignment;
        let json = serde_json::to_string(&high_risk).unwrap();
        assert_eq!(json, "\"high_risk_assignment\"");

        let sod = MicroCertTriggerType::SodViolation;
        let json = serde_json::to_string(&sod).unwrap();
        assert_eq!(json, "\"sod_violation\"");
    }

    #[test]
    fn test_decision_serialization() {
        let approve = MicroCertDecision::Approve;
        let json = serde_json::to_string(&approve).unwrap();
        assert_eq!(json, "\"approve\"");

        let revoke = MicroCertDecision::Revoke;
        let json = serde_json::to_string(&revoke).unwrap();
        assert_eq!(json, "\"revoke\"");
    }
}
