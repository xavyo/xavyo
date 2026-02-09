//! Unit tests for micro-certification creation from events (T016).
//!
//! Tests the creation of micro-certifications from various triggering events.

use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_db::{MicroCertDecision, MicroCertStatus};

/// Simulated certification creation input
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CreateCertificationInput {
    trigger_rule_id: Uuid,
    assignment_id: Option<Uuid>,
    user_id: Uuid,
    entitlement_id: Uuid,
    reviewer_id: Uuid,
    backup_reviewer_id: Option<Uuid>,
    triggering_event_type: String,
    triggering_event_id: Uuid,
    timeout_secs: i32,
    auto_revoke: bool,
}

/// Simulated certification output
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Certification {
    id: Uuid,
    tenant_id: Uuid,
    trigger_rule_id: Uuid,
    assignment_id: Option<Uuid>,
    user_id: Uuid,
    entitlement_id: Uuid,
    reviewer_id: Uuid,
    backup_reviewer_id: Option<Uuid>,
    status: MicroCertStatus,
    triggering_event_type: String,
    triggering_event_id: Uuid,
    deadline: chrono::DateTime<Utc>,
    escalation_deadline: Option<chrono::DateTime<Utc>>,
    reminder_sent: bool,
    escalated: bool,
    decision: Option<MicroCertDecision>,
}

mod certification_creation {
    use super::*;

    #[test]
    fn test_high_risk_assignment_creates_pending_certification() {
        let input = CreateCertificationInput {
            trigger_rule_id: Uuid::new_v4(),
            assignment_id: Some(Uuid::new_v4()),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: None,
            triggering_event_type: "EntitlementAssigned".to_string(),
            triggering_event_id: Uuid::new_v4(),
            timeout_secs: 86400,
            auto_revoke: true,
        };

        let cert = create_certification(Uuid::new_v4(), input.clone());

        assert_eq!(cert.status, MicroCertStatus::Pending);
        assert_eq!(cert.trigger_rule_id, input.trigger_rule_id);
        assert_eq!(cert.user_id, input.user_id);
        assert_eq!(cert.entitlement_id, input.entitlement_id);
        assert_eq!(cert.reviewer_id, input.reviewer_id);
        assert!(!cert.reminder_sent);
        assert!(!cert.escalated);
        assert!(cert.decision.is_none());
    }

    #[test]
    fn test_deadline_calculated_from_timeout() {
        let input = CreateCertificationInput {
            trigger_rule_id: Uuid::new_v4(),
            assignment_id: Some(Uuid::new_v4()),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: None,
            triggering_event_type: "EntitlementAssigned".to_string(),
            triggering_event_id: Uuid::new_v4(),
            timeout_secs: 3600, // 1 hour
            auto_revoke: true,
        };

        let before = Utc::now();
        let cert = create_certification(Uuid::new_v4(), input.clone());
        let after = Utc::now();

        // Deadline should be ~1 hour from now
        let expected_min = before + Duration::seconds(3600);
        let expected_max = after + Duration::seconds(3600);

        assert!(cert.deadline >= expected_min);
        assert!(cert.deadline <= expected_max);
    }

    #[test]
    fn test_escalation_deadline_set_when_backup_reviewer_exists() {
        let input = CreateCertificationInput {
            trigger_rule_id: Uuid::new_v4(),
            assignment_id: Some(Uuid::new_v4()),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: Some(Uuid::new_v4()), // Has backup
            triggering_event_type: "EntitlementAssigned".to_string(),
            triggering_event_id: Uuid::new_v4(),
            timeout_secs: 86400, // 24 hours
            auto_revoke: true,
        };

        let cert = create_certification_with_escalation(Uuid::new_v4(), input.clone(), 75);

        assert!(cert.escalation_deadline.is_some());

        // Escalation should be at 75% of timeout (18 hours)
        let expected_escalation = Utc::now() + Duration::seconds(i64::from(86400 * 75 / 100));
        let actual_escalation = cert.escalation_deadline.unwrap();

        // Allow 1 second tolerance
        assert!(
            (actual_escalation - expected_escalation)
                .num_seconds()
                .abs()
                <= 1
        );
    }

    #[test]
    fn test_no_escalation_deadline_without_backup_reviewer() {
        let input = CreateCertificationInput {
            trigger_rule_id: Uuid::new_v4(),
            assignment_id: Some(Uuid::new_v4()),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: None, // No backup
            triggering_event_type: "EntitlementAssigned".to_string(),
            triggering_event_id: Uuid::new_v4(),
            timeout_secs: 86400,
            auto_revoke: true,
        };

        let cert = create_certification_with_escalation(Uuid::new_v4(), input.clone(), 75);

        assert!(cert.escalation_deadline.is_none());
    }

    #[test]
    fn test_assignment_id_is_optional_for_deleted_assignments() {
        let input = CreateCertificationInput {
            trigger_rule_id: Uuid::new_v4(),
            assignment_id: None, // Assignment was deleted
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: None,
            triggering_event_type: "ManagerChanged".to_string(),
            triggering_event_id: Uuid::new_v4(),
            timeout_secs: 86400,
            auto_revoke: true,
        };

        let cert = create_certification(Uuid::new_v4(), input.clone());

        assert!(cert.assignment_id.is_none());
        assert_eq!(cert.status, MicroCertStatus::Pending);
    }

    #[test]
    fn test_triggering_event_stored_correctly() {
        let event_id = Uuid::new_v4();
        let event_type = "SodViolationDetected".to_string();

        let input = CreateCertificationInput {
            trigger_rule_id: Uuid::new_v4(),
            assignment_id: Some(Uuid::new_v4()),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: None,
            triggering_event_type: event_type.clone(),
            triggering_event_id: event_id,
            timeout_secs: 86400,
            auto_revoke: true,
        };

        let cert = create_certification(Uuid::new_v4(), input.clone());

        assert_eq!(cert.triggering_event_id, event_id);
        assert_eq!(cert.triggering_event_type, event_type);
    }
}

mod duplicate_prevention {
    use super::*;

    #[test]
    fn test_duplicate_check_same_assignment_and_rule() {
        let tenant_id = Uuid::new_v4();
        let assignment_id = Uuid::new_v4();
        let trigger_rule_id = Uuid::new_v4();

        let existing = vec![Certification {
            id: Uuid::new_v4(),
            tenant_id,
            trigger_rule_id,
            assignment_id: Some(assignment_id),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: None,
            status: MicroCertStatus::Pending,
            triggering_event_type: "EntitlementAssigned".to_string(),
            triggering_event_id: Uuid::new_v4(),
            deadline: Utc::now() + Duration::hours(24),
            escalation_deadline: None,
            reminder_sent: false,
            escalated: false,
            decision: None,
        }];

        let is_duplicate = check_duplicate(&existing, Some(assignment_id), trigger_rule_id);
        assert!(is_duplicate);
    }

    #[test]
    fn test_no_duplicate_different_assignment() {
        let tenant_id = Uuid::new_v4();
        let trigger_rule_id = Uuid::new_v4();

        let existing = vec![Certification {
            id: Uuid::new_v4(),
            tenant_id,
            trigger_rule_id,
            assignment_id: Some(Uuid::new_v4()), // Different assignment
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: None,
            status: MicroCertStatus::Pending,
            triggering_event_type: "EntitlementAssigned".to_string(),
            triggering_event_id: Uuid::new_v4(),
            deadline: Utc::now() + Duration::hours(24),
            escalation_deadline: None,
            reminder_sent: false,
            escalated: false,
            decision: None,
        }];

        let is_duplicate = check_duplicate(&existing, Some(Uuid::new_v4()), trigger_rule_id);
        assert!(!is_duplicate);
    }

    #[test]
    fn test_no_duplicate_different_trigger_rule() {
        let tenant_id = Uuid::new_v4();
        let assignment_id = Uuid::new_v4();

        let existing = vec![Certification {
            id: Uuid::new_v4(),
            tenant_id,
            trigger_rule_id: Uuid::new_v4(), // Different rule
            assignment_id: Some(assignment_id),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: None,
            status: MicroCertStatus::Pending,
            triggering_event_type: "EntitlementAssigned".to_string(),
            triggering_event_id: Uuid::new_v4(),
            deadline: Utc::now() + Duration::hours(24),
            escalation_deadline: None,
            reminder_sent: false,
            escalated: false,
            decision: None,
        }];

        let is_duplicate = check_duplicate(&existing, Some(assignment_id), Uuid::new_v4());
        assert!(!is_duplicate);
    }

    #[test]
    fn test_completed_certification_not_considered_duplicate() {
        let tenant_id = Uuid::new_v4();
        let assignment_id = Uuid::new_v4();
        let trigger_rule_id = Uuid::new_v4();

        let existing = vec![Certification {
            id: Uuid::new_v4(),
            tenant_id,
            trigger_rule_id,
            assignment_id: Some(assignment_id),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: None,
            status: MicroCertStatus::Approved, // Already decided
            triggering_event_type: "EntitlementAssigned".to_string(),
            triggering_event_id: Uuid::new_v4(),
            deadline: Utc::now() + Duration::hours(24),
            escalation_deadline: None,
            reminder_sent: false,
            escalated: false,
            decision: Some(MicroCertDecision::Approve),
        }];

        let is_duplicate = check_duplicate(&existing, Some(assignment_id), trigger_rule_id);
        assert!(!is_duplicate); // Can create new cert for already-decided one
    }
}

// Helper functions

fn create_certification(tenant_id: Uuid, input: CreateCertificationInput) -> Certification {
    Certification {
        id: Uuid::new_v4(),
        tenant_id,
        trigger_rule_id: input.trigger_rule_id,
        assignment_id: input.assignment_id,
        user_id: input.user_id,
        entitlement_id: input.entitlement_id,
        reviewer_id: input.reviewer_id,
        backup_reviewer_id: input.backup_reviewer_id,
        status: MicroCertStatus::Pending,
        triggering_event_type: input.triggering_event_type,
        triggering_event_id: input.triggering_event_id,
        deadline: Utc::now() + Duration::seconds(i64::from(input.timeout_secs)),
        escalation_deadline: None,
        reminder_sent: false,
        escalated: false,
        decision: None,
    }
}

fn create_certification_with_escalation(
    tenant_id: Uuid,
    input: CreateCertificationInput,
    reminder_threshold_percent: i32,
) -> Certification {
    let deadline = Utc::now() + Duration::seconds(i64::from(input.timeout_secs));
    let escalation_deadline = if input.backup_reviewer_id.is_some() {
        Some(
            Utc::now()
                + Duration::seconds(i64::from(
                    input.timeout_secs * reminder_threshold_percent / 100,
                )),
        )
    } else {
        None
    };

    Certification {
        id: Uuid::new_v4(),
        tenant_id,
        trigger_rule_id: input.trigger_rule_id,
        assignment_id: input.assignment_id,
        user_id: input.user_id,
        entitlement_id: input.entitlement_id,
        reviewer_id: input.reviewer_id,
        backup_reviewer_id: input.backup_reviewer_id,
        status: MicroCertStatus::Pending,
        triggering_event_type: input.triggering_event_type,
        triggering_event_id: input.triggering_event_id,
        deadline,
        escalation_deadline,
        reminder_sent: false,
        escalated: false,
        decision: None,
    }
}

fn check_duplicate(
    existing: &[Certification],
    assignment_id: Option<Uuid>,
    trigger_rule_id: Uuid,
) -> bool {
    existing.iter().any(|c| {
        c.trigger_rule_id == trigger_rule_id
            && c.assignment_id == assignment_id
            && c.status == MicroCertStatus::Pending
    })
}
