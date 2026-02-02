//! Integration tests for F054 Workflow Escalation notification events.
//!
//! These tests validate the Kafka events that trigger notifications:
//! - EscalationWarning (pre-escalation warning)
//! - EscalationOccurred (escalation happened)
//! - EscalationExhausted (all levels exhausted)

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    use xavyo_events::events::{
        EscalationCancelled, EscalationExhausted, EscalationOccurred, EscalationReason,
        EscalationReset, EscalationTargetTypeEvent as EscalationTargetType, EscalationWarning,
        FinalFallbackActionEvent as FinalFallbackAction,
    };
    use xavyo_events::Event;

    // ========================================================================
    // Original Approver Notification on Escalation (T042)
    // ========================================================================

    #[test]
    fn test_escalation_occurred_includes_original_approver() {
        let original_approver_id = Uuid::new_v4();
        let event = EscalationOccurred {
            request_id: Uuid::new_v4(),
            step_order: 1,
            escalation_level: 1,
            original_approver_id: Some(original_approver_id),
            target_type: EscalationTargetType::Manager,
            target_ids: vec![Uuid::new_v4()],
            reason: EscalationReason::Timeout,
            previous_deadline: Some(Utc::now()),
            new_deadline: Some(Utc::now() + Duration::hours(24)),
        };

        assert_eq!(event.original_approver_id, Some(original_approver_id));
    }

    #[test]
    fn test_escalation_occurred_event_topic() {
        assert_eq!(
            EscalationOccurred::TOPIC,
            "xavyo.governance.escalation.occurred"
        );
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
            new_deadline: Some(Utc::now() + Duration::hours(24)),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: EscalationOccurred = serde_json::from_str(&json).unwrap();

        assert_eq!(event.request_id, restored.request_id);
        assert_eq!(event.escalation_level, restored.escalation_level);
    }

    // ========================================================================
    // Escalation Target Notification (T043)
    // ========================================================================

    #[test]
    fn test_escalation_target_ids_for_single_user() {
        let target_id = Uuid::new_v4();
        let event = EscalationOccurred {
            request_id: Uuid::new_v4(),
            step_order: 1,
            escalation_level: 1,
            original_approver_id: None,
            target_type: EscalationTargetType::SpecificUser,
            target_ids: vec![target_id],
            reason: EscalationReason::ManualEscalation,
            previous_deadline: None,
            new_deadline: Some(Utc::now() + Duration::hours(24)),
        };

        assert_eq!(event.target_ids.len(), 1);
        assert_eq!(event.target_ids[0], target_id);
    }

    #[test]
    fn test_escalation_target_ids_for_approval_group() {
        let group_members = vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
        let event = EscalationOccurred {
            request_id: Uuid::new_v4(),
            step_order: 1,
            escalation_level: 2,
            original_approver_id: None,
            target_type: EscalationTargetType::ApprovalGroup,
            target_ids: group_members.clone(),
            reason: EscalationReason::Timeout,
            previous_deadline: None,
            new_deadline: Some(Utc::now() + Duration::hours(24)),
        };

        assert_eq!(event.target_ids.len(), 3);
        assert!(matches!(
            event.target_type,
            EscalationTargetType::ApprovalGroup
        ));
    }

    #[test]
    fn test_escalation_target_ids_for_manager_chain() {
        let chain = vec![Uuid::new_v4(), Uuid::new_v4()]; // Direct manager and skip-level
        let event = EscalationOccurred {
            request_id: Uuid::new_v4(),
            step_order: 1,
            escalation_level: 2,
            original_approver_id: Some(Uuid::new_v4()),
            target_type: EscalationTargetType::ManagerChain,
            target_ids: chain.clone(),
            reason: EscalationReason::Timeout,
            previous_deadline: None,
            new_deadline: Some(Utc::now() + Duration::hours(24)),
        };

        assert_eq!(event.target_ids.len(), 2);
        assert!(matches!(
            event.target_type,
            EscalationTargetType::ManagerChain
        ));
    }

    #[test]
    fn test_escalation_target_ids_for_tenant_admin() {
        let admins = vec![Uuid::new_v4(), Uuid::new_v4()];
        let event = EscalationOccurred {
            request_id: Uuid::new_v4(),
            step_order: 1,
            escalation_level: 3,
            original_approver_id: None,
            target_type: EscalationTargetType::TenantAdmin,
            target_ids: admins.clone(),
            reason: EscalationReason::Timeout,
            previous_deadline: None,
            new_deadline: Some(Utc::now() + Duration::hours(48)),
        };

        assert_eq!(event.target_ids.len(), 2);
        assert!(matches!(
            event.target_type,
            EscalationTargetType::TenantAdmin
        ));
    }

    // ========================================================================
    // Pre-Escalation Warning Notification (T044)
    // ========================================================================

    #[test]
    fn test_escalation_warning_event_structure() {
        let event = EscalationWarning {
            request_id: Uuid::new_v4(),
            step_order: 1,
            approver_id: Uuid::new_v4(),
            deadline: Utc::now() + Duration::hours(4),
            seconds_remaining: 4 * 3600, // 4 hours
            escalation_level: 0,         // Not yet escalated
        };

        assert_eq!(event.seconds_remaining, 14400);
        assert_eq!(event.escalation_level, 0);
    }

    #[test]
    fn test_escalation_warning_topic() {
        assert_eq!(
            EscalationWarning::TOPIC,
            "xavyo.governance.escalation.warning"
        );
    }

    #[test]
    fn test_escalation_warning_serialization() {
        let event = EscalationWarning {
            request_id: Uuid::new_v4(),
            step_order: 1,
            approver_id: Uuid::new_v4(),
            deadline: Utc::now() + Duration::hours(4),
            seconds_remaining: 4 * 3600,
            escalation_level: 0,
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: EscalationWarning = serde_json::from_str(&json).unwrap();

        assert_eq!(event.request_id, restored.request_id);
        assert_eq!(event.seconds_remaining, restored.seconds_remaining);
    }

    #[test]
    fn test_escalation_warning_at_different_levels() {
        // Warning at level 0 (before first escalation)
        let warning_level_0 = EscalationWarning {
            request_id: Uuid::new_v4(),
            step_order: 1,
            approver_id: Uuid::new_v4(),
            deadline: Utc::now() + Duration::hours(4),
            seconds_remaining: 4 * 3600,
            escalation_level: 0,
        };
        assert_eq!(warning_level_0.escalation_level, 0);

        // Warning at level 1 (after first escalation, before second)
        let warning_level_1 = EscalationWarning {
            request_id: Uuid::new_v4(),
            step_order: 1,
            approver_id: Uuid::new_v4(),
            deadline: Utc::now() + Duration::hours(4),
            seconds_remaining: 4 * 3600,
            escalation_level: 1,
        };
        assert_eq!(warning_level_1.escalation_level, 1);
    }

    // ========================================================================
    // Escalation Exhausted Notification
    // ========================================================================

    #[test]
    fn test_escalation_exhausted_event() {
        let event = EscalationExhausted {
            request_id: Uuid::new_v4(),
            step_order: 1,
            final_escalation_level: 3,
            fallback_action: FinalFallbackAction::AutoReject,
            result_status: "rejected".to_string(),
        };

        assert_eq!(event.final_escalation_level, 3);
        assert!(matches!(
            event.fallback_action,
            FinalFallbackAction::AutoReject
        ));
    }

    #[test]
    fn test_escalation_exhausted_topic() {
        assert_eq!(
            EscalationExhausted::TOPIC,
            "xavyo.governance.escalation.exhausted"
        );
    }

    #[test]
    fn test_escalation_exhausted_with_auto_approve() {
        let event = EscalationExhausted {
            request_id: Uuid::new_v4(),
            step_order: 1,
            final_escalation_level: 2,
            fallback_action: FinalFallbackAction::AutoApprove,
            result_status: "approved".to_string(),
        };

        assert!(matches!(
            event.fallback_action,
            FinalFallbackAction::AutoApprove
        ));
        assert_eq!(event.result_status, "approved");
    }

    #[test]
    fn test_escalation_exhausted_with_remain_pending() {
        let event = EscalationExhausted {
            request_id: Uuid::new_v4(),
            step_order: 1,
            final_escalation_level: 3,
            fallback_action: FinalFallbackAction::RemainPending,
            result_status: "pending".to_string(),
        };

        assert!(matches!(
            event.fallback_action,
            FinalFallbackAction::RemainPending
        ));
        assert_eq!(event.result_status, "pending");
    }

    // ========================================================================
    // Escalation Cancelled and Reset Events
    // ========================================================================

    #[test]
    fn test_escalation_cancelled_event() {
        let event = EscalationCancelled {
            request_id: Uuid::new_v4(),
            step_order: 1,
            escalation_level: 2,
            cancelled_by: Uuid::new_v4(),
            current_assignee_id: Uuid::new_v4(),
        };

        assert_eq!(event.escalation_level, 2);
    }

    #[test]
    fn test_escalation_cancelled_topic() {
        assert_eq!(
            EscalationCancelled::TOPIC,
            "xavyo.governance.escalation.cancelled"
        );
    }

    #[test]
    fn test_escalation_reset_event() {
        let event = EscalationReset {
            request_id: Uuid::new_v4(),
            step_order: 1,
            previous_escalation_level: 2,
            reset_by: Uuid::new_v4(),
            original_approver_id: Uuid::new_v4(),
            new_deadline: Some(Utc::now() + Duration::hours(24)),
        };

        assert_eq!(event.previous_escalation_level, 2);
    }

    #[test]
    fn test_escalation_reset_topic() {
        assert_eq!(EscalationReset::TOPIC, "xavyo.governance.escalation.reset");
    }

    // ========================================================================
    // Topic Convention Tests
    // ========================================================================

    #[test]
    fn test_all_escalation_topics_follow_convention() {
        // All topics should follow xavyo.governance.escalation.* pattern
        assert!(EscalationWarning::TOPIC.starts_with("xavyo.governance.escalation."));
        assert!(EscalationOccurred::TOPIC.starts_with("xavyo.governance.escalation."));
        assert!(EscalationCancelled::TOPIC.starts_with("xavyo.governance.escalation."));
        assert!(EscalationReset::TOPIC.starts_with("xavyo.governance.escalation."));
        assert!(EscalationExhausted::TOPIC.starts_with("xavyo.governance.escalation."));
    }

    // ========================================================================
    // Reason and Target Type in Events
    // ========================================================================

    #[test]
    fn test_escalation_reason_timeout() {
        let event = EscalationOccurred {
            request_id: Uuid::new_v4(),
            step_order: 1,
            escalation_level: 1,
            original_approver_id: Some(Uuid::new_v4()),
            target_type: EscalationTargetType::Manager,
            target_ids: vec![Uuid::new_v4()],
            reason: EscalationReason::Timeout,
            previous_deadline: Some(Utc::now()),
            new_deadline: Some(Utc::now() + Duration::hours(24)),
        };

        assert!(matches!(event.reason, EscalationReason::Timeout));
    }

    #[test]
    fn test_escalation_reason_manual() {
        let event = EscalationOccurred {
            request_id: Uuid::new_v4(),
            step_order: 1,
            escalation_level: 1,
            original_approver_id: None,
            target_type: EscalationTargetType::SpecificUser,
            target_ids: vec![Uuid::new_v4()],
            reason: EscalationReason::ManualEscalation,
            previous_deadline: None,
            new_deadline: Some(Utc::now() + Duration::hours(24)),
        };

        assert!(matches!(event.reason, EscalationReason::ManualEscalation));
    }

    #[test]
    fn test_escalation_reason_target_unavailable() {
        let event = EscalationOccurred {
            request_id: Uuid::new_v4(),
            step_order: 1,
            escalation_level: 2,
            original_approver_id: Some(Uuid::new_v4()),
            target_type: EscalationTargetType::ManagerChain,
            target_ids: vec![Uuid::new_v4()],
            reason: EscalationReason::TargetUnavailable,
            previous_deadline: None,
            new_deadline: Some(Utc::now() + Duration::hours(24)),
        };

        assert!(matches!(event.reason, EscalationReason::TargetUnavailable));
    }
}
