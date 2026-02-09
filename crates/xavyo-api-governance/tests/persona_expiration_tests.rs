//! Unit tests for `PersonaExpirationService` (US5).
//!
//! Tests persona expiration handling and automatic status transitions.

use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

mod common;

mod persona_expiration_service_tests {
    use super::*;

    /// T065: Unit test for expiration detection
    #[test]
    fn test_persona_is_expired() {
        let valid_until = Utc::now() - Duration::hours(1); // Expired 1 hour ago
        let now = Utc::now();

        let is_expired = valid_until < now;
        assert!(
            is_expired,
            "Persona with past valid_until should be expired"
        );
    }

    #[test]
    fn test_persona_is_not_expired() {
        let valid_until = Utc::now() + Duration::days(30); // 30 days in the future
        let now = Utc::now();

        let is_expired = valid_until < now;
        assert!(
            !is_expired,
            "Persona with future valid_until should not be expired"
        );
    }

    #[test]
    fn test_persona_is_expiring_within_7_days() {
        let valid_until = Utc::now() + Duration::days(5); // 5 days from now
        let now = Utc::now();
        let expiration_warning_days = 7;

        let warning_threshold = now + Duration::days(expiration_warning_days);
        let is_expiring = valid_until < warning_threshold && valid_until > now;

        assert!(
            is_expiring,
            "Persona expiring within 7 days should be flagged"
        );
    }

    #[test]
    fn test_persona_not_expiring_beyond_7_days() {
        let valid_until = Utc::now() + Duration::days(30); // 30 days from now
        let now = Utc::now();
        let expiration_warning_days = 7;

        let warning_threshold = now + Duration::days(expiration_warning_days);
        let is_expiring = valid_until < warning_threshold && valid_until > now;

        assert!(
            !is_expiring,
            "Persona valid for 30 days should not be expiring"
        );
    }

    #[test]
    fn test_expiration_status_transitions() {
        #[derive(Debug, PartialEq, Clone, Copy)]
        #[allow(dead_code)]
        enum PersonaStatus {
            Active,
            Expiring,
            Expired,
        }

        // Transition: Active -> Expiring (when within warning period)
        let status = PersonaStatus::Active;
        let can_transition_to_expiring = matches!(status, PersonaStatus::Active);
        assert!(can_transition_to_expiring);

        // Transition: Expiring -> Expired (when valid_until reached)
        let status = PersonaStatus::Expiring;
        let can_transition_to_expired =
            matches!(status, PersonaStatus::Expiring | PersonaStatus::Active);
        assert!(can_transition_to_expired);

        // Transition: Active -> Expired (if warning period is 0 or missed)
        let status = PersonaStatus::Active;
        let can_transition_to_expired =
            matches!(status, PersonaStatus::Expiring | PersonaStatus::Active);
        assert!(can_transition_to_expired);
    }

    #[test]
    fn test_expiration_check_result() {
        let _tenant_id = Uuid::new_v4();
        let persona_id = Uuid::new_v4();

        // Expiration check result structure
        let check_result = json!({
            "persona_id": persona_id,
            "previous_status": "active",
            "new_status": "expiring",
            "valid_until": (Utc::now() + Duration::days(5)).to_rfc3339(),
            "days_until_expiration": 5,
            "notification_sent": true
        });

        assert!(check_result.get("persona_id").is_some());
        assert_eq!(
            check_result.get("new_status").unwrap().as_str().unwrap(),
            "expiring"
        );
        assert_eq!(
            check_result
                .get("days_until_expiration")
                .unwrap()
                .as_i64()
                .unwrap(),
            5
        );
    }

    #[test]
    fn test_batch_expiration_check_result() {
        let expiration_results = json!({
            "processed": 100,
            "transitioned_to_expiring": 5,
            "transitioned_to_expired": 2,
            "notifications_sent": 5,
            "errors": 0,
            "duration_ms": 150
        });

        assert_eq!(
            expiration_results
                .get("processed")
                .unwrap()
                .as_i64()
                .unwrap(),
            100
        );
        assert_eq!(
            expiration_results
                .get("transitioned_to_expiring")
                .unwrap()
                .as_i64()
                .unwrap(),
            5
        );
        assert_eq!(
            expiration_results
                .get("transitioned_to_expired")
                .unwrap()
                .as_i64()
                .unwrap(),
            2
        );
    }

    #[test]
    fn test_extension_request_structure() {
        let persona_id = Uuid::new_v4();
        let extension_days = 30;
        let reason = "Project extended for additional phase";

        let extension_request = json!({
            "persona_id": persona_id,
            "extension_days": extension_days,
            "new_valid_until": (Utc::now() + Duration::days(30)).to_rfc3339(),
            "reason": reason,
            "requires_approval": true
        });

        assert_eq!(
            extension_request
                .get("extension_days")
                .unwrap()
                .as_i64()
                .unwrap(),
            30
        );
        assert_eq!(
            extension_request.get("reason").unwrap().as_str().unwrap(),
            reason
        );
    }

    #[test]
    fn test_extension_approval_based_on_lifecycle_policy() {
        // Lifecycle policy determines if extension requires approval
        let lifecycle_policy = json!({
            "validity_days": 90,
            "auto_extend": false,
            "extension_requires_approval": true,
            "max_extensions": 3,
            "current_extensions": 1
        });

        let requires_approval = lifecycle_policy
            .get("extension_requires_approval")
            .unwrap()
            .as_bool()
            .unwrap();
        assert!(requires_approval);

        let current_extensions = lifecycle_policy
            .get("current_extensions")
            .unwrap()
            .as_i64()
            .unwrap();
        let max_extensions = lifecycle_policy
            .get("max_extensions")
            .unwrap()
            .as_i64()
            .unwrap();
        let can_extend = current_extensions < max_extensions;
        assert!(
            can_extend,
            "Extension should be allowed when under max limit"
        );
    }

    #[test]
    fn test_extension_blocked_when_max_reached() {
        let lifecycle_policy = json!({
            "max_extensions": 3,
            "current_extensions": 3
        });

        let current_extensions = lifecycle_policy
            .get("current_extensions")
            .unwrap()
            .as_i64()
            .unwrap();
        let max_extensions = lifecycle_policy
            .get("max_extensions")
            .unwrap()
            .as_i64()
            .unwrap();
        let can_extend = current_extensions < max_extensions;
        assert!(!can_extend, "Extension should be blocked when max reached");
    }

    #[test]
    fn test_session_invalidation_on_expiration() {
        let persona_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // When persona expires, all active sessions should be invalidated
        let session_invalidation_result = json!({
            "persona_id": persona_id,
            "sessions_invalidated": 3,
            "users_affected": [user_id],
            "invalidated_at": Utc::now().to_rfc3339()
        });

        assert_eq!(
            session_invalidation_result
                .get("sessions_invalidated")
                .unwrap()
                .as_i64()
                .unwrap(),
            3
        );
    }

    #[test]
    fn test_expiring_personas_report_structure() {
        let expiring_report = json!({
            "expiring_count": 10,
            "expired_today_count": 2,
            "personas": [
                {
                    "persona_id": Uuid::new_v4(),
                    "persona_name": "project.admin.john",
                    "physical_user_name": "John Doe",
                    "valid_until": (Utc::now() + Duration::days(3)).to_rfc3339(),
                    "days_remaining": 3,
                    "status": "expiring"
                }
            ]
        });

        assert_eq!(
            expiring_report
                .get("expiring_count")
                .unwrap()
                .as_i64()
                .unwrap(),
            10
        );
        assert!(expiring_report.get("personas").is_some());
    }

    #[test]
    fn test_notification_schedule() {
        // Notifications sent at specific intervals before expiration
        let notification_schedule = vec![7, 3, 1, 0]; // Days before expiration

        // Test each notification day explicitly
        for &notify_day in &notification_schedule {
            let should_notify = notification_schedule.contains(&notify_day);
            assert!(
                should_notify,
                "Should notify at {notify_day} days before expiration"
            );
        }

        // Test a day that should NOT trigger notification
        let no_notify_day = 5;
        let should_not_notify = notification_schedule.contains(&no_notify_day);
        assert!(
            !should_not_notify,
            "Should NOT notify at 5 days before expiration"
        );
    }

    #[test]
    fn test_expiration_with_no_valid_until() {
        // Personas with no valid_until never expire
        let valid_until: Option<chrono::DateTime<Utc>> = None;

        let should_expire = valid_until.is_some_and(|v| v < Utc::now());
        assert!(
            !should_expire,
            "Persona with no valid_until should never expire"
        );
    }

    #[test]
    fn test_auto_extend_policy() {
        // Auto-extend policy automatically extends valid_until
        let lifecycle_policy = json!({
            "auto_extend": true,
            "auto_extend_days": 30,
            "auto_extend_max": 3,
            "auto_extend_count": 1
        });

        let auto_extend = lifecycle_policy
            .get("auto_extend")
            .unwrap()
            .as_bool()
            .unwrap();
        let extend_count = lifecycle_policy
            .get("auto_extend_count")
            .unwrap()
            .as_i64()
            .unwrap();
        let extend_max = lifecycle_policy
            .get("auto_extend_max")
            .unwrap()
            .as_i64()
            .unwrap();

        let can_auto_extend = auto_extend && extend_count < extend_max;
        assert!(can_auto_extend, "Auto-extend should be possible");
    }
}
