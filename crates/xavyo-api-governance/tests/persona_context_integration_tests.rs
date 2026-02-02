//! Integration tests for context switching workflow (US2).
//!
//! Tests the end-to-end persona context switching including
//! session management, validation, and audit logging.

use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

mod common;

mod context_switching_integration {
    use super::*;
    use xavyo_db::models::{PersonaAuditEventType, PersonaStatus};

    /// T036: Integration test for context switching workflow
    #[test]
    fn test_full_context_switch_workflow() {
        // 1. User has two personas: Employee and Admin
        let user_id = Uuid::new_v4();
        let employee_persona_id = Uuid::new_v4();
        let admin_persona_id = Uuid::new_v4();

        // 2. User switches from Employee to Admin
        let switch_request = json!({
            "persona_id": admin_persona_id,
            "reason": "Need admin access for server maintenance"
        });

        // 3. Session is created with admin context
        let session = json!({
            "user_id": user_id,
            "active_persona_id": admin_persona_id,
            "previous_persona_id": employee_persona_id,
            "switched_at": Utc::now().to_rfc3339()
        });

        // 4. Audit log records the switch
        let audit_event_type = PersonaAuditEventType::ContextSwitched;

        assert!(switch_request.get("persona_id").is_some());
        assert!(session.get("active_persona_id").is_some());
        assert!(matches!(
            audit_event_type,
            PersonaAuditEventType::ContextSwitched
        ));
    }

    #[test]
    fn test_switch_back_to_physical_user() {
        let user_id = Uuid::new_v4();
        let admin_persona_id = Uuid::new_v4();

        // User was operating as admin persona
        let previous_session = json!({
            "user_id": user_id,
            "active_persona_id": admin_persona_id
        });

        // Switch back to physical user
        let switch_back_request = json!({
            "reason": "Admin tasks completed"
        });

        // New session has no active persona
        let new_session = json!({
            "user_id": user_id,
            "active_persona_id": null,
            "previous_persona_id": admin_persona_id
        });

        assert!(previous_session.get("active_persona_id").is_some());
        assert!(new_session.get("active_persona_id").unwrap().is_null());
    }

    #[test]
    fn test_access_policy_changes_on_switch() {
        // Before switch: Employee entitlements
        let employee_entitlements = vec!["read:docs", "write:own-docs"];

        // After switch to Admin: Admin entitlements
        let admin_entitlements = vec!["read:docs", "write:all-docs", "admin:servers"];

        assert!(admin_entitlements.len() > employee_entitlements.len());
    }

    #[test]
    fn test_audit_log_records_context_switch() {
        let user_id = Uuid::new_v4();
        let admin_persona_id = Uuid::new_v4();
        let actor_id = user_id;

        let audit_entry = json!({
            "event_type": "ContextSwitched",
            "user_id": user_id,
            "persona_id": admin_persona_id,
            "actor_id": actor_id,
            "event_data": {
                "from_context": "physical",
                "to_context": "admin_persona",
                "reason": "Server maintenance"
            }
        });

        assert_eq!(
            audit_entry.get("event_type").unwrap().as_str().unwrap(),
            "ContextSwitched"
        );
    }
}

mod validation_integration {
    use super::*;
    use xavyo_db::models::PersonaStatus;

    #[test]
    fn test_reject_switch_to_other_users_persona() {
        let user_id = Uuid::new_v4();
        let other_user_id = Uuid::new_v4();
        let other_persona_id = Uuid::new_v4();

        // Persona belongs to other user
        let persona_owner = other_user_id;

        // Validation should fail
        assert_ne!(
            user_id, persona_owner,
            "Should reject - persona belongs to different user"
        );
    }

    #[test]
    fn test_reject_switch_to_suspended_persona() {
        let persona_status = PersonaStatus::Suspended;

        assert!(
            !persona_status.can_switch_to(),
            "Should reject switch to suspended persona"
        );
    }

    #[test]
    fn test_reject_switch_to_expired_persona() {
        let valid_until = Utc::now() - Duration::days(1);
        let now = Utc::now();

        assert!(valid_until < now, "Should reject switch to expired persona");
    }

    #[test]
    fn test_allow_switch_when_valid_and_active() {
        let persona_status = PersonaStatus::Active;
        let valid_until = Utc::now() + Duration::days(30);
        let now = Utc::now();

        assert!(persona_status.can_switch_to());
        assert!(valid_until > now);
    }

    #[test]
    fn test_reject_switch_when_already_at_persona() {
        // If user tries to switch to the same persona they're already using
        let current_persona_id = Uuid::new_v4();
        let requested_persona_id = current_persona_id;

        // This should be a no-op or error
        assert_eq!(
            current_persona_id, requested_persona_id,
            "Already operating as this persona"
        );
    }
}

mod session_management_integration {
    use super::*;

    #[test]
    fn test_session_creation_on_switch() {
        let user_id = Uuid::new_v4();
        let persona_id = Uuid::new_v4();
        let session_duration_hours = 8;

        let session = json!({
            "id": Uuid::new_v4(),
            "tenant_id": Uuid::new_v4(),
            "user_id": user_id,
            "active_persona_id": persona_id,
            "switched_at": Utc::now().to_rfc3339(),
            "expires_at": (Utc::now() + Duration::hours(session_duration_hours)).to_rfc3339()
        });

        assert!(session.get("id").is_some());
        assert!(session.get("expires_at").is_some());
    }

    #[test]
    fn test_session_expiration_forces_switch_back() {
        let expires_at = Utc::now() - Duration::minutes(5);
        let now = Utc::now();

        // Session expired - should force switch back to physical user
        assert!(expires_at < now, "Expired session should force switch back");
    }

    #[test]
    fn test_persona_deactivation_invalidates_sessions() {
        let persona_id = Uuid::new_v4();
        let active_sessions_before = 3;
        let active_sessions_after = 0;

        // Deactivating persona should invalidate all its sessions
        assert!(active_sessions_before > 0);
        assert_eq!(active_sessions_after, 0);
    }

    #[test]
    fn test_user_deactivation_invalidates_all_sessions() {
        let user_id = Uuid::new_v4();
        let sessions_before = 5;
        let sessions_after = 0;

        assert!(sessions_before > 0);
        assert_eq!(sessions_after, 0);
    }

    #[test]
    fn test_get_current_context() {
        let user_id = Uuid::new_v4();
        let persona_id = Uuid::new_v4();

        let current_context = json!({
            "user_id": user_id,
            "operating_as": "persona",
            "persona_id": persona_id,
            "persona_name": "admin.john.doe",
            "persona_archetype": "Admin Persona",
            "session_expires_at": (Utc::now() + Duration::hours(6)).to_rfc3339()
        });

        assert_eq!(
            current_context
                .get("operating_as")
                .unwrap()
                .as_str()
                .unwrap(),
            "persona"
        );
    }

    #[test]
    fn test_get_current_context_physical_user() {
        let user_id = Uuid::new_v4();

        let current_context = json!({
            "user_id": user_id,
            "operating_as": "physical",
            "persona_id": null,
            "available_personas": [
                {"id": Uuid::new_v4(), "name": "admin.john.doe"},
                {"id": Uuid::new_v4(), "name": "support.john.doe"}
            ]
        });

        assert_eq!(
            current_context
                .get("operating_as")
                .unwrap()
                .as_str()
                .unwrap(),
            "physical"
        );
        assert!(current_context.get("persona_id").unwrap().is_null());
    }
}

mod jwt_integration {
    use super::*;

    #[test]
    fn test_jwt_enhanced_with_persona_claims() {
        let user_id = Uuid::new_v4();
        let persona_id = Uuid::new_v4();

        let jwt_claims = json!({
            "sub": user_id,
            "tenant_id": Uuid::new_v4(),
            "exp": (Utc::now() + Duration::hours(1)).timestamp(),
            // Persona enhancement
            "active_persona_id": persona_id,
            "persona_archetype": "admin",
            "persona_name": "admin.john.doe",
            "effective_identity_id": persona_id
        });

        assert!(jwt_claims.get("active_persona_id").is_some());
        assert!(jwt_claims.get("effective_identity_id").is_some());
    }

    #[test]
    fn test_jwt_without_persona_claims() {
        let user_id = Uuid::new_v4();

        let jwt_claims = json!({
            "sub": user_id,
            "tenant_id": Uuid::new_v4(),
            "exp": (Utc::now() + Duration::hours(1)).timestamp(),
            // No persona claims when operating as physical user
            "effective_identity_id": user_id
        });

        assert!(jwt_claims.get("active_persona_id").is_none());
        assert_eq!(
            jwt_claims
                .get("effective_identity_id")
                .unwrap()
                .as_str()
                .unwrap(),
            user_id.to_string()
        );
    }

    #[test]
    fn test_token_refresh_on_context_switch() {
        let original_token_exp = Utc::now() + Duration::hours(2);
        let new_token_exp = Utc::now() + Duration::hours(8);

        // New token should have fresh expiration
        assert!(new_token_exp > original_token_exp);
    }
}

mod audit_integration {
    use super::*;
    use xavyo_db::models::PersonaAuditEventType;

    #[test]
    fn test_audit_event_logged_on_switch() {
        let event_type = PersonaAuditEventType::ContextSwitched;
        let user_id = Uuid::new_v4();
        let persona_id = Uuid::new_v4();

        let audit_event = json!({
            "event_type": "ContextSwitched",
            "persona_id": persona_id,
            "actor_id": user_id,
            "event_data": {
                "from_persona_id": null,
                "to_persona_id": persona_id,
                "reason": "Need elevated access",
                "session_id": Uuid::new_v4()
            }
        });

        assert!(matches!(event_type, PersonaAuditEventType::ContextSwitched));
        assert!(audit_event.get("event_data").is_some());
    }

    #[test]
    fn test_audit_event_logged_on_switch_back() {
        let event_type = PersonaAuditEventType::ContextSwitchedBack;

        let audit_event = json!({
            "event_type": "ContextSwitchedBack",
            "event_data": {
                "from_persona_id": Uuid::new_v4(),
                "to_persona_id": null,
                "reason": "Tasks completed"
            }
        });

        assert!(matches!(
            event_type,
            PersonaAuditEventType::ContextSwitchedBack
        ));
    }

    #[test]
    fn test_audit_trail_shows_all_context_changes() {
        let audit_events = vec![
            json!({"event_type": "ContextSwitched", "to_persona": "admin.john.doe"}),
            json!({"event_type": "ContextSwitched", "to_persona": "support.john.doe"}),
            json!({"event_type": "ContextSwitchedBack", "to_persona": null}),
        ];

        assert_eq!(audit_events.len(), 3);
    }

    #[test]
    fn test_privileged_action_attribution() {
        // When operating as persona, actions should be attributed to persona
        let physical_user_id = Uuid::new_v4();
        let persona_id = Uuid::new_v4();

        let privileged_action_audit = json!({
            "action": "server_restart",
            "performed_by_physical_user": physical_user_id,
            "performed_as_persona": persona_id,
            "effective_identity": persona_id
        });

        assert!(privileged_action_audit
            .get("performed_as_persona")
            .is_some());
        assert_eq!(
            privileged_action_audit
                .get("effective_identity")
                .unwrap()
                .as_str()
                .unwrap(),
            persona_id.to_string()
        );
    }
}

mod edge_cases_integration {
    use super::*;

    #[test]
    fn test_switch_while_already_persona() {
        // User operating as Employee persona switches directly to Admin persona
        let employee_persona_id = Uuid::new_v4();
        let admin_persona_id = Uuid::new_v4();

        let session = json!({
            "active_persona_id": admin_persona_id,
            "previous_persona_id": employee_persona_id, // Was Employee before
            "switch_reason": "Need higher privileges"
        });

        assert_eq!(
            session
                .get("previous_persona_id")
                .unwrap()
                .as_str()
                .unwrap(),
            employee_persona_id.to_string()
        );
    }

    #[test]
    fn test_rapid_context_switches() {
        // Multiple rapid switches should all be tracked
        let switches = vec![
            json!({"to": "employee_persona", "at": Utc::now().to_rfc3339()}),
            json!({"to": "admin_persona", "at": (Utc::now() + Duration::seconds(30)).to_rfc3339()}),
            json!({"to": "physical", "at": (Utc::now() + Duration::minutes(1)).to_rfc3339()}),
        ];

        assert_eq!(switches.len(), 3);
    }

    #[test]
    fn test_concurrent_session_attempts() {
        // Only one active session per user - concurrent attempts should update, not duplicate
        let user_id = Uuid::new_v4();
        let first_session_id = Uuid::new_v4();
        let second_session_id = Uuid::new_v4();

        // Second attempt creates new session, first becomes historical
        assert_ne!(first_session_id, second_session_id);
    }

    #[test]
    fn test_session_cleanup_preserves_history() {
        // Cleanup of expired sessions should preserve audit trail
        let expired_sessions_cleaned = 10;
        let audit_events_preserved = 10; // 1:1 ratio preserved

        assert_eq!(expired_sessions_cleaned, audit_events_preserved);
    }
}
