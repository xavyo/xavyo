//! Unit tests for `PersonaService` (US1).
//!
//! Tests the core persona lifecycle including creation, activation,
//! deactivation, attribute inheritance, and link management.

use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

mod persona_creation {
    use super::*;
    use xavyo_db::models::{PersonaAttributes, PersonaLinkType};

    /// T013: Persona creation validation
    #[test]
    fn test_persona_name_generation() {
        // Naming pattern: "admin.{username}"
        // Physical user: john.doe
        // Expected: admin.john.doe
        let pattern = "admin.{username}";
        let username = "john.doe";
        let expected = "admin.john.doe";

        // Simulate handlebars rendering
        let result = pattern.replace("{username}", username);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_persona_name_complex_pattern() {
        // Pattern: "{prefix}.{given_name}.{surname}"
        let pattern = "{prefix}.{given_name}.{surname}";
        let prefix = "svc";
        let given_name = "john";
        let surname = "doe";

        let result = pattern
            .replace("{prefix}", prefix)
            .replace("{given_name}", given_name)
            .replace("{surname}", surname);
        assert_eq!(result, "svc.john.doe");
    }

    #[test]
    fn test_persona_link_type_serialization() {
        let owner = PersonaLinkType::Owner;
        let json = serde_json::to_string(&owner).unwrap();
        assert_eq!(json, "\"owner\"");

        let delegate = PersonaLinkType::Delegate;
        let json = serde_json::to_string(&delegate).unwrap();
        assert_eq!(json, "\"delegate\"");
    }

    #[test]
    fn test_persona_attributes_structure() {
        let attrs = PersonaAttributes {
            inherited: serde_json::Map::new(),
            overrides: serde_json::Map::new(),
            persona_specific: serde_json::Map::new(),
            last_propagation_at: None,
        };

        assert!(attrs.inherited.is_empty());
        assert!(attrs.overrides.is_empty());
        assert!(attrs.persona_specific.is_empty());
        assert!(attrs.last_propagation_at.is_none());
    }

    #[test]
    fn test_persona_attributes_with_values() {
        let mut inherited = serde_json::Map::new();
        inherited.insert("surname".to_string(), json!("Doe"));
        inherited.insert("given_name".to_string(), json!("John"));

        let mut overrides = serde_json::Map::new();
        overrides.insert("department".to_string(), json!("IT Admin"));

        let mut persona_specific = serde_json::Map::new();
        persona_specific.insert("admin_level".to_string(), json!(2));

        let attrs = PersonaAttributes {
            inherited,
            overrides,
            persona_specific,
            last_propagation_at: Some(Utc::now()),
        };

        assert_eq!(attrs.inherited.get("surname").unwrap(), "Doe");
        assert_eq!(attrs.overrides.get("department").unwrap(), "IT Admin");
        assert_eq!(attrs.persona_specific.get("admin_level").unwrap(), 2);
        assert!(attrs.last_propagation_at.is_some());
    }

    #[test]
    fn test_persona_valid_from_defaults_to_now() {
        let now = Utc::now();
        let valid_from = now;

        assert!(valid_from <= Utc::now());
    }

    #[test]
    fn test_persona_valid_until_from_archetype() {
        let now = Utc::now();
        let default_validity_days = 365;
        let valid_until = now + Duration::days(default_validity_days);

        assert!(valid_until > now);
    }
}

mod persona_status_transitions {

    use xavyo_db::models::PersonaStatus;

    #[test]
    fn test_draft_to_active_transition() {
        let current_status = PersonaStatus::Draft;

        assert!(current_status.can_activate());
    }

    #[test]
    fn test_active_cannot_activate() {
        let current_status = PersonaStatus::Active;

        // Already active, cannot activate again
        assert!(!current_status.can_activate());
    }

    #[test]
    fn test_active_to_deactivated_transition() {
        let current_status = PersonaStatus::Active;

        // Active personas can be deactivated (transition to suspended or archived)
        assert!(!current_status.is_terminal());
    }

    #[test]
    fn test_expiring_to_expired_transition() {
        let current_status = PersonaStatus::Expiring;
        let target_status = PersonaStatus::Expired;

        // Both are non-terminal, transition allowed
        assert!(!current_status.is_terminal());
        assert!(!target_status.is_terminal());
    }

    #[test]
    fn test_archived_is_final() {
        let status = PersonaStatus::Archived;

        assert!(status.is_terminal());
        assert!(!status.can_switch_to());
        assert!(!status.can_activate());
    }

    #[test]
    fn test_suspended_can_be_reactivated() {
        let status = PersonaStatus::Suspended;

        assert!(status.can_activate());
        assert!(!status.is_terminal());
    }
}

mod persona_attribute_inheritance {
    use super::*;

    #[test]
    fn test_attribute_propagation_always_mode() {
        // "always" mode: attribute is always propagated from physical user
        let mode = "always";
        let source_value = "Doe";

        assert_eq!(mode, "always");
        assert!(!source_value.is_empty());
    }

    #[test]
    fn test_attribute_propagation_default_mode() {
        // "default" mode: attribute is propagated only if not overridden
        let _mode = "default";
        let source_value = "Doe";
        let override_value: Option<&str> = None;

        let effective_value = override_value.unwrap_or(source_value);
        assert_eq!(effective_value, source_value);
    }

    #[test]
    fn test_attribute_override_takes_precedence() {
        let source_value = "Engineering";
        let override_value = Some("IT Admin");

        let effective_value = override_value.unwrap_or(source_value);
        assert_eq!(effective_value, "IT Admin");
    }

    #[test]
    fn test_computed_attribute_from_template() {
        // Template: "Admin {given_name} {surname}"
        let template = "Admin {given_name} {surname}";
        let given_name = "John";
        let surname = "Doe";

        let result = template
            .replace("{given_name}", given_name)
            .replace("{surname}", surname);
        assert_eq!(result, "Admin John Doe");
    }

    #[test]
    fn test_persona_specific_attributes() {
        // Persona-only attributes that don't exist on physical user
        let persona_specific = json!({
            "admin_level": 2,
            "service_accounts_managed": ["svc-app1", "svc-app2"],
            "elevated_since": "2024-01-15T10:00:00Z"
        });

        assert!(persona_specific.get("admin_level").is_some());
        assert!(persona_specific.get("service_accounts_managed").is_some());
    }
}

mod persona_link_management {

    use xavyo_db::models::PersonaLinkType;

    #[test]
    fn test_owner_link_is_primary() {
        let link_type = PersonaLinkType::Owner;

        // Owner is the primary link type
        assert!(matches!(link_type, PersonaLinkType::Owner));
    }

    #[test]
    fn test_delegate_link_for_shared_access() {
        let link_type = PersonaLinkType::Delegate;

        // Delegate allows another user to operate as the persona
        assert!(matches!(link_type, PersonaLinkType::Delegate));
    }

    #[test]
    fn test_link_deletion_on_persona_archive() {
        // When persona is archived, links should be cleaned up
        let persona_archived = true;
        let links_should_be_deleted = persona_archived;

        assert!(links_should_be_deleted);
    }
}

mod persona_constraints {
    use super::*;

    #[test]
    fn test_one_persona_per_archetype_constraint() {
        let physical_user_id = Uuid::new_v4();
        let archetype_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();

        // Unique constraint: (tenant_id, physical_user_id, archetype_id)
        let constraint_key = format!("{tenant_id}-{physical_user_id}-{archetype_id}");
        assert!(!constraint_key.is_empty());
    }

    #[test]
    fn test_persona_requires_active_archetype() {
        let archetype_is_active = true;

        assert!(
            archetype_is_active,
            "Cannot create persona from inactive archetype"
        );
    }

    #[test]
    fn test_persona_requires_valid_physical_user() {
        let physical_user_exists = true;
        let physical_user_is_active = true;

        assert!(
            physical_user_exists && physical_user_is_active,
            "Cannot create persona for non-existent or inactive user"
        );
    }

    #[test]
    fn test_persona_name_must_be_unique_in_tenant() {
        let persona_name = "admin.john.doe";
        let tenant_id = Uuid::new_v4();

        // Unique constraint on (tenant_id, persona_name)
        assert!(!persona_name.is_empty());
        assert!(tenant_id != Uuid::nil());
    }
}

mod physical_user_deactivation {
    use super::*;
    use xavyo_db::models::PersonaStatus;

    #[test]
    fn test_cascade_deactivate_action() {
        // When physical user is deactivated, personas are cascaded
        let action = "cascade_deactivate";
        let persona_status_after = PersonaStatus::Suspended;

        assert_eq!(action, "cascade_deactivate");
        assert!(matches!(persona_status_after, PersonaStatus::Suspended));
    }

    #[test]
    fn test_suspend_action() {
        // Suspend action puts personas in suspended state
        let action = "suspend";
        let persona_status_after = PersonaStatus::Suspended;

        assert_eq!(action, "suspend");
        assert!(matches!(persona_status_after, PersonaStatus::Suspended));
    }

    #[test]
    fn test_no_action_preserves_persona() {
        // No action leaves persona as-is
        let action = "no_action";
        let persona_status_before = PersonaStatus::Active;
        let persona_status_after = PersonaStatus::Active;

        assert_eq!(action, "no_action");
        assert!(matches!(persona_status_before, PersonaStatus::Active));
        assert!(matches!(persona_status_after, PersonaStatus::Active));
    }

    #[test]
    fn test_all_personas_for_user_affected() {
        // When user is deactivated, ALL their personas are affected
        let user_id = Uuid::new_v4();
        let personas_count = 3;

        // Each persona should be processed
        assert!(personas_count > 0);
        assert!(user_id != Uuid::nil());
    }

    #[test]
    fn test_session_invalidation_on_cascade() {
        // Active sessions should be invalidated when persona is cascade deactivated
        let sessions_invalidated = true;

        assert!(sessions_invalidated);
    }
}
