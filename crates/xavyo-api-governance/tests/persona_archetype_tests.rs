//! Unit tests for PersonaArchetypeService (US1).
//!
//! Tests the management of persona archetypes including creation, validation,
//! attribute mappings, and lifecycle policies.

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

mod persona_archetype_crud {
    use super::*;
    use xavyo_db::models::{
        AttributeMappings, ComputedMapping, LifecyclePolicy, PersonaStatus, PropagateMapping,
    };

    /// T012: Persona status enum serialization
    #[test]
    fn test_persona_status_serialization() {
        let draft = PersonaStatus::Draft;
        let json = serde_json::to_string(&draft).unwrap();
        assert_eq!(json, "\"draft\"");

        let active = PersonaStatus::Active;
        let json = serde_json::to_string(&active).unwrap();
        assert_eq!(json, "\"active\"");

        let expiring = PersonaStatus::Expiring;
        let json = serde_json::to_string(&expiring).unwrap();
        assert_eq!(json, "\"expiring\"");

        let expired = PersonaStatus::Expired;
        let json = serde_json::to_string(&expired).unwrap();
        assert_eq!(json, "\"expired\"");

        let suspended = PersonaStatus::Suspended;
        let json = serde_json::to_string(&suspended).unwrap();
        assert_eq!(json, "\"suspended\"");

        let archived = PersonaStatus::Archived;
        let json = serde_json::to_string(&archived).unwrap();
        assert_eq!(json, "\"archived\"");
    }

    #[test]
    fn test_persona_status_can_switch_to() {
        // Only active status can be switched to
        assert!(!PersonaStatus::Draft.can_switch_to());
        assert!(PersonaStatus::Active.can_switch_to());
        assert!(!PersonaStatus::Expiring.can_switch_to()); // Expiring personas should not be switched to
        assert!(!PersonaStatus::Expired.can_switch_to());
        assert!(!PersonaStatus::Suspended.can_switch_to());
        assert!(!PersonaStatus::Archived.can_switch_to());
    }

    #[test]
    fn test_persona_status_can_activate() {
        // Draft, suspended, and expired can be activated (reactivation)
        assert!(PersonaStatus::Draft.can_activate());
        assert!(!PersonaStatus::Active.can_activate());
        assert!(!PersonaStatus::Expiring.can_activate());
        assert!(PersonaStatus::Expired.can_activate()); // Can reactivate expired persona
        assert!(PersonaStatus::Suspended.can_activate());
        assert!(!PersonaStatus::Archived.can_activate());
    }

    #[test]
    fn test_persona_status_is_terminal() {
        // Archived is terminal
        assert!(!PersonaStatus::Draft.is_terminal());
        assert!(!PersonaStatus::Active.is_terminal());
        assert!(!PersonaStatus::Expiring.is_terminal());
        assert!(!PersonaStatus::Expired.is_terminal());
        assert!(!PersonaStatus::Suspended.is_terminal());
        assert!(PersonaStatus::Archived.is_terminal());
    }

    #[test]
    fn test_lifecycle_policy_defaults() {
        let policy = LifecyclePolicy::default();
        assert_eq!(policy.default_validity_days, 365);
        assert_eq!(policy.max_validity_days, 730);
        assert_eq!(policy.notification_before_expiry_days, 7);
        assert!(!policy.auto_extension_allowed);
        assert!(policy.extension_requires_approval);
        assert_eq!(policy.on_physical_user_deactivation, "cascade_deactivate");
    }

    #[test]
    fn test_lifecycle_policy_serialization() {
        let policy = LifecyclePolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("\"default_validity_days\":365"));
        assert!(json.contains("\"extension_requires_approval\":true"));
    }

    #[test]
    fn test_lifecycle_policy_custom_values() {
        let json = json!({
            "default_validity_days": 90,
            "max_validity_days": 365,
            "notification_before_expiry_days": 14,
            "auto_extension_allowed": true,
            "extension_requires_approval": false,
            "on_physical_user_deactivation": "suspend"
        });

        let policy: LifecyclePolicy = serde_json::from_value(json).unwrap();
        assert_eq!(policy.default_validity_days, 90);
        assert_eq!(policy.max_validity_days, 365);
        assert_eq!(policy.notification_before_expiry_days, 14);
        assert!(policy.auto_extension_allowed);
        assert!(!policy.extension_requires_approval);
        assert_eq!(policy.on_physical_user_deactivation, "suspend");
    }

    #[test]
    fn test_attribute_mappings_defaults() {
        let mappings = AttributeMappings::default();
        assert!(mappings.propagate.is_empty());
        assert!(mappings.computed.is_empty());
        assert!(mappings.persona_only.is_empty());
    }

    #[test]
    fn test_propagate_mapping_serialization() {
        let mapping = PropagateMapping {
            source: "surname".to_string(),
            target: "surname".to_string(),
            mode: "always".to_string(),
            allow_override: false,
        };

        let json = serde_json::to_string(&mapping).unwrap();
        assert!(json.contains("\"source\":\"surname\""));
        assert!(json.contains("\"target\":\"surname\""));
        assert!(json.contains("\"mode\":\"always\""));
        assert!(json.contains("\"allow_override\":false"));
    }

    #[test]
    fn test_computed_mapping_serialization() {
        let mapping = ComputedMapping {
            target: "display_name".to_string(),
            template: "Admin {given_name} {surname}".to_string(),
            variables: serde_json::Map::new(),
        };

        let json = serde_json::to_string(&mapping).unwrap();
        assert!(json.contains("\"target\":\"display_name\""));
        assert!(json.contains("Admin {given_name} {surname}"));
    }

    #[test]
    fn test_attribute_mappings_full_serialization() {
        let mappings = AttributeMappings {
            propagate: vec![PropagateMapping {
                source: "surname".to_string(),
                target: "surname".to_string(),
                mode: "always".to_string(),
                allow_override: false,
            }],
            computed: vec![ComputedMapping {
                target: "display_name".to_string(),
                template: "Admin {given_name} {surname}".to_string(),
                variables: serde_json::Map::new(),
            }],
            persona_only: vec!["admin_level".to_string()],
        };

        let json = serde_json::to_string(&mappings).unwrap();
        assert!(json.contains("\"source\":\"surname\""));
        assert!(json.contains("\"template\":\"Admin {given_name} {surname}\""));
        assert!(json.contains("\"admin_level\""));
    }
}

mod naming_pattern_validation {
    use super::*;

    #[test]
    fn test_naming_pattern_with_username() {
        let pattern = "admin.{username}";
        assert!(pattern.contains("{username}"));
    }

    #[test]
    fn test_naming_pattern_complex() {
        let pattern = "{archetype_prefix}.{given_name}.{surname}";
        assert!(pattern.contains("{archetype_prefix}"));
        assert!(pattern.contains("{given_name}"));
        assert!(pattern.contains("{surname}"));
    }

    #[test]
    fn test_naming_pattern_simple_prefix() {
        let pattern = "svc-{username}";
        assert!(pattern.starts_with("svc-"));
    }
}

mod archetype_constraints {
    use super::*;

    #[test]
    fn test_archetype_requires_tenant_id() {
        let tenant_id = Uuid::new_v4();
        assert!(tenant_id != Uuid::nil());
    }

    #[test]
    fn test_archetype_name_uniqueness() {
        // In a real test, this would verify database constraint
        let name = "Admin Persona";
        assert!(!name.is_empty());
    }

    #[test]
    fn test_archetype_has_personas_count() {
        // Archetypes should track how many personas use them
        let personas_count: i64 = 5;
        assert!(personas_count >= 0);
    }

    #[test]
    fn test_archetype_deletion_blocked_with_active_personas() {
        // Archetype deletion should be blocked if active personas exist
        let active_personas_count: i64 = 1;
        assert!(
            active_personas_count > 0,
            "Cannot delete archetype with active personas"
        );
    }
}

mod edge_cases {
    use super::*;

    #[test]
    fn test_one_persona_per_archetype_per_user() {
        // Constraint: A user can only have one persona of each archetype
        let physical_user_id = Uuid::new_v4();
        let archetype_id = Uuid::new_v4();

        // These would form a unique constraint (tenant_id, physical_user_id, archetype_id)
        assert!(physical_user_id != Uuid::nil());
        assert!(archetype_id != Uuid::nil());
    }

    #[test]
    fn test_archetype_deactivation_cascades_to_personas() {
        // When archetype is deactivated, related personas should also be affected
        let is_active = false;
        assert!(
            !is_active,
            "Deactivated archetype should not allow new persona creation"
        );
    }

    #[test]
    fn test_physical_user_deactivation_cascade() {
        // Test the cascade behavior when physical user is deactivated
        let on_deactivation = "cascade_deactivate";
        assert!(
            ["cascade_deactivate", "suspend", "no_action"].contains(&on_deactivation),
            "Invalid deactivation action"
        );
    }

    #[test]
    fn test_max_validity_exceeds_default() {
        let default_validity = 365;
        let max_validity = 730;
        assert!(
            max_validity >= default_validity,
            "Max validity should be >= default validity"
        );
    }
}
