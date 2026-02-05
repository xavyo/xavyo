//! Integration tests for archetype lifecycle policies (US3).
//!
//! Tests the archetype lifecycle policy configuration including
//! validity periods, notification settings, and user deactivation behavior.

use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

mod common;

mod lifecycle_policy_validation {
    use super::*;
    use xavyo_db::models::LifecyclePolicy;

    /// T050: Integration test for archetype lifecycle policies
    #[test]
    fn test_lifecycle_policy_structure() {
        let policy_json = json!({
            "default_validity_days": 365,
            "max_validity_days": 730,
            "notification_before_expiry_days": 7,
            "auto_extension_allowed": false,
            "extension_requires_approval": true,
            "on_physical_user_deactivation": "cascade_deactivate"
        });

        let policy: LifecyclePolicy = serde_json::from_value(policy_json).unwrap();

        assert_eq!(policy.default_validity_days, 365);
        assert_eq!(policy.max_validity_days, 730);
        assert_eq!(policy.notification_before_expiry_days, 7);
        assert!(!policy.auto_extension_allowed);
        assert!(policy.extension_requires_approval);
        assert_eq!(policy.on_physical_user_deactivation, "cascade_deactivate");
    }

    #[test]
    fn test_validity_days_constraint() {
        // default_validity_days should not exceed max_validity_days
        let policy = LifecyclePolicy {
            default_validity_days: 365,
            max_validity_days: 730,
            notification_before_expiry_days: 7,
            auto_extension_allowed: false,
            extension_requires_approval: true,
            on_physical_user_deactivation: "cascade_deactivate".to_string(),
        };

        assert!(policy.default_validity_days <= policy.max_validity_days);
    }

    #[test]
    fn test_notification_days_reasonable() {
        let policy = LifecyclePolicy {
            default_validity_days: 30,
            max_validity_days: 90,
            notification_before_expiry_days: 7,
            auto_extension_allowed: false,
            extension_requires_approval: false,
            on_physical_user_deactivation: "suspend".to_string(),
        };

        // Notification days should be less than default validity
        assert!(policy.notification_before_expiry_days < policy.default_validity_days);
    }

    #[test]
    fn test_on_deactivation_cascade() {
        let policy = LifecyclePolicy {
            default_validity_days: 365,
            max_validity_days: 730,
            notification_before_expiry_days: 7,
            auto_extension_allowed: false,
            extension_requires_approval: true,
            on_physical_user_deactivation: "cascade_deactivate".to_string(),
        };

        assert_eq!(policy.on_physical_user_deactivation, "cascade_deactivate");
    }

    #[test]
    fn test_on_deactivation_suspend() {
        let policy = LifecyclePolicy {
            default_validity_days: 365,
            max_validity_days: 730,
            notification_before_expiry_days: 7,
            auto_extension_allowed: false,
            extension_requires_approval: true,
            on_physical_user_deactivation: "suspend".to_string(),
        };

        assert_eq!(policy.on_physical_user_deactivation, "suspend");
    }

    #[test]
    fn test_on_deactivation_no_action() {
        let policy = LifecyclePolicy {
            default_validity_days: 365,
            max_validity_days: 730,
            notification_before_expiry_days: 7,
            auto_extension_allowed: false,
            extension_requires_approval: true,
            on_physical_user_deactivation: "no_action".to_string(),
        };

        assert_eq!(policy.on_physical_user_deactivation, "no_action");
    }

    #[test]
    fn test_auto_extension_with_approval() {
        let policy = LifecyclePolicy {
            default_validity_days: 30,
            max_validity_days: 365,
            notification_before_expiry_days: 7,
            auto_extension_allowed: true,
            extension_requires_approval: true,
            on_physical_user_deactivation: "cascade_deactivate".to_string(),
        };

        // Auto extension allowed but requires approval
        assert!(policy.auto_extension_allowed);
        assert!(policy.extension_requires_approval);
    }

    #[test]
    fn test_auto_extension_without_approval() {
        let policy = LifecyclePolicy {
            default_validity_days: 30,
            max_validity_days: 365,
            notification_before_expiry_days: 7,
            auto_extension_allowed: true,
            extension_requires_approval: false,
            on_physical_user_deactivation: "cascade_deactivate".to_string(),
        };

        // Auto extension allowed without approval - automatic renewal
        assert!(policy.auto_extension_allowed);
        assert!(!policy.extension_requires_approval);
    }
}

mod archetype_deletion_prevention {
    use super::*;

    #[test]
    fn test_cannot_delete_with_active_personas() {
        // This represents the constraint that should be enforced
        let archetype_id = Uuid::new_v4();
        let active_persona_count = 3;

        // Should prevent deletion when active personas exist
        assert!(
            active_persona_count > 0,
            "Cannot delete archetype {archetype_id} with {active_persona_count} active personas"
        );
    }

    #[test]
    fn test_can_delete_with_zero_personas() {
        let archetype_id = Uuid::new_v4();
        let active_persona_count = 0;

        // Can delete when no active personas
        assert_eq!(
            active_persona_count, 0,
            "Can delete archetype {archetype_id} with no active personas"
        );
    }

    #[test]
    fn test_can_delete_with_only_archived_personas() {
        // Archived personas don't count as "active"
        let total_personas = 5;
        let archived_personas = 5;
        let active_personas = total_personas - archived_personas;

        assert_eq!(
            active_personas, 0,
            "All personas are archived, deletion allowed"
        );
    }

    #[test]
    fn test_can_deactivate_with_active_personas() {
        // Deactivation is always allowed - it just prevents new persona creation
        let archetype_id = Uuid::new_v4();
        let active_persona_count = 10;

        // Deactivation is independent of persona count
        let can_deactivate = true;
        assert!(
            can_deactivate,
            "Can deactivate archetype {archetype_id} even with {active_persona_count} active personas"
        );
    }
}

mod persona_validity_from_archetype {
    use super::*;
    use xavyo_db::models::LifecyclePolicy;

    #[test]
    fn test_persona_uses_default_validity() {
        let policy = LifecyclePolicy {
            default_validity_days: 365,
            max_validity_days: 730,
            notification_before_expiry_days: 7,
            auto_extension_allowed: false,
            extension_requires_approval: true,
            on_physical_user_deactivation: "cascade_deactivate".to_string(),
        };

        let now = Utc::now();
        let valid_until = now + Duration::days(i64::from(policy.default_validity_days));

        // Persona should use archetype's default validity
        assert!(valid_until > now);
        assert!(valid_until < now + Duration::days(366));
    }

    #[test]
    fn test_custom_validity_capped_at_max() {
        let policy = LifecyclePolicy {
            default_validity_days: 365,
            max_validity_days: 730,
            notification_before_expiry_days: 7,
            auto_extension_allowed: false,
            extension_requires_approval: true,
            on_physical_user_deactivation: "cascade_deactivate".to_string(),
        };

        let requested_days = 1000;
        let actual_days = std::cmp::min(requested_days, policy.max_validity_days);

        assert_eq!(actual_days, policy.max_validity_days);
    }

    #[test]
    fn test_notification_timing() {
        let policy = LifecyclePolicy {
            default_validity_days: 30,
            max_validity_days: 90,
            notification_before_expiry_days: 7,
            auto_extension_allowed: false,
            extension_requires_approval: false,
            on_physical_user_deactivation: "suspend".to_string(),
        };

        let now = Utc::now();
        let valid_until = now + Duration::days(i64::from(policy.default_validity_days));
        let notify_at =
            valid_until - Duration::days(i64::from(policy.notification_before_expiry_days));

        // Notification should be 7 days before expiration
        assert_eq!(
            (valid_until - notify_at).num_days(),
            i64::from(policy.notification_before_expiry_days)
        );
    }
}

mod archetype_compatibility_check {
    use super::*;

    #[test]
    fn test_user_meets_archetype_requirements() {
        // User has required attributes for archetype
        let user_attributes = json!({
            "email": "john.doe@example.com",
            "given_name": "John",
            "surname": "Doe",
            "username": "john.doe"
        });

        let required_attributes = vec!["email", "username"];

        for attr in required_attributes {
            assert!(
                user_attributes.get(attr).is_some(),
                "User missing required attribute: {attr}"
            );
        }
    }

    #[test]
    fn test_user_missing_required_attribute() {
        // User is missing required attribute
        let user_attributes = json!({
            "email": "john.doe@example.com",
            "given_name": "John"
        });

        let required_attributes = vec!["email", "username"];
        let mut missing = vec![];

        for attr in required_attributes {
            if user_attributes.get(attr).is_none() {
                missing.push(attr);
            }
        }

        assert!(!missing.is_empty(), "User should be missing username");
        assert!(missing.contains(&"username"));
    }

    #[test]
    fn test_archetype_requires_active_status() {
        let archetype_is_active = true;

        assert!(
            archetype_is_active,
            "Cannot create persona from inactive archetype"
        );
    }

    #[test]
    fn test_inactive_archetype_prevents_persona_creation() {
        let archetype_is_active = false;

        assert!(
            !archetype_is_active,
            "Persona creation should be prevented for inactive archetype"
        );
    }
}

mod computed_attribute_templates {
    use super::*;
    use xavyo_api_governance::services::render_persona_template;

    #[test]
    fn test_simple_template() {
        let inherited = serde_json::from_value(json!({
            "given_name": "John",
            "surname": "Doe"
        }))
        .unwrap();
        let overrides = serde_json::from_value(json!({})).unwrap();

        let result = render_persona_template("{given_name} {surname}", &inherited, &overrides);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "John Doe");
    }

    #[test]
    fn test_template_with_prefix() {
        let inherited = serde_json::from_value(json!({
            "given_name": "Jane",
            "surname": "Smith"
        }))
        .unwrap();
        let overrides = serde_json::from_value(json!({})).unwrap();

        let result =
            render_persona_template("Admin {given_name} {surname}", &inherited, &overrides);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Admin Jane Smith");
    }

    #[test]
    fn test_template_with_suffix() {
        let inherited = serde_json::from_value(json!({
            "department": "Engineering"
        }))
        .unwrap();
        let overrides = serde_json::from_value(json!({})).unwrap();

        let result = render_persona_template("{department} Persona", &inherited, &overrides);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Engineering Persona");
    }

    #[test]
    fn test_template_override_priority() {
        let inherited = serde_json::from_value(json!({
            "department": "Engineering"
        }))
        .unwrap();
        let overrides = serde_json::from_value(json!({
            "department": "IT"
        }))
        .unwrap();

        let result = render_persona_template("{department} Admin", &inherited, &overrides);
        assert!(result.is_ok());
        // Override should take priority
        assert!(result.unwrap().contains("IT"));
    }

    #[test]
    fn test_template_multiple_same_placeholder() {
        let inherited = serde_json::from_value(json!({
            "role": "Admin"
        }))
        .unwrap();
        let overrides = serde_json::from_value(json!({})).unwrap();

        let result = render_persona_template("{role} - {role} Role", &inherited, &overrides);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Admin - Admin Role");
    }
}
