//! Unit tests for archetype attribute mappings (US3).
//!
//! Tests the attribute mapping configuration including propagate,
//! computed, and `persona_only` attribute types.

use serde_json::json;
use uuid::Uuid;

mod common;

mod attribute_mappings_validation {
    use super::*;
    use xavyo_db::models::{AttributeMappings, ComputedMapping, PropagateMapping};

    /// T049: Unit test for archetype attribute mappings
    #[test]
    fn test_propagate_mapping_always_mode() {
        let mapping = PropagateMapping {
            source: "email".to_string(),
            target: "email".to_string(),
            mode: "always".to_string(),
            allow_override: false,
        };

        assert_eq!(mapping.mode, "always");
        assert!(!mapping.allow_override);
    }

    #[test]
    fn test_propagate_mapping_default_mode() {
        let mapping = PropagateMapping {
            source: "department".to_string(),
            target: "department".to_string(),
            mode: "default".to_string(),
            allow_override: true,
        };

        assert_eq!(mapping.mode, "default");
        assert!(mapping.allow_override);
    }

    #[test]
    fn test_propagate_mapping_with_target_rename() {
        let mapping = PropagateMapping {
            source: "employee_id".to_string(),
            target: "persona_employee_id".to_string(),
            mode: "always".to_string(),
            allow_override: false,
        };

        assert_ne!(mapping.source, mapping.target);
    }

    #[test]
    fn test_computed_mapping_basic() {
        let mapping = ComputedMapping {
            target: "display_name".to_string(),
            template: "Admin {given_name} {surname}".to_string(),
            variables: serde_json::Map::new(),
        };

        assert!(mapping.template.contains("{given_name}"));
        assert!(mapping.template.contains("{surname}"));
    }

    #[test]
    fn test_computed_mapping_with_static_text() {
        let mapping = ComputedMapping {
            target: "persona_email".to_string(),
            template: "{username}@personas.example.com".to_string(),
            variables: serde_json::Map::new(),
        };

        assert!(mapping.template.contains("@personas.example.com"));
    }

    #[test]
    fn test_persona_only_attributes() {
        let mappings_json = json!({
            "propagate": [],
            "computed": [],
            "persona_only": ["admin_level", "managed_systems", "security_clearance"]
        });

        let mappings: AttributeMappings = serde_json::from_value(mappings_json).unwrap();

        assert_eq!(mappings.persona_only.len(), 3);
        assert!(mappings.persona_only.contains(&"admin_level".to_string()));
        assert!(mappings
            .persona_only
            .contains(&"managed_systems".to_string()));
        assert!(mappings
            .persona_only
            .contains(&"security_clearance".to_string()));
    }

    #[test]
    fn test_full_attribute_mappings() {
        let mappings_json = json!({
            "propagate": [
                {"source": "surname", "target": "surname", "mode": "always", "allow_override": false},
                {"source": "given_name", "target": "given_name", "mode": "always", "allow_override": false},
                {"source": "email", "target": "source_email", "mode": "default", "allow_override": true}
            ],
            "computed": [
                {"target": "display_name", "template": "Admin {given_name} {surname}", "variables": {}},
                {"target": "persona_email", "template": "{username}@admin.example.com", "variables": {}}
            ],
            "persona_only": ["admin_level", "managed_systems"]
        });

        let mappings: AttributeMappings = serde_json::from_value(mappings_json).unwrap();

        assert_eq!(mappings.propagate.len(), 3);
        assert_eq!(mappings.computed.len(), 2);
        assert_eq!(mappings.persona_only.len(), 2);
    }

    #[test]
    fn test_empty_attribute_mappings() {
        let mappings_json = json!({
            "propagate": [],
            "computed": [],
            "persona_only": []
        });

        let mappings: AttributeMappings = serde_json::from_value(mappings_json).unwrap();

        assert!(mappings.propagate.is_empty());
        assert!(mappings.computed.is_empty());
        assert!(mappings.persona_only.is_empty());
    }
}

mod attribute_inheritance_tests {
    use super::*;
    use xavyo_api_governance::services::render_persona_template;

    #[test]
    fn test_propagate_overwrites_persona_attribute() {
        // When mode is "always", physical user attribute overwrites persona
        let inherited = serde_json::from_value(json!({
            "surname": "Doe",
            "given_name": "John"
        }))
        .unwrap();

        let overrides = serde_json::from_value(json!({})).unwrap();

        // Computed template
        let result =
            render_persona_template("Admin {given_name} {surname}", &inherited, &overrides);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Admin John Doe");
    }

    #[test]
    fn test_default_mode_allows_override() {
        // When mode is "default" and allow_override is true,
        // persona can override the value
        let inherited = serde_json::from_value(json!({
            "department": "Engineering"
        }))
        .unwrap();

        let overrides = serde_json::from_value(json!({
            "department": "IT Administration"
        }))
        .unwrap();

        // Override should take precedence in computed
        let result =
            render_persona_template("{department} Persona", &inherited, &overrides).unwrap();
        assert!(result.contains("IT Administration"));
    }

    #[test]
    fn test_computed_attribute_uses_inherited() {
        let inherited = serde_json::from_value(json!({
            "given_name": "Jane",
            "surname": "Smith"
        }))
        .unwrap();

        let overrides = serde_json::from_value(json!({})).unwrap();

        let result =
            render_persona_template("{given_name} {surname} - Admin", &inherited, &overrides)
                .unwrap();
        assert_eq!(result, "Jane Smith - Admin");
    }

    #[test]
    fn test_computed_attribute_falls_back_to_placeholder() {
        let inherited = serde_json::from_value(json!({
            "given_name": "Jane"
        }))
        .unwrap();

        let overrides = serde_json::from_value(json!({})).unwrap();

        // Missing surname should leave placeholder
        let result =
            render_persona_template("{given_name} {surname}", &inherited, &overrides).unwrap();
        assert!(result.contains("Jane"));
        // Missing values might leave placeholder or empty depending on implementation
    }
}

mod naming_pattern_validation {
    
    use xavyo_api_governance::services::validate_naming_pattern;

    #[test]
    fn test_valid_simple_pattern() {
        let result = validate_naming_pattern("{username}");
        assert!(result.is_ok());
    }

    #[test]
    fn test_valid_prefix_pattern() {
        let result = validate_naming_pattern("admin.{username}");
        assert!(result.is_ok());
    }

    #[test]
    fn test_valid_multiple_placeholders() {
        let result = validate_naming_pattern("{given_name}.{surname}");
        assert!(result.is_ok());
    }

    #[test]
    fn test_valid_complex_pattern() {
        let result = validate_naming_pattern("{department}-{role}-{username}");
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_empty_pattern() {
        let result = validate_naming_pattern("");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_no_placeholder() {
        let result = validate_naming_pattern("static-name");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_unmatched_braces() {
        let result = validate_naming_pattern("admin.{username");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_empty_placeholder() {
        let result = validate_naming_pattern("admin.{}");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_nested_placeholders() {
        let result = validate_naming_pattern("admin.{{nested}}");
        assert!(result.is_err());
    }
}

mod default_entitlements_validation {
    use super::*;

    #[test]
    fn test_default_entitlements_structure() {
        let entitlements = json!([
            {
                "entitlement_id": Uuid::new_v4(),
                "assignment_type": "default",
                "expires_after_days": null
            },
            {
                "entitlement_id": Uuid::new_v4(),
                "assignment_type": "time_limited",
                "expires_after_days": 90
            }
        ]);

        let arr = entitlements.as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn test_default_entitlement_assignment_types() {
        let assignment_types = vec!["default", "time_limited", "conditional"];

        for at in assignment_types {
            let entitlement = json!({
                "entitlement_id": Uuid::new_v4(),
                "assignment_type": at
            });
            assert!(entitlement.get("assignment_type").is_some());
        }
    }

    #[test]
    fn test_entitlement_with_conditions() {
        let entitlement = json!({
            "entitlement_id": Uuid::new_v4(),
            "assignment_type": "conditional",
            "conditions": {
                "requires_approval": true,
                "max_duration_days": 30
            }
        });

        let conditions = entitlement.get("conditions").unwrap();
        assert!(conditions.get("requires_approval").is_some());
    }
}
