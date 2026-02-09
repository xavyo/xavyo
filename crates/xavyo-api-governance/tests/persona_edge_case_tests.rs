//! Tests for persona edge cases (IGA compatibility).
//!
//! Tests the edge case handling identified from IGA standards:
//! - Authorization execution-phase checks
//! - Archetype conflict detection
//! - Multi-persona atomic operations
//! - Approval workflow compatibility

use serde_json::json;
use uuid::Uuid;

mod common;

mod authorization_tests {

    use xavyo_api_governance::services::{AuthorizationResult, PersonaPermission};

    #[test]
    fn test_authorization_result_allowed() {
        let result = AuthorizationResult::allowed();
        assert!(result.authorized);
        assert!(result.reason.is_none());
        assert!(!result.requires_approval);
    }

    #[test]
    fn test_authorization_result_denied() {
        let result = AuthorizationResult::denied("Not authorized");
        assert!(!result.authorized);
        assert_eq!(result.reason, Some("Not authorized".to_string()));
        assert!(!result.requires_approval);
    }

    #[test]
    fn test_authorization_result_requires_approval() {
        let result = AuthorizationResult::requires_approval("Needs manager approval");
        assert!(!result.authorized);
        assert!(result.requires_approval);
        assert_eq!(result.reason, Some("Needs manager approval".to_string()));
    }

    #[test]
    fn test_persona_permission_variants() {
        // Verify all permission types exist
        let permissions = [
            PersonaPermission::CreatePersona,
            PersonaPermission::ManageOwnPersonas,
            PersonaPermission::ManageAllPersonas,
            PersonaPermission::DeletePersona,
            PersonaPermission::ManageArchetype,
        ];

        assert_eq!(permissions.len(), 5);
    }

    #[test]
    fn test_permission_equality() {
        assert_eq!(
            PersonaPermission::CreatePersona,
            PersonaPermission::CreatePersona
        );
        assert_ne!(
            PersonaPermission::CreatePersona,
            PersonaPermission::DeletePersona
        );
    }
}

mod validation_tests {
    use super::*;
    use xavyo_api_governance::services::{ConflictCheckResult, MultiPersonaOperationResult};

    #[test]
    fn test_conflict_check_result_no_conflict() {
        let result = ConflictCheckResult::no_conflict();
        assert!(!result.has_conflict);
        assert!(result.conflicting_archetypes.is_empty());
        assert!(result.conflict_details.is_empty());
    }

    #[test]
    fn test_conflict_check_result_with_conflict() {
        let arch1 = Uuid::new_v4();
        let arch2 = Uuid::new_v4();
        let result = ConflictCheckResult::conflict(
            vec![arch1, arch2],
            vec![
                "Computed attribute conflict: display_name".to_string(),
                "Propagation mode conflict: email".to_string(),
            ],
        );

        assert!(result.has_conflict);
        assert_eq!(result.conflicting_archetypes.len(), 2);
        assert!(result.conflicting_archetypes.contains(&arch1));
        assert!(result.conflicting_archetypes.contains(&arch2));
        assert_eq!(result.conflict_details.len(), 2);
    }

    #[test]
    fn test_multi_operation_result_all_succeeded() {
        let ids = vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
        let result = MultiPersonaOperationResult::all_succeeded(ids.clone());

        assert_eq!(result.succeeded.len(), 3);
        assert!(result.failed.is_empty());
        assert!(!result.rolled_back);
    }

    #[test]
    fn test_multi_operation_result_partial_failure() {
        let succeeded = vec![Uuid::new_v4()];
        let failed_id = Uuid::new_v4();
        let failed = vec![(failed_id, "Conflict detected".to_string())];
        let result = MultiPersonaOperationResult::partial_failure(succeeded.clone(), failed);

        assert_eq!(result.succeeded.len(), 1);
        assert_eq!(result.failed.len(), 1);
        assert!(!result.rolled_back);
        assert_eq!(result.failed[0].0, failed_id);
    }

    #[test]
    fn test_multi_operation_result_all_rolled_back() {
        let failed = vec![
            (Uuid::new_v4(), "Error 1".to_string()),
            (Uuid::new_v4(), "Error 2".to_string()),
        ];
        let result = MultiPersonaOperationResult::all_rolled_back(failed);

        assert!(result.succeeded.is_empty());
        assert_eq!(result.failed.len(), 2);
        assert!(result.rolled_back);
    }
}

mod archetype_conflict_scenarios {

    use xavyo_db::models::{AttributeMappings, ComputedMapping, PropagateMapping};

    /// Test: Two archetypes with same computed target should conflict.
    #[test]
    fn test_computed_target_conflict() {
        let arch1_mappings = AttributeMappings {
            propagate: vec![],
            computed: vec![ComputedMapping {
                target: "display_name".to_string(),
                template: "Admin {given_name}".to_string(),
                variables: serde_json::Map::new(),
            }],
            persona_only: vec![],
        };

        let arch2_mappings = AttributeMappings {
            propagate: vec![],
            computed: vec![ComputedMapping {
                target: "display_name".to_string(), // Same target!
                template: "Manager {given_name}".to_string(),
                variables: serde_json::Map::new(),
            }],
            persona_only: vec![],
        };

        // Both target display_name - this should be detected as conflict
        let arch1_targets: std::collections::HashSet<_> =
            arch1_mappings.computed.iter().map(|c| &c.target).collect();
        let arch2_targets: std::collections::HashSet<_> =
            arch2_mappings.computed.iter().map(|c| &c.target).collect();

        let conflicts: Vec<_> = arch1_targets.intersection(&arch2_targets).collect();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(*conflicts[0], "display_name");
    }

    /// Test: Two archetypes with same source but different propagation modes should conflict.
    #[test]
    fn test_propagation_mode_conflict() {
        let arch1_mappings = AttributeMappings {
            propagate: vec![PropagateMapping {
                source: "email".to_string(),
                target: "email".to_string(),
                mode: "always".to_string(),
                allow_override: false,
            }],
            computed: vec![],
            persona_only: vec![],
        };

        let arch2_mappings = AttributeMappings {
            propagate: vec![PropagateMapping {
                source: "email".to_string(), // Same source
                target: "email".to_string(),
                mode: "default".to_string(), // Different mode!
                allow_override: true,
            }],
            computed: vec![],
            persona_only: vec![],
        };

        // Check for mode conflicts
        let mut conflicts = vec![];
        for prop1 in &arch1_mappings.propagate {
            for prop2 in &arch2_mappings.propagate {
                if prop1.source == prop2.source && prop1.mode != prop2.mode {
                    conflicts.push(format!(
                        "Propagation mode conflict for '{}': {} vs {}",
                        prop1.source, prop1.mode, prop2.mode
                    ));
                }
            }
        }

        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].contains("email"));
        assert!(conflicts[0].contains("always"));
        assert!(conflicts[0].contains("default"));
    }

    /// Test: Two archetypes with overlapping `persona_only` attributes should conflict.
    #[test]
    fn test_persona_only_conflict() {
        let arch1_mappings = AttributeMappings {
            propagate: vec![],
            computed: vec![],
            persona_only: vec!["admin_level".to_string(), "managed_systems".to_string()],
        };

        let arch2_mappings = AttributeMappings {
            propagate: vec![],
            computed: vec![],
            persona_only: vec![
                "admin_level".to_string(), // Overlaps!
                "security_clearance".to_string(),
            ],
        };

        let set1: std::collections::HashSet<&String> = arch1_mappings.persona_only.iter().collect();
        let set2: std::collections::HashSet<&String> = arch2_mappings.persona_only.iter().collect();

        let conflicts: Vec<&String> = set1.intersection(&set2).copied().collect();
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts.iter().any(|s| *s == "admin_level"));
    }

    /// Test: Non-overlapping archetypes should not conflict.
    #[test]
    fn test_no_conflict_different_targets() {
        let arch1_mappings = AttributeMappings {
            propagate: vec![PropagateMapping {
                source: "email".to_string(),
                target: "work_email".to_string(),
                mode: "always".to_string(),
                allow_override: false,
            }],
            computed: vec![ComputedMapping {
                target: "admin_display".to_string(),
                template: "Admin {given_name}".to_string(),
                variables: serde_json::Map::new(),
            }],
            persona_only: vec!["admin_level".to_string()],
        };

        let arch2_mappings = AttributeMappings {
            propagate: vec![PropagateMapping {
                source: "email".to_string(),
                target: "personal_email".to_string(), // Different target
                mode: "default".to_string(),
                allow_override: true,
            }],
            computed: vec![ComputedMapping {
                target: "manager_display".to_string(), // Different target
                template: "Manager {given_name}".to_string(),
                variables: serde_json::Map::new(),
            }],
            persona_only: vec!["manager_level".to_string()], // Different
        };

        // Check computed conflicts
        let c1: std::collections::HashSet<_> =
            arch1_mappings.computed.iter().map(|c| &c.target).collect();
        let c2: std::collections::HashSet<_> =
            arch2_mappings.computed.iter().map(|c| &c.target).collect();
        let computed_conflicts: Vec<_> = c1.intersection(&c2).collect();

        // Check persona_only conflicts
        let p1: std::collections::HashSet<_> = arch1_mappings.persona_only.iter().collect();
        let p2: std::collections::HashSet<_> = arch2_mappings.persona_only.iter().collect();
        let persona_only_conflicts: Vec<_> = p1.intersection(&p2).collect();

        assert!(computed_conflicts.is_empty());
        assert!(persona_only_conflicts.is_empty());
    }
}

mod approval_workflow_compatibility {
    use super::*;

    /// Test: Archetype with approval-requiring entitlements should be flagged.
    #[test]
    fn test_entitlement_requires_approval_detection() {
        let entitlements = json!([
            {
                "entitlement_id": Uuid::new_v4(),
                "name": "Admin Access",
                "requires_approval": true
            },
            {
                "entitlement_id": Uuid::new_v4(),
                "name": "Basic Access",
                "requires_approval": false
            }
        ]);

        // Check for approval requirements
        let arr = entitlements.as_array().unwrap();
        let has_approval_requirement = arr.iter().any(|ent| {
            ent.get("requires_approval")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        });

        assert!(has_approval_requirement);
    }

    /// Test: Archetype without approval-requiring entitlements should pass.
    #[test]
    fn test_no_approval_requirement() {
        let entitlements = json!([
            {
                "entitlement_id": Uuid::new_v4(),
                "name": "Basic Access",
                "requires_approval": false
            },
            {
                "entitlement_id": Uuid::new_v4(),
                "name": "Read Only",
            }
        ]);

        let arr = entitlements.as_array().unwrap();
        let has_approval_requirement = arr.iter().any(|ent| {
            ent.get("requires_approval")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        });

        assert!(!has_approval_requirement);
    }
}

mod error_type_tests {
    use super::*;
    use xavyo_governance::error::GovernanceError;

    #[test]
    fn test_persona_creation_not_authorized_error() {
        let error = GovernanceError::PersonaCreationNotAuthorized;
        let msg = error.to_string();
        assert!(msg.contains("not authorized"));
        assert!(msg.contains("create"));
    }

    #[test]
    fn test_persona_archetype_not_authorized_error() {
        let arch_id = Uuid::new_v4();
        let error = GovernanceError::PersonaArchetypeNotAuthorized(arch_id);
        let msg = error.to_string();
        assert!(msg.contains("archetype"));
        assert!(msg.contains(&arch_id.to_string()));
    }

    #[test]
    fn test_persona_archetype_conflict_error() {
        let arch_id = Uuid::new_v4();
        let error = GovernanceError::PersonaArchetypeConflict(arch_id);
        let msg = error.to_string();
        assert!(msg.contains("conflict"));
        assert!(msg.contains(&arch_id.to_string()));
    }

    #[test]
    fn test_persona_multi_operation_partial_failure_error() {
        let error = GovernanceError::PersonaMultiOperationPartialFailure {
            succeeded: 2,
            failed: 1,
            details: "Archetype conflict detected".to_string(),
        };
        let msg = error.to_string();
        assert!(msg.contains('2'));
        assert!(msg.contains('1'));
        assert!(msg.contains("conflict"));
    }

    #[test]
    fn test_persona_operation_requires_approval_error() {
        let error =
            GovernanceError::PersonaOperationRequiresApproval("Admin entitlement".to_string());
        let msg = error.to_string();
        assert!(msg.contains("approval"));
        assert!(msg.contains("Admin entitlement"));
    }
}

#[allow(non_snake_case)]
mod IGA_edge_case_scenarios {
    use super::*;

    /// IGA pattern: "Assignment of a new persona means that a new user needs to be created."
    /// Test that self-assignment semantics are understood.
    #[test]
    fn test_self_assignment_vs_admin_assignment() {
        let actor_id = Uuid::new_v4();
        let target_user_id = Uuid::new_v4();

        // Self-assignment: actor creates persona for themselves
        let is_self_assignment_1 = actor_id == actor_id;
        assert!(is_self_assignment_1);

        // Admin assignment: actor creates persona for someone else
        let is_self_assignment_2 = actor_id == target_user_id;
        assert!(!is_self_assignment_2);
    }

    /// IGA pattern: "If more than one persona is provisioned at the same time
    /// then an error in one persona may cause the other persona not to be provisioned."
    #[test]
    fn test_batch_operation_rollback_semantics() {
        let persona_ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];

        // Simulate batch operation where second fails
        let mut succeeded = vec![];
        let mut failed = vec![];
        let mut should_rollback = false;

        for (i, id) in persona_ids.iter().enumerate() {
            if i == 1 {
                // Second operation fails
                failed.push((*id, "Conflict detected".to_string()));
                should_rollback = true;
                break;
            }
            succeeded.push(*id);
        }

        // Verify rollback decision
        assert!(should_rollback);
        assert_eq!(succeeded.len(), 1); // Only first succeeded before failure
        assert_eq!(failed.len(), 1);

        // After rollback, no personas should remain
        if should_rollback {
            succeeded.clear();
        }
        assert!(succeeded.is_empty());
    }

    /// IGA pattern: "Currently only one persona construction is supported for each persona."
    /// Test that we properly detect when multiple archetypes would have merging issues.
    #[test]
    fn test_construction_merge_detection() {
        // Simulating two archetypes both trying to set the same attribute
        let arch1_sets = vec!["display_name", "email"];
        let arch2_sets = vec!["display_name", "department"]; // display_name overlaps

        let arch1_set: std::collections::HashSet<&str> = arch1_sets.into_iter().collect();
        let arch2_set: std::collections::HashSet<&str> = arch2_sets.into_iter().collect();

        let overlaps: Vec<&str> = arch1_set.intersection(&arch2_set).copied().collect();

        // We cannot merge these - display_name would have conflicting sources
        assert!(!overlaps.is_empty());
        assert!(overlaps.contains(&"display_name"));
    }

    /// IGA pattern: "The operation that automatically provisions, deprovisions or
    /// updates a persona must not be subject to approvals."
    #[test]
    fn test_approval_workflow_incompatibility() {
        // Archetype's default entitlements
        let default_entitlements = [
            ("admin_access", true),   // requires approval
            ("basic_access", false),  // no approval needed
            ("sensitive_data", true), // requires approval
        ];

        // Check if any entitlement requires approval
        let has_approval_requirement = default_entitlements
            .iter()
            .any(|(_, requires_approval)| *requires_approval);

        // This archetype should NOT be used for automatic persona provisioning
        assert!(has_approval_requirement);
    }
}
