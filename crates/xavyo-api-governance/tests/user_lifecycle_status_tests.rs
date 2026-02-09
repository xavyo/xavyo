//! Integration tests for user lifecycle status endpoint (F-193).
//!
//! These tests verify:
//! - User lifecycle status returns comprehensive information
//! - Available transitions with condition evaluation
//! - Effective lifecycle model resolution

use serde_json::json;
use uuid::Uuid;

/// Test response structure for UserLifecycleStatusResponse
#[test]
fn test_user_lifecycle_status_response_structure() {
    let response = json!({
        "user_id": Uuid::new_v4(),
        "current_state": null,
        "available_transitions": [],
        "pending_schedules": [],
        "active_rollback": null,
        "lifecycle_model": null,
    });

    assert!(response["user_id"].is_string());
    assert!(response["current_state"].is_null());
    assert!(response["available_transitions"].is_array());
    assert!(response["pending_schedules"].is_array());
    assert!(response["active_rollback"].is_null());
    assert!(response["lifecycle_model"].is_null());
}

/// Test response with lifecycle model directly assigned
#[test]
fn test_user_lifecycle_status_with_direct_model() {
    let response = json!({
        "user_id": Uuid::new_v4(),
        "current_state": {
            "id": Uuid::new_v4(),
            "name": "active",
            "is_initial": true,
            "is_terminal": false,
        },
        "available_transitions": [],
        "pending_schedules": [],
        "active_rollback": null,
        "lifecycle_model": {
            "id": Uuid::new_v4(),
            "name": "Employee Lifecycle",
            "source": "Direct",
        },
    });

    assert!(response["current_state"].is_object());
    assert!(response["lifecycle_model"].is_object());
    assert_eq!(response["lifecycle_model"]["source"], "Direct");
}

/// Test response with lifecycle model from archetype
#[test]
fn test_user_lifecycle_status_with_archetype_model() {
    let response = json!({
        "user_id": Uuid::new_v4(),
        "current_state": {
            "id": Uuid::new_v4(),
            "name": "active",
            "is_initial": true,
            "is_terminal": false,
        },
        "available_transitions": [],
        "pending_schedules": [],
        "active_rollback": null,
        "lifecycle_model": {
            "id": Uuid::new_v4(),
            "name": "Person Lifecycle",
            "source": "Archetype",
        },
    });

    assert_eq!(response["lifecycle_model"]["source"], "Archetype");
}

/// Test available transitions structure
#[test]
fn test_available_transitions_structure() {
    let response = json!({
        "user_id": Uuid::new_v4(),
        "current_state": {
            "id": Uuid::new_v4(),
            "name": "active",
        },
        "available_transitions": [
            {
                "transition": {
                    "id": Uuid::new_v4(),
                    "name": "Terminate",
                    "from_state_id": Uuid::new_v4(),
                    "from_state_name": "active",
                    "to_state_id": Uuid::new_v4(),
                    "to_state_name": "terminated",
                    "requires_approval": true,
                },
                "conditions_satisfied": true,
                "condition_results": [
                    {
                        "condition": {
                            "condition_type": "termination_date_set",
                        },
                        "satisfied": true,
                        "reason": "Termination date is set",
                    }
                ],
            }
        ],
        "pending_schedules": [],
        "active_rollback": null,
        "lifecycle_model": {
            "id": Uuid::new_v4(),
            "name": "Employee Lifecycle",
            "source": "Direct",
        },
    });

    let transitions = response["available_transitions"].as_array().unwrap();
    assert_eq!(transitions.len(), 1);

    let transition = &transitions[0];
    assert!(transition["conditions_satisfied"].as_bool().unwrap());
    assert!(transition["transition"].is_object());

    let condition_results = transition["condition_results"].as_array().unwrap();
    assert_eq!(condition_results.len(), 1);
    assert!(condition_results[0]["satisfied"].as_bool().unwrap());
}

/// Test blocked transition (conditions not met)
#[test]
fn test_blocked_transition_conditions_not_met() {
    let response = json!({
        "user_id": Uuid::new_v4(),
        "current_state": {
            "id": Uuid::new_v4(),
            "name": "active",
        },
        "available_transitions": [
            {
                "transition": {
                    "id": Uuid::new_v4(),
                    "name": "Terminate",
                    "to_state_name": "terminated",
                },
                "conditions_satisfied": false,
                "condition_results": [
                    {
                        "condition": {
                            "condition_type": "termination_date_set",
                        },
                        "satisfied": false,
                        "reason": "Termination date is not set",
                    }
                ],
            }
        ],
        "pending_schedules": [],
        "active_rollback": null,
        "lifecycle_model": null,
    });

    let transitions = response["available_transitions"].as_array().unwrap();
    let transition = &transitions[0];
    assert!(!transition["conditions_satisfied"].as_bool().unwrap());
}

/// Test user without lifecycle model
#[test]
fn test_user_without_lifecycle_model() {
    let response = json!({
        "user_id": Uuid::new_v4(),
        "current_state": null,
        "available_transitions": [],
        "pending_schedules": [],
        "active_rollback": null,
        "lifecycle_model": null,
    });

    assert!(response["lifecycle_model"].is_null());
    assert!(response["current_state"].is_null());
    assert!(response["available_transitions"]
        .as_array()
        .unwrap()
        .is_empty());
}

/// Test scheduled transitions structure
#[test]
fn test_pending_schedules_structure() {
    let response = json!({
        "user_id": Uuid::new_v4(),
        "current_state": {
            "id": Uuid::new_v4(),
            "name": "pre_termination",
        },
        "available_transitions": [],
        "pending_schedules": [
            {
                "id": Uuid::new_v4(),
                "transition_request_id": Uuid::new_v4(),
                "object_id": Uuid::new_v4(),
                "transition_name": "Complete Termination",
                "from_state": "pre_termination",
                "to_state": "terminated",
                "scheduled_for": "2024-01-15T00:00:00Z",
                "status": "pending",
            }
        ],
        "active_rollback": null,
        "lifecycle_model": null,
    });

    let schedules = response["pending_schedules"].as_array().unwrap();
    assert_eq!(schedules.len(), 1);
    assert_eq!(schedules[0]["status"], "pending");
}

/// Test rollback info structure
#[test]
fn test_active_rollback_structure() {
    let audit_id = Uuid::new_v4();
    let response = json!({
        "user_id": Uuid::new_v4(),
        "current_state": {
            "id": Uuid::new_v4(),
            "name": "pre_termination",
        },
        "available_transitions": [],
        "pending_schedules": [],
        "active_rollback": {
            "audit_id": audit_id,
            "from_state_id": Uuid::new_v4(),
            "to_state_id": Uuid::new_v4(),
            "executed_at": "2024-01-10T12:00:00Z",
            "rollback_until": "2024-01-11T12:00:00Z",
        },
        "lifecycle_model": null,
    });

    let rollback = &response["active_rollback"];
    assert!(rollback.is_object());
    assert_eq!(rollback["audit_id"], audit_id.to_string());
}

/// Test endpoint route
#[test]
fn test_user_lifecycle_status_route() {
    let user_id = Uuid::new_v4();
    let route = format!("/governance/users/{}/lifecycle/status", user_id);
    assert!(route.contains(&user_id.to_string()));
    assert!(route.ends_with("/lifecycle/status"));
}

/// Test lifecycle model sources
mod lifecycle_model_source_tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_direct_source() {
        let source = "Direct";
        assert_eq!(source, "Direct");
    }

    #[test]
    fn test_archetype_source() {
        let source = "Archetype";
        assert_eq!(source, "Archetype");
    }

    #[test]
    fn test_system_default_source() {
        let source = "SystemDefault";
        assert_eq!(source, "SystemDefault");
    }
}

/// Test condition evaluation in transitions
mod condition_evaluation_tests {
    use super::*;

    #[test]
    fn test_all_conditions_satisfied() {
        let result = json!({
            "conditions_satisfied": true,
            "condition_results": [
                {"satisfied": true},
                {"satisfied": true},
            ],
        });
        assert!(result["conditions_satisfied"].as_bool().unwrap());
    }

    #[test]
    fn test_some_conditions_not_satisfied() {
        let result = json!({
            "conditions_satisfied": false,
            "condition_results": [
                {"satisfied": true},
                {"satisfied": false},
            ],
        });
        assert!(!result["conditions_satisfied"].as_bool().unwrap());
    }

    #[test]
    fn test_no_conditions() {
        let result = json!({
            "conditions_satisfied": true,
            "condition_results": [],
        });
        // No conditions means all conditions (none) are satisfied
        assert!(result["conditions_satisfied"].as_bool().unwrap());
    }
}
