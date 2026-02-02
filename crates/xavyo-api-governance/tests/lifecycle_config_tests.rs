//! Integration tests for Object Lifecycle States (F052).
//!
//! These tests cover lifecycle configuration, states, and transitions.
//! Run with: `cargo test -p xavyo-api-governance --features integration lifecycle_config`

mod common;

#[cfg(feature = "integration")]
mod lifecycle_config_tests {
    use super::common::*;
    use xavyo_api_governance::models::{
        CreateLifecycleConfigRequest, CreateLifecycleStateRequest,
        CreateLifecycleTransitionRequest, ListLifecycleConfigsQuery, UpdateLifecycleConfigRequest,
        UpdateLifecycleStateRequest,
    };
    use xavyo_api_governance::services::LifecycleConfigService;
    use xavyo_db::{EntitlementAction, LifecycleObjectType};

    // =========================================================================
    // Lifecycle Configuration CRUD Tests
    // =========================================================================

    mod config_crud {
        use super::*;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_create_lifecycle_config() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            let request = CreateLifecycleConfigRequest {
                name: "User Lifecycle".to_string(),
                description: Some("Lifecycle configuration for user objects".to_string()),
                object_type: LifecycleObjectType::User,
            };

            let config = service
                .create_config(tenant_id, request)
                .await
                .expect("Failed to create config");

            assert_eq!(config.name, "User Lifecycle");
            assert_eq!(config.object_type, LifecycleObjectType::User);
            assert!(config.is_active);
            assert_eq!(config.state_count, 0);
            assert_eq!(config.transition_count, 0);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_create_duplicate_config_fails() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            let request = CreateLifecycleConfigRequest {
                name: "User Lifecycle".to_string(),
                description: None,
                object_type: LifecycleObjectType::User,
            };

            // First creation should succeed
            let _ = service
                .create_config(tenant_id, request.clone())
                .await
                .expect("Failed to create first config");

            // Second creation with same object type should fail
            let result = service.create_config(tenant_id, request).await;
            assert!(result.is_err(), "Expected error for duplicate config");

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_list_lifecycle_configs() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            // Create multiple configs
            for obj_type in [
                LifecycleObjectType::User,
                LifecycleObjectType::Role,
                LifecycleObjectType::Entitlement,
            ] {
                let request = CreateLifecycleConfigRequest {
                    name: format!("{:?} Lifecycle", obj_type),
                    description: None,
                    object_type: obj_type,
                };
                let _ = service.create_config(tenant_id, request).await.unwrap();
            }

            let params = ListLifecycleConfigsQuery {
                object_type: None,
                is_active: None,
                limit: Some(10),
                offset: None,
            };

            let response = service
                .list_configs(tenant_id, &params)
                .await
                .expect("Failed to list configs");

            assert_eq!(response.total, 3);
            assert_eq!(response.items.len(), 3);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_list_configs_with_filter() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            // Create user config
            let user_request = CreateLifecycleConfigRequest {
                name: "User Lifecycle".to_string(),
                description: None,
                object_type: LifecycleObjectType::User,
            };
            let _ = service
                .create_config(tenant_id, user_request)
                .await
                .unwrap();

            // Create role config
            let role_request = CreateLifecycleConfigRequest {
                name: "Role Lifecycle".to_string(),
                description: None,
                object_type: LifecycleObjectType::Role,
            };
            let _ = service
                .create_config(tenant_id, role_request)
                .await
                .unwrap();

            // Filter by object type
            let params = ListLifecycleConfigsQuery {
                object_type: Some(LifecycleObjectType::User),
                is_active: None,
                limit: Some(10),
                offset: None,
            };

            let response = service
                .list_configs(tenant_id, &params)
                .await
                .expect("Failed to list configs");

            assert_eq!(response.total, 1);
            assert_eq!(response.items[0].object_type, LifecycleObjectType::User);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_get_lifecycle_config() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            let request = CreateLifecycleConfigRequest {
                name: "User Lifecycle".to_string(),
                description: Some("Test description".to_string()),
                object_type: LifecycleObjectType::User,
            };

            let created = service
                .create_config(tenant_id, request)
                .await
                .expect("Failed to create config");

            let detail = service
                .get_config(tenant_id, created.id)
                .await
                .expect("Failed to get config");

            assert_eq!(detail.config.id, created.id);
            assert_eq!(detail.config.name, "User Lifecycle");
            assert!(detail.states.is_empty());
            assert!(detail.transitions.is_empty());

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_update_lifecycle_config() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            let create_request = CreateLifecycleConfigRequest {
                name: "User Lifecycle".to_string(),
                description: None,
                object_type: LifecycleObjectType::User,
            };

            let created = service
                .create_config(tenant_id, create_request)
                .await
                .expect("Failed to create config");

            let update_request = UpdateLifecycleConfigRequest {
                name: Some("Updated User Lifecycle".to_string()),
                description: Some("New description".to_string()),
                is_active: Some(false),
            };

            let updated = service
                .update_config(tenant_id, created.id, update_request)
                .await
                .expect("Failed to update config");

            assert_eq!(updated.name, "Updated User Lifecycle");
            assert_eq!(updated.description, Some("New description".to_string()));
            assert!(!updated.is_active);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_delete_lifecycle_config() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            let request = CreateLifecycleConfigRequest {
                name: "User Lifecycle".to_string(),
                description: None,
                object_type: LifecycleObjectType::User,
            };

            let created = service
                .create_config(tenant_id, request)
                .await
                .expect("Failed to create config");

            service
                .delete_config(tenant_id, created.id)
                .await
                .expect("Failed to delete config");

            // Verify it's deleted
            let result = service.get_config(tenant_id, created.id).await;
            assert!(result.is_err(), "Config should be deleted");

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }

    // =========================================================================
    // Lifecycle State Management Tests
    // =========================================================================

    mod state_management {
        use super::*;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_add_lifecycle_state() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            // Create config first
            let config_request = CreateLifecycleConfigRequest {
                name: "User Lifecycle".to_string(),
                description: None,
                object_type: LifecycleObjectType::User,
            };
            let config = service
                .create_config(tenant_id, config_request)
                .await
                .unwrap();

            // Add state
            let state_request = CreateLifecycleStateRequest {
                name: "Draft".to_string(),
                description: Some("Initial draft state".to_string()),
                is_initial: true,
                is_terminal: false,
                entitlement_action: EntitlementAction::None,
                position: 0,
            };

            let state = service
                .add_state(tenant_id, config.id, state_request)
                .await
                .expect("Failed to add state");

            assert_eq!(state.name, "Draft");
            assert!(state.is_initial);
            assert!(!state.is_terminal);
            assert_eq!(state.object_count, 0);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_add_multiple_states() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            let config_request = CreateLifecycleConfigRequest {
                name: "User Lifecycle".to_string(),
                description: None,
                object_type: LifecycleObjectType::User,
            };
            let config = service
                .create_config(tenant_id, config_request)
                .await
                .unwrap();

            // Add Draft state (initial)
            let draft = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Draft".to_string(),
                        description: None,
                        is_initial: true,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 0,
                    },
                )
                .await
                .unwrap();

            // Add Active state
            let active = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Active".to_string(),
                        description: None,
                        is_initial: false,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 1,
                    },
                )
                .await
                .unwrap();

            // Add Suspended state (with pause action)
            let suspended = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Suspended".to_string(),
                        description: Some("Temporarily suspended".to_string()),
                        is_initial: false,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::Pause,
                        position: 2,
                    },
                )
                .await
                .unwrap();

            // Add Archived state (terminal with revoke)
            let archived = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Archived".to_string(),
                        description: None,
                        is_initial: false,
                        is_terminal: true,
                        entitlement_action: EntitlementAction::Revoke,
                        position: 3,
                    },
                )
                .await
                .unwrap();

            // Add Deleted state (terminal)
            let deleted = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Deleted".to_string(),
                        description: None,
                        is_initial: false,
                        is_terminal: true,
                        entitlement_action: EntitlementAction::Revoke,
                        position: 4,
                    },
                )
                .await
                .unwrap();

            // Verify config has 5 states
            let detail = service.get_config(tenant_id, config.id).await.unwrap();
            assert_eq!(detail.config.state_count, 5);
            assert_eq!(detail.states.len(), 5);

            // Verify initial state
            assert!(draft.is_initial);
            assert!(!active.is_initial);

            // Verify terminal states
            assert!(!draft.is_terminal);
            assert!(!active.is_terminal);
            assert!(!suspended.is_terminal);
            assert!(archived.is_terminal);
            assert!(deleted.is_terminal);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_update_lifecycle_state() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            let config_request = CreateLifecycleConfigRequest {
                name: "User Lifecycle".to_string(),
                description: None,
                object_type: LifecycleObjectType::User,
            };
            let config = service
                .create_config(tenant_id, config_request)
                .await
                .unwrap();

            let state = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Draft".to_string(),
                        description: None,
                        is_initial: true,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 0,
                    },
                )
                .await
                .unwrap();

            // Update state
            let update_request = UpdateLifecycleStateRequest {
                name: Some("Pending".to_string()),
                description: Some("Pending approval".to_string()),
                is_initial: None,
                is_terminal: None,
                entitlement_action: None,
                position: None,
            };

            let updated = service
                .update_state(tenant_id, config.id, state.id, update_request)
                .await
                .expect("Failed to update state");

            assert_eq!(updated.name, "Pending");
            assert_eq!(updated.description, Some("Pending approval".to_string()));
            assert!(updated.is_initial); // Should remain unchanged

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_change_initial_state() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            let config_request = CreateLifecycleConfigRequest {
                name: "User Lifecycle".to_string(),
                description: None,
                object_type: LifecycleObjectType::User,
            };
            let config = service
                .create_config(tenant_id, config_request)
                .await
                .unwrap();

            // Add Draft as initial
            let draft = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Draft".to_string(),
                        description: None,
                        is_initial: true,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 0,
                    },
                )
                .await
                .unwrap();

            // Add Active
            let active = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Active".to_string(),
                        description: None,
                        is_initial: false,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 1,
                    },
                )
                .await
                .unwrap();

            assert!(draft.is_initial);
            assert!(!active.is_initial);

            // Change Active to be initial (should clear Draft's initial flag)
            let _ = service
                .update_state(
                    tenant_id,
                    config.id,
                    active.id,
                    UpdateLifecycleStateRequest {
                        name: None,
                        description: None,
                        is_initial: Some(true),
                        is_terminal: None,
                        entitlement_action: None,
                        position: None,
                    },
                )
                .await
                .unwrap();

            // Verify only Active is now initial
            let detail = service.get_config(tenant_id, config.id).await.unwrap();
            let draft_state = detail.states.iter().find(|s| s.name == "Draft").unwrap();
            let active_state = detail.states.iter().find(|s| s.name == "Active").unwrap();

            assert!(!draft_state.is_initial);
            assert!(active_state.is_initial);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_delete_lifecycle_state() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            let config_request = CreateLifecycleConfigRequest {
                name: "User Lifecycle".to_string(),
                description: None,
                object_type: LifecycleObjectType::User,
            };
            let config = service
                .create_config(tenant_id, config_request)
                .await
                .unwrap();

            let state = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Draft".to_string(),
                        description: None,
                        is_initial: true,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 0,
                    },
                )
                .await
                .unwrap();

            // Delete state
            service
                .delete_state(tenant_id, config.id, state.id)
                .await
                .expect("Failed to delete state");

            // Verify it's deleted
            let detail = service.get_config(tenant_id, config.id).await.unwrap();
            assert_eq!(detail.config.state_count, 0);

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }

    // =========================================================================
    // Lifecycle Transition Management Tests
    // =========================================================================

    mod transition_management {
        use super::*;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_add_lifecycle_transition() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            let config_request = CreateLifecycleConfigRequest {
                name: "User Lifecycle".to_string(),
                description: None,
                object_type: LifecycleObjectType::User,
            };
            let config = service
                .create_config(tenant_id, config_request)
                .await
                .unwrap();

            // Add states
            let draft = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Draft".to_string(),
                        description: None,
                        is_initial: true,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 0,
                    },
                )
                .await
                .unwrap();

            let active = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Active".to_string(),
                        description: None,
                        is_initial: false,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 1,
                    },
                )
                .await
                .unwrap();

            // Add transition
            let transition_request = CreateLifecycleTransitionRequest {
                name: "Activate".to_string(),
                from_state_id: draft.id,
                to_state_id: active.id,
                requires_approval: false,
                approval_workflow_id: None,
                grace_period_hours: 0,
            };

            let transition = service
                .add_transition(tenant_id, config.id, transition_request)
                .await
                .expect("Failed to add transition");

            assert_eq!(transition.name, "Activate");
            assert_eq!(transition.from_state_id, draft.id);
            assert_eq!(transition.to_state_id, active.id);
            assert_eq!(transition.from_state_name, "Draft");
            assert_eq!(transition.to_state_name, "Active");
            assert!(!transition.requires_approval);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_add_transition_with_approval() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            let config_request = CreateLifecycleConfigRequest {
                name: "User Lifecycle".to_string(),
                description: None,
                object_type: LifecycleObjectType::User,
            };
            let config = service
                .create_config(tenant_id, config_request)
                .await
                .unwrap();

            let active = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Active".to_string(),
                        description: None,
                        is_initial: true,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 0,
                    },
                )
                .await
                .unwrap();

            let archived = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Archived".to_string(),
                        description: None,
                        is_initial: false,
                        is_terminal: true,
                        entitlement_action: EntitlementAction::None,
                        position: 1,
                    },
                )
                .await
                .unwrap();

            // Add transition requiring approval
            let transition_request = CreateLifecycleTransitionRequest {
                name: "Archive".to_string(),
                from_state_id: active.id,
                to_state_id: archived.id,
                requires_approval: true,
                approval_workflow_id: None,
                grace_period_hours: 24,
            };

            let transition = service
                .add_transition(tenant_id, config.id, transition_request)
                .await
                .expect("Failed to add transition");

            assert!(transition.requires_approval);
            assert_eq!(transition.grace_period_hours, 24);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_add_multiple_transitions() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            let config_request = CreateLifecycleConfigRequest {
                name: "User Lifecycle".to_string(),
                description: None,
                object_type: LifecycleObjectType::User,
            };
            let config = service
                .create_config(tenant_id, config_request)
                .await
                .unwrap();

            // Create states: Draft -> Active -> Suspended -> Archived
            let draft = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Draft".to_string(),
                        description: None,
                        is_initial: true,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 0,
                    },
                )
                .await
                .unwrap();

            let active = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Active".to_string(),
                        description: None,
                        is_initial: false,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 1,
                    },
                )
                .await
                .unwrap();

            let suspended = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Suspended".to_string(),
                        description: None,
                        is_initial: false,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 2,
                    },
                )
                .await
                .unwrap();

            let archived = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Archived".to_string(),
                        description: None,
                        is_initial: false,
                        is_terminal: true,
                        entitlement_action: EntitlementAction::None,
                        position: 3,
                    },
                )
                .await
                .unwrap();

            // Create transitions
            // Draft -> Active
            let _ = service
                .add_transition(
                    tenant_id,
                    config.id,
                    CreateLifecycleTransitionRequest {
                        name: "Activate".to_string(),
                        from_state_id: draft.id,
                        to_state_id: active.id,
                        requires_approval: false,
                        approval_workflow_id: None,
                        grace_period_hours: 0,
                    },
                )
                .await
                .unwrap();

            // Active -> Suspended
            let _ = service
                .add_transition(
                    tenant_id,
                    config.id,
                    CreateLifecycleTransitionRequest {
                        name: "Suspend".to_string(),
                        from_state_id: active.id,
                        to_state_id: suspended.id,
                        requires_approval: false,
                        approval_workflow_id: None,
                        grace_period_hours: 0,
                    },
                )
                .await
                .unwrap();

            // Suspended -> Active
            let _ = service
                .add_transition(
                    tenant_id,
                    config.id,
                    CreateLifecycleTransitionRequest {
                        name: "Reactivate".to_string(),
                        from_state_id: suspended.id,
                        to_state_id: active.id,
                        requires_approval: true,
                        approval_workflow_id: None,
                        grace_period_hours: 0,
                    },
                )
                .await
                .unwrap();

            // Active -> Archived
            let _ = service
                .add_transition(
                    tenant_id,
                    config.id,
                    CreateLifecycleTransitionRequest {
                        name: "Archive".to_string(),
                        from_state_id: active.id,
                        to_state_id: archived.id,
                        requires_approval: true,
                        approval_workflow_id: None,
                        grace_period_hours: 72,
                    },
                )
                .await
                .unwrap();

            // Suspended -> Archived
            let _ = service
                .add_transition(
                    tenant_id,
                    config.id,
                    CreateLifecycleTransitionRequest {
                        name: "Archive from Suspended".to_string(),
                        from_state_id: suspended.id,
                        to_state_id: archived.id,
                        requires_approval: false,
                        approval_workflow_id: None,
                        grace_period_hours: 0,
                    },
                )
                .await
                .unwrap();

            // Verify config has correct counts
            let detail = service.get_config(tenant_id, config.id).await.unwrap();
            assert_eq!(detail.config.state_count, 4);
            assert_eq!(detail.config.transition_count, 5);
            assert_eq!(detail.states.len(), 4);
            assert_eq!(detail.transitions.len(), 5);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_delete_lifecycle_transition() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            let config_request = CreateLifecycleConfigRequest {
                name: "User Lifecycle".to_string(),
                description: None,
                object_type: LifecycleObjectType::User,
            };
            let config = service
                .create_config(tenant_id, config_request)
                .await
                .unwrap();

            let draft = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Draft".to_string(),
                        description: None,
                        is_initial: true,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 0,
                    },
                )
                .await
                .unwrap();

            let active = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Active".to_string(),
                        description: None,
                        is_initial: false,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 1,
                    },
                )
                .await
                .unwrap();

            let transition = service
                .add_transition(
                    tenant_id,
                    config.id,
                    CreateLifecycleTransitionRequest {
                        name: "Activate".to_string(),
                        from_state_id: draft.id,
                        to_state_id: active.id,
                        requires_approval: false,
                        approval_workflow_id: None,
                        grace_period_hours: 0,
                    },
                )
                .await
                .unwrap();

            // Delete transition
            service
                .delete_transition(tenant_id, config.id, transition.id)
                .await
                .expect("Failed to delete transition");

            // Verify it's deleted
            let detail = service.get_config(tenant_id, config.id).await.unwrap();
            assert_eq!(detail.config.transition_count, 0);
            assert!(detail.transitions.is_empty());

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_transition_invalid_state_fails() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            let config_request = CreateLifecycleConfigRequest {
                name: "User Lifecycle".to_string(),
                description: None,
                object_type: LifecycleObjectType::User,
            };
            let config = service
                .create_config(tenant_id, config_request)
                .await
                .unwrap();

            let draft = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Draft".to_string(),
                        description: None,
                        is_initial: true,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 0,
                    },
                )
                .await
                .unwrap();

            // Try to create transition with non-existent to_state
            let invalid_id = uuid::Uuid::new_v4();
            let result = service
                .add_transition(
                    tenant_id,
                    config.id,
                    CreateLifecycleTransitionRequest {
                        name: "Invalid".to_string(),
                        from_state_id: draft.id,
                        to_state_id: invalid_id,
                        requires_approval: false,
                        approval_workflow_id: None,
                        grace_period_hours: 0,
                    },
                )
                .await;

            assert!(result.is_err(), "Expected error for invalid state");

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }

    // =========================================================================
    // Full Lifecycle Configuration Test (as specified in tasks.md)
    // =========================================================================

    mod full_lifecycle {
        use super::*;

        /// Test creating a lifecycle configuration for users with 5 states and 8 transitions
        /// This matches the Independent Test criteria for User Story 1
        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_full_user_lifecycle_with_5_states_8_transitions() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = LifecycleConfigService::new(pool.clone());

            // Create User lifecycle config
            let config = service
                .create_config(
                    tenant_id,
                    CreateLifecycleConfigRequest {
                        name: "User Lifecycle".to_string(),
                        description: Some("Complete user lifecycle management".to_string()),
                        object_type: LifecycleObjectType::User,
                    },
                )
                .await
                .expect("Failed to create config");

            // Create 5 states: Draft, Active, Suspended, Archived, Deleted
            let draft = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Draft".to_string(),
                        description: Some("Newly created, not yet activated".to_string()),
                        is_initial: true,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 0,
                    },
                )
                .await
                .expect("Failed to add Draft state");

            let active = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Active".to_string(),
                        description: Some("Fully active user with all access".to_string()),
                        is_initial: false,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::None,
                        position: 1,
                    },
                )
                .await
                .expect("Failed to add Active state");

            let suspended = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Suspended".to_string(),
                        description: Some("Temporarily suspended, access paused".to_string()),
                        is_initial: false,
                        is_terminal: false,
                        entitlement_action: EntitlementAction::Pause,
                        position: 2,
                    },
                )
                .await
                .expect("Failed to add Suspended state");

            let archived = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Archived".to_string(),
                        description: Some("Permanently archived, access revoked".to_string()),
                        is_initial: false,
                        is_terminal: true,
                        entitlement_action: EntitlementAction::Revoke,
                        position: 3,
                    },
                )
                .await
                .expect("Failed to add Archived state");

            let deleted = service
                .add_state(
                    tenant_id,
                    config.id,
                    CreateLifecycleStateRequest {
                        name: "Deleted".to_string(),
                        description: Some("Marked for deletion".to_string()),
                        is_initial: false,
                        is_terminal: true,
                        entitlement_action: EntitlementAction::Revoke,
                        position: 4,
                    },
                )
                .await
                .expect("Failed to add Deleted state");

            // Create 8 transitions
            // 1. Draft -> Active (Activate)
            let _ = service
                .add_transition(
                    tenant_id,
                    config.id,
                    CreateLifecycleTransitionRequest {
                        name: "Activate".to_string(),
                        from_state_id: draft.id,
                        to_state_id: active.id,
                        requires_approval: false,
                        approval_workflow_id: None,
                        grace_period_hours: 0,
                    },
                )
                .await
                .expect("Failed to add Activate transition");

            // 2. Active -> Suspended (Suspend)
            let _ = service
                .add_transition(
                    tenant_id,
                    config.id,
                    CreateLifecycleTransitionRequest {
                        name: "Suspend".to_string(),
                        from_state_id: active.id,
                        to_state_id: suspended.id,
                        requires_approval: false,
                        approval_workflow_id: None,
                        grace_period_hours: 0,
                    },
                )
                .await
                .expect("Failed to add Suspend transition");

            // 3. Suspended -> Active (Reactivate)
            let _ = service
                .add_transition(
                    tenant_id,
                    config.id,
                    CreateLifecycleTransitionRequest {
                        name: "Reactivate".to_string(),
                        from_state_id: suspended.id,
                        to_state_id: active.id,
                        requires_approval: true,
                        approval_workflow_id: None,
                        grace_period_hours: 0,
                    },
                )
                .await
                .expect("Failed to add Reactivate transition");

            // 4. Active -> Archived (Archive)
            let _ = service
                .add_transition(
                    tenant_id,
                    config.id,
                    CreateLifecycleTransitionRequest {
                        name: "Archive".to_string(),
                        from_state_id: active.id,
                        to_state_id: archived.id,
                        requires_approval: true,
                        approval_workflow_id: None,
                        grace_period_hours: 72,
                    },
                )
                .await
                .expect("Failed to add Archive transition");

            // 5. Suspended -> Archived (Archive from Suspended)
            let _ = service
                .add_transition(
                    tenant_id,
                    config.id,
                    CreateLifecycleTransitionRequest {
                        name: "Archive from Suspended".to_string(),
                        from_state_id: suspended.id,
                        to_state_id: archived.id,
                        requires_approval: false,
                        approval_workflow_id: None,
                        grace_period_hours: 0,
                    },
                )
                .await
                .expect("Failed to add Archive from Suspended transition");

            // 6. Active -> Deleted (Delete)
            let _ = service
                .add_transition(
                    tenant_id,
                    config.id,
                    CreateLifecycleTransitionRequest {
                        name: "Delete".to_string(),
                        from_state_id: active.id,
                        to_state_id: deleted.id,
                        requires_approval: true,
                        approval_workflow_id: None,
                        grace_period_hours: 168, // 7 day grace period
                    },
                )
                .await
                .expect("Failed to add Delete transition");

            // 7. Suspended -> Deleted (Delete from Suspended)
            let _ = service
                .add_transition(
                    tenant_id,
                    config.id,
                    CreateLifecycleTransitionRequest {
                        name: "Delete from Suspended".to_string(),
                        from_state_id: suspended.id,
                        to_state_id: deleted.id,
                        requires_approval: true,
                        approval_workflow_id: None,
                        grace_period_hours: 168,
                    },
                )
                .await
                .expect("Failed to add Delete from Suspended transition");

            // 8. Draft -> Deleted (Discard)
            let _ = service
                .add_transition(
                    tenant_id,
                    config.id,
                    CreateLifecycleTransitionRequest {
                        name: "Discard".to_string(),
                        from_state_id: draft.id,
                        to_state_id: deleted.id,
                        requires_approval: false,
                        approval_workflow_id: None,
                        grace_period_hours: 0,
                    },
                )
                .await
                .expect("Failed to add Discard transition");

            // Verify configuration persists and is retrievable
            let detail = service
                .get_config(tenant_id, config.id)
                .await
                .expect("Failed to retrieve config");

            // Assertions
            assert_eq!(detail.config.name, "User Lifecycle");
            assert_eq!(detail.config.object_type, LifecycleObjectType::User);
            assert!(detail.config.is_active);
            assert_eq!(detail.config.state_count, 5, "Expected 5 states");
            assert_eq!(detail.config.transition_count, 8, "Expected 8 transitions");
            assert_eq!(detail.states.len(), 5, "Expected 5 states in response");
            assert_eq!(
                detail.transitions.len(),
                8,
                "Expected 8 transitions in response"
            );

            // Verify states
            let state_names: Vec<&str> = detail.states.iter().map(|s| s.name.as_str()).collect();
            assert!(state_names.contains(&"Draft"));
            assert!(state_names.contains(&"Active"));
            assert!(state_names.contains(&"Suspended"));
            assert!(state_names.contains(&"Archived"));
            assert!(state_names.contains(&"Deleted"));

            // Verify initial state
            let initial_states: Vec<_> = detail.states.iter().filter(|s| s.is_initial).collect();
            assert_eq!(
                initial_states.len(),
                1,
                "Expected exactly one initial state"
            );
            assert_eq!(initial_states[0].name, "Draft");

            // Verify terminal states
            let terminal_states: Vec<_> = detail.states.iter().filter(|s| s.is_terminal).collect();
            assert_eq!(terminal_states.len(), 2, "Expected 2 terminal states");

            // Verify transition names
            let transition_names: Vec<&str> =
                detail.transitions.iter().map(|t| t.name.as_str()).collect();
            assert!(transition_names.contains(&"Activate"));
            assert!(transition_names.contains(&"Suspend"));
            assert!(transition_names.contains(&"Reactivate"));
            assert!(transition_names.contains(&"Archive"));
            assert!(transition_names.contains(&"Archive from Suspended"));
            assert!(transition_names.contains(&"Delete"));
            assert!(transition_names.contains(&"Delete from Suspended"));
            assert!(transition_names.contains(&"Discard"));

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }
}
