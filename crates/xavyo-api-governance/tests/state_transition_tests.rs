//! Integration tests for State Transition Service (F052).
//!
//! Tests for executing state transitions, rollback, approval integration,
//! and audit record creation.
//!
//! Run with: `cargo test -p xavyo-api-governance --features integration state_transition`

mod common;

#[cfg(feature = "integration")]
mod state_transition_tests {
    use super::common::*;
    use std::sync::Arc;
    use xavyo_api_governance::models::{
        CreateLifecycleConfigRequest, CreateLifecycleStateRequest,
        CreateLifecycleTransitionRequest, ExecuteTransitionRequest, ListTransitionAuditQuery,
    };
    use xavyo_api_governance::services::{
        LifecycleConfigService, StateAccessRuleService, StateTransitionService,
    };
    use xavyo_db::{
        AuditActionType, EntitlementAction, LifecycleObjectType, TransitionRequestStatus, User,
    };

    /// Helper to create a user for testing transitions.
    async fn create_transition_test_user(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        email: &str,
    ) -> uuid::Uuid {
        let user = sqlx::query_as::<_, (uuid::Uuid,)>(
            r#"
            INSERT INTO users (tenant_id, email, password_hash, is_active, email_verified)
            VALUES ($1, $2, 'test_hash', true, true)
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_one(pool)
        .await
        .expect("Failed to create test user");

        user.0
    }

    /// Helper to update user's lifecycle state directly.
    async fn set_user_lifecycle_state(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        user_id: uuid::Uuid,
        state_id: uuid::Uuid,
    ) {
        sqlx::query(
            r#"
            UPDATE users SET lifecycle_state_id = $3
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(state_id)
        .execute(pool)
        .await
        .expect("Failed to update user lifecycle state");
    }

    /// Helper to create a complete lifecycle configuration with states and transitions.
    async fn create_test_lifecycle(
        config_service: &LifecycleConfigService,
        tenant_id: uuid::Uuid,
    ) -> (uuid::Uuid, uuid::Uuid, uuid::Uuid, uuid::Uuid) {
        // Create configuration
        let config = config_service
            .create_config(
                tenant_id,
                CreateLifecycleConfigRequest {
                    name: "Test User Lifecycle".to_string(),
                    object_type: LifecycleObjectType::User,
                    description: Some("Test lifecycle for users".to_string()),
                },
            )
            .await
            .expect("Failed to create config");

        // Create states: Draft (initial) -> Active -> Suspended
        let draft = config_service
            .add_state(
                tenant_id,
                config.id,
                CreateLifecycleStateRequest {
                    name: "Draft".to_string(),
                    description: Some("Initial draft state".to_string()),
                    is_initial: true,
                    is_terminal: false,
                    entitlement_action: EntitlementAction::None,
                    position: 0,
                },
            )
            .await
            .expect("Failed to create Draft state");

        let active = config_service
            .add_state(
                tenant_id,
                config.id,
                CreateLifecycleStateRequest {
                    name: "Active".to_string(),
                    description: Some("Active state".to_string()),
                    is_initial: false,
                    is_terminal: false,
                    entitlement_action: EntitlementAction::None,
                    position: 1,
                },
            )
            .await
            .expect("Failed to create Active state");

        let suspended = config_service
            .add_state(
                tenant_id,
                config.id,
                CreateLifecycleStateRequest {
                    name: "Suspended".to_string(),
                    description: Some("Suspended state".to_string()),
                    is_initial: false,
                    is_terminal: false,
                    entitlement_action: EntitlementAction::Pause,
                    position: 2,
                },
            )
            .await
            .expect("Failed to create Suspended state");

        // Create transition: Draft -> Active (no approval, 24h grace period)
        let _activate = config_service
            .add_transition(
                tenant_id,
                config.id,
                CreateLifecycleTransitionRequest {
                    name: "activate".to_string(),
                    from_state_id: draft.id,
                    to_state_id: active.id,
                    requires_approval: false,
                    approval_workflow_id: None,
                    grace_period_hours: 24,
                },
            )
            .await
            .expect("Failed to create activate transition");

        // Create transition: Active -> Suspended (no approval)
        let _suspend = config_service
            .add_transition(
                tenant_id,
                config.id,
                CreateLifecycleTransitionRequest {
                    name: "suspend".to_string(),
                    from_state_id: active.id,
                    to_state_id: suspended.id,
                    requires_approval: false,
                    approval_workflow_id: None,
                    grace_period_hours: 0,
                },
            )
            .await
            .expect("Failed to create suspend transition");

        (config.id, draft.id, active.id, suspended.id)
    }

    // =========================================================================
    // Execute Transition Tests
    // =========================================================================

    mod execute_transition {
        use super::*;
        use axum::http::StatusCode;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_execute_transition_draft_to_active() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let config_service = LifecycleConfigService::new(pool.clone());
            let transition_service = StateTransitionService::new(
                pool.clone(),
                Arc::new(StateAccessRuleService::new(pool.clone())),
            );

            // Create lifecycle configuration
            let (config_id, draft_id, active_id, _) =
                create_test_lifecycle(&config_service, tenant_id).await;

            // Create a test user
            let user_id =
                create_transition_test_user(&pool, tenant_id, "transition-test@example.com").await;

            // Set user to Draft state
            set_user_lifecycle_state(&pool, tenant_id, user_id, draft_id).await;

            // Get the transition ID for Draft -> Active
            let config = config_service
                .get_config(tenant_id, config_id)
                .await
                .unwrap();
            let activate_transition = config
                .transitions
                .iter()
                .find(|t| t.name == "activate")
                .expect("activate transition not found");

            // Execute transition
            let result = transition_service
                .execute_transition(
                    tenant_id,
                    user_id, // user requesting own transition
                    ExecuteTransitionRequest {
                        object_type: LifecycleObjectType::User,
                        object_id: user_id,
                        transition_id: activate_transition.id,
                        scheduled_for: None,
                        reason: None,
                    },
                )
                .await;

            assert!(
                result.is_ok(),
                "Execute transition failed: {:?}",
                result.err()
            );
            let (status, response) = result.unwrap();

            assert_eq!(status, StatusCode::OK);
            assert_eq!(response.status, TransitionRequestStatus::Executed);
            assert_eq!(response.from_state.name, "Draft");
            assert_eq!(response.to_state.name, "Active");
            assert!(response.rollback_available); // 24h grace period
            assert!(response.grace_period_ends_at.is_some());
            assert!(response.executed_at.is_some());

            // Verify user's lifecycle state was updated
            let user_state = User::get_lifecycle_state_id(&pool, tenant_id, user_id)
                .await
                .expect("Failed to get user state");
            assert_eq!(user_state, Some(active_id));
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_execute_transition_wrong_current_state() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let config_service = LifecycleConfigService::new(pool.clone());
            let transition_service = StateTransitionService::new(
                pool.clone(),
                Arc::new(StateAccessRuleService::new(pool.clone())),
            );

            // Create lifecycle configuration
            let (config_id, _draft_id, active_id, _) =
                create_test_lifecycle(&config_service, tenant_id).await;

            // Create a test user
            let user_id =
                create_transition_test_user(&pool, tenant_id, "wrong-state@example.com").await;

            // Set user to Active state (not Draft)
            set_user_lifecycle_state(&pool, tenant_id, user_id, active_id).await;

            // Get the transition ID for Draft -> Active
            let config = config_service
                .get_config(tenant_id, config_id)
                .await
                .unwrap();
            let activate_transition = config
                .transitions
                .iter()
                .find(|t| t.name == "activate")
                .expect("activate transition not found");

            // Try to execute transition - should fail because user is not in Draft
            let result = transition_service
                .execute_transition(
                    tenant_id,
                    user_id,
                    ExecuteTransitionRequest {
                        object_type: LifecycleObjectType::User,
                        object_id: user_id,
                        transition_id: activate_transition.id,
                        scheduled_for: None,
                        reason: None,
                    },
                )
                .await;

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                matches!(
                    err,
                    xavyo_governance::error::GovernanceError::InvalidTransition(_)
                ),
                "Expected InvalidTransition error, got: {:?}",
                err
            );
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_execute_transition_inactive_config() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let config_service = LifecycleConfigService::new(pool.clone());
            let transition_service = StateTransitionService::new(
                pool.clone(),
                Arc::new(StateAccessRuleService::new(pool.clone())),
            );

            // Create lifecycle configuration
            let (config_id, draft_id, _, _) =
                create_test_lifecycle(&config_service, tenant_id).await;

            // Deactivate the configuration
            config_service
                .update_config(
                    tenant_id,
                    config_id,
                    xavyo_api_governance::models::UpdateLifecycleConfigRequest {
                        name: None,
                        description: None,
                        is_active: Some(false),
                    },
                )
                .await
                .expect("Failed to deactivate config");

            // Create a test user
            let user_id =
                create_transition_test_user(&pool, tenant_id, "inactive-config@example.com").await;

            // Set user to Draft state
            set_user_lifecycle_state(&pool, tenant_id, user_id, draft_id).await;

            // Get the transition ID
            let config = config_service
                .get_config(tenant_id, config_id)
                .await
                .unwrap();
            let activate_transition = config
                .transitions
                .iter()
                .find(|t| t.name == "activate")
                .expect("activate transition not found");

            // Try to execute transition - should fail because config is inactive
            let result = transition_service
                .execute_transition(
                    tenant_id,
                    user_id,
                    ExecuteTransitionRequest {
                        object_type: LifecycleObjectType::User,
                        object_id: user_id,
                        transition_id: activate_transition.id,
                        scheduled_for: None,
                        reason: None,
                    },
                )
                .await;

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                matches!(err, xavyo_governance::error::GovernanceError::Validation(_)),
                "Expected Validation error for inactive config, got: {:?}",
                err
            );
        }
    }

    // =========================================================================
    // Rollback Tests
    // =========================================================================

    mod rollback {
        use super::*;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_rollback_transition() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let config_service = LifecycleConfigService::new(pool.clone());
            let transition_service = StateTransitionService::new(
                pool.clone(),
                Arc::new(StateAccessRuleService::new(pool.clone())),
            );

            // Create lifecycle configuration (activate has 24h grace period)
            let (config_id, draft_id, active_id, _) =
                create_test_lifecycle(&config_service, tenant_id).await;

            // Create and prepare user
            let user_id =
                create_transition_test_user(&pool, tenant_id, "rollback-test@example.com").await;
            set_user_lifecycle_state(&pool, tenant_id, user_id, draft_id).await;

            // Get transition and execute
            let config = config_service
                .get_config(tenant_id, config_id)
                .await
                .unwrap();
            let activate_transition = config
                .transitions
                .iter()
                .find(|t| t.name == "activate")
                .expect("activate transition not found");

            let (_, response) = transition_service
                .execute_transition(
                    tenant_id,
                    user_id,
                    ExecuteTransitionRequest {
                        object_type: LifecycleObjectType::User,
                        object_id: user_id,
                        transition_id: activate_transition.id,
                        scheduled_for: None,
                        reason: None,
                    },
                )
                .await
                .expect("Execute transition failed");

            assert!(response.rollback_available);
            let request_id = response.id;

            // Verify user is now in Active state
            let user_state = User::get_lifecycle_state_id(&pool, tenant_id, user_id)
                .await
                .unwrap();
            assert_eq!(user_state, Some(active_id));

            // Rollback the transition
            let rollback_result = transition_service
                .rollback_transition(
                    tenant_id,
                    request_id,
                    user_id,
                    Some("Testing rollback".to_string()),
                )
                .await;

            assert!(
                rollback_result.is_ok(),
                "Rollback failed: {:?}",
                rollback_result.err()
            );
            let rollback_response = rollback_result.unwrap();

            assert_eq!(
                rollback_response.status,
                TransitionRequestStatus::RolledBack
            );
            assert!(!rollback_response.rollback_available); // No longer available after rollback

            // Verify user is back in Draft state
            let user_state = User::get_lifecycle_state_id(&pool, tenant_id, user_id)
                .await
                .unwrap();
            assert_eq!(user_state, Some(draft_id));
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_rollback_not_available_no_grace_period() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let config_service = LifecycleConfigService::new(pool.clone());
            let transition_service = StateTransitionService::new(
                pool.clone(),
                Arc::new(StateAccessRuleService::new(pool.clone())),
            );

            // Create lifecycle configuration
            let (config_id, _draft_id, active_id, suspended_id) =
                create_test_lifecycle(&config_service, tenant_id).await;

            // Create and prepare user in Active state
            let user_id =
                create_transition_test_user(&pool, tenant_id, "no-grace@example.com").await;
            set_user_lifecycle_state(&pool, tenant_id, user_id, active_id).await;

            // Get suspend transition (has 0 grace period)
            let config = config_service
                .get_config(tenant_id, config_id)
                .await
                .unwrap();
            let suspend_transition = config
                .transitions
                .iter()
                .find(|t| t.name == "suspend")
                .expect("suspend transition not found");

            // Execute suspend transition
            let (_, response) = transition_service
                .execute_transition(
                    tenant_id,
                    user_id,
                    ExecuteTransitionRequest {
                        object_type: LifecycleObjectType::User,
                        object_id: user_id,
                        transition_id: suspend_transition.id,
                        scheduled_for: None,
                        reason: None,
                    },
                )
                .await
                .expect("Execute transition failed");

            // Rollback should not be available (0 grace period)
            assert!(!response.rollback_available);
            let request_id = response.id;

            // Try to rollback - should fail
            let rollback_result = transition_service
                .rollback_transition(tenant_id, request_id, user_id, None)
                .await;

            assert!(rollback_result.is_err());

            // User should still be in Suspended state
            let user_state = User::get_lifecycle_state_id(&pool, tenant_id, user_id)
                .await
                .unwrap();
            assert_eq!(user_state, Some(suspended_id));
        }
    }

    // =========================================================================
    // Get Object State Tests
    // =========================================================================

    mod get_object_state {
        use super::*;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_get_object_state_with_available_transitions() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let config_service = LifecycleConfigService::new(pool.clone());
            let transition_service = StateTransitionService::new(
                pool.clone(),
                Arc::new(StateAccessRuleService::new(pool.clone())),
            );

            // Create lifecycle configuration
            let (_config_id, draft_id, _active_id, _) =
                create_test_lifecycle(&config_service, tenant_id).await;

            // Create user in Draft state
            let user_id =
                create_transition_test_user(&pool, tenant_id, "get-state@example.com").await;
            set_user_lifecycle_state(&pool, tenant_id, user_id, draft_id).await;

            // Get object state
            let result = transition_service
                .get_object_state(tenant_id, "user", user_id)
                .await;

            assert!(
                result.is_ok(),
                "get_object_state failed: {:?}",
                result.err()
            );
            let status = result.unwrap();

            assert_eq!(status.object_id, user_id);
            assert_eq!(status.object_type, LifecycleObjectType::User);
            assert!(status.current_state.is_some());
            assert_eq!(status.current_state.as_ref().unwrap().name, "Draft");

            // Should have one available transition: activate
            assert_eq!(status.available_transitions.len(), 1);
            assert_eq!(status.available_transitions[0].name, "activate");

            // No active rollback window
            assert!(status.active_rollback.is_none());
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_get_object_state_invalid_object_type() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let transition_service = StateTransitionService::new(
                pool.clone(),
                Arc::new(StateAccessRuleService::new(pool.clone())),
            );

            let result = transition_service
                .get_object_state(tenant_id, "invalid_type", uuid::Uuid::new_v4())
                .await;

            assert!(result.is_err());
        }
    }

    // =========================================================================
    // Audit Tests
    // =========================================================================

    mod audit {
        use super::*;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_audit_record_created_on_execute() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let config_service = LifecycleConfigService::new(pool.clone());
            let transition_service = StateTransitionService::new(
                pool.clone(),
                Arc::new(StateAccessRuleService::new(pool.clone())),
            );

            // Create lifecycle and user
            let (config_id, draft_id, _, _) =
                create_test_lifecycle(&config_service, tenant_id).await;
            let user_id =
                create_transition_test_user(&pool, tenant_id, "audit-exec@example.com").await;
            set_user_lifecycle_state(&pool, tenant_id, user_id, draft_id).await;

            // Execute transition
            let config = config_service
                .get_config(tenant_id, config_id)
                .await
                .unwrap();
            let activate_transition = config
                .transitions
                .iter()
                .find(|t| t.name == "activate")
                .unwrap();

            let (_, response) = transition_service
                .execute_transition(
                    tenant_id,
                    user_id,
                    ExecuteTransitionRequest {
                        object_type: LifecycleObjectType::User,
                        object_id: user_id,
                        transition_id: activate_transition.id,
                        scheduled_for: None,
                        reason: None,
                    },
                )
                .await
                .expect("Execute transition failed");

            // List audit records
            let audit_result = transition_service
                .list_transition_audit(
                    tenant_id,
                    &ListTransitionAuditQuery {
                        object_id: Some(user_id),
                        ..Default::default()
                    },
                )
                .await;

            assert!(audit_result.is_ok());
            let audit_list = audit_result.unwrap();

            assert_eq!(audit_list.total, 1);
            assert_eq!(audit_list.items.len(), 1);

            let audit = &audit_list.items[0];
            assert_eq!(audit.request_id, response.id);
            assert_eq!(audit.object_id, user_id);
            assert_eq!(audit.from_state, "Draft");
            assert_eq!(audit.to_state, "Active");
            assert_eq!(audit.transition_name, "activate");
            assert_eq!(audit.action_type, AuditActionType::Execute);
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_audit_record_created_on_rollback() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let config_service = LifecycleConfigService::new(pool.clone());
            let transition_service = StateTransitionService::new(
                pool.clone(),
                Arc::new(StateAccessRuleService::new(pool.clone())),
            );

            // Create lifecycle and user
            let (config_id, draft_id, _, _) =
                create_test_lifecycle(&config_service, tenant_id).await;
            let user_id =
                create_transition_test_user(&pool, tenant_id, "audit-rollback@example.com").await;
            set_user_lifecycle_state(&pool, tenant_id, user_id, draft_id).await;

            // Execute transition
            let config = config_service
                .get_config(tenant_id, config_id)
                .await
                .unwrap();
            let activate_transition = config
                .transitions
                .iter()
                .find(|t| t.name == "activate")
                .unwrap();

            let (_, response) = transition_service
                .execute_transition(
                    tenant_id,
                    user_id,
                    ExecuteTransitionRequest {
                        object_type: LifecycleObjectType::User,
                        object_id: user_id,
                        transition_id: activate_transition.id,
                        scheduled_for: None,
                        reason: None,
                    },
                )
                .await
                .expect("Execute transition failed");

            // Rollback
            transition_service
                .rollback_transition(tenant_id, response.id, user_id, Some("Testing".to_string()))
                .await
                .expect("Rollback failed");

            // List audit records
            let audit_result = transition_service
                .list_transition_audit(
                    tenant_id,
                    &ListTransitionAuditQuery {
                        object_id: Some(user_id),
                        ..Default::default()
                    },
                )
                .await;

            assert!(audit_result.is_ok());
            let audit_list = audit_result.unwrap();

            // Should have 2 records: execute and rollback
            assert_eq!(audit_list.total, 2);

            // Find rollback record
            let rollback_audit = audit_list
                .items
                .iter()
                .find(|a| a.action_type == AuditActionType::Rollback)
                .expect("Rollback audit record not found");

            assert_eq!(rollback_audit.from_state, "Active"); // Rolling back FROM Active
            assert_eq!(rollback_audit.to_state, "Draft"); // TO Draft
            assert!(rollback_audit.transition_name.starts_with("rollback_"));
        }
    }

    // =========================================================================
    // List Transition Requests Tests
    // =========================================================================

    mod list_transition_requests {
        use super::*;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_list_transition_requests() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let config_service = LifecycleConfigService::new(pool.clone());
            let transition_service = StateTransitionService::new(
                pool.clone(),
                Arc::new(StateAccessRuleService::new(pool.clone())),
            );

            // Create lifecycle and execute some transitions
            let (config_id, draft_id, active_id, _) =
                create_test_lifecycle(&config_service, tenant_id).await;

            let config = config_service
                .get_config(tenant_id, config_id)
                .await
                .unwrap();
            let activate_transition = config
                .transitions
                .iter()
                .find(|t| t.name == "activate")
                .unwrap();
            let suspend_transition = config
                .transitions
                .iter()
                .find(|t| t.name == "suspend")
                .unwrap();

            // Create and transition multiple users
            for i in 0..3 {
                let user_id = create_transition_test_user(
                    &pool,
                    tenant_id,
                    &format!("list-test-{}@example.com", i),
                )
                .await;
                set_user_lifecycle_state(&pool, tenant_id, user_id, draft_id).await;

                transition_service
                    .execute_transition(
                        tenant_id,
                        user_id,
                        ExecuteTransitionRequest {
                            object_type: LifecycleObjectType::User,
                            object_id: user_id,
                            transition_id: activate_transition.id,
                            scheduled_for: None,
                            reason: None,
                        },
                    )
                    .await
                    .expect("Execute transition failed");
            }

            // Create one more user and do two transitions
            let user_id =
                create_transition_test_user(&pool, tenant_id, "list-test-extra@example.com").await;
            set_user_lifecycle_state(&pool, tenant_id, user_id, draft_id).await;

            transition_service
                .execute_transition(
                    tenant_id,
                    user_id,
                    ExecuteTransitionRequest {
                        object_type: LifecycleObjectType::User,
                        object_id: user_id,
                        transition_id: activate_transition.id,
                        scheduled_for: None,
                        reason: None,
                    },
                )
                .await
                .expect("Execute transition failed");

            // Now suspend this user
            set_user_lifecycle_state(&pool, tenant_id, user_id, active_id).await;
            transition_service
                .execute_transition(
                    tenant_id,
                    user_id,
                    ExecuteTransitionRequest {
                        object_type: LifecycleObjectType::User,
                        object_id: user_id,
                        transition_id: suspend_transition.id,
                        scheduled_for: None,
                        reason: None,
                    },
                )
                .await
                .expect("Execute suspend transition failed");

            // List all requests
            let list_result = transition_service
                .list_transition_requests(
                    tenant_id,
                    &xavyo_api_governance::models::ListTransitionRequestsQuery {
                        limit: Some(100),
                        ..Default::default()
                    },
                )
                .await;

            assert!(list_result.is_ok());
            let list = list_result.unwrap();

            // Should have 5 total: 3 activate + 1 activate + 1 suspend
            assert_eq!(list.total, 5);
            assert_eq!(list.items.len(), 5);

            // All should be Executed status
            assert!(list
                .items
                .iter()
                .all(|r| r.status == TransitionRequestStatus::Executed));
        }
    }
}
