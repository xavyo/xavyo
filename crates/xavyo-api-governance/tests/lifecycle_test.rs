//! Integration tests for xavyo-api-governance JML Lifecycle Workflows (F037).
//!
//! These tests require a running `PostgreSQL` database with the test schema.
//! Run with: `cargo test -p xavyo-api-governance --features integration`

mod common;

#[cfg(feature = "integration")]
mod lifecycle_tests {
    use super::common::*;
    use std::sync::Arc;
    use xavyo_api_governance::services::{
        AssignmentService, BirthrightPolicyService, LifecycleEventService,
    };
    use xavyo_db::{
        BirthrightPolicyStatus, ConditionOperator, CreateLifecycleEvent, LifecycleActionType,
        LifecycleEventFilter, LifecycleEventType,
    };

    // =========================================================================
    // Birthright Policy Tests (US4)
    // =========================================================================

    mod birthright_policies {
        use super::*;
        use xavyo_api_governance::models::PolicyConditionRequest;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_create_birthright_policy() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

            let service = BirthrightPolicyService::new(pool.clone());

            let conditions = vec![PolicyConditionRequest {
                attribute: "department".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("Engineering"),
            }];

            let policy = service
                .create(
                    tenant_id,
                    "Engineering Policy".to_string(),
                    Some("Auto-provision for Engineering".to_string()),
                    100,
                    conditions,
                    vec![entitlement_id],
                    None,    // evaluation_mode (default AllMatch)
                    Some(7), // grace_period_days
                    user_id,
                )
                .await
                .expect("Failed to create policy");

            assert_eq!(policy.name, "Engineering Policy");
            // New policies start as Active by database default
            assert_eq!(policy.status, BirthrightPolicyStatus::Active);
            assert_eq!(policy.entitlement_ids, vec![entitlement_id]);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_enable_disable_policy() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

            let service = BirthrightPolicyService::new(pool.clone());

            let conditions = vec![PolicyConditionRequest {
                attribute: "department".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("Sales"),
            }];

            let policy = service
                .create(
                    tenant_id,
                    "Sales Policy".to_string(),
                    None,
                    50,
                    conditions,
                    vec![entitlement_id],
                    None, // evaluation_mode
                    None, // grace_period_days
                    user_id,
                )
                .await
                .expect("Failed to create policy");

            // Policy starts as Active by default, so first disable it
            let disabled = service
                .disable(tenant_id, policy.id)
                .await
                .expect("Failed to disable");
            assert_eq!(disabled.status, BirthrightPolicyStatus::Inactive);

            // Re-enable
            let enabled = service
                .enable(tenant_id, policy.id)
                .await
                .expect("Failed to enable");
            assert_eq!(enabled.status, BirthrightPolicyStatus::Active);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_simulate_policy() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

            let service = BirthrightPolicyService::new(pool.clone());

            let conditions = vec![
                PolicyConditionRequest {
                    attribute: "department".to_string(),
                    operator: ConditionOperator::Equals,
                    value: serde_json::json!("HR"),
                },
                PolicyConditionRequest {
                    attribute: "location".to_string(),
                    operator: ConditionOperator::In,
                    value: serde_json::json!(["US", "CA"]),
                },
            ];

            let policy = service
                .create(
                    tenant_id,
                    "HR US/CA Policy".to_string(),
                    None,
                    100,
                    conditions,
                    vec![entitlement_id],
                    None, // evaluation_mode
                    None, // grace_period_days
                    user_id,
                )
                .await
                .expect("Failed to create policy");

            // Test matching attributes
            let result = service
                .simulate_policy(
                    tenant_id,
                    policy.id,
                    &serde_json::json!({
                        "department": "HR",
                        "location": "US"
                    }),
                )
                .await
                .expect("Failed to simulate");

            assert!(result.matches);
            assert!(result.condition_results.iter().all(|r| r.matched));

            // Test non-matching attributes
            let result = service
                .simulate_policy(
                    tenant_id,
                    policy.id,
                    &serde_json::json!({
                        "department": "Engineering",
                        "location": "US"
                    }),
                )
                .await
                .expect("Failed to simulate");

            assert!(!result.matches);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_archive_policy() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

            let service = BirthrightPolicyService::new(pool.clone());

            let conditions = vec![PolicyConditionRequest {
                attribute: "department".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("Legal"),
            }];

            let policy = service
                .create(
                    tenant_id,
                    "Legal Policy".to_string(),
                    None,
                    100,
                    conditions,
                    vec![entitlement_id],
                    None, // evaluation_mode
                    None, // grace_period_days
                    user_id,
                )
                .await
                .expect("Failed to create policy");

            // Archive
            let archived = service
                .archive(tenant_id, policy.id)
                .await
                .expect("Failed to archive");
            assert_eq!(archived.status, BirthrightPolicyStatus::Archived);

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }

    // =========================================================================
    // Joiner Auto-Provisioning Tests (US1)
    // =========================================================================

    mod joiner {
        use super::*;
        use xavyo_api_governance::models::PolicyConditionRequest;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_process_joiner_event() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let admin_id = create_test_user(&pool, tenant_id).await;
            let new_user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

            // Create and enable policy
            let policy_service = BirthrightPolicyService::new(pool.clone());
            let conditions = vec![PolicyConditionRequest {
                attribute: "department".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("Engineering"),
            }];

            let _policy = policy_service
                .create(
                    tenant_id,
                    "Engineering Policy".to_string(),
                    None,
                    100,
                    conditions,
                    vec![entitlement_id],
                    None, // evaluation_mode
                    None, // grace_period_days
                    admin_id,
                )
                .await
                .expect("Failed to create policy");

            // Policy is already Active by default, no need to enable

            // Create lifecycle event service
            let assignment_service = Arc::new(AssignmentService::new(pool.clone()));
            let lifecycle_service = LifecycleEventService::new(
                pool.clone(),
                Arc::new(BirthrightPolicyService::new(pool.clone())),
                assignment_service.clone(),
            );

            // Create joiner event using CreateLifecycleEvent struct
            let event = lifecycle_service
                .create(
                    tenant_id,
                    CreateLifecycleEvent {
                        user_id: new_user_id,
                        event_type: LifecycleEventType::Joiner,
                        attributes_before: None,
                        attributes_after: Some(serde_json::json!({
                            "department": "Engineering",
                            "title": "Software Engineer"
                        })),
                        source: Some("integration_test".to_string()),
                    },
                )
                .await
                .expect("Failed to create event");

            // Process joiner event
            let result = lifecycle_service
                .process_event(tenant_id, event.id)
                .await
                .expect("Failed to process joiner");

            // Verify entitlement was provisioned
            assert_eq!(result.summary.provisioned, 1);
            assert_eq!(result.summary.skipped, 0);

            // Verify assignment exists
            let assignments = assignment_service
                .list_user_assignments(tenant_id, new_user_id)
                .await
                .expect("Failed to list assignments");

            assert_eq!(assignments.len(), 1);
            assert_eq!(assignments[0].entitlement_id, entitlement_id);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_joiner_no_matching_policies() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let admin_id = create_test_user(&pool, tenant_id).await;
            let user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

            // Create policy for Sales department
            let policy_service = BirthrightPolicyService::new(pool.clone());
            let conditions = vec![PolicyConditionRequest {
                attribute: "department".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("Sales"),
            }];

            let _policy = policy_service
                .create(
                    tenant_id,
                    "Sales Policy".to_string(),
                    None,
                    100,
                    conditions,
                    vec![entitlement_id],
                    None, // evaluation_mode
                    None, // grace_period_days
                    admin_id,
                )
                .await
                .expect("Failed to create policy");

            // Policy is already Active by default

            let assignment_service = Arc::new(AssignmentService::new(pool.clone()));
            let lifecycle_service = LifecycleEventService::new(
                pool.clone(),
                Arc::new(BirthrightPolicyService::new(pool.clone())),
                assignment_service.clone(),
            );

            // Create joiner for Engineering (not Sales)
            let event = lifecycle_service
                .create(
                    tenant_id,
                    CreateLifecycleEvent {
                        user_id,
                        event_type: LifecycleEventType::Joiner,
                        attributes_before: None,
                        attributes_after: Some(serde_json::json!({"department": "Engineering"})),
                        source: Some("integration_test".to_string()),
                    },
                )
                .await
                .expect("Failed to create event");

            let result = lifecycle_service
                .process_event(tenant_id, event.id)
                .await
                .expect("Failed to process");

            // No provisioning should occur
            assert_eq!(result.summary.provisioned, 0);

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }

    // =========================================================================
    // Leaver Auto-Deprovisioning Tests (US2)
    // =========================================================================

    mod leaver {
        use super::*;
        use xavyo_api_governance::models::PolicyConditionRequest;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_process_leaver_event() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let admin_id = create_test_user(&pool, tenant_id).await;
            let user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

            // Create and enable policy
            let policy_service = BirthrightPolicyService::new(pool.clone());
            let conditions = vec![PolicyConditionRequest {
                attribute: "department".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("HR"),
            }];

            let _policy = policy_service
                .create(
                    tenant_id,
                    "HR Policy".to_string(),
                    None,
                    100,
                    conditions,
                    vec![entitlement_id],
                    None, // evaluation_mode
                    None, // grace_period_days
                    admin_id,
                )
                .await
                .expect("Failed to create policy");

            // Policy is already Active by default

            let assignment_service = Arc::new(AssignmentService::new(pool.clone()));
            let lifecycle_service = LifecycleEventService::new(
                pool.clone(),
                Arc::new(BirthrightPolicyService::new(pool.clone())),
                assignment_service.clone(),
            );

            // First, provision via joiner
            let joiner_event = lifecycle_service
                .create(
                    tenant_id,
                    CreateLifecycleEvent {
                        user_id,
                        event_type: LifecycleEventType::Joiner,
                        attributes_before: None,
                        attributes_after: Some(serde_json::json!({"department": "HR"})),
                        source: Some("integration_test".to_string()),
                    },
                )
                .await
                .expect("Failed to create joiner event");

            lifecycle_service
                .process_event(tenant_id, joiner_event.id)
                .await
                .expect("Joiner failed");

            // Verify assignment exists
            let assignments_before = assignment_service
                .list_user_assignments(tenant_id, user_id)
                .await
                .expect("Failed to list");
            assert_eq!(assignments_before.len(), 1);

            // Create and process leaver event
            let leaver_event = lifecycle_service
                .create(
                    tenant_id,
                    CreateLifecycleEvent {
                        user_id,
                        event_type: LifecycleEventType::Leaver,
                        attributes_before: Some(serde_json::json!({"department": "HR"})),
                        attributes_after: None,
                        source: Some("integration_test".to_string()),
                    },
                )
                .await
                .expect("Failed to create leaver event");

            let result = lifecycle_service
                .process_event(tenant_id, leaver_event.id)
                .await
                .expect("Leaver failed");

            assert_eq!(result.summary.revoked, 1);

            // Verify assignment is revoked (list should return empty for active assignments)
            let assignments_after = assignment_service
                .list_user_assignments(tenant_id, user_id)
                .await
                .expect("Failed to list");
            assert_eq!(assignments_after.len(), 0);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_leaver_creates_snapshot() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let admin_id = create_test_user(&pool, tenant_id).await;
            let user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

            let policy_service = BirthrightPolicyService::new(pool.clone());
            let conditions = vec![PolicyConditionRequest {
                attribute: "department".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("Finance"),
            }];

            let _policy = policy_service
                .create(
                    tenant_id,
                    "Finance Policy".to_string(),
                    None,
                    100,
                    conditions,
                    vec![entitlement_id],
                    None, // evaluation_mode
                    None, // grace_period_days
                    admin_id,
                )
                .await
                .expect("Failed to create policy");

            // Policy is already Active by default

            let assignment_service = Arc::new(AssignmentService::new(pool.clone()));
            let lifecycle_service = LifecycleEventService::new(
                pool.clone(),
                Arc::new(BirthrightPolicyService::new(pool.clone())),
                assignment_service,
            );

            // Joiner first
            let joiner_event = lifecycle_service
                .create(
                    tenant_id,
                    CreateLifecycleEvent {
                        user_id,
                        event_type: LifecycleEventType::Joiner,
                        attributes_before: None,
                        attributes_after: Some(serde_json::json!({"department": "Finance"})),
                        source: Some("integration_test".to_string()),
                    },
                )
                .await
                .expect("Failed to create joiner");

            lifecycle_service
                .process_event(tenant_id, joiner_event.id)
                .await
                .expect("Joiner failed");

            // Leaver
            let leaver_event = lifecycle_service
                .create(
                    tenant_id,
                    CreateLifecycleEvent {
                        user_id,
                        event_type: LifecycleEventType::Leaver,
                        attributes_before: Some(serde_json::json!({"department": "Finance"})),
                        attributes_after: None,
                        source: Some("integration_test".to_string()),
                    },
                )
                .await
                .expect("Failed to create leaver");

            let result = lifecycle_service
                .process_event(tenant_id, leaver_event.id)
                .await
                .expect("Leaver failed");

            // Verify snapshot was created
            assert!(result.snapshot.is_some());

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }

    // =========================================================================
    // Mover Access Adjustment Tests (US3)
    // =========================================================================

    mod mover {
        use super::*;
        use xavyo_api_governance::models::PolicyConditionRequest;
        use xavyo_db::LifecycleActionFilter;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_process_mover_event() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let admin_id = create_test_user(&pool, tenant_id).await;
            let user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let eng_entitlement = create_test_entitlement(&pool, tenant_id, app_id, None).await;
            let sales_entitlement = create_test_entitlement(&pool, tenant_id, app_id, None).await;

            let policy_service = BirthrightPolicyService::new(pool.clone());

            // Engineering policy with grace period
            let _eng_policy = policy_service
                .create(
                    tenant_id,
                    "Engineering Policy".to_string(),
                    None,
                    100,
                    vec![PolicyConditionRequest {
                        attribute: "department".to_string(),
                        operator: ConditionOperator::Equals,
                        value: serde_json::json!("Engineering"),
                    }],
                    vec![eng_entitlement],
                    None,    // evaluation_mode
                    Some(7), // 7 day grace period
                    admin_id,
                )
                .await
                .expect("Failed to create eng policy");

            // Policy is already Active by default

            // Sales policy
            let _sales_policy = policy_service
                .create(
                    tenant_id,
                    "Sales Policy".to_string(),
                    None,
                    100,
                    vec![PolicyConditionRequest {
                        attribute: "department".to_string(),
                        operator: ConditionOperator::Equals,
                        value: serde_json::json!("Sales"),
                    }],
                    vec![sales_entitlement],
                    None,    // evaluation_mode
                    Some(7), // grace_period_days
                    admin_id,
                )
                .await
                .expect("Failed to create sales policy");

            // Sales policy is also already Active by default

            let assignment_service = Arc::new(AssignmentService::new(pool.clone()));
            let lifecycle_service = LifecycleEventService::new(
                pool.clone(),
                Arc::new(BirthrightPolicyService::new(pool.clone())),
                assignment_service.clone(),
            );

            // Start in Engineering
            let joiner_event = lifecycle_service
                .create(
                    tenant_id,
                    CreateLifecycleEvent {
                        user_id,
                        event_type: LifecycleEventType::Joiner,
                        attributes_before: None,
                        attributes_after: Some(serde_json::json!({"department": "Engineering"})),
                        source: Some("integration_test".to_string()),
                    },
                )
                .await
                .expect("Failed to create joiner");

            lifecycle_service
                .process_event(tenant_id, joiner_event.id)
                .await
                .expect("Joiner failed");

            // Move to Sales
            let mover_event = lifecycle_service
                .create(
                    tenant_id,
                    CreateLifecycleEvent {
                        user_id,
                        event_type: LifecycleEventType::Mover,
                        attributes_before: Some(serde_json::json!({"department": "Engineering"})),
                        attributes_after: Some(serde_json::json!({"department": "Sales"})),
                        source: Some("integration_test".to_string()),
                    },
                )
                .await
                .expect("Failed to create mover");

            let result = lifecycle_service
                .process_event(tenant_id, mover_event.id)
                .await
                .expect("Mover failed");

            // Should provision Sales and schedule revocation of Engineering
            assert_eq!(result.summary.provisioned, 1); // Sales
            assert_eq!(result.summary.scheduled, 1); // Engineering revocation scheduled

            // Check scheduled action exists
            let (actions, _) = lifecycle_service
                .list_actions(
                    tenant_id,
                    &LifecycleActionFilter {
                        event_id: Some(result.event.id),
                        action_type: Some(LifecycleActionType::ScheduleRevoke),
                        assignment_id: None,
                        pending: Some(true),
                    },
                    10,
                    0,
                )
                .await
                .expect("Failed to list actions");

            assert_eq!(actions.len(), 1);
            assert!(actions[0].scheduled_at.is_some());

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }

    // =========================================================================
    // Lifecycle Event Management Tests (US5)
    // =========================================================================

    mod event_management {
        use super::*;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_list_lifecycle_events() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let user_id = create_test_user(&pool, tenant_id).await;

            let assignment_service = Arc::new(AssignmentService::new(pool.clone()));
            let lifecycle_service = LifecycleEventService::new(
                pool.clone(),
                Arc::new(BirthrightPolicyService::new(pool.clone())),
                assignment_service,
            );

            // Create multiple events
            lifecycle_service
                .create(
                    tenant_id,
                    CreateLifecycleEvent {
                        user_id,
                        event_type: LifecycleEventType::Joiner,
                        attributes_before: None,
                        attributes_after: Some(serde_json::json!({"department": "HR"})),
                        source: Some("integration_test".to_string()),
                    },
                )
                .await
                .expect("Failed to create event 1");

            lifecycle_service
                .create(
                    tenant_id,
                    CreateLifecycleEvent {
                        user_id,
                        event_type: LifecycleEventType::Mover,
                        attributes_before: Some(serde_json::json!({"department": "HR"})),
                        attributes_after: Some(serde_json::json!({"department": "Sales"})),
                        source: Some("integration_test".to_string()),
                    },
                )
                .await
                .expect("Failed to create event 2");

            // List all events for user
            let (events, total) = lifecycle_service
                .list(
                    tenant_id,
                    &LifecycleEventFilter {
                        user_id: Some(user_id),
                        event_type: None,
                        from: None,
                        to: None,
                        processed: None,
                    },
                    10,
                    0,
                )
                .await
                .expect("Failed to list events");

            assert_eq!(total, 2);
            assert_eq!(events.len(), 2);

            // List only joiner events
            let (joiner_events, joiner_total) = lifecycle_service
                .list(
                    tenant_id,
                    &LifecycleEventFilter {
                        user_id: Some(user_id),
                        event_type: Some(LifecycleEventType::Joiner),
                        from: None,
                        to: None,
                        processed: None,
                    },
                    10,
                    0,
                )
                .await
                .expect("Failed to list joiner events");

            assert_eq!(joiner_total, 1);
            assert_eq!(joiner_events.len(), 1);
            assert_eq!(joiner_events[0].event_type, LifecycleEventType::Joiner);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_get_event_with_actions() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let admin_id = create_test_user(&pool, tenant_id).await;
            let user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

            // Create and enable policy
            let policy_service = BirthrightPolicyService::new(pool.clone());
            let _policy = policy_service
                .create(
                    tenant_id,
                    "Test Policy".to_string(),
                    None,
                    100,
                    vec![xavyo_api_governance::models::PolicyConditionRequest {
                        attribute: "department".to_string(),
                        operator: ConditionOperator::Equals,
                        value: serde_json::json!("Test"),
                    }],
                    vec![entitlement_id],
                    None, // evaluation_mode
                    None, // grace_period_days
                    admin_id,
                )
                .await
                .expect("Failed to create policy");

            // Policy is already Active by default

            let assignment_service = Arc::new(AssignmentService::new(pool.clone()));
            let lifecycle_service = LifecycleEventService::new(
                pool.clone(),
                Arc::new(BirthrightPolicyService::new(pool.clone())),
                assignment_service,
            );

            // Create and process event
            let event = lifecycle_service
                .create(
                    tenant_id,
                    CreateLifecycleEvent {
                        user_id,
                        event_type: LifecycleEventType::Joiner,
                        attributes_before: None,
                        attributes_after: Some(serde_json::json!({"department": "Test"})),
                        source: Some("integration_test".to_string()),
                    },
                )
                .await
                .expect("Failed to create event");

            lifecycle_service
                .process_event(tenant_id, event.id)
                .await
                .expect("Failed to process");

            // Get event actions
            let actions = lifecycle_service
                .get_event_actions(event.id)
                .await
                .expect("Failed to get actions");

            assert!(!actions.is_empty());
            assert_eq!(actions[0].event_id, event.id);

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }
}
