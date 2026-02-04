//! Integration tests for xavyo-api-governance Access Request Workflows (F035).
//!
//! These tests require a running `PostgreSQL` database with the test schema.
//! Run with: `cargo test -p xavyo-api-governance --features integration`

mod common;

#[cfg(feature = "integration")]
mod integration_tests {
    use super::common::*;
    use chrono::{Duration, Utc};
    use xavyo_api_governance::services::{
        AccessRequestService, ApprovalService, ApprovalWorkflowService, DelegationService,
    };
    use xavyo_db::models::{GovApproverType, GovRequestStatus};

    // =========================================================================
    // T016: Access Request Submission Tests
    // =========================================================================

    mod access_requests {
        use super::*;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_submit_access_request() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

            let service = AccessRequestService::new(pool.clone());

            // Submit a valid request
            let result = service
                .create_request(
                    tenant_id,
                    user_id,
                    entitlement_id,
                    "This is a business justification that is long enough to pass validation"
                        .to_string(),
                    None,
                )
                .await;

            assert!(
                result.is_ok(),
                "Failed to create request: {:?}",
                result.err()
            );
            let request = result.unwrap();
            assert_eq!(request.requester_id, user_id);
            assert_eq!(request.entitlement_id, entitlement_id);
            assert!(request.status.is_pending());

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_submit_request_short_justification() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

            let service = AccessRequestService::new(pool.clone());

            // Try to submit with too short justification
            let result = service
                .create_request(
                    tenant_id,
                    user_id,
                    entitlement_id,
                    "Too short".to_string(),
                    None,
                )
                .await;

            assert!(result.is_err());

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_list_my_requests() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

            let service = AccessRequestService::new(pool.clone());

            // Create a request
            service
                .create_request(
                    tenant_id,
                    user_id,
                    entitlement_id,
                    "This is a business justification that is long enough".to_string(),
                    None,
                )
                .await
                .expect("Failed to create request");

            // List requests
            let (requests, total) = service
                .list_my_requests(tenant_id, user_id, None, 10, 0)
                .await
                .expect("Failed to list requests");

            assert_eq!(total, 1);
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].requester_id, user_id);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_cancel_request() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

            let service = AccessRequestService::new(pool.clone());

            // Create a request
            let request = service
                .create_request(
                    tenant_id,
                    user_id,
                    entitlement_id,
                    "This is a business justification that is long enough".to_string(),
                    None,
                )
                .await
                .expect("Failed to create request");

            // Cancel the request
            let cancelled = service
                .cancel_request(tenant_id, request.id, user_id)
                .await
                .expect("Failed to cancel request");

            assert!(matches!(cancelled.status, GovRequestStatus::Cancelled));

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }

    // =========================================================================
    // T028: Approval Flow Tests
    // =========================================================================

    mod approvals {
        use super::*;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_approve_request() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let requester_id = create_test_user(&pool, tenant_id).await;
            let approver_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id =
                create_test_entitlement(&pool, tenant_id, app_id, Some(approver_id)).await;

            // Create workflow with EntitlementOwner as approver
            let workflow_service = ApprovalWorkflowService::new(pool.clone());
            let _workflow = workflow_service
                .create_workflow(
                    tenant_id,
                    "Test Workflow".to_string(),
                    None,
                    true, // default
                    vec![xavyo_api_governance::services::CreateStepInput {
                        approver_type: GovApproverType::EntitlementOwner,
                        specific_approvers: None,
                    }],
                )
                .await
                .expect("Failed to create workflow");

            // Submit request
            let access_service = AccessRequestService::new(pool.clone());
            let request = access_service
                .create_request(
                    tenant_id,
                    requester_id,
                    entitlement_id,
                    "This is a business justification that is long enough".to_string(),
                    None,
                )
                .await
                .expect("Failed to create request");

            // Approve
            let approval_service = ApprovalService::new(pool.clone());
            let result = approval_service
                .approve_request(
                    tenant_id,
                    request.id,
                    approver_id,
                    Some("Approved".to_string()),
                )
                .await
                .expect("Failed to approve");

            assert!(matches!(result.new_status, GovRequestStatus::Provisioned));
            assert!(result.provisioned_assignment_id.is_some());

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_reject_request() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let requester_id = create_test_user(&pool, tenant_id).await;
            let approver_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id =
                create_test_entitlement(&pool, tenant_id, app_id, Some(approver_id)).await;

            // Create workflow
            let workflow_service = ApprovalWorkflowService::new(pool.clone());
            workflow_service
                .create_workflow(
                    tenant_id,
                    "Test Workflow".to_string(),
                    None,
                    true,
                    vec![xavyo_api_governance::services::CreateStepInput {
                        approver_type: GovApproverType::EntitlementOwner,
                        specific_approvers: None,
                    }],
                )
                .await
                .expect("Failed to create workflow");

            // Submit request
            let access_service = AccessRequestService::new(pool.clone());
            let request = access_service
                .create_request(
                    tenant_id,
                    requester_id,
                    entitlement_id,
                    "This is a business justification that is long enough".to_string(),
                    None,
                )
                .await
                .expect("Failed to create request");

            // Reject
            let approval_service = ApprovalService::new(pool.clone());
            let result = approval_service
                .reject_request(
                    tenant_id,
                    request.id,
                    approver_id,
                    "Not appropriate access".to_string(),
                )
                .await
                .expect("Failed to reject");

            assert!(matches!(result.new_status, GovRequestStatus::Rejected));
            assert!(result.provisioned_assignment_id.is_none());

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_self_approval_prevented() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id =
                create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

            // Create workflow with user as entitlement owner
            let workflow_service = ApprovalWorkflowService::new(pool.clone());
            workflow_service
                .create_workflow(
                    tenant_id,
                    "Test Workflow".to_string(),
                    None,
                    true,
                    vec![xavyo_api_governance::services::CreateStepInput {
                        approver_type: GovApproverType::EntitlementOwner,
                        specific_approvers: None,
                    }],
                )
                .await
                .expect("Failed to create workflow");

            // Submit request (user is also the owner)
            let access_service = AccessRequestService::new(pool.clone());
            let request = access_service
                .create_request(
                    tenant_id,
                    user_id,
                    entitlement_id,
                    "This is a business justification that is long enough".to_string(),
                    None,
                )
                .await
                .expect("Failed to create request");

            // Try self-approval - should fail
            let approval_service = ApprovalService::new(pool.clone());
            let result = approval_service
                .approve_request(tenant_id, request.id, user_id, None)
                .await;

            assert!(result.is_err());

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }

    // =========================================================================
    // T041: Multi-Level Workflow Tests
    // =========================================================================

    mod multi_level_workflows {
        use super::*;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_two_level_approval_chain() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let requester_id = create_test_user(&pool, tenant_id).await;
            let approver1_id = create_test_user(&pool, tenant_id).await;
            let approver2_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

            // Create two-level workflow with specific approvers
            let workflow_service = ApprovalWorkflowService::new(pool.clone());
            workflow_service
                .create_workflow(
                    tenant_id,
                    "Two Level Workflow".to_string(),
                    Some("Manager then owner".to_string()),
                    true,
                    vec![
                        xavyo_api_governance::services::CreateStepInput {
                            approver_type: GovApproverType::SpecificUsers,
                            specific_approvers: Some(vec![approver1_id]),
                        },
                        xavyo_api_governance::services::CreateStepInput {
                            approver_type: GovApproverType::SpecificUsers,
                            specific_approvers: Some(vec![approver2_id]),
                        },
                    ],
                )
                .await
                .expect("Failed to create workflow");

            // Submit request
            let access_service = AccessRequestService::new(pool.clone());
            let request = access_service
                .create_request(
                    tenant_id,
                    requester_id,
                    entitlement_id,
                    "This is a business justification that is long enough".to_string(),
                    None,
                )
                .await
                .expect("Failed to create request");

            // First approval
            let approval_service = ApprovalService::new(pool.clone());
            let result1 = approval_service
                .approve_request(
                    tenant_id,
                    request.id,
                    approver1_id,
                    Some("Level 1 OK".to_string()),
                )
                .await
                .expect("Failed first approval");

            // Should still be pending (not provisioned yet)
            assert!(matches!(
                result1.new_status,
                GovRequestStatus::PendingApproval
            ));
            assert!(result1.provisioned_assignment_id.is_none());

            // Second approval
            let result2 = approval_service
                .approve_request(
                    tenant_id,
                    request.id,
                    approver2_id,
                    Some("Level 2 OK".to_string()),
                )
                .await
                .expect("Failed second approval");

            // Now should be provisioned
            assert!(matches!(result2.new_status, GovRequestStatus::Provisioned));
            assert!(result2.provisioned_assignment_id.is_some());

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }

    // =========================================================================
    // T048: Workflow Configuration Tests
    // =========================================================================

    mod workflow_configuration {
        use super::*;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_create_workflow() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = ApprovalWorkflowService::new(pool.clone());

            let workflow = service
                .create_workflow(
                    tenant_id,
                    "Test Workflow".to_string(),
                    Some("A test workflow".to_string()),
                    false,
                    vec![xavyo_api_governance::services::CreateStepInput {
                        approver_type: GovApproverType::EntitlementOwner,
                        specific_approvers: None,
                    }],
                )
                .await
                .expect("Failed to create workflow");

            assert_eq!(workflow.workflow.name, "Test Workflow");
            assert_eq!(workflow.steps.len(), 1);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_workflow_step_limit() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = ApprovalWorkflowService::new(pool.clone());

            // Try to create workflow with 6 steps (max is 5)
            let result = service
                .create_workflow(
                    tenant_id,
                    "Too Many Steps".to_string(),
                    None,
                    false,
                    vec![
                        xavyo_api_governance::services::CreateStepInput {
                            approver_type: GovApproverType::EntitlementOwner,
                            specific_approvers: None,
                        };
                        6
                    ],
                )
                .await;

            assert!(result.is_err());

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_set_default_workflow() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;

            let service = ApprovalWorkflowService::new(pool.clone());

            // Create first workflow as default
            let workflow1 = service
                .create_workflow(
                    tenant_id,
                    "First Workflow".to_string(),
                    None,
                    true,
                    vec![xavyo_api_governance::services::CreateStepInput {
                        approver_type: GovApproverType::EntitlementOwner,
                        specific_approvers: None,
                    }],
                )
                .await
                .expect("Failed to create first workflow");

            assert!(workflow1.workflow.is_default);

            // Create second workflow and set as default
            let workflow2 = service
                .create_workflow(
                    tenant_id,
                    "Second Workflow".to_string(),
                    None,
                    false,
                    vec![xavyo_api_governance::services::CreateStepInput {
                        approver_type: GovApproverType::EntitlementOwner,
                        specific_approvers: None,
                    }],
                )
                .await
                .expect("Failed to create second workflow");

            // Set second as default
            let updated = service
                .set_default_workflow(tenant_id, workflow2.workflow.id)
                .await
                .expect("Failed to set default");

            assert!(updated.workflow.is_default);

            // Verify first is no longer default
            let first = service
                .get_workflow(tenant_id, workflow1.workflow.id)
                .await
                .expect("Failed to get first workflow");

            assert!(!first.workflow.is_default);

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }

    // =========================================================================
    // T061: Delegation Tests
    // =========================================================================

    mod delegations {
        use super::*;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_create_delegation() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let delegator_id = create_test_user(&pool, tenant_id).await;
            let delegate_id = create_test_user(&pool, tenant_id).await;

            let service = DelegationService::new(pool.clone());

            let starts_at = Utc::now() + Duration::hours(1);
            let ends_at = Utc::now() + Duration::days(7);

            let delegation = service
                .create_delegation(tenant_id, delegator_id, delegate_id, starts_at, ends_at)
                .await
                .expect("Failed to create delegation");

            assert_eq!(delegation.delegator_id, delegator_id);
            assert_eq!(delegation.delegate_id, delegate_id);
            assert!(delegation.is_active);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_self_delegation_prevented() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let user_id = create_test_user(&pool, tenant_id).await;

            let service = DelegationService::new(pool.clone());

            let starts_at = Utc::now() + Duration::hours(1);
            let ends_at = Utc::now() + Duration::days(7);

            let result = service
                .create_delegation(tenant_id, user_id, user_id, starts_at, ends_at)
                .await;

            assert!(result.is_err());

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_revoke_delegation() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let delegator_id = create_test_user(&pool, tenant_id).await;
            let delegate_id = create_test_user(&pool, tenant_id).await;

            let service = DelegationService::new(pool.clone());

            let starts_at = Utc::now() - Duration::hours(1); // Already started
            let ends_at = Utc::now() + Duration::days(7);

            let delegation = service
                .create_delegation(tenant_id, delegator_id, delegate_id, starts_at, ends_at)
                .await
                .expect("Failed to create delegation");

            // Revoke
            let revoked = service
                .revoke_delegation(tenant_id, delegation.id, delegator_id)
                .await
                .expect("Failed to revoke delegation");

            assert!(!revoked.is_active);

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_delegate_can_approve() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let requester_id = create_test_user(&pool, tenant_id).await;
            let approver_id = create_test_user(&pool, tenant_id).await;
            let delegate_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

            // Create workflow with specific approver
            let workflow_service = ApprovalWorkflowService::new(pool.clone());
            workflow_service
                .create_workflow(
                    tenant_id,
                    "Test Workflow".to_string(),
                    None,
                    true,
                    vec![xavyo_api_governance::services::CreateStepInput {
                        approver_type: GovApproverType::SpecificUsers,
                        specific_approvers: Some(vec![approver_id]),
                    }],
                )
                .await
                .expect("Failed to create workflow");

            // Create delegation (starts immediately)
            let delegation_service = DelegationService::new(pool.clone());
            delegation_service
                .create_delegation(
                    tenant_id,
                    approver_id,
                    delegate_id,
                    Utc::now() - Duration::hours(1),
                    Utc::now() + Duration::days(7),
                )
                .await
                .expect("Failed to create delegation");

            // Submit request
            let access_service = AccessRequestService::new(pool.clone());
            let request = access_service
                .create_request(
                    tenant_id,
                    requester_id,
                    entitlement_id,
                    "This is a business justification that is long enough".to_string(),
                    None,
                )
                .await
                .expect("Failed to create request");

            // Delegate approves
            let approval_service = ApprovalService::new(pool.clone());
            let result = approval_service
                .approve_request(
                    tenant_id,
                    request.id,
                    delegate_id,
                    Some("Approved by delegate".to_string()),
                )
                .await
                .expect("Delegate approval failed");

            assert!(matches!(result.new_status, GovRequestStatus::Provisioned));

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }
}
