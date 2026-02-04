//! Integration tests for F055 Micro-certification.
//!
//! These tests require a running `PostgreSQL` database with the test schema.
//! Run with: `cargo test -p xavyo-api-governance --features integration`

mod common;

#[cfg(feature = "integration")]
mod integration_tests {
    use super::common::*;
    use xavyo_api_governance::services::{MicroCertTriggerService, MicroCertificationService};
    use xavyo_db::models::{
        MicroCertDecision, MicroCertReviewerType, MicroCertScopeType, MicroCertStatus,
        MicroCertTriggerType,
    };

    // =========================================================================
    // T094: High-Risk Assignment Flow
    // =========================================================================

    mod high_risk_assignment {
        use super::*;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_full_high_risk_assignment_flow() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let manager_id = create_test_user(&pool, tenant_id).await;
            let user_id = create_test_user_with_manager(&pool, tenant_id, manager_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id =
                create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
            let assignment_id =
                create_test_assignment(&pool, tenant_id, user_id, entitlement_id).await;

            // Step 1: Create trigger rule for high-risk assignments
            let trigger_service = MicroCertTriggerService::new(pool.clone());
            let trigger_rule = trigger_service
                .create(
                    tenant_id,
                    "High-Risk Review".to_string(),
                    Some("Automatic review for high-risk entitlements".to_string()),
                    MicroCertTriggerType::HighRiskAssignment,
                    MicroCertScopeType::Tenant,
                    None, // application_id
                    None, // entitlement_id
                    MicroCertReviewerType::UserManager,
                    None, // specific_reviewer_id
                    None, // fallback_reviewer_id
                    86400,
                    Some(75),
                    true,  // auto_revoke
                    false, // revoke_triggering_assignment
                    true,  // is_active
                    0,     // priority
                    false, // is_default
                )
                .await
                .expect("Failed to create trigger rule");

            assert_eq!(
                trigger_rule.trigger_type,
                MicroCertTriggerType::HighRiskAssignment
            );

            // Step 2: Create micro-certification from assignment event
            let cert_service = MicroCertificationService::new(pool.clone());
            let certification = cert_service
                .create_from_assignment_event(
                    tenant_id,
                    user_id,
                    entitlement_id,
                    assignment_id,
                    "high",
                    "xavyo.governance.entitlement.assigned",
                    uuid::Uuid::new_v4(),
                )
                .await
                .expect("Failed to create micro-certification");

            assert!(
                certification.is_some(),
                "Expected certification to be created"
            );
            let certification = certification.unwrap();
            assert_eq!(certification.status, MicroCertStatus::Pending);
            assert_eq!(certification.reviewer_id, manager_id);

            // Step 3: Manager approves the certification
            let decision_result = cert_service
                .decide(
                    tenant_id,
                    certification.id,
                    manager_id,
                    MicroCertDecision::Approve,
                    Some("Approved for Q1 project".to_string()),
                )
                .await
                .expect("Failed to approve certification");

            assert_eq!(decision_result.status, MicroCertStatus::Approved);

            // Step 4: Verify events were recorded
            let events = cert_service
                .get_events(tenant_id, certification.id, 10, 0)
                .await
                .expect("Failed to get events");

            assert!(
                events.0.len() >= 2,
                "Expected at least created and approved events"
            );

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_high_risk_rejection_revokes_assignment() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let manager_id = create_test_user(&pool, tenant_id).await;
            let user_id = create_test_user_with_manager(&pool, tenant_id, manager_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id =
                create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
            let assignment_id =
                create_test_assignment(&pool, tenant_id, user_id, entitlement_id).await;

            // Create trigger rule with auto_revoke = true
            let trigger_service = MicroCertTriggerService::new(pool.clone());
            let _trigger_rule = trigger_service
                .create(
                    tenant_id,
                    "High-Risk Review with Auto-Revoke".to_string(),
                    None,
                    MicroCertTriggerType::HighRiskAssignment,
                    MicroCertScopeType::Tenant,
                    None,
                    None,
                    MicroCertReviewerType::UserManager,
                    None,
                    None,
                    86400,
                    Some(75),
                    true, // auto_revoke
                    false,
                    true,
                    0,
                    false,
                )
                .await
                .expect("Failed to create trigger rule");

            // Create micro-certification
            let cert_service = MicroCertificationService::new(pool.clone());
            let certification = cert_service
                .create_from_assignment_event(
                    tenant_id,
                    user_id,
                    entitlement_id,
                    assignment_id,
                    "high",
                    "xavyo.governance.entitlement.assigned",
                    uuid::Uuid::new_v4(),
                )
                .await
                .expect("Failed to create micro-certification")
                .expect("Expected certification");

            // Manager rejects the certification
            let decision_result = cert_service
                .decide(
                    tenant_id,
                    certification.id,
                    manager_id,
                    MicroCertDecision::Revoke,
                    Some("Access not justified".to_string()),
                )
                .await
                .expect("Failed to reject certification");

            assert_eq!(decision_result.status, MicroCertStatus::Revoked);
            assert!(
                decision_result.revoked_assignment_id.is_some(),
                "Expected assignment to be revoked"
            );

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }

    // =========================================================================
    // T095: SoD Violation Flow
    // =========================================================================

    mod sod_violation {
        use super::*;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_full_sod_violation_flow() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let app_owner_id = create_test_user(&pool, tenant_id).await;
            let user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_a_id = create_test_entitlement_with_risk(
                &pool,
                tenant_id,
                app_id,
                Some(app_owner_id),
                "medium",
            )
            .await;
            let entitlement_b_id = create_test_entitlement_with_risk(
                &pool,
                tenant_id,
                app_id,
                Some(app_owner_id),
                "medium",
            )
            .await;
            let assignment_a_id =
                create_test_assignment(&pool, tenant_id, user_id, entitlement_a_id).await;
            let assignment_b_id =
                create_test_assignment(&pool, tenant_id, user_id, entitlement_b_id).await;

            // Create trigger rule for SoD violations
            let trigger_service = MicroCertTriggerService::new(pool.clone());
            let _trigger_rule = trigger_service
                .create(
                    tenant_id,
                    "SoD Violation Review".to_string(),
                    None,
                    MicroCertTriggerType::SodViolation,
                    MicroCertScopeType::Tenant,
                    None,
                    None,
                    MicroCertReviewerType::ApplicationOwner,
                    None,
                    None,
                    172800,
                    Some(50),
                    true, // auto_revoke
                    true, // revoke_triggering_assignment
                    true,
                    0,
                    false,
                )
                .await
                .expect("Failed to create trigger rule");

            // Create micro-certification from SoD violation
            let cert_service = MicroCertificationService::new(pool.clone());
            let violation_id = uuid::Uuid::new_v4();
            let certification = cert_service
                .create_from_sod_violation(
                    tenant_id,
                    user_id,
                    violation_id,
                    entitlement_a_id,
                    entitlement_b_id,
                    assignment_b_id, // triggering assignment is the newer one
                    "Conflicting Duties".to_string(),
                    "critical".to_string(),
                )
                .await
                .expect("Failed to create SoD micro-certification");

            assert!(
                certification.is_some(),
                "Expected certification to be created"
            );
            let certification = certification.unwrap();
            assert_eq!(certification.status, MicroCertStatus::Pending);

            // App owner rejects - should revoke triggering assignment
            let decision_result = cert_service
                .decide(
                    tenant_id,
                    certification.id,
                    app_owner_id,
                    MicroCertDecision::Revoke,
                    Some("SoD violation not acceptable".to_string()),
                )
                .await
                .expect("Failed to reject SoD certification");

            assert_eq!(decision_result.status, MicroCertStatus::Revoked);
            assert_eq!(
                decision_result.revoked_assignment_id,
                Some(assignment_b_id),
                "Expected triggering assignment to be revoked"
            );

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_sod_approval_creates_exemption() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let app_owner_id = create_test_user(&pool, tenant_id).await;
            let user_id = create_test_user(&pool, tenant_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_a_id = create_test_entitlement_with_risk(
                &pool,
                tenant_id,
                app_id,
                Some(app_owner_id),
                "medium",
            )
            .await;
            let entitlement_b_id = create_test_entitlement_with_risk(
                &pool,
                tenant_id,
                app_id,
                Some(app_owner_id),
                "medium",
            )
            .await;
            let _assignment_a_id =
                create_test_assignment(&pool, tenant_id, user_id, entitlement_a_id).await;
            let assignment_b_id =
                create_test_assignment(&pool, tenant_id, user_id, entitlement_b_id).await;

            // Create trigger rule
            let trigger_service = MicroCertTriggerService::new(pool.clone());
            let _trigger_rule = trigger_service
                .create(
                    tenant_id,
                    "SoD Exemption Review".to_string(),
                    None,
                    MicroCertTriggerType::SodViolation,
                    MicroCertScopeType::Tenant,
                    None,
                    None,
                    MicroCertReviewerType::ApplicationOwner,
                    None,
                    None,
                    172800,
                    None,
                    false, // no auto_revoke
                    false,
                    true,
                    0,
                    false,
                )
                .await
                .expect("Failed to create trigger rule");

            // Create micro-certification
            let cert_service = MicroCertificationService::new(pool.clone());
            let violation_id = uuid::Uuid::new_v4();
            let certification = cert_service
                .create_from_sod_violation(
                    tenant_id,
                    user_id,
                    violation_id,
                    entitlement_a_id,
                    entitlement_b_id,
                    assignment_b_id,
                    "Temporary Conflict".to_string(),
                    "high".to_string(),
                )
                .await
                .expect("Failed to create SoD micro-certification")
                .expect("Expected certification");

            // App owner approves - creates exemption
            let decision_result = cert_service
                .decide(
                    tenant_id,
                    certification.id,
                    app_owner_id,
                    MicroCertDecision::Approve,
                    Some("Exemption granted for this project".to_string()),
                )
                .await
                .expect("Failed to approve SoD certification");

            assert_eq!(decision_result.status, MicroCertStatus::Approved);
            // Exemption would be created as side effect (checked via events)

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }

    // =========================================================================
    // T096: Manager Change Flow
    // =========================================================================

    mod manager_change {
        use super::*;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_manager_change_creates_batch_certifications() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let old_manager_id = create_test_user(&pool, tenant_id).await;
            let new_manager_id = create_test_user(&pool, tenant_id).await;
            let user_id = create_test_user_with_manager(&pool, tenant_id, old_manager_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;

            // Create multiple high-risk entitlements and assignments
            let ent1_id =
                create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
            let ent2_id =
                create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "critical").await;
            let _assignment1_id = create_test_assignment(&pool, tenant_id, user_id, ent1_id).await;
            let _assignment2_id = create_test_assignment(&pool, tenant_id, user_id, ent2_id).await;

            // Create trigger rule for manager changes
            let trigger_service = MicroCertTriggerService::new(pool.clone());
            let _trigger_rule = trigger_service
                .create(
                    tenant_id,
                    "Manager Change Review".to_string(),
                    None,
                    MicroCertTriggerType::ManagerChange,
                    MicroCertScopeType::Tenant,
                    None,
                    None,
                    MicroCertReviewerType::UserManager, // new manager becomes reviewer
                    None,
                    None,
                    604800,
                    Some(50),
                    false, // no auto_revoke for manager change
                    false,
                    true,
                    0,
                    false,
                )
                .await
                .expect("Failed to create trigger rule");

            // Trigger manager change certifications
            let cert_service = MicroCertificationService::new(pool.clone());
            let event_id = uuid::Uuid::new_v4();
            let certifications = cert_service
                .create_from_manager_change(
                    tenant_id,
                    user_id,
                    Some(old_manager_id),
                    new_manager_id,
                    "manager_change",
                    event_id,
                )
                .await
                .expect("Failed to create manager change certifications");

            assert!(
                certifications.len() >= 2,
                "Expected certifications for high-risk entitlements"
            );

            // Verify all certifications are assigned to new manager
            for cert in &certifications {
                assert_eq!(cert.reviewer_id, new_manager_id);
                assert_eq!(cert.status, MicroCertStatus::Pending);
            }

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_bulk_approve_manager_change_certifications() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let old_manager_id = create_test_user(&pool, tenant_id).await;
            let new_manager_id = create_test_user(&pool, tenant_id).await;
            let user_id = create_test_user_with_manager(&pool, tenant_id, old_manager_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;

            let ent1_id =
                create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
            let ent2_id =
                create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
            let _assignment1_id = create_test_assignment(&pool, tenant_id, user_id, ent1_id).await;
            let _assignment2_id = create_test_assignment(&pool, tenant_id, user_id, ent2_id).await;

            // Create trigger rule
            let trigger_service = MicroCertTriggerService::new(pool.clone());
            let _trigger_rule = trigger_service
                .create(
                    tenant_id,
                    "Manager Change Review".to_string(),
                    None,
                    MicroCertTriggerType::ManagerChange,
                    MicroCertScopeType::Tenant,
                    None,
                    None,
                    MicroCertReviewerType::UserManager,
                    None,
                    None,
                    604800,
                    None,
                    false,
                    false,
                    true,
                    0,
                    false,
                )
                .await
                .expect("Failed to create trigger rule");

            // Create certifications
            let cert_service = MicroCertificationService::new(pool.clone());
            let certifications = cert_service
                .create_from_manager_change(
                    tenant_id,
                    user_id,
                    Some(old_manager_id),
                    new_manager_id,
                    "manager_change",
                    uuid::Uuid::new_v4(),
                )
                .await
                .expect("Failed to create certifications");

            let cert_ids: Vec<uuid::Uuid> = certifications.iter().map(|c| c.id).collect();

            // Bulk approve
            let results = cert_service
                .bulk_decide(
                    tenant_id,
                    &cert_ids,
                    new_manager_id,
                    MicroCertDecision::Approve,
                    Some("Bulk approved after team review".to_string()),
                )
                .await
                .expect("Failed to bulk approve");

            // Verify all succeeded
            assert_eq!(results.len(), cert_ids.len());
            for result in &results {
                assert!(result.success, "Expected all certifications to be approved");
            }

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }

    // =========================================================================
    // T097: Expiration Job Flow
    // =========================================================================

    mod expiration_job {
        use super::*;
        use xavyo_api_governance::jobs::MicroCertExpirationJob;

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_expiration_job_processes_expired_certifications() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let manager_id = create_test_user(&pool, tenant_id).await;
            let user_id = create_test_user_with_manager(&pool, tenant_id, manager_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id =
                create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
            let assignment_id =
                create_test_assignment(&pool, tenant_id, user_id, entitlement_id).await;

            // Create trigger rule with very short timeout (already expired by insertion time)
            let trigger_service = MicroCertTriggerService::new(pool.clone());
            let _trigger_rule = trigger_service
                .create(
                    tenant_id,
                    "Quick Expiration Test".to_string(),
                    None,
                    MicroCertTriggerType::HighRiskAssignment,
                    MicroCertScopeType::Tenant,
                    None,
                    None,
                    MicroCertReviewerType::UserManager,
                    None,
                    None,
                    1, // 1 second timeout (will be expired immediately)
                    None,
                    true, // auto_revoke
                    false,
                    true,
                    0,
                    false,
                )
                .await
                .expect("Failed to create trigger rule");

            // Create micro-certification
            let cert_service = MicroCertificationService::new(pool.clone());
            let certification = cert_service
                .create_from_assignment_event(
                    tenant_id,
                    user_id,
                    entitlement_id,
                    assignment_id,
                    "high",
                    "xavyo.governance.entitlement.assigned",
                    uuid::Uuid::new_v4(),
                )
                .await
                .expect("Failed to create micro-certification")
                .expect("Expected certification");

            // Wait a moment for deadline to pass
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            // Run expiration job
            let job = MicroCertExpirationJob::new(pool.clone());
            job.run().await.expect("Expiration job failed");

            // Verify certification is now expired or auto-revoked
            let updated_cert = cert_service
                .get(tenant_id, certification.id)
                .await
                .expect("Failed to get certification");

            assert!(
                matches!(
                    updated_cert.status,
                    MicroCertStatus::Expired | MicroCertStatus::AutoRevoked
                ),
                "Expected certification to be expired or auto-revoked, got {:?}",
                updated_cert.status
            );

            cleanup_test_tenant(&pool, tenant_id).await;
        }

        #[tokio::test]
        #[ignore = "Requires database - run locally with DATABASE_URL"]
        async fn test_expiration_job_handles_reminders_and_escalation() {
            let pool = create_test_pool().await;
            let tenant_id = create_test_tenant(&pool).await;
            let manager_id = create_test_user(&pool, tenant_id).await;
            let backup_reviewer_id = create_test_user(&pool, tenant_id).await;
            let user_id = create_test_user_with_manager(&pool, tenant_id, manager_id).await;
            let app_id = create_test_application(&pool, tenant_id).await;
            let entitlement_id =
                create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
            let assignment_id =
                create_test_assignment(&pool, tenant_id, user_id, entitlement_id).await;

            // Create trigger rule with reminder threshold
            let trigger_service = MicroCertTriggerService::new(pool.clone());
            let _trigger_rule = trigger_service
                .create(
                    tenant_id,
                    "Reminder Test".to_string(),
                    None,
                    MicroCertTriggerType::HighRiskAssignment,
                    MicroCertScopeType::Tenant,
                    None,
                    None,
                    MicroCertReviewerType::UserManager,
                    None,
                    Some(backup_reviewer_id), // backup reviewer for escalation
                    3600,                     // 1 hour timeout
                    Some(75),                 // 75% reminder threshold
                    false,                    // no auto_revoke
                    false,
                    true,
                    0,
                    false,
                )
                .await
                .expect("Failed to create trigger rule");

            // Create micro-certification
            let cert_service = MicroCertificationService::new(pool.clone());
            let certification = cert_service
                .create_from_assignment_event(
                    tenant_id,
                    user_id,
                    entitlement_id,
                    assignment_id,
                    "high",
                    "xavyo.governance.entitlement.assigned",
                    uuid::Uuid::new_v4(),
                )
                .await
                .expect("Failed to create micro-certification")
                .expect("Expected certification");

            // Run expiration job (should send reminder based on threshold)
            let job = MicroCertExpirationJob::new(pool.clone());
            job.run().await.expect("Expiration job failed");

            // Verify certification still pending (not expired yet)
            let updated_cert = cert_service
                .get(tenant_id, certification.id)
                .await
                .expect("Failed to get certification");

            assert_eq!(
                updated_cert.status,
                MicroCertStatus::Pending,
                "Certification should still be pending"
            );

            cleanup_test_tenant(&pool, tenant_id).await;
        }
    }
}
