//! Integration tests for F055 Micro-certification using current service APIs.
//!
//! Run with:
//! `DATABASE_URL=postgres://... SQLX_OFFLINE=true \
//!  cargo test -p xavyo-api-governance --features integration \
//!  --test micro_cert_integration_tests -- --test-threads=1`

#![cfg(feature = "integration")]

mod common;

use common::{
    cleanup_test_tenant, create_test_assignment, create_test_entitlement_with_risk,
    create_test_pool, create_test_tenant, create_test_user, create_test_user_with_manager,
    create_test_application,
};
use uuid::Uuid;
use xavyo_api_governance::{
    jobs::MicroCertExpirationJob,
    services::{MicroCertTriggerService, MicroCertificationService},
};
use xavyo_db::models::{
    CreateMicroCertTrigger, MicroCertDecision, MicroCertReviewerType, MicroCertScopeType,
    MicroCertStatus, MicroCertTriggerType,
};

fn high_risk_trigger(name: &str, auto_revoke: bool, timeout_secs: i32) -> CreateMicroCertTrigger {
    CreateMicroCertTrigger {
        name: name.to_string(),
        trigger_type: MicroCertTriggerType::HighRiskAssignment,
        scope_type: Some(MicroCertScopeType::Tenant),
        scope_id: None,
        reviewer_type: Some(MicroCertReviewerType::UserManager),
        specific_reviewer_id: None,
        fallback_reviewer_id: None,
        timeout_secs: Some(timeout_secs),
        reminder_threshold_percent: Some(75),
        auto_revoke: Some(auto_revoke),
        revoke_triggering_assignment: Some(false),
        is_default: Some(true),
        priority: Some(0),
        metadata: None,
    }
}

fn manager_change_trigger(name: &str) -> CreateMicroCertTrigger {
    CreateMicroCertTrigger {
        name: name.to_string(),
        trigger_type: MicroCertTriggerType::ManagerChange,
        scope_type: Some(MicroCertScopeType::Tenant),
        scope_id: None,
        reviewer_type: Some(MicroCertReviewerType::UserManager),
        specific_reviewer_id: None,
        fallback_reviewer_id: None,
        timeout_secs: Some(604800),
        reminder_threshold_percent: Some(50),
        auto_revoke: Some(false),
        revoke_triggering_assignment: Some(false),
        is_default: Some(true),
        priority: Some(0),
        metadata: None,
    }
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_high_risk_assignment_create_and_approve() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let manager_id = create_test_user(&pool, tenant_id).await;
    let user_id = create_test_user_with_manager(&pool, tenant_id, manager_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let entitlement_id =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
    let assignment_id = create_test_assignment(&pool, tenant_id, user_id, entitlement_id).await;

    let trigger_service = MicroCertTriggerService::new(pool.clone());
    trigger_service
        .create(tenant_id, high_risk_trigger("High-Risk Review", false, 86400))
        .await
        .expect("Failed to create trigger rule");

    let cert_service = MicroCertificationService::new(pool.clone());
    let creation = cert_service
        .create_from_assignment_event(
            tenant_id,
            assignment_id,
            user_id,
            entitlement_id,
            "xavyo.governance.entitlement.assigned",
            Uuid::new_v4(),
            None,
        )
        .await
        .expect("Failed to create micro-certification")
        .expect("Expected certification to be created");

    assert!(!creation.duplicate_skipped);
    assert_eq!(creation.certification.status, MicroCertStatus::Pending);
    assert_eq!(creation.certification.reviewer_id, manager_id);

    let decision = cert_service
        .decide(
            tenant_id,
            creation.certification.id,
            manager_id,
            MicroCertDecision::Approve,
            Some("Approved for Q1 project".to_string()),
        )
        .await
        .expect("Failed to approve certification");

    assert_eq!(decision.certification.status, MicroCertStatus::Approved);

    let events = cert_service
        .get_events(tenant_id, creation.certification.id)
        .await
        .expect("Failed to get events");
    assert!(events.len() >= 2, "Expected created and approved events");

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_expiration_job_marks_expired_without_auto_revoke() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let manager_id = create_test_user(&pool, tenant_id).await;
    let user_id = create_test_user_with_manager(&pool, tenant_id, manager_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let entitlement_id =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
    let assignment_id = create_test_assignment(&pool, tenant_id, user_id, entitlement_id).await;

    MicroCertTriggerService::new(pool.clone())
        .create(tenant_id, high_risk_trigger("Quick Expiration", false, 1))
        .await
        .expect("Failed to create trigger rule");

    let cert_service = MicroCertificationService::new(pool.clone());
    let creation = cert_service
        .create_from_assignment_event(
            tenant_id,
            assignment_id,
            user_id,
            entitlement_id,
            "xavyo.governance.entitlement.assigned",
            Uuid::new_v4(),
            None,
        )
        .await
        .expect("Failed to create micro-certification")
        .expect("Expected certification");

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    MicroCertExpirationJob::new(MicroCertificationService::new(pool.clone()))
        .poll()
        .await
        .expect("Expiration job failed");

    let updated = cert_service
        .get(tenant_id, creation.certification.id)
        .await
        .expect("Failed to get certification");

    assert_eq!(updated.status, MicroCertStatus::Expired);

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_manager_change_creates_certifications() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let old_manager_id = create_test_user(&pool, tenant_id).await;
    let new_manager_id = create_test_user(&pool, tenant_id).await;
    let user_id = create_test_user_with_manager(&pool, tenant_id, old_manager_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let ent1_id = create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
    let ent2_id =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "critical").await;
    create_test_assignment(&pool, tenant_id, user_id, ent1_id).await;
    create_test_assignment(&pool, tenant_id, user_id, ent2_id).await;

    sqlx::query("UPDATE users SET manager_id = $1 WHERE id = $2 AND tenant_id = $3")
        .bind(new_manager_id)
        .bind(user_id)
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("Failed to update manager");

    MicroCertTriggerService::new(pool.clone())
        .create(tenant_id, manager_change_trigger("Manager Change Review"))
        .await
        .expect("Failed to create trigger rule");

    let cert_service = MicroCertificationService::new(pool.clone());
    let creations = cert_service
        .create_from_manager_change(
            tenant_id,
            user_id,
            Some(old_manager_id),
            new_manager_id,
            "manager_change",
            Uuid::new_v4(),
        )
        .await
        .expect("Failed to create manager change certifications");

    assert!(creations.len() >= 2);
    for creation in &creations {
        assert_eq!(creation.certification.reviewer_id, new_manager_id);
        assert_eq!(creation.certification.status, MicroCertStatus::Pending);
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

    let ent1_id = create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
    let ent2_id = create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
    create_test_assignment(&pool, tenant_id, user_id, ent1_id).await;
    create_test_assignment(&pool, tenant_id, user_id, ent2_id).await;

    sqlx::query("UPDATE users SET manager_id = $1 WHERE id = $2 AND tenant_id = $3")
        .bind(new_manager_id)
        .bind(user_id)
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("Failed to update manager");

    MicroCertTriggerService::new(pool.clone())
        .create(tenant_id, manager_change_trigger("Manager Change Bulk"))
        .await
        .expect("Failed to create trigger rule");

    let cert_service = MicroCertificationService::new(pool.clone());
    let creations = cert_service
        .create_from_manager_change(
            tenant_id,
            user_id,
            Some(old_manager_id),
            new_manager_id,
            "manager_change",
            Uuid::new_v4(),
        )
        .await
        .expect("Failed to create certifications");

    let cert_ids: Vec<Uuid> = creations
        .iter()
        .map(|c| c.certification.id)
        .collect();

    let results = cert_service
        .bulk_decide(
            tenant_id,
            &cert_ids,
            new_manager_id,
            MicroCertDecision::Approve,
            Some("Bulk approved".to_string()),
        )
        .await
        .expect("Failed to bulk approve");

    assert_eq!(results.succeeded.len(), cert_ids.len());
    assert!(results.failed.is_empty());

    cleanup_test_tenant(&pool, tenant_id).await;
}
