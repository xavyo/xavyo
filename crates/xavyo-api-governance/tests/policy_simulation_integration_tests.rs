//! Integration tests for Policy Simulation (F060).
//!
//! Tests the policy simulation service including:
//! - `SoD` rule violation detection
//! - Birthright policy entitlement calculation
//! - Impact summary aggregation
//! - Full simulation workflow
//!
//! These tests require a running `PostgreSQL` database.
//! Run with: cargo test -p xavyo-api-governance --test `policy_simulation_integration_tests` -- --ignored

mod common;

use common::{
    cleanup_simulation_data, cleanup_test_tenant, create_test_application, create_test_entitlement,
    create_test_entitlement_assignment, create_test_pool, create_test_tenant,
    create_test_user_with_attributes,
};

use uuid::Uuid;
use xavyo_api_governance::services::PolicySimulationService;
use xavyo_db::{ImpactType, PolicySimulationType, SimulationStatus};

// ============================================================================
// SoD Rule Impact Tests
// ============================================================================

#[tokio::test]
#[ignore = "Requires running PostgreSQL database"]
async fn test_sod_rule_simulation_detects_violations() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id =
        create_test_user_with_attributes(&pool, tenant_id, Some("Engineering"), None).await;

    // Create application and two entitlements
    let app_id = create_test_application(&pool, tenant_id).await;
    let ent1_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    let ent2_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    // Assign both entitlements to user (creates a potential SoD violation)
    create_test_entitlement_assignment(&pool, tenant_id, user_id, ent1_id).await;
    create_test_entitlement_assignment(&pool, tenant_id, user_id, ent2_id).await;

    // Create service
    let service = PolicySimulationService::new(pool.clone());

    // Create simulation for proposed SoD rule
    let simulation = service
        .create(
            tenant_id,
            "Test SoD Simulation".to_string(),
            PolicySimulationType::SodRule,
            None,
            serde_json::json!({
                "first_entitlement_id": ent1_id.to_string(),
                "second_entitlement_id": ent2_id.to_string(),
                "severity": "high",
                "name": "Payment Approval Conflict"
            }),
            user_id,
        )
        .await
        .expect("Failed to create simulation");

    assert_eq!(simulation.status, SimulationStatus::Draft);
    assert_eq!(simulation.simulation_type, PolicySimulationType::SodRule);

    // Execute the simulation
    let executed = service
        .execute(tenant_id, simulation.id, None)
        .await
        .expect("Failed to execute simulation");

    assert_eq!(executed.status, SimulationStatus::Executed);
    assert_eq!(executed.affected_users.len(), 1);
    assert!(executed.affected_users.contains(&user_id));

    // Verify impact summary
    let impact = executed.parse_impact_summary();
    assert_eq!(impact.affected_users, 1);
    assert_eq!(impact.by_severity.high, 1);
    assert_eq!(impact.by_impact_type.violation, 1);

    // Get detailed results
    let (results, total) = service
        .get_results(tenant_id, simulation.id, None, None, None, 100, 0)
        .await
        .expect("Failed to get results");

    assert_eq!(total, 1);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].user_id, user_id);
    assert_eq!(results[0].impact_type, ImpactType::Violation);
    assert_eq!(results[0].severity, Some("high".to_string()));

    // Cleanup
    cleanup_simulation_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires running PostgreSQL database"]
async fn test_sod_rule_simulation_no_violations() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id =
        create_test_user_with_attributes(&pool, tenant_id, Some("Engineering"), None).await;

    // Create application and two entitlements
    let app_id = create_test_application(&pool, tenant_id).await;
    let ent1_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    let ent2_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    // Only assign ONE entitlement (no violation)
    create_test_entitlement_assignment(&pool, tenant_id, user_id, ent1_id).await;

    // Create service
    let service = PolicySimulationService::new(pool.clone());

    // Create simulation
    let simulation = service
        .create(
            tenant_id,
            "Test No Violations".to_string(),
            PolicySimulationType::SodRule,
            None,
            serde_json::json!({
                "first_entitlement_id": ent1_id.to_string(),
                "second_entitlement_id": ent2_id.to_string(),
                "severity": "critical",
                "name": "No Conflict Rule"
            }),
            user_id,
        )
        .await
        .expect("Failed to create simulation");

    // Execute
    let executed = service
        .execute(tenant_id, simulation.id, None)
        .await
        .expect("Failed to execute simulation");

    // No violations expected
    assert_eq!(executed.affected_users.len(), 0);
    let impact = executed.parse_impact_summary();
    assert_eq!(impact.affected_users, 0);
    assert_eq!(impact.by_impact_type.violation, 0);

    // Cleanup
    cleanup_simulation_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires running PostgreSQL database"]
async fn test_sod_rule_simulation_filtered_users() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Create two users
    let user1_id =
        create_test_user_with_attributes(&pool, tenant_id, Some("Engineering"), None).await;
    let user2_id = create_test_user_with_attributes(&pool, tenant_id, Some("Finance"), None).await;

    let app_id = create_test_application(&pool, tenant_id).await;
    let ent1_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user1_id)).await;
    let ent2_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user1_id)).await;

    // Both users have both entitlements (both violate)
    create_test_entitlement_assignment(&pool, tenant_id, user1_id, ent1_id).await;
    create_test_entitlement_assignment(&pool, tenant_id, user1_id, ent2_id).await;
    create_test_entitlement_assignment(&pool, tenant_id, user2_id, ent1_id).await;
    create_test_entitlement_assignment(&pool, tenant_id, user2_id, ent2_id).await;

    let service = PolicySimulationService::new(pool.clone());

    // Create simulation
    let simulation = service
        .create(
            tenant_id,
            "Filtered Users Test".to_string(),
            PolicySimulationType::SodRule,
            None,
            serde_json::json!({
                "first_entitlement_id": ent1_id.to_string(),
                "second_entitlement_id": ent2_id.to_string(),
                "severity": "medium",
                "name": "Filtered Test Rule"
            }),
            user1_id,
        )
        .await
        .expect("Failed to create simulation");

    // Execute with user filter (only user1)
    let executed = service
        .execute(tenant_id, simulation.id, Some(vec![user1_id]))
        .await
        .expect("Failed to execute simulation");

    // Should only detect user1's violation
    assert_eq!(executed.affected_users.len(), 1);
    assert!(executed.affected_users.contains(&user1_id));
    assert!(!executed.affected_users.contains(&user2_id));

    let impact = executed.parse_impact_summary();
    assert_eq!(impact.total_users_analyzed, 1); // Only analyzed 1 user
    assert_eq!(impact.affected_users, 1);

    // Cleanup
    cleanup_simulation_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Birthright Policy Impact Tests
// ============================================================================

#[tokio::test]
#[ignore = "Requires running PostgreSQL database"]
async fn test_birthright_policy_simulation_grants_entitlements() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Create users in Engineering department
    let eng_user_id =
        create_test_user_with_attributes(&pool, tenant_id, Some("Engineering"), None).await;
    let finance_user_id =
        create_test_user_with_attributes(&pool, tenant_id, Some("Finance"), None).await;

    let app_id = create_test_application(&pool, tenant_id).await;
    let github_ent_id = create_test_entitlement(&pool, tenant_id, app_id, Some(eng_user_id)).await;

    let service = PolicySimulationService::new(pool.clone());

    // Create simulation for birthright policy that grants GitHub to Engineering
    let simulation = service
        .create(
            tenant_id,
            "Engineering GitHub Policy".to_string(),
            PolicySimulationType::BirthrightPolicy,
            None,
            serde_json::json!({
                "name": "Engineering GitHub Access",
                "conditions": [
                    {
                        "attribute": "department",
                        "operator": "equals",
                        "value": "Engineering"
                    }
                ],
                "entitlement_ids": [github_ent_id.to_string()]
            }),
            eng_user_id,
        )
        .await
        .expect("Failed to create simulation");

    // Execute
    let executed = service
        .execute(tenant_id, simulation.id, None)
        .await
        .expect("Failed to execute simulation");

    // Should affect the Engineering user (who would gain the entitlement)
    // Finance user doesn't match the condition
    let impact = executed.parse_impact_summary();
    assert!(impact.affected_users >= 1); // At least Engineering user

    // Get results
    let (results, _total) = service
        .get_results(tenant_id, simulation.id, None, None, None, 100, 0)
        .await
        .expect("Failed to get results");

    // Engineering user should gain entitlement
    let eng_result = results.iter().find(|r| r.user_id == eng_user_id);
    if let Some(result) = eng_result {
        assert_eq!(result.impact_type, ImpactType::EntitlementGain);
    }

    // Finance user should NOT be in results (doesn't match condition)
    let finance_result = results.iter().find(|r| r.user_id == finance_user_id);
    assert!(finance_result.is_none());

    // Cleanup
    cleanup_simulation_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires running PostgreSQL database"]
async fn test_birthright_policy_simulation_no_change_when_already_assigned() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let user_id =
        create_test_user_with_attributes(&pool, tenant_id, Some("Engineering"), None).await;

    let app_id = create_test_application(&pool, tenant_id).await;
    let ent_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    // User ALREADY has the entitlement
    create_test_entitlement_assignment(&pool, tenant_id, user_id, ent_id).await;

    let service = PolicySimulationService::new(pool.clone());

    // Create simulation
    let simulation = service
        .create(
            tenant_id,
            "Already Assigned Test".to_string(),
            PolicySimulationType::BirthrightPolicy,
            None,
            serde_json::json!({
                "name": "Engineering Access",
                "conditions": [
                    {
                        "attribute": "department",
                        "operator": "equals",
                        "value": "Engineering"
                    }
                ],
                "entitlement_ids": [ent_id.to_string()]
            }),
            user_id,
        )
        .await
        .expect("Failed to create simulation");

    // Execute
    let executed = service
        .execute(tenant_id, simulation.id, None)
        .await
        .expect("Failed to execute simulation");

    // User matches condition but already has entitlement - should NOT be affected
    let impact = executed.parse_impact_summary();
    assert_eq!(impact.affected_users, 0); // No one gains/loses

    // Cleanup
    cleanup_simulation_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Simulation Lifecycle Tests
// ============================================================================

#[tokio::test]
#[ignore = "Requires running PostgreSQL database"]
async fn test_simulation_lifecycle_draft_execute_cancel() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id =
        create_test_user_with_attributes(&pool, tenant_id, Some("Engineering"), None).await;

    let app_id = create_test_application(&pool, tenant_id).await;
    let ent1_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    let ent2_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    let service = PolicySimulationService::new(pool.clone());

    // Create (Draft)
    let simulation = service
        .create(
            tenant_id,
            "Lifecycle Test".to_string(),
            PolicySimulationType::SodRule,
            None,
            serde_json::json!({
                "first_entitlement_id": ent1_id.to_string(),
                "second_entitlement_id": ent2_id.to_string(),
                "severity": "low",
                "name": "Lifecycle Test Rule"
            }),
            user_id,
        )
        .await
        .expect("Failed to create simulation");

    assert_eq!(simulation.status, SimulationStatus::Draft);

    // Execute
    let executed = service
        .execute(tenant_id, simulation.id, None)
        .await
        .expect("Failed to execute simulation");

    assert_eq!(executed.status, SimulationStatus::Executed);
    assert!(executed.executed_at.is_some());
    assert!(executed.data_snapshot_at.is_some());

    // Cancel
    let cancelled = service
        .cancel(tenant_id, simulation.id)
        .await
        .expect("Failed to cancel simulation");

    assert_eq!(cancelled.status, SimulationStatus::Cancelled);

    // Cleanup
    cleanup_simulation_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires running PostgreSQL database"]
async fn test_simulation_cannot_execute_twice() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id =
        create_test_user_with_attributes(&pool, tenant_id, Some("Engineering"), None).await;

    let app_id = create_test_application(&pool, tenant_id).await;
    let ent1_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    let ent2_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    let service = PolicySimulationService::new(pool.clone());

    let simulation = service
        .create(
            tenant_id,
            "Execute Twice Test".to_string(),
            PolicySimulationType::SodRule,
            None,
            serde_json::json!({
                "first_entitlement_id": ent1_id.to_string(),
                "second_entitlement_id": ent2_id.to_string(),
                "severity": "medium",
                "name": "Execute Twice Rule"
            }),
            user_id,
        )
        .await
        .expect("Failed to create simulation");

    // Execute first time - success
    service
        .execute(tenant_id, simulation.id, None)
        .await
        .expect("Failed to execute simulation");

    // Execute second time - should fail
    let result = service.execute(tenant_id, simulation.id, None).await;
    assert!(result.is_err());

    // Cleanup
    cleanup_simulation_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires running PostgreSQL database"]
async fn test_simulation_archive_and_notes() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id =
        create_test_user_with_attributes(&pool, tenant_id, Some("Engineering"), None).await;

    let app_id = create_test_application(&pool, tenant_id).await;
    let ent1_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    let ent2_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    let service = PolicySimulationService::new(pool.clone());

    let simulation = service
        .create(
            tenant_id,
            "Archive Test".to_string(),
            PolicySimulationType::SodRule,
            None,
            serde_json::json!({
                "first_entitlement_id": ent1_id.to_string(),
                "second_entitlement_id": ent2_id.to_string(),
                "severity": "low",
                "name": "Archive Test Rule"
            }),
            user_id,
        )
        .await
        .expect("Failed to create simulation");

    // Update notes
    let with_notes = service
        .update_notes(
            tenant_id,
            simulation.id,
            Some("This simulation is for testing archival.".to_string()),
        )
        .await
        .expect("Failed to update notes");

    assert_eq!(
        with_notes.notes,
        Some("This simulation is for testing archival.".to_string())
    );

    // Archive
    let archived = service
        .archive(tenant_id, simulation.id)
        .await
        .expect("Failed to archive simulation");

    assert!(archived.is_archived);

    // Cleanup
    cleanup_simulation_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Validation Tests
// ============================================================================

#[tokio::test]
#[ignore = "Requires running PostgreSQL database"]
async fn test_simulation_validates_name() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id =
        create_test_user_with_attributes(&pool, tenant_id, Some("Engineering"), None).await;

    let service = PolicySimulationService::new(pool.clone());

    // Empty name should fail
    let result = service
        .create(
            tenant_id,
            String::new(),
            PolicySimulationType::SodRule,
            None,
            serde_json::json!({"first_entitlement_id": "00000000-0000-0000-0000-000000000001", "second_entitlement_id": "00000000-0000-0000-0000-000000000002"}),
            user_id,
        )
        .await;

    assert!(result.is_err());

    // Name too long should fail
    let long_name = "x".repeat(300);
    let result = service
        .create(
            tenant_id,
            long_name,
            PolicySimulationType::SodRule,
            None,
            serde_json::json!({"first_entitlement_id": "00000000-0000-0000-0000-000000000001", "second_entitlement_id": "00000000-0000-0000-0000-000000000002"}),
            user_id,
        )
        .await;

    assert!(result.is_err());

    // Cleanup
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires running PostgreSQL database"]
async fn test_sod_simulation_validates_entitlement_ids() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id =
        create_test_user_with_attributes(&pool, tenant_id, Some("Engineering"), None).await;

    let service = PolicySimulationService::new(pool.clone());

    // Create simulation with valid config
    let simulation = service
        .create(
            tenant_id,
            "Validation Test".to_string(),
            PolicySimulationType::SodRule,
            None,
            serde_json::json!({
                "first_entitlement_id": Uuid::new_v4().to_string(),
                "second_entitlement_id": Uuid::new_v4().to_string(),
                "severity": "high"
            }),
            user_id,
        )
        .await
        .expect("Failed to create simulation");

    // Execute should fail because entitlements don't exist
    let result = service.execute(tenant_id, simulation.id, None).await;
    assert!(result.is_err());

    // Cleanup
    cleanup_simulation_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires running PostgreSQL database"]
async fn test_birthright_simulation_validates_entitlement_ids() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id =
        create_test_user_with_attributes(&pool, tenant_id, Some("Engineering"), None).await;

    let service = PolicySimulationService::new(pool.clone());

    // Create simulation - empty entitlement_ids should fail on execute
    let simulation = service
        .create(
            tenant_id,
            "Empty Entitlements Test".to_string(),
            PolicySimulationType::BirthrightPolicy,
            None,
            serde_json::json!({
                "name": "Empty Policy",
                "conditions": [{"attribute": "department", "operator": "equals", "value": "Engineering"}],
                "entitlement_ids": []
            }),
            user_id,
        )
        .await
        .expect("Failed to create simulation");

    // Execute should fail
    let result = service.execute(tenant_id, simulation.id, None).await;
    assert!(result.is_err());

    // Cleanup
    cleanup_simulation_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}
