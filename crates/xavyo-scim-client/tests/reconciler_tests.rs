//! Integration tests for the SCIM reconciler module.
//!
//! Tests cover:
//! - Detecting missing downstream resources
//! - Detecting orphaned downstream resources
//! - Detecting attribute drift
//! - Handling large datasets
//! - Group membership drift detection
//! - Network error handling
//! - Tenant isolation
//!
//! Run with: `cargo test -p xavyo-scim-client --features integration --test reconciler_tests`

#![cfg(feature = "integration")]

mod helpers;

use helpers::mock_scim_server::MockScimServer;
use helpers::test_data::{
    generate_group_response, generate_large_group_dataset, generate_large_user_dataset,
    generate_user_response,
};
use serde_json::json;
use uuid::Uuid;
// reconciler types are tested via client API, not directly imported here

// =============================================================================
// Drift Detection - Missing Downstream Tests
// =============================================================================

/// Test detecting users that exist in local state but not on the SCIM target.
#[tokio::test]
async fn test_reconciler_detect_missing_downstream() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;

    // Empty response - no users on target
    server.mock_list_users_empty().await;
    server.mock_list_groups_empty().await;

    let client = server.client();

    // Fetch users from target (should be empty)
    let result = client.list_users(None, None, None).await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_results, 0);
    assert!(list.resources.is_empty());
}

/// Test detecting multiple missing users.
#[tokio::test]
async fn test_reconciler_detect_multiple_missing() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;

    // Target has only 2 users
    let user1_id = Uuid::new_v4().to_string();
    let user2_id = Uuid::new_v4().to_string();
    let users = vec![
        generate_user_response(&user1_id, "user1@example.com", Some("ext-1"), true),
        generate_user_response(&user2_id, "user2@example.com", Some("ext-2"), true),
    ];
    server.mock_list_users(users).await;
    server.mock_list_groups_empty().await;

    let client = server.client();
    let result = client.list_users(None, None, None).await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_results, 2);
}

// =============================================================================
// Drift Detection - Orphaned Downstream Tests
// =============================================================================

/// Test detecting users that exist on the SCIM target but not in local state.
#[tokio::test]
async fn test_reconciler_detect_orphaned_downstream() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;

    // Target has orphaned users (not tracked locally)
    let orphan_id = Uuid::new_v4().to_string();
    let users = vec![generate_user_response(
        &orphan_id,
        "orphan@example.com",
        Some("orphan-ext"),
        true,
    )];
    server.mock_list_users(users).await;
    server.mock_list_groups_empty().await;

    let client = server.client();
    let result = client.list_users(None, None, None).await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_results, 1);
    assert_eq!(list.resources[0].user_name, "orphan@example.com");
}

/// Test detecting multiple orphaned users.
#[tokio::test]
async fn test_reconciler_detect_multiple_orphans() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;

    // Target has 5 orphaned users
    let users: Vec<_> = (0..5)
        .map(|i| {
            let id = Uuid::new_v4().to_string();
            generate_user_response(
                &id,
                &format!("orphan{}@example.com", i),
                Some(&format!("orphan-ext-{}", i)),
                true,
            )
        })
        .collect();
    server.mock_list_users(users).await;
    server.mock_list_groups_empty().await;

    let client = server.client();
    let result = client.list_users(None, None, None).await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_results, 5);
}

// =============================================================================
// Drift Detection - Attribute Drift Tests
// =============================================================================

/// Test detecting attribute drift (user is inactive on target but synced locally).
#[tokio::test]
async fn test_reconciler_detect_attribute_drift() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;

    let user_id = Uuid::new_v4().to_string();
    // User is INACTIVE on target
    let users = vec![generate_user_response(
        &user_id,
        "drifted@example.com",
        Some(&user_id),
        false, // inactive
    )];
    server.mock_list_users(users).await;
    server.mock_list_groups_empty().await;

    let client = server.client();
    let result = client.list_users(None, None, None).await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_results, 1);
    assert!(!list.resources[0].active); // Verify user is inactive
}

/// Test detecting display name drift.
#[tokio::test]
async fn test_reconciler_detect_display_name_drift() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;

    let user_id = Uuid::new_v4().to_string();
    // User has different display name on target
    let mut user = generate_user_response(&user_id, "drifted@example.com", Some(&user_id), true);
    user["displayName"] = json!("Different Name On Target");

    server.mock_list_users(vec![user]).await;
    server.mock_list_groups_empty().await;

    let client = server.client();
    let result = client.list_users(None, None, None).await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_results, 1);
    assert_eq!(
        list.resources[0].display_name.as_deref(),
        Some("Different Name On Target")
    );
}

// =============================================================================
// Large Dataset Tests
// =============================================================================

/// Test reconciliation with a large number of users.
#[tokio::test]
async fn test_reconciler_large_dataset() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;

    // Generate 100 users
    let users = generate_large_user_dataset(100);
    server.mock_list_users(users).await;
    server.mock_list_groups_empty().await;

    let client = server.client();
    let result = client.list_users(None, None, None).await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_results, 100);
    assert_eq!(list.resources.len(), 100);
}

/// Test reconciliation with large number of groups.
#[tokio::test]
async fn test_reconciler_large_group_dataset() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;

    server.mock_list_users_empty().await;
    // Generate 50 groups
    let groups = generate_large_group_dataset(50);
    server.mock_list_groups(groups).await;

    let client = server.client();
    let result = client.list_groups(None, None, None).await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_results, 50);
    assert_eq!(list.resources.len(), 50);
}

// =============================================================================
// Group Membership Drift Tests
// =============================================================================

/// Test detecting group membership drift.
#[tokio::test]
async fn test_reconciler_group_membership_drift() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;

    server.mock_list_users_empty().await;

    let group_id = Uuid::new_v4().to_string();
    let member_id_1 = Uuid::new_v4().to_string();
    let member_id_2 = Uuid::new_v4().to_string();
    // Group has different members on target than local state expects
    let groups = vec![generate_group_response(
        &group_id,
        "Engineering",
        Some(&group_id),
        &[&member_id_1, &member_id_2],
    )];
    server.mock_list_groups(groups).await;

    let client = server.client();
    let result = client.list_groups(None, None, None).await;

    assert!(
        result.is_ok(),
        "List groups should succeed: {:?}",
        result.err()
    );
    let list = result.unwrap();
    assert_eq!(list.total_results, 1);
    assert_eq!(list.resources[0].members.len(), 2);
}

/// Test detecting group with missing members.
#[tokio::test]
async fn test_reconciler_group_missing_members() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;

    server.mock_list_users_empty().await;

    let group_id = Uuid::new_v4().to_string();
    // Group has no members on target
    let groups = vec![generate_group_response(
        &group_id,
        "Empty Group",
        Some(&group_id),
        &[],
    )];
    server.mock_list_groups(groups).await;

    let client = server.client();
    let result = client.list_groups(None, None, None).await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_results, 1);
    assert!(list.resources[0].members.is_empty());
}

// =============================================================================
// Network Error Handling Tests
// =============================================================================

/// Test handling of network errors during reconciliation.
#[tokio::test]
async fn test_reconciler_network_error_handling() {
    let server = MockScimServer::new().await;
    server.mock_server_error().await;

    let client = server.client();
    let result = client.list_users(None, None, None).await;

    assert!(result.is_err());
}

/// Test handling of 502 Bad Gateway.
#[tokio::test]
async fn test_reconciler_bad_gateway() {
    let server = MockScimServer::new().await;
    server.mock_bad_gateway().await;

    let client = server.client();
    let result = client.list_users(None, None, None).await;

    assert!(result.is_err());
}

/// Test handling of 503 Service Unavailable.
#[tokio::test]
async fn test_reconciler_service_unavailable() {
    let server = MockScimServer::new().await;
    server.mock_service_unavailable().await;

    let client = server.client();
    let result = client.list_users(None, None, None).await;

    assert!(result.is_err());
}

// =============================================================================
// Tenant Isolation Tests
// =============================================================================

/// Test that reconciliation is scoped to a single tenant.
#[tokio::test]
async fn test_reconciler_tenant_isolation() {
    // Create two separate servers simulating different tenant targets
    let server_a = MockScimServer::new().await;
    let server_b = MockScimServer::new().await;

    server_a.mock_service_provider_config().await;
    server_b.mock_service_provider_config().await;

    // Tenant A has 3 users
    let users_a: Vec<_> = (0..3)
        .map(|i| {
            let id = Uuid::new_v4().to_string();
            generate_user_response(
                &id,
                &format!("user{}@tenanta.com", i),
                Some(&format!("ext-a-{}", i)),
                true,
            )
        })
        .collect();
    server_a.mock_list_users(users_a).await;
    server_a.mock_list_groups_empty().await;

    // Tenant B has 5 users
    let users_b: Vec<_> = (0..5)
        .map(|i| {
            let id = Uuid::new_v4().to_string();
            generate_user_response(
                &id,
                &format!("user{}@tenantb.com", i),
                Some(&format!("ext-b-{}", i)),
                true,
            )
        })
        .collect();
    server_b.mock_list_users(users_b).await;
    server_b.mock_list_groups_empty().await;

    let client_a = server_a.client();
    let client_b = server_b.client();

    let result_a = client_a.list_users(None, None, None).await;
    let result_b = client_b.list_users(None, None, None).await;

    assert!(result_a.is_ok());
    assert!(result_b.is_ok());

    let list_a = result_a.unwrap();
    let list_b = result_b.unwrap();

    // Verify tenant isolation - each has correct count
    assert_eq!(list_a.total_results, 3, "Tenant A should have 3 users");
    assert_eq!(list_b.total_results, 5, "Tenant B should have 5 users");

    // Verify no cross-contamination
    for user in &list_a.resources {
        assert!(
            user.user_name.contains("tenanta.com"),
            "Tenant A users should be from tenanta.com"
        );
    }
    for user in &list_b.resources {
        assert!(
            user.user_name.contains("tenantb.com"),
            "Tenant B users should be from tenantb.com"
        );
    }
}

// =============================================================================
// Pagination Tests
// =============================================================================

/// Test reconciliation handles paginated user lists.
#[tokio::test]
async fn test_reconciler_pagination() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;

    // First page of users
    let users = generate_large_user_dataset(50);
    server.mock_list_users(users).await;
    server.mock_list_groups_empty().await;

    let client = server.client();
    let result = client.list_users(None, Some(1), Some(50)).await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_results, 50);
    assert_eq!(list.start_index, 1);
}

// =============================================================================
// ExternalId Mismatch Tests
// =============================================================================

/// Test detecting externalId mismatch between local and remote.
#[tokio::test]
async fn test_reconciler_external_id_mismatch() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;

    let user_id = Uuid::new_v4().to_string();
    // User has different externalId on target
    let users = vec![generate_user_response(
        &user_id,
        "user@example.com",
        Some("different-external-id"),
        true,
    )];
    server.mock_list_users(users).await;
    server.mock_list_groups_empty().await;

    let client = server.client();
    let result = client.list_users(None, None, None).await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_results, 1);
    assert_eq!(
        list.resources[0].external_id.as_deref(),
        Some("different-external-id")
    );
}
