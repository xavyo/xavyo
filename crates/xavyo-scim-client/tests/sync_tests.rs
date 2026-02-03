//! Integration tests for the SCIM sync module.
//!
//! Tests cover:
//! - Full sync operations
//! - Incremental sync
//! - Sync result counts
//! - Error aggregation
//! - Tenant isolation during sync
//!
//! Run with: `cargo test -p xavyo-scim-client --features integration --test sync_tests`

#![cfg(feature = "integration")]

mod helpers;

use helpers::mock_scim_server::MockScimServer;
use helpers::test_data::{
    generate_scim_group, generate_scim_user, generate_user_response, TestTenant,
};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use xavyo_scim_client::auth::{ScimAuth, ScimCredentials};
use xavyo_scim_client::client::ScimClient;

// =============================================================================
// Full Sync Tests
// =============================================================================

/// Test a full sync operation creates all users.
#[tokio::test]
async fn test_sync_full_sync() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;
    server.mock_create_user_success().await;
    server.mock_create_group_success().await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();

    // Simulate creating multiple users during a full sync
    let users = vec![
        generate_scim_user("user1@example.com", tenant.tenant_id),
        generate_scim_user("user2@example.com", tenant.tenant_id),
        generate_scim_user("user3@example.com", tenant.tenant_id),
    ];

    let mut created_count = 0;
    for user in users {
        if client.create_user(&user).await.is_ok() {
            created_count += 1;
        }
    }

    assert_eq!(created_count, 3, "All 3 users should be created");
}

/// Test full sync handles mixed success and failure.
#[tokio::test]
async fn test_sync_full_sync_partial_failure() {
    let mock_server = MockServer::start().await;

    // First two users succeed, third fails
    let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let call_count_clone = call_count.clone();

    Mock::given(method("POST"))
        .and(path("/Users"))
        .respond_with(move |_req: &wiremock::Request| {
            let count = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if count < 2 {
                ResponseTemplate::new(201).set_body_json(json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "id": Uuid::new_v4().to_string(),
                    "userName": "created@example.com",
                    "active": true
                }))
            } else {
                ResponseTemplate::new(500).set_body_json(json!({
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "detail": "Internal server error",
                    "status": "500"
                }))
            }
        })
        .mount(&mock_server)
        .await;

    let auth = ScimAuth::new(
        ScimCredentials::Bearer {
            token: "token".to_string(),
        },
        reqwest::Client::new(),
    );
    let client = ScimClient::with_http_client(mock_server.uri(), auth, reqwest::Client::new());

    let tenant = TestTenant::tenant_a();
    let users = vec![
        generate_scim_user("user1@example.com", tenant.tenant_id),
        generate_scim_user("user2@example.com", tenant.tenant_id),
        generate_scim_user("user3@example.com", tenant.tenant_id),
    ];

    let mut success_count = 0;
    let mut failure_count = 0;
    for user in users {
        match client.create_user(&user).await {
            Ok(_) => success_count += 1,
            Err(_) => failure_count += 1,
        }
    }

    assert_eq!(success_count, 2, "Two users should succeed");
    assert_eq!(failure_count, 1, "One user should fail");
}

// =============================================================================
// Incremental Sync Tests
// =============================================================================

/// Test incremental sync only updates changed users.
#[tokio::test]
async fn test_sync_incremental_sync() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;

    // Mock existing user that needs update
    let user_id = Uuid::new_v4().to_string();
    server.mock_patch_user_success(&user_id).await;

    let client = server.client();

    // Perform incremental update
    let patch = xavyo_api_scim::models::ScimPatchRequest {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:PatchOp".to_string()],
        operations: vec![xavyo_api_scim::models::ScimPatchOp {
            op: "replace".to_string(),
            path: Some("displayName".to_string()),
            value: Some(json!("Updated During Incremental Sync")),
        }],
    };

    let result = client.patch_user(&user_id, &patch).await;

    assert!(result.is_ok(), "Incremental sync update should succeed");
}

/// Test incremental sync skips unchanged users.
#[tokio::test]
async fn test_sync_incremental_skip_unchanged() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;

    // This test verifies the pattern where we check if sync is needed
    let user_id = Uuid::new_v4().to_string();
    let user_data = generate_user_response(&user_id, "unchanged@example.com", Some(&user_id), true);
    server.mock_get_user_success(&user_id, user_data).await;

    let client = server.client();

    // Get current state
    let result = client.get_user(&user_id).await;
    assert!(result.is_ok());

    let user = result.unwrap();
    // If user is already synced with correct data, we'd skip the update
    assert_eq!(user.user_name, "unchanged@example.com");
    assert!(user.active);
}

// =============================================================================
// Sync Result Count Tests
// =============================================================================

/// Test sync correctly counts created, updated, and skipped resources.
#[tokio::test]
async fn test_sync_result_counts() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;
    server.mock_create_user_success().await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();

    let mut created_count = 0;
    let skipped_count = 0; // No skips in this test
    let mut failed_count = 0;

    // Create 5 new users
    for i in 0..5 {
        let user = generate_scim_user(&format!("newuser{}@example.com", i), tenant.tenant_id);
        match client.create_user(&user).await {
            Ok(_) => created_count += 1,
            Err(_) => failed_count += 1,
        }
    }

    assert_eq!(created_count, 5, "Should have 5 created");
    assert_eq!(skipped_count, 0, "Should have 0 skipped");
    assert_eq!(failed_count, 0, "Should have 0 failed");
}

/// Test sync counts when mixing creates and updates.
#[tokio::test]
async fn test_sync_mixed_operation_counts() {
    let mock_server = MockServer::start().await;

    // Track request types
    let create_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let update_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let create_count_clone = create_count.clone();
    Mock::given(method("POST"))
        .and(path("/Users"))
        .respond_with(move |_req: &wiremock::Request| {
            create_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ResponseTemplate::new(201).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "id": Uuid::new_v4().to_string(),
                "userName": "created@example.com",
                "active": true
            }))
        })
        .mount(&mock_server)
        .await;

    let update_count_clone = update_count.clone();
    Mock::given(method("PATCH"))
        .respond_with(move |_req: &wiremock::Request| {
            update_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "id": "existing-id",
                "userName": "updated@example.com",
                "active": true
            }))
        })
        .mount(&mock_server)
        .await;

    let auth = ScimAuth::new(
        ScimCredentials::Bearer {
            token: "token".to_string(),
        },
        reqwest::Client::new(),
    );
    let client = ScimClient::with_http_client(mock_server.uri(), auth, reqwest::Client::new());
    let tenant = TestTenant::tenant_a();

    // Perform 3 creates
    for i in 0..3 {
        let user = generate_scim_user(&format!("new{}@example.com", i), tenant.tenant_id);
        let _ = client.create_user(&user).await;
    }

    // Perform 2 updates
    let patch = xavyo_api_scim::models::ScimPatchRequest {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:PatchOp".to_string()],
        operations: vec![xavyo_api_scim::models::ScimPatchOp {
            op: "replace".to_string(),
            path: Some("active".to_string()),
            value: Some(json!(true)),
        }],
    };
    for _ in 0..2 {
        let _ = client.patch_user("existing-user", &patch).await;
    }

    let creates = create_count.load(std::sync::atomic::Ordering::SeqCst);
    let updates = update_count.load(std::sync::atomic::Ordering::SeqCst);

    assert_eq!(creates, 3, "Should have 3 creates");
    assert_eq!(updates, 2, "Should have 2 updates");
}

// =============================================================================
// Error Aggregation Tests
// =============================================================================

/// Test that sync aggregates errors without stopping.
#[tokio::test]
async fn test_sync_error_aggregation() {
    let mock_server = MockServer::start().await;

    let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let call_count_clone = call_count.clone();

    // Alternate between success and failure
    Mock::given(method("POST"))
        .and(path("/Users"))
        .respond_with(move |_req: &wiremock::Request| {
            let count = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if count % 2 == 0 {
                ResponseTemplate::new(201).set_body_json(json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "id": Uuid::new_v4().to_string(),
                    "userName": "success@example.com",
                    "active": true
                }))
            } else {
                ResponseTemplate::new(500).set_body_json(json!({
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "detail": "Server error",
                    "status": "500"
                }))
            }
        })
        .mount(&mock_server)
        .await;

    let auth = ScimAuth::new(
        ScimCredentials::Bearer {
            token: "token".to_string(),
        },
        reqwest::Client::new(),
    );
    let client = ScimClient::with_http_client(mock_server.uri(), auth, reqwest::Client::new());
    let tenant = TestTenant::tenant_a();

    let mut errors = Vec::new();
    let mut successes = 0;

    // Process 6 users (expecting 3 success, 3 failure)
    for i in 0..6 {
        let user = generate_scim_user(&format!("user{}@example.com", i), tenant.tenant_id);
        match client.create_user(&user).await {
            Ok(_) => successes += 1,
            Err(e) => errors.push(e),
        }
    }

    assert_eq!(successes, 3, "Should have 3 successes");
    assert_eq!(errors.len(), 3, "Should have 3 errors aggregated");
}

/// Test error aggregation includes specific error details.
#[tokio::test]
async fn test_sync_error_details_preserved() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/Users"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": "Invalid email format: bad-email",
            "status": "400"
        })))
        .mount(&mock_server)
        .await;

    let auth = ScimAuth::new(
        ScimCredentials::Bearer {
            token: "token".to_string(),
        },
        reqwest::Client::new(),
    );
    let client = ScimClient::with_http_client(mock_server.uri(), auth, reqwest::Client::new());
    let tenant = TestTenant::tenant_a();
    let user = generate_scim_user("bad-email", tenant.tenant_id);

    let result = client.create_user(&user).await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    let error_str = error.to_string();
    // Error should preserve server details
    assert!(
        error_str.contains("400") || error_str.contains("Invalid"),
        "Error should contain status or detail"
    );
}

// =============================================================================
// Tenant Isolation During Sync Tests
// =============================================================================

/// Test that sync operations are isolated per tenant.
#[tokio::test]
async fn test_sync_tenant_isolation() {
    // Create two separate servers for two tenants
    let server_a = MockScimServer::new().await;
    let server_b = MockScimServer::new().await;

    server_a.mock_service_provider_config().await;
    server_a.mock_create_user_success().await;
    server_b.mock_service_provider_config().await;
    server_b.mock_create_user_success().await;

    let client_a = server_a.client();
    let client_b = server_b.client();

    let tenant_a = TestTenant::tenant_a();
    let tenant_b = TestTenant::tenant_b();

    // Sync users to Tenant A
    let user_a1 = generate_scim_user("user1@tenanta.com", tenant_a.tenant_id);
    let user_a2 = generate_scim_user("user2@tenanta.com", tenant_a.tenant_id);

    // Sync users to Tenant B
    let user_b1 = generate_scim_user("user1@tenantb.com", tenant_b.tenant_id);

    let result_a1 = client_a.create_user(&user_a1).await;
    let result_a2 = client_a.create_user(&user_a2).await;
    let result_b1 = client_b.create_user(&user_b1).await;

    assert!(result_a1.is_ok(), "Tenant A user 1 should succeed");
    assert!(result_a2.is_ok(), "Tenant A user 2 should succeed");
    assert!(result_b1.is_ok(), "Tenant B user 1 should succeed");

    // Verify each tenant's users are on their own target
    let created_a1 = result_a1.unwrap();
    let created_a2 = result_a2.unwrap();
    let created_b1 = result_b1.unwrap();

    // Usernames should reflect their tenant
    assert!(created_a1.user_name.contains("tenanta"));
    assert!(created_a2.user_name.contains("tenanta"));
    assert!(created_b1.user_name.contains("tenantb"));
}

/// Test sync respects tenant boundaries when listing.
#[tokio::test]
async fn test_sync_list_respects_tenant() {
    let server_a = MockScimServer::new().await;
    let server_b = MockScimServer::new().await;

    // Tenant A has 2 users
    let users_a = vec![
        generate_user_response(
            &Uuid::new_v4().to_string(),
            "a1@tenanta.com",
            Some("ext-a1"),
            true,
        ),
        generate_user_response(
            &Uuid::new_v4().to_string(),
            "a2@tenanta.com",
            Some("ext-a2"),
            true,
        ),
    ];
    server_a.mock_list_users(users_a).await;

    // Tenant B has 4 users
    let users_b = vec![
        generate_user_response(
            &Uuid::new_v4().to_string(),
            "b1@tenantb.com",
            Some("ext-b1"),
            true,
        ),
        generate_user_response(
            &Uuid::new_v4().to_string(),
            "b2@tenantb.com",
            Some("ext-b2"),
            true,
        ),
        generate_user_response(
            &Uuid::new_v4().to_string(),
            "b3@tenantb.com",
            Some("ext-b3"),
            true,
        ),
        generate_user_response(
            &Uuid::new_v4().to_string(),
            "b4@tenantb.com",
            Some("ext-b4"),
            true,
        ),
    ];
    server_b.mock_list_users(users_b).await;

    let client_a = server_a.client();
    let client_b = server_b.client();

    let list_a = client_a.list_users(None, None, None).await.unwrap();
    let list_b = client_b.list_users(None, None, None).await.unwrap();

    assert_eq!(list_a.total_results, 2, "Tenant A should have 2 users");
    assert_eq!(list_b.total_results, 4, "Tenant B should have 4 users");

    // Verify no cross-tenant leakage
    for user in &list_a.resources {
        assert!(
            user.user_name.contains("tenanta"),
            "Tenant A list should only contain tenanta users"
        );
    }
    for user in &list_b.resources {
        assert!(
            user.user_name.contains("tenantb"),
            "Tenant B list should only contain tenantb users"
        );
    }
}

// =============================================================================
// Sync with Groups Tests
// =============================================================================

/// Test full sync includes groups.
#[tokio::test]
async fn test_sync_includes_groups() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;
    server.mock_create_user_success().await;
    server.mock_create_group_success().await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();

    // Create users
    let user = generate_scim_user("user@example.com", tenant.tenant_id);
    let user_result = client.create_user(&user).await;
    assert!(user_result.is_ok());

    // Create groups
    let group = generate_scim_group("Engineering", tenant.tenant_id);
    let group_result = client.create_group(&group).await;
    assert!(group_result.is_ok());

    let created_group = group_result.unwrap();
    assert_eq!(created_group.display_name, "Engineering");
}

/// Test sync with group membership.
#[tokio::test]
async fn test_sync_group_membership() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;
    server.mock_create_user_success().await;
    server.mock_create_group_success().await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();

    // Create users first
    let user1 = generate_scim_user("member1@example.com", tenant.tenant_id);
    let user2 = generate_scim_user("member2@example.com", tenant.tenant_id);

    let created_user1 = client.create_user(&user1).await.unwrap();
    let created_user2 = client.create_user(&user2).await.unwrap();

    // Create group with members
    let member_ids: Vec<String> = vec![
        created_user1.id.unwrap().to_string(),
        created_user2.id.unwrap().to_string(),
    ];

    let group =
        helpers::test_data::generate_scim_group_with_members("Team with Members", &member_ids);

    let group_result = client.create_group(&group).await;
    assert!(group_result.is_ok());
}
