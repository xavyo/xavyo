//! Integration tests for the SCIM provisioner module.
//!
//! Tests cover:
//! - User CRUD operations (create, update, delete, get)
//! - Group CRUD operations (create, update, delete)
//! - Batch user creation
//! - Rate limit handling
//! - Tenant isolation
//!
//! Run with: `cargo test -p xavyo-scim-client --features integration --test provisioner_tests`

#![cfg(feature = "integration")]

mod helpers;

use helpers::mock_scim_server::MockScimServer;
use helpers::test_data::{
    generate_group_response, generate_scim_group, generate_scim_user, generate_scim_user_full,
    generate_user_batch, generate_user_response, TestTenant,
};
use serde_json::json;
use uuid::Uuid;
use xavyo_scim_client::error::ScimClientError;

// =============================================================================
// User Create Tests
// =============================================================================

/// Test successful user creation via SCIM POST /Users.
#[tokio::test]
async fn test_provisioner_create_user() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;
    server.mock_create_user_success().await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();
    let user = generate_scim_user("john.doe@example.com", tenant.tenant_id);

    let result = client.create_user(&user).await;

    assert!(result.is_ok(), "User creation should succeed");
    let created = result.unwrap();
    assert!(created.id.is_some(), "Created user should have an ID");
    assert_eq!(created.user_name, "john.doe@example.com");
    assert!(created.active);
}

/// Test user creation with full profile details.
#[tokio::test]
async fn test_provisioner_create_user_full_profile() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;
    server.mock_create_user_success().await;

    let client = server.client();
    let user = generate_scim_user_full(
        "jane.smith@example.com",
        "Jane",
        "Smith",
        true,
        Some("ext-jane-123"),
    );

    let result = client.create_user(&user).await;

    assert!(result.is_ok());
    let created = result.unwrap();
    assert_eq!(created.user_name, "jane.smith@example.com");
    assert!(created.id.is_some());
}

/// Test user creation returns 409 Conflict when user already exists.
#[tokio::test]
async fn test_provisioner_create_user_conflict() {
    let server = MockScimServer::new().await;
    server.mock_create_user_conflict().await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();
    let user = generate_scim_user("existing@example.com", tenant.tenant_id);

    let result = client.create_user(&user).await;

    assert!(matches!(result, Err(ScimClientError::Conflict(_))));
}

// =============================================================================
// User Update Tests
// =============================================================================

/// Test successful user update via SCIM PATCH /Users/{id}.
#[tokio::test]
async fn test_provisioner_update_user() {
    let server = MockScimServer::new().await;
    let user_id = Uuid::new_v4().to_string();

    server.mock_service_provider_config().await;
    server.mock_patch_user_success(&user_id).await;

    let client = server.client();

    let patch = xavyo_api_scim::models::ScimPatchRequest {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:PatchOp".to_string()],
        operations: vec![xavyo_api_scim::models::ScimPatchOp {
            op: "replace".to_string(),
            path: Some("displayName".to_string()),
            value: Some(json!("Updated Name")),
        }],
    };

    let result = client.patch_user(&user_id, &patch).await;

    assert!(
        result.is_ok(),
        "User update should succeed: {:?}",
        result.err()
    );
}

/// Test user update via PUT when PATCH is not supported.
#[tokio::test]
async fn test_provisioner_update_user_via_put() {
    let server = MockScimServer::new().await;
    let user_id = Uuid::new_v4().to_string();

    server.mock_service_provider_config_no_patch().await;
    server.mock_replace_user_success(&user_id).await;

    let client = server.client();

    let user = generate_scim_user_full(
        "updated@example.com",
        "Updated",
        "User",
        true,
        Some(&user_id),
    );

    let result = client.replace_user(&user_id, &user).await;

    assert!(
        result.is_ok(),
        "User replace should succeed: {:?}",
        result.err()
    );
}

// =============================================================================
// User Delete Tests
// =============================================================================

/// Test successful user deletion via SCIM DELETE /Users/{id}.
#[tokio::test]
async fn test_provisioner_delete_user() {
    let server = MockScimServer::new().await;
    let user_id = Uuid::new_v4().to_string();

    server.mock_delete_user_success(&user_id).await;

    let client = server.client();
    let result = client.delete_user(&user_id).await;

    assert!(result.is_ok(), "User deletion should succeed");
}

/// Test user deletion returns 404 when user doesn't exist.
#[tokio::test]
async fn test_provisioner_delete_user_not_found() {
    let server = MockScimServer::new().await;
    let user_id = Uuid::new_v4().to_string();

    server.mock_delete_user_not_found(&user_id).await;

    let client = server.client();
    let result = client.delete_user(&user_id).await;

    assert!(matches!(result, Err(ScimClientError::NotFound(_))));
}

// =============================================================================
// User Get Tests
// =============================================================================

/// Test successful user retrieval via SCIM GET /Users/{id}.
#[tokio::test]
async fn test_provisioner_get_user() {
    let server = MockScimServer::new().await;
    let user_id = Uuid::new_v4().to_string();

    let user_data =
        generate_user_response(&user_id, "getuser@example.com", Some("ext-get-123"), true);
    server.mock_get_user_success(&user_id, user_data).await;

    let client = server.client();
    let result = client.get_user(&user_id).await;

    assert!(result.is_ok(), "User retrieval should succeed");
    let user = result.unwrap();
    assert_eq!(user.user_name, "getuser@example.com");
}

/// Test user retrieval returns 404 when user doesn't exist.
#[tokio::test]
async fn test_provisioner_get_user_not_found() {
    let server = MockScimServer::new().await;
    let user_id = Uuid::new_v4().to_string();

    server.mock_get_user_not_found(&user_id).await;

    let client = server.client();
    let result = client.get_user(&user_id).await;

    assert!(matches!(result, Err(ScimClientError::NotFound(_))));
}

// =============================================================================
// Batch User Tests
// =============================================================================

/// Test creating multiple users in sequence.
#[tokio::test]
async fn test_provisioner_batch_create_users() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;
    server.mock_create_user_success().await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();
    let users = generate_user_batch(5, tenant.tenant_id);

    let mut created_count = 0;
    for user in users {
        let result = client.create_user(&user).await;
        if result.is_ok() {
            created_count += 1;
        }
    }

    assert_eq!(created_count, 5, "All 5 users should be created");
}

// =============================================================================
// Group Create Tests
// =============================================================================

/// Test successful group creation via SCIM POST /Groups.
#[tokio::test]
async fn test_provisioner_create_group() {
    let server = MockScimServer::new().await;
    server.mock_service_provider_config().await;
    server.mock_create_group_success().await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();
    let group = generate_scim_group("Engineering", tenant.tenant_id);

    let result = client.create_group(&group).await;

    assert!(
        result.is_ok(),
        "Group creation should succeed: {:?}",
        result.err()
    );
    let created = result.unwrap();
    assert!(created.id.is_some(), "Created group should have an ID");
    assert_eq!(created.display_name, "Engineering");
}

/// Test group creation returns 409 Conflict when group already exists.
#[tokio::test]
async fn test_provisioner_create_group_conflict() {
    let server = MockScimServer::new().await;
    server.mock_create_group_conflict().await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();
    let group = generate_scim_group("Existing Group", tenant.tenant_id);

    let result = client.create_group(&group).await;

    assert!(matches!(result, Err(ScimClientError::Conflict(_))));
}

// =============================================================================
// Group Update Tests
// =============================================================================

/// Test successful group update via SCIM PATCH /Groups/{id}.
#[tokio::test]
async fn test_provisioner_update_group() {
    let server = MockScimServer::new().await;
    let group_id = Uuid::new_v4().to_string();

    server.mock_service_provider_config().await;
    server.mock_patch_group_success(&group_id).await;

    let client = server.client();

    // Add members to group
    let result = client
        .patch_group_members(&group_id, &["user-1".to_string()], &[])
        .await;

    assert!(result.is_ok(), "Group update should succeed");
}

// =============================================================================
// Group Delete Tests
// =============================================================================

/// Test successful group deletion via SCIM DELETE /Groups/{id}.
#[tokio::test]
async fn test_provisioner_delete_group() {
    let server = MockScimServer::new().await;
    let group_id = Uuid::new_v4().to_string();

    server.mock_delete_group_success(&group_id).await;

    let client = server.client();
    let result = client.delete_group(&group_id).await;

    assert!(result.is_ok(), "Group deletion should succeed");
}

// =============================================================================
// Rate Limit Handling Tests
// =============================================================================

/// Test handling of 429 Too Many Requests with Retry-After header.
#[tokio::test]
async fn test_provisioner_rate_limit_handling() {
    let server = MockScimServer::new().await;
    server.mock_rate_limited(30).await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();
    let user = generate_scim_user("ratelimited@example.com", tenant.tenant_id);

    let result = client.create_user(&user).await;

    match result {
        Err(ScimClientError::RateLimited { retry_after_secs }) => {
            assert_eq!(retry_after_secs, Some(30));
        }
        other => panic!("Expected RateLimited error, got {:?}", other),
    }
}

// =============================================================================
// Tenant Isolation Tests
// =============================================================================

/// Test that operations are isolated per tenant (different servers simulate different targets).
#[tokio::test]
async fn test_provisioner_tenant_isolation() {
    // Create two separate mock servers to simulate tenant isolation
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

    let user_a = generate_scim_user("user_a@tenanta.com", tenant_a.tenant_id);
    let user_b = generate_scim_user("user_b@tenantb.com", tenant_b.tenant_id);

    // Create users in separate tenant targets
    let result_a = client_a.create_user(&user_a).await;
    let result_b = client_b.create_user(&user_b).await;

    assert!(result_a.is_ok(), "Tenant A user creation should succeed");
    assert!(result_b.is_ok(), "Tenant B user creation should succeed");

    // Verify users were created with correct data
    let created_a = result_a.unwrap();
    let created_b = result_b.unwrap();

    assert_eq!(created_a.user_name, "user_a@tenanta.com");
    assert_eq!(created_b.user_name, "user_b@tenantb.com");
}

// =============================================================================
// User Deactivation Tests
// =============================================================================

/// Test user deactivation via SCIM PATCH setting active=false.
#[tokio::test]
async fn test_provisioner_deactivate_user() {
    let server = MockScimServer::new().await;
    let user_id = Uuid::new_v4().to_string();

    server.mock_patch_user_success(&user_id).await;

    let client = server.client();
    let result = client.deactivate_user(&user_id).await;

    assert!(result.is_ok(), "User deactivation should succeed");
}

// =============================================================================
// Find User by External ID Tests
// =============================================================================

/// Test finding a user by their external ID.
#[tokio::test]
async fn test_provisioner_find_user_by_external_id() {
    let server = MockScimServer::new().await;
    let user_id = Uuid::new_v4().to_string();
    let external_id = "ext-find-user-123";

    let user_data = generate_user_response(&user_id, "found@example.com", Some(external_id), true);
    server
        .mock_find_user_by_external_id(external_id, Some(user_data))
        .await;

    let client = server.client();
    let result = client.find_user_by_external_id(external_id).await;

    assert!(result.is_ok());
    let found = result.unwrap();
    assert!(found.is_some(), "User should be found");
    assert_eq!(found.unwrap().user_name, "found@example.com");
}

/// Test finding a user by external ID when user doesn't exist.
#[tokio::test]
async fn test_provisioner_find_user_by_external_id_not_found() {
    let server = MockScimServer::new().await;
    server
        .mock_find_user_by_external_id("nonexistent-ext-id", None)
        .await;

    let client = server.client();
    let result = client.find_user_by_external_id("nonexistent-ext-id").await;

    assert!(result.is_ok());
    let found = result.unwrap();
    assert!(found.is_none(), "User should not be found");
}

// =============================================================================
// Find Group by External ID Tests
// =============================================================================

/// Test finding a group by their external ID.
#[tokio::test]
async fn test_provisioner_find_group_by_external_id() {
    let server = MockScimServer::new().await;
    let group_id = Uuid::new_v4().to_string();
    let external_id = "ext-find-group-123";

    let group_data = generate_group_response(&group_id, "Found Group", Some(external_id), &[]);
    server
        .mock_find_group_by_external_id(external_id, Some(group_data))
        .await;

    let client = server.client();
    let result = client.find_group_by_external_id(external_id).await;

    assert!(result.is_ok());
    let found = result.unwrap();
    assert!(found.is_some(), "Group should be found");
    assert_eq!(found.unwrap().display_name, "Found Group");
}

/// Test finding a group by external ID when group doesn't exist.
#[tokio::test]
async fn test_provisioner_find_group_by_external_id_not_found() {
    let server = MockScimServer::new().await;
    server
        .mock_find_group_by_external_id("nonexistent-ext-id", None)
        .await;

    let client = server.client();
    let result = client.find_group_by_external_id("nonexistent-ext-id").await;

    assert!(result.is_ok());
    let found = result.unwrap();
    assert!(found.is_none(), "Group should not be found");
}
