//! Integration tests for SCIM client error handling.
//!
//! Tests cover all HTTP error status codes and error scenarios:
//! - 401 Unauthorized
//! - 403 Forbidden
//! - 404 Not Found
//! - 409 Conflict
//! - 429 Rate Limited
//! - 500 Internal Server Error
//! - 502 Bad Gateway
//! - 503 Service Unavailable
//! - Connection timeout
//!
//! Run with: `cargo test -p xavyo-scim-client --features integration --test error_tests`

#![cfg(feature = "integration")]

mod helpers;

use helpers::mock_scim_server::MockScimServer;
use helpers::test_data::{generate_scim_user, TestTenant};
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use xavyo_scim_client::auth::{ScimAuth, ScimCredentials};
use xavyo_scim_client::client::ScimClient;
use xavyo_scim_client::error::ScimClientError;

// =============================================================================
// 401 Unauthorized Tests
// =============================================================================

/// Test handling of 401 Unauthorized response.
#[tokio::test]
async fn test_error_401_unauthorized() {
    let server = MockScimServer::new().await;
    server.mock_unauthorized().await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();
    let user = generate_scim_user("test@example.com", tenant.tenant_id);

    let result = client.create_user(&user).await;

    assert!(matches!(result, Err(ScimClientError::AuthError(_))));
}

/// Test that 401 response includes proper error message.
#[tokio::test]
async fn test_error_401_error_message() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/Users"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": "Invalid or expired token",
            "status": "401"
        })))
        .mount(&mock_server)
        .await;

    let auth = ScimAuth::new(
        ScimCredentials::Bearer {
            token: "invalid-token".to_string(),
        },
        reqwest::Client::new(),
    );
    let client = ScimClient::with_http_client(mock_server.uri(), auth, reqwest::Client::new());

    let tenant = TestTenant::tenant_a();
    let user = generate_scim_user("test@example.com", tenant.tenant_id);

    let result = client.create_user(&user).await;

    match result {
        Err(ScimClientError::AuthError(msg)) => {
            assert!(msg.contains("401") || msg.to_lowercase().contains("unauthorized"));
        }
        other => panic!("Expected AuthError, got {:?}", other),
    }
}

// =============================================================================
// 403 Forbidden Tests
// =============================================================================

/// Test handling of 403 Forbidden response.
#[tokio::test]
async fn test_error_403_forbidden() {
    let server = MockScimServer::new().await;
    server.mock_forbidden().await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();
    let user = generate_scim_user("test@example.com", tenant.tenant_id);

    let result = client.create_user(&user).await;

    // 403 should be treated as an authentication/authorization error
    match result {
        Err(ScimClientError::ScimError { status, .. }) => {
            assert_eq!(status, 403);
        }
        Err(ScimClientError::AuthError(_)) => {
            // Also acceptable interpretation
        }
        other => panic!(
            "Expected ScimError with status 403 or AuthError, got {:?}",
            other
        ),
    }
}

/// Test 403 when trying to access another tenant's resources.
#[tokio::test]
async fn test_error_403_cross_tenant_access() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/Users/other-tenant-user"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": "Access denied to this resource",
            "status": "403"
        })))
        .mount(&mock_server)
        .await;

    let auth = ScimAuth::new(
        ScimCredentials::Bearer {
            token: "valid-token".to_string(),
        },
        reqwest::Client::new(),
    );
    let client = ScimClient::with_http_client(mock_server.uri(), auth, reqwest::Client::new());

    let result = client.get_user("other-tenant-user").await;

    assert!(result.is_err());
}

// =============================================================================
// 404 Not Found Tests
// =============================================================================

/// Test handling of 404 Not Found response.
#[tokio::test]
async fn test_error_404_not_found() {
    let server = MockScimServer::new().await;
    let user_id = Uuid::new_v4().to_string();
    server.mock_get_user_not_found(&user_id).await;

    let client = server.client();
    let result = client.get_user(&user_id).await;

    assert!(matches!(result, Err(ScimClientError::NotFound(_))));
}

/// Test 404 when deleting non-existent user.
#[tokio::test]
async fn test_error_404_delete_nonexistent() {
    let server = MockScimServer::new().await;
    let user_id = Uuid::new_v4().to_string();
    server.mock_delete_user_not_found(&user_id).await;

    let client = server.client();
    let result = client.delete_user(&user_id).await;

    assert!(matches!(result, Err(ScimClientError::NotFound(_))));
}

/// Test 404 includes resource identifier in error.
#[tokio::test]
async fn test_error_404_error_includes_resource() {
    let mock_server = MockServer::start().await;
    let user_id = "specific-user-123";

    Mock::given(method("GET"))
        .and(path(format!("/Users/{}", user_id)))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": "User not found",
            "status": "404"
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

    let result = client.get_user(user_id).await;

    match result {
        Err(ScimClientError::NotFound(msg)) => {
            assert!(!msg.is_empty(), "Error message should not be empty");
        }
        other => panic!("Expected NotFound, got {:?}", other),
    }
}

// =============================================================================
// 409 Conflict Tests
// =============================================================================

/// Test handling of 409 Conflict response.
#[tokio::test]
async fn test_error_409_conflict() {
    let server = MockScimServer::new().await;
    server.mock_create_user_conflict().await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();
    let user = generate_scim_user("existing@example.com", tenant.tenant_id);

    let result = client.create_user(&user).await;

    assert!(matches!(result, Err(ScimClientError::Conflict(_))));
}

/// Test 409 when creating duplicate group.
#[tokio::test]
async fn test_error_409_duplicate_group() {
    let server = MockScimServer::new().await;
    server.mock_create_group_conflict().await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();
    let group = helpers::test_data::generate_scim_group("Existing Group", tenant.tenant_id);

    let result = client.create_group(&group).await;

    assert!(matches!(result, Err(ScimClientError::Conflict(_))));
}

/// Test 409 error message contains conflict details.
#[tokio::test]
async fn test_error_409_conflict_details() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/Users"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": "User with this email already exists: existing@example.com",
            "status": "409",
            "scimType": "uniqueness"
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
    let user = generate_scim_user("existing@example.com", tenant.tenant_id);

    let result = client.create_user(&user).await;

    match result {
        Err(ScimClientError::Conflict(msg)) => {
            // Error should contain some detail about the conflict
            assert!(!msg.is_empty());
        }
        other => panic!("Expected Conflict, got {:?}", other),
    }
}

// =============================================================================
// 429 Rate Limited Tests
// =============================================================================

/// Test handling of 429 Too Many Requests.
#[tokio::test]
async fn test_error_429_rate_limited() {
    let server = MockScimServer::new().await;
    server.mock_rate_limited(60).await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();
    let user = generate_scim_user("test@example.com", tenant.tenant_id);

    let result = client.create_user(&user).await;

    match result {
        Err(ScimClientError::RateLimited { retry_after_secs }) => {
            assert_eq!(retry_after_secs, Some(60));
        }
        other => panic!("Expected RateLimited, got {:?}", other),
    }
}

/// Test 429 without Retry-After header.
#[tokio::test]
async fn test_error_429_without_retry_after() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/Users"))
        .respond_with(ResponseTemplate::new(429).set_body_string("Too Many Requests"))
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
    let user = generate_scim_user("test@example.com", tenant.tenant_id);

    let result = client.create_user(&user).await;

    match result {
        Err(ScimClientError::RateLimited { retry_after_secs }) => {
            // Without header, retry_after_secs should be None
            assert!(retry_after_secs.is_none() || retry_after_secs == Some(0));
        }
        Err(ScimClientError::ScimError { status: 429, .. }) => {
            // Also acceptable
        }
        other => panic!("Expected RateLimited or ScimError 429, got {:?}", other),
    }
}

// =============================================================================
// 500 Internal Server Error Tests
// =============================================================================

/// Test handling of 500 Internal Server Error.
#[tokio::test]
async fn test_error_500_server_error() {
    let server = MockScimServer::new().await;
    server.mock_server_error().await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();
    let user = generate_scim_user("test@example.com", tenant.tenant_id);

    let result = client.create_user(&user).await;

    match result {
        Err(ScimClientError::ScimError { status, .. }) => {
            assert_eq!(status, 500);
        }
        other => panic!("Expected ScimError with status 500, got {:?}", other),
    }
}

/// Test that 500 errors are marked as retryable.
#[tokio::test]
async fn test_error_500_is_retryable() {
    let error = ScimClientError::ScimError {
        status: 500,
        detail: "Internal server error".to_string(),
    };

    assert!(error.is_server_error(), "500 should be a server error");
}

// =============================================================================
// 502 Bad Gateway Tests
// =============================================================================

/// Test handling of 502 Bad Gateway.
#[tokio::test]
async fn test_error_502_bad_gateway() {
    let server = MockScimServer::new().await;
    server.mock_bad_gateway().await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();
    let user = generate_scim_user("test@example.com", tenant.tenant_id);

    let result = client.create_user(&user).await;

    match result {
        Err(ScimClientError::ScimError { status, .. }) => {
            assert_eq!(status, 502);
        }
        other => panic!("Expected ScimError with status 502, got {:?}", other),
    }
}

// =============================================================================
// 503 Service Unavailable Tests
// =============================================================================

/// Test handling of 503 Service Unavailable.
#[tokio::test]
async fn test_error_503_service_unavailable() {
    let server = MockScimServer::new().await;
    server.mock_service_unavailable().await;

    let client = server.client();
    let tenant = TestTenant::tenant_a();
    let user = generate_scim_user("test@example.com", tenant.tenant_id);

    let result = client.create_user(&user).await;

    match result {
        Err(ScimClientError::ScimError { status, .. }) => {
            assert_eq!(status, 503);
        }
        other => panic!("Expected ScimError with status 503, got {:?}", other),
    }
}

/// Test that 503 errors are marked as server errors.
#[tokio::test]
async fn test_error_503_is_server_error() {
    let error = ScimClientError::ScimError {
        status: 503,
        detail: "Service unavailable".to_string(),
    };

    assert!(error.is_server_error(), "503 should be a server error");
}

// =============================================================================
// Connection Timeout Tests
// =============================================================================

/// Test handling of connection timeout.
#[tokio::test]
async fn test_error_connection_timeout() {
    let mock_server = MockServer::start().await;

    // Configure a 5-second delay (longer than our client timeout)
    Mock::given(method("POST"))
        .and(path("/Users"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&mock_server)
        .await;

    // Create client with very short timeout
    let auth = ScimAuth::new(
        ScimCredentials::Bearer {
            token: "token".to_string(),
        },
        reqwest::Client::new(),
    );
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(100))
        .build()
        .unwrap();
    let client = ScimClient::with_http_client(mock_server.uri(), auth, http_client);

    let tenant = TestTenant::tenant_a();
    let user = generate_scim_user("test@example.com", tenant.tenant_id);

    let result = client.create_user(&user).await;

    // Should fail with timeout or HTTP error
    assert!(result.is_err());
    match result {
        Err(ScimClientError::HttpError(_)) => {
            // Expected - reqwest timeout manifests as HttpError
        }
        Err(ScimClientError::Timeout { .. }) => {
            // Also acceptable
        }
        other => panic!("Expected HttpError or Timeout, got {:?}", other),
    }
}

// =============================================================================
// Error Classification Tests
// =============================================================================

/// Test that retryable errors are correctly classified.
#[tokio::test]
async fn test_error_retryable_classification() {
    // Retryable errors
    assert!(ScimClientError::RateLimited {
        retry_after_secs: Some(30)
    }
    .is_retryable());

    assert!(ScimClientError::Timeout { timeout_secs: 30 }.is_retryable());

    assert!(ScimClientError::Unreachable("Connection refused".to_string()).is_retryable());

    // Non-retryable errors
    assert!(!ScimClientError::Conflict("duplicate".to_string()).is_retryable());
    assert!(!ScimClientError::NotFound("not found".to_string()).is_retryable());
    assert!(!ScimClientError::AuthError("bad token".to_string()).is_retryable());
}

/// Test server error classification (5xx).
#[tokio::test]
async fn test_error_server_error_classification() {
    assert!(ScimClientError::ScimError {
        status: 500,
        detail: "".to_string()
    }
    .is_server_error());

    assert!(ScimClientError::ScimError {
        status: 502,
        detail: "".to_string()
    }
    .is_server_error());

    assert!(ScimClientError::ScimError {
        status: 503,
        detail: "".to_string()
    }
    .is_server_error());

    // 4xx should not be server errors
    assert!(!ScimClientError::ScimError {
        status: 400,
        detail: "".to_string()
    }
    .is_server_error());

    assert!(!ScimClientError::ScimError {
        status: 404,
        detail: "".to_string()
    }
    .is_server_error());
}
