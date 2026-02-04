//! Integration tests for REST Connector using wiremock.
//!
//! These tests verify the connector against a mock HTTP server,
//! covering CRUD operations, authentication, pagination, rate limiting,
//! retry logic, timeout handling, and security validations.

use serde_json::json;
use std::time::Duration;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use xavyo_connector::config::ConnectorConfig;
use xavyo_connector::operation::{AttributeDelta, AttributeSet, Filter, PageRequest, Uid};
use xavyo_connector::traits::{Connector, CreateOp, DeleteOp, SearchOp, UpdateOp};
use xavyo_connector_rest::{
    LogVerbosity, PaginationStyle, RateLimitConfig, RestConfig, RestConnector, RetryConfig,
};

// =============================================================================
// Test Helpers
// =============================================================================

async fn setup_mock_server() -> MockServer {
    MockServer::start().await
}

fn create_config(base_url: &str) -> RestConfig {
    RestConfig::new(base_url)
        .with_allow_localhost()
        .with_rate_limit(RateLimitConfig::disabled())
        .with_retry(RetryConfig::disabled())
        .with_log_verbosity(LogVerbosity::Debug)
}

fn create_config_with_rate_limit(base_url: &str) -> RestConfig {
    RestConfig::new(base_url)
        .with_allow_localhost()
        .with_rate_limit(RateLimitConfig::new(100).with_max_concurrent(10))
        .with_retry(
            RetryConfig::new(3)
                .with_initial_backoff(10)
                .with_max_backoff(100),
        )
        .with_log_verbosity(LogVerbosity::Debug)
}

// =============================================================================
// Connection Tests
// =============================================================================

#[tokio::test]
async fn test_connection_success() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let result = connector.test_connection().await;
    assert!(
        result.is_ok(),
        "Connection should succeed: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_connection_failure_server_error() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let result = connector.test_connection().await;
    assert!(result.is_err(), "Connection should fail on 500");
}

#[tokio::test]
async fn test_connection_auth_failure() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let result = connector.test_connection().await;
    assert!(result.is_err(), "Connection should fail on 401");
}

// =============================================================================
// Authentication Tests
// =============================================================================

#[tokio::test]
async fn test_bearer_token_authentication() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .and(header("Authorization", "Bearer test-token-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let config = create_config(&server.uri()).with_bearer_token("test-token-123");
    let connector = RestConnector::new(config).unwrap();

    let result = connector.test_connection().await;
    assert!(
        result.is_ok(),
        "Bearer auth should work: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_basic_authentication() {
    let server = setup_mock_server().await;

    // Basic auth header for admin:secret is "YWRtaW46c2VjcmV0"
    Mock::given(method("GET"))
        .and(path("/users"))
        .and(header("Authorization", "Basic YWRtaW46c2VjcmV0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let config = create_config(&server.uri()).with_basic_auth("admin", "secret");
    let connector = RestConnector::new(config).unwrap();

    let result = connector.test_connection().await;
    assert!(result.is_ok(), "Basic auth should work: {:?}", result.err());
}

#[tokio::test]
async fn test_api_key_authentication() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .and(header("X-API-Key", "my-api-key-12345"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let config = create_config(&server.uri()).with_api_key("my-api-key-12345");
    let connector = RestConnector::new(config).unwrap();

    let result = connector.test_connection().await;
    assert!(
        result.is_ok(),
        "API key auth should work: {:?}",
        result.err()
    );
}

// =============================================================================
// CRUD Operations - Create
// =============================================================================

#[tokio::test]
async fn test_create_user_success() {
    let server = setup_mock_server().await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .and(body_json(json!({
            "email": "john@example.com",
            "firstName": "John",
            "lastName": "Doe"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "user-123",
            "email": "john@example.com",
            "firstName": "John",
            "lastName": "Doe"
        })))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let mut attrs = AttributeSet::new();
    attrs.set("email", "john@example.com".to_string());
    attrs.set("firstName", "John".to_string());
    attrs.set("lastName", "Doe".to_string());

    let result = connector.create("user", attrs).await;
    assert!(result.is_ok(), "Create should succeed: {:?}", result.err());
    assert_eq!(result.unwrap().value(), "user-123");
}

#[tokio::test]
async fn test_create_user_conflict() {
    let server = setup_mock_server().await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "message": "User already exists"
        })))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let mut attrs = AttributeSet::new();
    attrs.set("email", "existing@example.com".to_string());

    let result = connector.create("user", attrs).await;
    assert!(result.is_err(), "Create should fail on conflict");
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            xavyo_connector::error::ConnectorError::ObjectAlreadyExists { .. }
        ),
        "Should be ObjectAlreadyExists error"
    );
}

// =============================================================================
// CRUD Operations - Update
// =============================================================================

#[tokio::test]
async fn test_update_user_success() {
    let server = setup_mock_server().await;

    Mock::given(method("PUT"))
        .and(path("/users/user-123"))
        .and(body_json(json!({
            "lastName": "Smith"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "user-123",
            "email": "john@example.com",
            "firstName": "John",
            "lastName": "Smith"
        })))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let uid = Uid::from_id("user-123".to_string());
    let mut delta = AttributeDelta::new();
    delta.replace("lastName", "Smith".to_string());

    let result = connector.update("user", &uid, delta).await;
    assert!(result.is_ok(), "Update should succeed: {:?}", result.err());
}

#[tokio::test]
async fn test_update_user_not_found() {
    let server = setup_mock_server().await;

    Mock::given(method("PUT"))
        .and(path("/users/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "message": "User not found"
        })))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let uid = Uid::from_id("nonexistent".to_string());
    let mut delta = AttributeDelta::new();
    delta.replace("lastName", "Smith".to_string());

    let result = connector.update("user", &uid, delta).await;
    assert!(result.is_err(), "Update should fail for nonexistent user");
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            xavyo_connector::error::ConnectorError::ObjectNotFound { .. }
        ),
        "Should be ObjectNotFound error"
    );
}

#[tokio::test]
async fn test_update_empty_delta() {
    let server = setup_mock_server().await;
    // No mock needed - empty delta should short-circuit

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let uid = Uid::from_id("user-123".to_string());
    let delta = AttributeDelta::new(); // Empty

    let result = connector.update("user", &uid, delta).await;
    assert!(result.is_ok(), "Update with empty delta should succeed");
    assert_eq!(result.unwrap().value(), "user-123");
}

// =============================================================================
// CRUD Operations - Delete
// =============================================================================

#[tokio::test]
async fn test_delete_user_success() {
    let server = setup_mock_server().await;

    Mock::given(method("DELETE"))
        .and(path("/users/user-123"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let uid = Uid::from_id("user-123".to_string());
    let result = connector.delete("user", &uid).await;
    assert!(result.is_ok(), "Delete should succeed: {:?}", result.err());
}

#[tokio::test]
async fn test_delete_user_not_found() {
    let server = setup_mock_server().await;

    Mock::given(method("DELETE"))
        .and(path("/users/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "message": "User not found"
        })))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let uid = Uid::from_id("nonexistent".to_string());
    let result = connector.delete("user", &uid).await;
    assert!(result.is_err(), "Delete should fail for nonexistent user");
}

// =============================================================================
// CRUD Operations - Search
// =============================================================================

#[tokio::test]
async fn test_search_users_success() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "user-1", "email": "user1@example.com", "firstName": "User", "lastName": "One"},
            {"id": "user-2", "email": "user2@example.com", "firstName": "User", "lastName": "Two"},
            {"id": "user-3", "email": "user3@example.com", "firstName": "User", "lastName": "Three"}
        ])))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let result = connector.search("user", None, None, None).await;
    assert!(result.is_ok(), "Search should succeed: {:?}", result.err());

    let search_result = result.unwrap();
    assert_eq!(search_result.objects.len(), 3);
}

#[tokio::test]
async fn test_search_users_with_filter() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .and(query_param("status", "active"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "user-1", "email": "active@example.com", "status": "active"}
        ])))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let filter = Filter::Equals {
        attribute: "status".to_string(),
        value: "active".to_string(),
    };

    let result = connector.search("user", Some(filter), None, None).await;
    assert!(
        result.is_ok(),
        "Search with filter should succeed: {:?}",
        result.err()
    );
    assert_eq!(result.unwrap().objects.len(), 1);
}

#[tokio::test]
async fn test_search_users_empty_results() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let result = connector.search("user", None, None, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().objects.len(), 0);
}

// =============================================================================
// Pagination Tests
// =============================================================================

#[tokio::test]
async fn test_search_with_page_based_pagination() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .and(query_param("page", "1"))
        .and(query_param("pageSize", "10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "user-1"},
            {"id": "user-2"}
        ])))
        .mount(&server)
        .await;

    let mut config = create_config(&server.uri());
    config.pagination.style = PaginationStyle::PageBased;
    config.pagination.default_page_size = 10;

    let connector = RestConnector::new(config).unwrap();

    let page = PageRequest::new(10);
    let result = connector.search("user", None, None, Some(page)).await;
    assert!(result.is_ok(), "Pagination should work: {:?}", result.err());
}

#[tokio::test]
async fn test_search_with_offset_pagination() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .and(query_param("offset", "20"))
        .and(query_param("pageSize", "10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let mut config = create_config(&server.uri());
    config.pagination.style = PaginationStyle::OffsetBased;

    let connector = RestConnector::new(config).unwrap();

    let page = PageRequest::new(10).with_offset(20);
    let result = connector.search("user", None, None, Some(page)).await;
    assert!(
        result.is_ok(),
        "Offset pagination should work: {:?}",
        result.err()
    );
}

// =============================================================================
// Response Parsing Tests
// =============================================================================

#[tokio::test]
async fn test_search_with_nested_results_path() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "user-1", "email": "user1@example.com"},
                {"id": "user-2", "email": "user2@example.com"}
            ],
            "meta": {
                "total": 100,
                "page": 1
            }
        })))
        .mount(&server)
        .await;

    let mut config = create_config(&server.uri());
    config.response.results_path = Some("data".to_string());
    config.response.total_count_path = Some("meta.total".to_string());

    let connector = RestConnector::new(config).unwrap();

    let result = connector.search("user", None, None, None).await;
    assert!(result.is_ok());

    let search_result = result.unwrap();
    assert_eq!(search_result.objects.len(), 2);
    assert_eq!(search_result.total_count, Some(100));
}

// =============================================================================
// Retry Logic Tests
// =============================================================================

#[tokio::test]
async fn test_retry_on_503_service_unavailable() {
    let server = setup_mock_server().await;

    // First two requests fail with 503, third succeeds
    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
        .up_to_n_times(2)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let config = create_config_with_rate_limit(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let result = connector.test_connection().await;
    assert!(
        result.is_ok(),
        "Should succeed after retries: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_retry_on_502_bad_gateway() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(502).set_body_string("Bad Gateway"))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let config = create_config_with_rate_limit(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let result = connector.test_connection().await;
    assert!(
        result.is_ok(),
        "Should succeed after retry: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_retry_exhausted() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
        .mount(&server)
        .await;

    let config = RestConfig::new(server.uri())
        .with_allow_localhost()
        .with_rate_limit(RateLimitConfig::disabled())
        .with_retry(
            RetryConfig::new(2)
                .with_initial_backoff(1)
                .with_max_backoff(5),
        );

    let connector = RestConnector::new(config).unwrap();

    let result = connector.test_connection().await;
    assert!(result.is_err(), "Should fail after max retries");
}

#[tokio::test]
async fn test_no_retry_on_400_bad_request() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"message": "Bad request"})))
        .expect(1) // Should only be called once (no retry)
        .mount(&server)
        .await;

    let config = create_config_with_rate_limit(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let result = connector.test_connection().await;
    assert!(result.is_err(), "Should fail without retry on 400");
}

// =============================================================================
// Rate Limiting Tests
// =============================================================================

#[tokio::test]
async fn test_rate_limit_429_with_retry_after() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_string("Too Many Requests")
                .insert_header("Retry-After", "1"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let config = create_config_with_rate_limit(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let result = connector.test_connection().await;
    assert!(
        result.is_ok(),
        "Should succeed after respecting Retry-After: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_rate_limiter_stats() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let config = RestConfig::new(server.uri())
        .with_allow_localhost()
        .with_rate_limit(RateLimitConfig::new(10).with_max_concurrent(5))
        .with_retry(RetryConfig::disabled());

    let connector = RestConnector::new(config).unwrap();

    // Get initial stats
    let stats = connector.rate_limit_stats().await;
    assert_eq!(stats.global_available_permits, 5);

    // Make a request
    let _ = connector.test_connection().await;

    // Stats should still show permits available after request completes
    let stats = connector.rate_limit_stats().await;
    assert_eq!(stats.global_available_permits, 5);
}

// =============================================================================
// Timeout Tests
// =============================================================================

#[tokio::test]
async fn test_request_timeout() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(10)))
        .mount(&server)
        .await;

    let mut config = create_config(&server.uri());
    config.connection.read_timeout_secs = 1; // 1 second timeout

    let connector = RestConnector::new(config).unwrap();

    let result = connector.test_connection().await;
    assert!(result.is_err(), "Request should timeout");
}

// =============================================================================
// Custom Headers Tests
// =============================================================================

#[tokio::test]
async fn test_custom_headers() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .and(header("X-Custom-Header", "custom-value"))
        .and(header("X-Another-Header", "another-value"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let config = create_config(&server.uri())
        .with_header("X-Custom-Header", "custom-value")
        .with_header("X-Another-Header", "another-value");

    let connector = RestConnector::new(config).unwrap();

    let result = connector.test_connection().await;
    assert!(
        result.is_ok(),
        "Custom headers should be sent: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_content_type_header() {
    let server = setup_mock_server().await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "123"})))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let mut attrs = AttributeSet::new();
    attrs.set("name", "test".to_string());

    let result = connector.create("user", attrs).await;
    assert!(result.is_ok(), "Should send correct Content-Type");
}

// =============================================================================
// Error Response Parsing Tests
// =============================================================================

#[tokio::test]
async fn test_error_message_extraction() {
    let server = setup_mock_server().await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "message": "Email is required",
            "code": "VALIDATION_ERROR"
        })))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let attrs = AttributeSet::new();
    let result = connector.create("user", attrs).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("Email is required"),
        "Error should contain message: {err_str}"
    );
}

// =============================================================================
// SSRF Protection Tests
// =============================================================================

#[test]
fn test_ssrf_blocks_localhost() {
    let result = RestConfig::new("http://localhost:8080");
    // The URL is valid but validate() should fail
    assert!(result.validate().is_err(), "Should block localhost");
}

#[test]
fn test_ssrf_blocks_127_0_0_1() {
    let result = RestConfig::new("http://127.0.0.1:8080");
    assert!(result.validate().is_err(), "Should block 127.0.0.1");
}

#[test]
fn test_ssrf_blocks_private_10_network() {
    let result = RestConfig::new("http://10.0.0.1:8080");
    assert!(
        result.validate().is_err(),
        "Should block 10.x.x.x private network"
    );
}

#[test]
fn test_ssrf_blocks_private_172_network() {
    let result = RestConfig::new("http://172.16.0.1:8080");
    assert!(
        result.validate().is_err(),
        "Should block 172.16.x.x private network"
    );
}

#[test]
fn test_ssrf_blocks_private_192_168_network() {
    let result = RestConfig::new("http://192.168.1.1:8080");
    assert!(
        result.validate().is_err(),
        "Should block 192.168.x.x private network"
    );
}

#[test]
fn test_ssrf_blocks_metadata_endpoint() {
    let result = RestConfig::new("http://169.254.169.254/latest/meta-data");
    assert!(
        result.validate().is_err(),
        "Should block cloud metadata endpoint"
    );
}

#[test]
fn test_ssrf_allows_public_urls() {
    let result = RestConfig::new("https://api.example.com/v1");
    assert!(result.validate().is_ok(), "Should allow public URLs");
}

// =============================================================================
// Dispose/Lifecycle Tests
// =============================================================================

#[tokio::test]
async fn test_connector_dispose() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    // Connection works before dispose
    let result = connector.test_connection().await;
    assert!(result.is_ok());

    // Dispose
    connector.dispose().await.unwrap();

    // Connection should fail after dispose
    let result = connector.test_connection().await;
    assert!(result.is_err(), "Should fail after dispose");
}

// =============================================================================
// Custom Object Class Tests
// =============================================================================

#[tokio::test]
async fn test_custom_object_class() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/applications"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "app-1", "name": "App One"},
            {"id": "app-2", "name": "App Two"}
        ])))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let result = connector.search("applications", None, None, None).await;
    assert!(result.is_ok(), "Custom object class should work");
    assert_eq!(result.unwrap().objects.len(), 2);
}

// =============================================================================
// Schema Discovery Tests
// =============================================================================

#[tokio::test]
async fn test_schema_discovery_default() {
    let server = setup_mock_server().await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    use xavyo_connector::traits::SchemaDiscovery;
    let schema = connector.discover_schema().await;
    assert!(schema.is_ok(), "Schema discovery should succeed");

    let schema = schema.unwrap();
    assert!(
        schema.object_classes.len() >= 2,
        "Should have user and group classes"
    );
}

// =============================================================================
// Group Operations Tests
// =============================================================================

#[tokio::test]
async fn test_search_groups() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/groups"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "group-1", "name": "Admins"},
            {"id": "group-2", "name": "Users"}
        ])))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let result = connector.search("group", None, None, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().objects.len(), 2);
}

#[tokio::test]
async fn test_create_group() {
    let server = setup_mock_server().await;

    Mock::given(method("POST"))
        .and(path("/groups"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "group-123",
            "name": "New Group"
        })))
        .mount(&server)
        .await;

    let config = create_config(&server.uri());
    let connector = RestConnector::new(config).unwrap();

    let mut attrs = AttributeSet::new();
    attrs.set("name", "New Group".to_string());

    // Use "groups" plural to match the endpoint path - the connector uses
    // the object_class directly for non-user operations
    let result = connector.create("groups", attrs).await;
    assert!(result.is_ok(), "Create group failed: {:?}", result.err());
    assert_eq!(result.unwrap().value(), "group-123");
}
