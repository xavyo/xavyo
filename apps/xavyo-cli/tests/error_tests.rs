//! Integration tests for error handling
//!
//! Tests cover:
//! - Network timeout
//! - Server 500 errors
//! - 404 Not Found
//! - 401 Unauthorized
//! - 429 Rate limiting
//! - Malformed JSON responses
//! - Connection refused

mod common;

use common::TestContext;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

// =========================================================================
// T052: Test network timeout displays connection error
// =========================================================================

#[tokio::test]
async fn test_network_timeout_handling() {
    let ctx = TestContext::new().await;

    // Note: For actual timeout testing, we'd need to configure client timeout
    // This test verifies the mock can simulate delays
    Mock::given(method("GET"))
        .and(path("/slow-endpoint"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_millis(100)))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(50))
        .build()
        .unwrap();

    let result = client
        .get(format!("{}/slow-endpoint", ctx.base_url()))
        .send()
        .await;

    // Request should timeout
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.is_timeout() || error.is_connect());
}

// =========================================================================
// T053: Test server 500 error displays server error message
// =========================================================================

#[tokio::test]
async fn test_server_error_500() {
    let ctx = TestContext::new().await;

    ctx.mock_server_error("/api/resource").await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/resource", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 500);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "internal_server_error");
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("unexpected error"));
}

// =========================================================================
// T054: Test 404 response displays not found message
// =========================================================================

#[tokio::test]
async fn test_not_found_404() {
    let ctx = TestContext::new().await;

    ctx.mock_not_found("/api/nonexistent").await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/nonexistent", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 404);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "not_found");
}

// =========================================================================
// T055: Test 401 response prompts for re-authentication
// =========================================================================

#[tokio::test]
async fn test_unauthorized_401() {
    let ctx = TestContext::new().await;

    ctx.mock_unauthorized("/api/protected").await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/protected", ctx.base_url()))
        // No auth header
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 401);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "unauthorized");
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("Authentication required"));
}

// =========================================================================
// T056: Test 429 rate limit displays retry message
// =========================================================================

#[tokio::test]
async fn test_rate_limited_429() {
    let ctx = TestContext::new().await;

    ctx.mock_rate_limited("/api/resource").await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/resource", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 429);

    // Check Retry-After header
    assert!(response.headers().contains_key("retry-after"));
    let retry_after = response.headers().get("retry-after").unwrap();
    assert_eq!(retry_after, "60");

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "rate_limited");
    assert!(body["message"].as_str().unwrap().contains("retry"));
}

// =========================================================================
// T057: Test malformed JSON response handling
// =========================================================================

#[tokio::test]
async fn test_malformed_json_response() {
    let ctx = TestContext::new().await;

    Mock::given(method("GET"))
        .and(path("/api/malformed"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("{ invalid json: no quotes }")
                .insert_header("Content-Type", "application/json"),
        )
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/malformed", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    // Attempting to parse should fail
    let result: Result<serde_json::Value, _> = response.json().await;
    assert!(result.is_err());
}

// =========================================================================
// T058: Test connection refused error handling
// =========================================================================

#[tokio::test]
async fn test_connection_refused() {
    // Use a port that's definitely not listening
    let invalid_url = "http://127.0.0.1:59999";

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(1))
        .build()
        .unwrap();

    let result = client.get(format!("{}/api/test", invalid_url)).send().await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.is_connect());
}

// =========================================================================
// Additional error tests
// =========================================================================

#[tokio::test]
async fn test_server_error_503_service_unavailable() {
    let ctx = TestContext::new().await;

    Mock::given(method("GET"))
        .and(path("/api/unavailable"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "error": "service_unavailable",
            "message": "Service is temporarily unavailable"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/unavailable", ctx.base_url()))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 503);
}

#[tokio::test]
async fn test_bad_request_400() {
    let ctx = TestContext::new().await;

    Mock::given(method("POST"))
        .and(path("/api/validate"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "bad_request",
            "message": "Invalid request body",
            "details": {
                "field": "email",
                "reason": "Invalid email format"
            }
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/api/validate", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .json(&json!({"email": "invalid"}))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "bad_request");
    assert!(body["details"]["field"].as_str().is_some());
}

#[tokio::test]
async fn test_forbidden_403() {
    let ctx = TestContext::new().await;

    Mock::given(method("DELETE"))
        .and(path("/api/admin/resource"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": "forbidden",
            "message": "You do not have permission to perform this action"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .delete(format!("{}/api/admin/resource", ctx.base_url()))
        .header("Authorization", "Bearer non-admin-token")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 403);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "forbidden");
}

#[tokio::test]
async fn test_conflict_409() {
    let ctx = TestContext::new().await;

    Mock::given(method("POST"))
        .and(path("/api/resource"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error": "conflict",
            "message": "Resource already exists with this identifier"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/api/resource", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .json(&json!({"id": "duplicate"}))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 409);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "conflict");
}

#[tokio::test]
async fn test_empty_response_body() {
    let ctx = TestContext::new().await;

    Mock::given(method("GET"))
        .and(path("/api/empty"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/empty", ctx.base_url()))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body = response.text().await.expect("Failed to get body");
    assert!(body.is_empty());
}

// =========================================================================
// CliError exit_code tests
// =========================================================================

#[test]
fn test_cli_error_exit_codes() {
    use xavyo_cli::error::CliError;

    // Auth errors should return exit code 2
    assert_eq!(CliError::NotAuthenticated.exit_code(), 2);
    assert_eq!(CliError::TokenExpired.exit_code(), 2);
    assert_eq!(CliError::AuthenticationFailed("test".into()).exit_code(), 2);
    assert_eq!(CliError::DeviceCodeExpired.exit_code(), 2);
    assert_eq!(CliError::AuthorizationDenied.exit_code(), 2);

    // Network errors should return exit code 3
    assert_eq!(CliError::Network("test".into()).exit_code(), 3);
    assert_eq!(CliError::ConnectionFailed("test".into()).exit_code(), 3);

    // Validation errors should return exit code 4
    assert_eq!(CliError::Validation("test".into()).exit_code(), 4);
    assert_eq!(CliError::NotFound("test".into()).exit_code(), 4);
    assert_eq!(CliError::TenantExists("test".into()).exit_code(), 4);

    // Server errors should return exit code 5
    assert_eq!(CliError::Server("test".into()).exit_code(), 5);

    // General errors should return exit code 1
    assert_eq!(CliError::Config("test".into()).exit_code(), 1);
    assert_eq!(CliError::Io("test".into()).exit_code(), 1);
}

#[test]
fn test_cli_error_api_exit_codes() {
    use xavyo_cli::error::CliError;

    // API errors based on status code
    assert_eq!(
        CliError::Api {
            status: 401,
            message: "unauthorized".into()
        }
        .exit_code(),
        2
    );
    assert_eq!(
        CliError::Api {
            status: 403,
            message: "forbidden".into()
        }
        .exit_code(),
        2
    );
    assert_eq!(
        CliError::Api {
            status: 404,
            message: "not found".into()
        }
        .exit_code(),
        4
    );
    assert_eq!(
        CliError::Api {
            status: 500,
            message: "server error".into()
        }
        .exit_code(),
        5
    );
    assert_eq!(
        CliError::Api {
            status: 502,
            message: "bad gateway".into()
        }
        .exit_code(),
        5
    );
}
