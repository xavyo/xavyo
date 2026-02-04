//! Integration tests for authentication flow
//!
//! Tests cover:
//! - Device code flow (login)
//! - Token exchange and refresh
//! - Whoami endpoint
//! - Logout and credential cleanup
//! - Error scenarios (expired, denied, etc.)

mod common;

use common::{
    create_credentials_json, create_expired_credentials_json, create_user_fixture,
    credentials_exist, delete_credentials, write_test_config, write_test_credentials, TestContext,
};
use serde_json::json;

// =========================================================================
// T010: Test login success with valid device code
// =========================================================================

#[tokio::test]
async fn test_login_device_code_request_success() {
    let ctx = TestContext::new().await;

    // Setup mock for device code request
    ctx.mock_device_code_success().await;

    // Verify mock server is responding
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/oauth/device/code", ctx.base_url()))
        .form(&[
            ("client_id", "xavyo-cli"),
            ("scope", "openid profile email"),
        ])
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["device_code"], "test-device-code-12345");
    assert_eq!(body["user_code"], "ABCD-1234");
    assert!(body["expires_in"].as_i64().unwrap() > 0);
}

#[tokio::test]
async fn test_login_token_exchange_success() {
    let ctx = TestContext::new().await;

    // Setup mocks
    ctx.mock_device_code_success().await;
    ctx.mock_token_success().await;

    // Verify token exchange works
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/oauth/token", ctx.base_url()))
        .form(&[
            ("client_id", "xavyo-cli"),
            ("device_code", "test-device-code-12345"),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ])
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert!(body["access_token"].as_str().is_some());
    assert!(body["refresh_token"].as_str().is_some());
    assert_eq!(body["token_type"], "Bearer");
}

// =========================================================================
// T011: Test login failure with invalid device code
// =========================================================================

#[tokio::test]
async fn test_login_invalid_device_code() {
    let ctx = TestContext::new().await;

    // Setup mock for failure
    ctx.mock_device_code_failure(400, "invalid_request").await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/oauth/device/code", ctx.base_url()))
        .form(&[("client_id", "invalid-client"), ("scope", "openid")])
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "invalid_request");
}

// =========================================================================
// T012: Test login failure with expired device code
// =========================================================================

#[tokio::test]
async fn test_login_expired_device_code() {
    let ctx = TestContext::new().await;

    // Setup mock for expired token
    ctx.mock_token_expired().await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/oauth/token", ctx.base_url()))
        .form(&[
            ("client_id", "xavyo-cli"),
            ("device_code", "expired-device-code"),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ])
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "expired_token");
}

// =========================================================================
// T013: Test whoami returns correct identity when authenticated
// =========================================================================

#[tokio::test]
async fn test_whoami_authenticated() {
    let ctx = TestContext::new().await;

    // Setup user info mock
    let user_info = create_user_fixture("test@example.com");
    ctx.mock_whoami(user_info.clone()).await;

    // Write valid credentials
    let creds = create_credentials_json();
    write_test_credentials(ctx.credentials_path().as_path(), &creds);

    // Make authenticated request
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/userinfo", ctx.base_url()))
        .header("Authorization", "Bearer test-access-token-xyz")
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["email"], "test@example.com");
    assert_eq!(body["name"], "Test User");
}

// =========================================================================
// T014: Test whoami fails when not authenticated
// =========================================================================

#[tokio::test]
async fn test_whoami_not_authenticated() {
    let ctx = TestContext::new().await;

    // Setup 401 mock for userinfo
    ctx.mock_unauthorized("/userinfo").await;

    // Ensure no credentials exist
    assert!(!credentials_exist(ctx.credentials_path().as_path()));

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/userinfo", ctx.base_url()))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 401);
}

// =========================================================================
// T015: Test logout clears stored credentials
// =========================================================================

#[tokio::test]
async fn test_logout_clears_credentials() {
    let ctx = TestContext::new().await;

    // Write credentials first
    let creds = create_credentials_json();
    write_test_credentials(ctx.credentials_path().as_path(), &creds);

    // Verify credentials exist
    assert!(credentials_exist(ctx.credentials_path().as_path()));

    // Simulate logout by deleting credentials
    delete_credentials(ctx.credentials_path().as_path());

    // Verify credentials are gone
    assert!(!credentials_exist(ctx.credentials_path().as_path()));
}

// =========================================================================
// T016: Test token refresh when token expires
// =========================================================================

#[tokio::test]
async fn test_token_refresh_on_expiry() {
    let ctx = TestContext::new().await;

    // Setup refresh token mock
    ctx.mock_token_refresh_success().await;

    // Write expired credentials
    let expired_creds = create_expired_credentials_json();
    write_test_credentials(ctx.credentials_path().as_path(), &expired_creds);

    // Simulate refresh token request
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/oauth/token", ctx.base_url()))
        .form(&[
            ("client_id", "xavyo-cli"),
            ("grant_type", "refresh_token"),
            ("refresh_token", "expired-refresh-token"),
        ])
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["access_token"], "refreshed-access-token-xyz");
}

// =========================================================================
// T017: Test full flow: login → whoami → logout
// =========================================================================

#[tokio::test]
async fn test_full_auth_flow() {
    let ctx = TestContext::new().await;

    // Setup all mocks
    ctx.mock_device_code_success().await;
    ctx.mock_token_success().await;

    let user_info = create_user_fixture("flow-test@example.com");
    ctx.mock_whoami(user_info).await;

    let client = reqwest::Client::new();

    // Step 1: Request device code
    let device_response = client
        .post(format!("{}/oauth/device/code", ctx.base_url()))
        .form(&[
            ("client_id", "xavyo-cli"),
            ("scope", "openid profile email"),
        ])
        .send()
        .await
        .expect("Device code request failed");
    assert!(device_response.status().is_success());

    // Step 2: Exchange for token
    let token_response = client
        .post(format!("{}/oauth/token", ctx.base_url()))
        .form(&[
            ("client_id", "xavyo-cli"),
            ("device_code", "test-device-code-12345"),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ])
        .send()
        .await
        .expect("Token request failed");
    assert!(token_response.status().is_success());

    // Store credentials
    let creds = create_credentials_json();
    write_test_credentials(ctx.credentials_path().as_path(), &creds);

    // Step 3: Get user info (whoami)
    let whoami_response = client
        .get(format!("{}/userinfo", ctx.base_url()))
        .header("Authorization", "Bearer test-access-token-xyz")
        .send()
        .await
        .expect("Whoami request failed");
    assert!(whoami_response.status().is_success());

    let user: serde_json::Value = whoami_response.json().await.unwrap();
    assert_eq!(user["email"], "flow-test@example.com");

    // Step 4: Logout
    delete_credentials(ctx.credentials_path().as_path());
    assert!(!credentials_exist(ctx.credentials_path().as_path()));
}

// =========================================================================
// T018: Test authorization denied scenario
// =========================================================================

#[tokio::test]
async fn test_authorization_denied() {
    let ctx = TestContext::new().await;

    // Setup mock for access denied
    ctx.mock_token_denied().await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/oauth/token", ctx.base_url()))
        .form(&[
            ("client_id", "xavyo-cli"),
            ("device_code", "test-device-code"),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ])
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "access_denied");
}

// =========================================================================
// Additional auth tests for robustness
// =========================================================================

#[tokio::test]
async fn test_token_pending_response() {
    let ctx = TestContext::new().await;

    // Setup mock for pending authorization
    ctx.mock_token_pending().await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/oauth/token", ctx.base_url()))
        .form(&[
            ("client_id", "xavyo-cli"),
            ("device_code", "pending-device-code"),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ])
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "authorization_pending");
}

#[tokio::test]
async fn test_credentials_isolation_between_tests() {
    // Test 1 context
    let ctx1 = TestContext::new().await;
    let creds1 = json!({"access_token": "token-1", "refresh_token": "refresh-1"});
    write_test_credentials(ctx1.credentials_path().as_path(), &creds1);

    // Test 2 context - should be completely isolated
    let ctx2 = TestContext::new().await;

    // Verify ctx2 has no credentials from ctx1
    assert!(!credentials_exist(ctx2.credentials_path().as_path()));

    // Write different credentials to ctx2
    let creds2 = json!({"access_token": "token-2", "refresh_token": "refresh-2"});
    write_test_credentials(ctx2.credentials_path().as_path(), &creds2);

    // Verify both have their own credentials
    assert!(credentials_exist(ctx1.credentials_path().as_path()));
    assert!(credentials_exist(ctx2.credentials_path().as_path()));

    // Verify paths are different
    assert_ne!(ctx1.credentials_path(), ctx2.credentials_path());
}
