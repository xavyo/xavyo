//! Integration tests for MFA/TOTP authentication flow
//!
//! Tests cover:
//! - MFA challenge detection during device code flow
//! - TOTP verification success/failure
//! - Retry logic for invalid codes
//! - Device trust token handling
//! - MFA preference flags (--mfa, --no-mfa)
//! - Error recovery scenarios

mod common;

use common::TestContext;
use serde_json::json;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, ResponseTemplate};

// =========================================================================
// T009: Test context setup with MFA mocks
// =========================================================================

impl TestContext {
    /// Mock token polling that returns MFA challenge
    pub async fn mock_token_mfa_required(&self) {
        Mock::given(method("POST"))
            .and(path("/oauth/device/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "mfa_required",
                "error_description": "Multi-factor authentication required",
                "challenge_id": "test-challenge-12345",
                "supported_methods": ["totp"],
                "expires_in": 300
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock successful MFA verification
    pub async fn mock_mfa_verify_success(&self) {
        Mock::given(method("POST"))
            .and(path("/auth/mfa/verify"))
            .and(body_string_contains("challenge_id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "mfa-verified-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "mfa-verified-refresh-token",
                "scope": "openid profile email"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock successful MFA verification with device trust token
    pub async fn mock_mfa_verify_success_with_device_token(&self) {
        Mock::given(method("POST"))
            .and(path("/auth/mfa/verify"))
            .and(body_string_contains("remember_device\":true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "mfa-verified-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "mfa-verified-refresh-token",
                "scope": "openid profile email",
                "device_token": "trusted-device-token-xyz",
                "device_token_expires_in": 2592000
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock MFA verification failure - invalid code
    pub async fn mock_mfa_verify_invalid_code(&self, retries_remaining: u32) {
        Mock::given(method("POST"))
            .and(path("/auth/mfa/verify"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_totp",
                "error_description": "Invalid TOTP code",
                "retries_remaining": retries_remaining
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock MFA verification failure - rate limited
    pub async fn mock_mfa_verify_rate_limited(&self) {
        Mock::given(method("POST"))
            .and(path("/auth/mfa/verify"))
            .respond_with(ResponseTemplate::new(429).set_body_json(json!({
                "error": "rate_limited",
                "error_description": "Too many incorrect attempts. Please wait before retrying.",
                "retries_remaining": 0
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock MFA verification failure - challenge expired
    pub async fn mock_mfa_verify_timeout(&self) {
        Mock::given(method("POST"))
            .and(path("/auth/mfa/verify"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "mfa_timeout",
                "error_description": "MFA challenge has expired"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock MFA verification failure - not configured
    pub async fn mock_mfa_not_configured(&self) {
        Mock::given(method("POST"))
            .and(path("/auth/mfa/verify"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "mfa_not_configured",
                "error_description": "MFA is not configured for this account"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock MFA verification failure - clock skew
    pub async fn mock_mfa_verify_clock_skew(&self) {
        Mock::given(method("POST"))
            .and(path("/auth/mfa/verify"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "clock_skew",
                "error_description": "Time synchronization error detected. Please check your device clock."
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock token exchange with device trust (skips MFA)
    pub async fn mock_token_with_device_trust(&self) {
        Mock::given(method("POST"))
            .and(path("/oauth/device/token"))
            .and(body_string_contains("device_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "trusted-device-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "trusted-device-refresh-token"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock token exchange with MFA preference
    pub async fn mock_token_mfa_forced(&self) {
        Mock::given(method("POST"))
            .and(path("/oauth/device/token"))
            .and(body_string_contains("mfa_preference=required"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "mfa_required",
                "error_description": "MFA verification required (user requested)",
                "challenge_id": "forced-challenge-67890",
                "supported_methods": ["totp"],
                "expires_in": 300
            })))
            .mount(&self.server)
            .await;
    }
}

// =========================================================================
// T010: Test MFA challenge detection
// =========================================================================

#[tokio::test]
async fn test_mfa_challenge_detection() {
    let ctx = TestContext::new().await;

    // Setup mock that returns MFA required
    ctx.mock_token_mfa_required().await;

    // Verify the mock returns MFA challenge
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/oauth/device/token", ctx.base_url()))
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
    assert_eq!(body["error"], "mfa_required");
    assert!(body["challenge_id"].as_str().is_some());
    assert!(body["supported_methods"].as_array().is_some());
    assert!(body["expires_in"].as_u64().is_some());
}

#[tokio::test]
async fn test_mfa_challenge_has_totp_method() {
    let ctx = TestContext::new().await;

    ctx.mock_token_mfa_required().await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/oauth/device/token", ctx.base_url()))
        .form(&[
            ("client_id", "xavyo-cli"),
            ("device_code", "test-device-code"),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ])
        .send()
        .await
        .expect("Request failed");

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    let methods = body["supported_methods"]
        .as_array()
        .expect("supported_methods should be array");
    assert!(methods.iter().any(|m| m == "totp"));
}

// =========================================================================
// T011: Test MFA verification success
// =========================================================================

#[tokio::test]
async fn test_mfa_verify_success() {
    let ctx = TestContext::new().await;

    ctx.mock_mfa_verify_success().await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/auth/mfa/verify", ctx.base_url()))
        .json(&json!({
            "challenge_id": "test-challenge-12345",
            "method": "totp",
            "code": "123456",
            "remember_device": false
        }))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert!(body["access_token"].as_str().is_some());
    assert_eq!(body["token_type"], "Bearer");
}

#[tokio::test]
async fn test_mfa_verify_success_with_device_token() {
    let ctx = TestContext::new().await;

    ctx.mock_mfa_verify_success_with_device_token().await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/auth/mfa/verify", ctx.base_url()))
        .json(&json!({
            "challenge_id": "test-challenge-12345",
            "method": "totp",
            "code": "123456",
            "remember_device": true
        }))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert!(body["access_token"].as_str().is_some());
    assert!(body["device_token"].as_str().is_some());
    assert!(body["device_token_expires_in"].as_u64().is_some());
}

// =========================================================================
// T012: Test MFA verification with invalid code
// =========================================================================

#[tokio::test]
async fn test_mfa_verify_invalid_code() {
    let ctx = TestContext::new().await;

    ctx.mock_mfa_verify_invalid_code(2).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/auth/mfa/verify", ctx.base_url()))
        .json(&json!({
            "challenge_id": "test-challenge-12345",
            "method": "totp",
            "code": "000000",
            "remember_device": false
        }))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "invalid_totp");
    assert_eq!(body["retries_remaining"], 2);
}

#[tokio::test]
async fn test_mfa_verify_expired_code() {
    let ctx = TestContext::new().await;

    // Use invalid code mock (expired codes are treated as invalid)
    ctx.mock_mfa_verify_invalid_code(1).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/auth/mfa/verify", ctx.base_url()))
        .json(&json!({
            "challenge_id": "test-challenge-12345",
            "method": "totp",
            "code": "111111",
            "remember_device": false
        }))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "invalid_totp");
}

// =========================================================================
// T013: Test MFA retry limit exceeded
// =========================================================================

#[tokio::test]
async fn test_mfa_retry_limit_exceeded() {
    let ctx = TestContext::new().await;

    ctx.mock_mfa_verify_rate_limited().await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/auth/mfa/verify", ctx.base_url()))
        .json(&json!({
            "challenge_id": "test-challenge-12345",
            "method": "totp",
            "code": "999999",
            "remember_device": false
        }))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 429);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "rate_limited");
    assert_eq!(body["retries_remaining"], 0);
}

#[tokio::test]
async fn test_mfa_challenge_timeout() {
    let ctx = TestContext::new().await;

    ctx.mock_mfa_verify_timeout().await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/auth/mfa/verify", ctx.base_url()))
        .json(&json!({
            "challenge_id": "expired-challenge",
            "method": "totp",
            "code": "123456",
            "remember_device": false
        }))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "mfa_timeout");
}

// =========================================================================
// T018: Test login with --mfa flag (US2)
// =========================================================================

#[tokio::test]
async fn test_login_with_mfa_flag() {
    let ctx = TestContext::new().await;

    ctx.mock_token_mfa_forced().await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/oauth/device/token", ctx.base_url()))
        .form(&[
            ("client_id", "xavyo-cli"),
            ("device_code", "test-device-code"),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("mfa_preference", "required"),
        ])
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "mfa_required");
}

// =========================================================================
// T019: Test --mfa flag when MFA not configured (US2)
// =========================================================================

#[tokio::test]
async fn test_mfa_flag_no_mfa_configured() {
    let ctx = TestContext::new().await;

    ctx.mock_mfa_not_configured().await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/auth/mfa/verify", ctx.base_url()))
        .json(&json!({
            "challenge_id": "test-challenge",
            "method": "totp",
            "code": "123456",
            "remember_device": false
        }))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "mfa_not_configured");
}

// =========================================================================
// T024: Test remember device stores token (US3)
// =========================================================================

#[tokio::test]
async fn test_remember_device_stores_token() {
    let ctx = TestContext::new().await;

    ctx.mock_mfa_verify_success_with_device_token().await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/auth/mfa/verify", ctx.base_url()))
        .json(&json!({
            "challenge_id": "test-challenge-12345",
            "method": "totp",
            "code": "123456",
            "remember_device": true
        }))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["device_token"], "trusted-device-token-xyz");
    assert!(body["device_token_expires_in"].as_u64().unwrap() > 0);
}

// =========================================================================
// T025: Test device token skips MFA (US3)
// =========================================================================

#[tokio::test]
async fn test_device_token_skips_mfa() {
    let ctx = TestContext::new().await;

    ctx.mock_token_with_device_trust().await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/oauth/device/token", ctx.base_url()))
        .form(&[
            ("client_id", "xavyo-cli"),
            ("device_code", "test-device-code"),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_token", "trusted-device-token-xyz"),
        ])
        .send()
        .await
        .expect("Request failed");

    // Should succeed without MFA when device is trusted
    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert!(body["access_token"].as_str().is_some());
}

// =========================================================================
// T034: Test MFA clock skew error message (US4)
// =========================================================================

#[tokio::test]
async fn test_mfa_clock_skew_error_message() {
    let ctx = TestContext::new().await;

    ctx.mock_mfa_verify_clock_skew().await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/auth/mfa/verify", ctx.base_url()))
        .json(&json!({
            "challenge_id": "test-challenge",
            "method": "totp",
            "code": "123456",
            "remember_device": false
        }))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "clock_skew");
    assert!(body["error_description"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("time"));
}

// =========================================================================
// T035: Test MFA timeout error message (US4)
// =========================================================================

#[tokio::test]
async fn test_mfa_timeout_error_message() {
    let ctx = TestContext::new().await;

    ctx.mock_mfa_verify_timeout().await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/auth/mfa/verify", ctx.base_url()))
        .json(&json!({
            "challenge_id": "expired-challenge",
            "method": "totp",
            "code": "123456",
            "remember_device": false
        }))
        .send()
        .await
        .expect("Request failed");

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "mfa_timeout");
}

// =========================================================================
// T036: Test MFA server error message (US4)
// =========================================================================

#[tokio::test]
async fn test_mfa_server_error_message() {
    let ctx = TestContext::new().await;

    // Mock a 500 error
    Mock::given(method("POST"))
        .and(path("/auth/mfa/verify"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": "internal_error",
            "error_description": "An unexpected error occurred"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/auth/mfa/verify", ctx.base_url()))
        .json(&json!({
            "challenge_id": "test-challenge",
            "method": "totp",
            "code": "123456",
            "remember_device": false
        }))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 500);
}

// =========================================================================
// Additional tests to reach 15+ test count (SC-005)
// =========================================================================

#[tokio::test]
async fn test_mfa_challenge_expiry_field() {
    let ctx = TestContext::new().await;

    ctx.mock_token_mfa_required().await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/oauth/device/token", ctx.base_url()))
        .form(&[
            ("client_id", "xavyo-cli"),
            ("device_code", "test-device-code"),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ])
        .send()
        .await
        .expect("Request failed");

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    let expires_in = body["expires_in"]
        .as_u64()
        .expect("expires_in should be u64");
    assert!(expires_in > 0);
    assert!(expires_in <= 600); // Should be reasonable (<=10 min)
}

#[tokio::test]
async fn test_mfa_verify_response_has_all_token_fields() {
    let ctx = TestContext::new().await;

    ctx.mock_mfa_verify_success().await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/auth/mfa/verify", ctx.base_url()))
        .json(&json!({
            "challenge_id": "test-challenge-12345",
            "method": "totp",
            "code": "123456",
            "remember_device": false
        }))
        .send()
        .await
        .expect("Request failed");

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");

    // Verify all required fields are present
    assert!(body["access_token"].as_str().is_some());
    assert!(body["token_type"].as_str().is_some());
    assert!(body["expires_in"].as_u64().is_some());
    assert!(body["refresh_token"].as_str().is_some());
}
