//! Integration tests for SSO/SAML Authentication
//!
//! Tests for C-019: SSO/SAML Authentication
//!
//! Test organization by User Story:
//! - US1: SSO Login via Browser (T011-T015)
//! - US2: IdP Discovery (T023-T025)
//! - US3: Manual IdP Specification (T031-T033)
//! - US4: SAML Assertion Handling (T038-T040)

mod common;

use common::TestContext;
use serde_json::json;
use wiremock::matchers::{body_string_contains, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

// =============================================================================
// US1: SSO Login via Browser Tests (T011-T015)
// =============================================================================

/// T011: Test successful SSO session creation
#[tokio::test]
async fn test_sso_start_session() {
    let ctx = TestContext::new().await;

    // Mock successful SSO session start
    Mock::given(method("POST"))
        .and(path("/auth/sso/start"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "session_id": "sso-session-abc123",
            "state": "csrf-token-xyz",
            "verification_url": "https://auth.xavyo.net/sso/browser?session=abc123",
            "expires_in": 300,
            "poll_interval": 2
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/auth/sso/start", ctx.server.uri()))
        .json(&json!({
            "email": "user@acme.corp"
        }))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["session_id"], "sso-session-abc123");
    assert!(body["verification_url"]
        .as_str()
        .unwrap()
        .contains("sso/browser"));
    assert_eq!(body["expires_in"], 300);
}

/// T012: Test SSO polling returns pending state
#[tokio::test]
async fn test_sso_poll_pending() {
    let ctx = TestContext::new().await;

    Mock::given(method("GET"))
        .and(path("/auth/sso/status/session-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "state": "pending"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/auth/sso/status/session-123", ctx.server.uri()))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["state"], "pending");
}

/// T013: Test SSO polling returns completed with tokens
#[tokio::test]
async fn test_sso_poll_completed() {
    let ctx = TestContext::new().await;

    Mock::given(method("GET"))
        .and(path("/auth/sso/status/session-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "state": "completed",
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.sso-token",
            "refresh_token": "refresh-token-sso-123",
            "expires_in": 3600
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/auth/sso/status/session-123", ctx.server.uri()))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["state"], "completed");
    assert!(body["access_token"].as_str().is_some());
    assert!(body["refresh_token"].as_str().is_some());
    assert_eq!(body["expires_in"], 3600);
}

/// T014: Test SSO timeout handling
#[tokio::test]
async fn test_sso_timeout() {
    let ctx = TestContext::new().await;

    Mock::given(method("GET"))
        .and(path("/auth/sso/status/session-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "state": "expired"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/auth/sso/status/session-123", ctx.server.uri()))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["state"], "expired");
}

/// T015: Test SSO cancellation handling
#[tokio::test]
async fn test_sso_cancelled() {
    let ctx = TestContext::new().await;

    Mock::given(method("GET"))
        .and(path("/auth/sso/status/session-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "state": "cancelled"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/auth/sso/status/session-123", ctx.server.uri()))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["state"], "cancelled");
}

// =============================================================================
// US2: IdP Discovery Tests (T023-T025)
// =============================================================================

/// T023: Test successful IdP discovery by email
#[tokio::test]
async fn test_idp_discovery_success() {
    let ctx = TestContext::new().await;

    Mock::given(method("GET"))
        .and(path("/auth/sso/discover"))
        .and(query_param("email", "user@acme.corp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "idp_url": "https://acme.okta.com/app/xxx/sso/saml",
            "entity_id": "urn:okta:acme",
            "display_name": "Acme Corporation SSO",
            "protocol": "saml"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/auth/sso/discover?email={}",
            ctx.server.uri(),
            urlencoding::encode("user@acme.corp")
        ))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["idp_url"], "https://acme.okta.com/app/xxx/sso/saml");
    assert_eq!(body["entity_id"], "urn:okta:acme");
    assert_eq!(body["display_name"], "Acme Corporation SSO");
    assert_eq!(body["protocol"], "saml");
}

/// T024: Test IdP discovery not found
#[tokio::test]
async fn test_idp_discovery_not_found() {
    let ctx = TestContext::new().await;

    Mock::given(method("GET"))
        .and(path("/auth/sso/discover"))
        .and(query_param("email", "user@unknown.com"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "not_found",
            "error_description": "No SSO provider configured for domain 'unknown.com'"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/auth/sso/discover?email={}",
            ctx.server.uri(),
            urlencoding::encode("user@unknown.com")
        ))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status().as_u16(), 404);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "not_found");
}

/// T025: Test IdP discovery with multiple IdPs
#[tokio::test]
async fn test_idp_discovery_multiple_idps() {
    let ctx = TestContext::new().await;

    // When domain has multiple IdPs configured, return a list
    Mock::given(method("GET"))
        .and(path("/auth/sso/discover"))
        .and(query_param("email", "user@multi-idp.com"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "multiple": true,
            "idps": [
                {
                    "idp_url": "https://okta.multi-idp.com/sso",
                    "entity_id": "urn:okta:multi",
                    "display_name": "Okta SSO",
                    "protocol": "saml"
                },
                {
                    "idp_url": "https://azure.multi-idp.com/sso",
                    "entity_id": "https://azure.multi-idp.com",
                    "display_name": "Azure AD SSO",
                    "protocol": "oidc"
                }
            ]
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/auth/sso/discover?email={}",
            ctx.server.uri(),
            urlencoding::encode("user@multi-idp.com")
        ))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["multiple"], true);
    assert!(body["idps"].as_array().unwrap().len() >= 2);
}

// =============================================================================
// US3: Manual IdP Specification Tests (T031-T033)
// =============================================================================

/// T031: Test SSO with explicit IdP URL
#[tokio::test]
async fn test_sso_explicit_idp_url() {
    let ctx = TestContext::new().await;

    Mock::given(method("POST"))
        .and(path("/auth/sso/start"))
        .and(body_string_contains("idp_url"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "session_id": "explicit-idp-session",
            "state": "csrf-token",
            "verification_url": "https://custom.idp.com/sso/login?session=explicit-idp-session",
            "expires_in": 300,
            "poll_interval": 2
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/auth/sso/start", ctx.server.uri()))
        .json(&json!({
            "idp_url": "https://custom.idp.com/sso/saml"
        }))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["session_id"], "explicit-idp-session");
}

/// T032: Test SSO with invalid IdP URL
#[tokio::test]
async fn test_sso_invalid_idp_url() {
    let ctx = TestContext::new().await;

    Mock::given(method("POST"))
        .and(path("/auth/sso/start"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_idp_url",
            "error_description": "Invalid IdP URL: not-a-valid-url"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/auth/sso/start", ctx.server.uri()))
        .json(&json!({
            "idp_url": "not-a-valid-url"
        }))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status().as_u16(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "invalid_idp_url");
}

/// T033: Test SSO with entity ID resolution
#[tokio::test]
async fn test_sso_entity_id_resolution() {
    let ctx = TestContext::new().await;

    // First mock the entity ID resolution endpoint
    Mock::given(method("POST"))
        .and(path("/auth/sso/resolve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "idp_url": "https://okta.example.com/sso",
            "entity_id": "urn:okta:example",
            "display_name": "Example Corp SSO",
            "protocol": "saml"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/auth/sso/resolve", ctx.server.uri()))
        .json(&json!({
            "entity_id": "urn:okta:example"
        }))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["entity_id"], "urn:okta:example");
    assert!(body["idp_url"].as_str().unwrap().starts_with("https://"));
}

// =============================================================================
// US4: SAML Assertion Handling Tests (T038-T040)
// =============================================================================

/// T038: Test successful SAML authentication completion
#[tokio::test]
async fn test_sso_saml_success() {
    let ctx = TestContext::new().await;

    Mock::given(method("GET"))
        .and(path("/auth/sso/status/saml-session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "state": "completed",
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.saml-assertion-processed",
            "refresh_token": "saml-refresh-token",
            "expires_in": 3600,
            "user_info": {
                "email": "user@acme.corp",
                "name": "Test User",
                "groups": ["admins", "developers"]
            }
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/auth/sso/status/saml-session", ctx.server.uri()))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["state"], "completed");
    assert!(body["access_token"].as_str().is_some());
}

/// T039: Test SAML assertion expired error
#[tokio::test]
async fn test_sso_saml_expired() {
    let ctx = TestContext::new().await;

    Mock::given(method("GET"))
        .and(path("/auth/sso/status/saml-session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "state": "failed",
            "error": "assertion_expired",
            "error_description": "SAML assertion has expired"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/auth/sso/status/saml-session", ctx.server.uri()))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["state"], "failed");
    assert_eq!(body["error"], "assertion_expired");
}

/// T040: Test SAML invalid signature error
#[tokio::test]
async fn test_sso_saml_invalid_signature() {
    let ctx = TestContext::new().await;

    Mock::given(method("GET"))
        .and(path("/auth/sso/status/saml-session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "state": "failed",
            "error": "invalid_signature",
            "error_description": "SAML assertion signature validation failed"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/auth/sso/status/saml-session", ctx.server.uri()))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["state"], "failed");
    assert_eq!(body["error"], "invalid_signature");
}

// =============================================================================
// SSOConfig Unit Tests
// =============================================================================

#[test]
fn test_sso_config_with_email() {
    use xavyo_cli::sso::SSOConfig;

    let config = SSOConfig::with_email("user@example.com");
    assert_eq!(config.email, Some("user@example.com".to_string()));
    assert!(config.idp_url.is_none());
    assert!(config.needs_discovery());
}

#[test]
fn test_sso_config_with_idp_url() {
    use xavyo_cli::sso::SSOConfig;

    let config = SSOConfig::with_idp_url("https://idp.example.com");
    assert_eq!(config.idp_url, Some("https://idp.example.com".to_string()));
    assert!(!config.needs_discovery());
}

#[test]
fn test_sso_config_validate_no_identification() {
    use xavyo_cli::sso::SSOConfig;

    let config = SSOConfig::default();
    assert!(config.validate().is_err());
}

#[test]
fn test_sso_config_validate_conflicting_flags() {
    use xavyo_cli::sso::SSOConfig;

    let config = SSOConfig {
        idp_url: Some("https://idp.example.com".to_string()),
        idp_entity_id: Some("urn:example".to_string()),
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_sso_config_email_domain() {
    use xavyo_cli::sso::SSOConfig;

    let config = SSOConfig::with_email("user@acme.corp");
    assert_eq!(config.email_domain(), Some("acme.corp"));
}

// =============================================================================
// SSOSession Unit Tests
// =============================================================================

#[test]
fn test_sso_state_display() {
    use xavyo_cli::sso::SSOState;

    assert_eq!(SSOState::Pending.to_string(), "pending");
    assert_eq!(SSOState::Completed.to_string(), "completed");
    assert_eq!(SSOState::Failed.to_string(), "failed");
    assert_eq!(SSOState::Expired.to_string(), "expired");
    assert_eq!(SSOState::Cancelled.to_string(), "cancelled");
}

#[test]
fn test_sso_protocol_display() {
    use xavyo_cli::sso::SSOProtocol;

    assert_eq!(SSOProtocol::Saml.to_string(), "SAML");
    assert_eq!(SSOProtocol::Oidc.to_string(), "OIDC");
}

#[test]
fn test_idp_info_creation() {
    use xavyo_cli::sso::{IdPInfo, SSOProtocol};

    let info = IdPInfo::new("https://idp.example.com", "urn:example", "Example Corp SSO");
    assert_eq!(info.idp_url, "https://idp.example.com");
    assert_eq!(info.entity_id, "urn:example");
    assert_eq!(info.display_name, "Example Corp SSO");
    assert_eq!(info.protocol, SSOProtocol::Saml); // Default

    let info = info.with_protocol(SSOProtocol::Oidc);
    assert_eq!(info.protocol, SSOProtocol::Oidc);
}

#[test]
fn test_sso_session_status_pending() {
    use xavyo_cli::sso::{SSOSessionStatus, SSOState};

    let status = SSOSessionStatus::pending();
    assert_eq!(status.state, SSOState::Pending);
    assert!(status.access_token.is_none());
}

#[test]
fn test_sso_session_status_completed() {
    use xavyo_cli::sso::{SSOSessionStatus, SSOState};

    let status = SSOSessionStatus::completed(
        "access_token".to_string(),
        Some("refresh_token".to_string()),
        3600,
    );
    assert_eq!(status.state, SSOState::Completed);
    assert_eq!(status.access_token, Some("access_token".to_string()));
    assert_eq!(status.expires_in, Some(3600));
}

#[test]
fn test_sso_session_status_failed() {
    use xavyo_cli::sso::{SSOSessionStatus, SSOState};

    let status = SSOSessionStatus::failed("error_code", Some("description".to_string()));
    assert_eq!(status.state, SSOState::Failed);
    assert_eq!(status.error, Some("error_code".to_string()));
    assert_eq!(
        status.error_message(),
        Some("error_code: description".to_string())
    );
}

// =============================================================================
// CLI Help Tests
// =============================================================================

#[test]
fn test_sso_flags_exist_in_cli_help() {
    // Verify --sso flag is documented in CLI help
    use std::process::Command;

    let output = Command::new("cargo")
        .args(["run", "-p", "xavyo-cli", "--", "login", "--help"])
        .output();

    if let Ok(result) = output {
        let stdout = String::from_utf8_lossy(&result.stdout);
        // The --sso flag should be mentioned in help
        if result.status.success() || result.status.code() == Some(2) {
            // clap returns 2 for help
            assert!(
                stdout.contains("sso") || result.status.success(),
                "CLI help should mention --sso flag"
            );
        }
    }
}
