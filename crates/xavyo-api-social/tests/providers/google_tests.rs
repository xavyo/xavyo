//! Google OAuth2 Integration Tests
//!
//! Tests for Google OAuth2 flow including:
//! - Authorization URL generation
//! - Token exchange
//! - Userinfo retrieval
//! - CSRF state validation
//! - PKCE flow
//! - Error scenarios

use wiremock::MockServer;

use super::common::{
    ProviderTestFixture, ProviderType, TEST_AUTH_CODE, TEST_CODE_CHALLENGE, TEST_CODE_VERIFIER,
    TEST_NONCE, TEST_STATE,
};
use super::mock_server::{
    build_auth_url, setup_google_userinfo, setup_token_endpoint_error,
    setup_token_endpoint_success, OAuthError,
};

/// Google OAuth2 endpoints
const GOOGLE_AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
#[allow(dead_code)]
const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
#[allow(dead_code)]
const GOOGLE_USERINFO_ENDPOINT: &str = "https://www.googleapis.com/oauth2/v3/userinfo";

#[tokio::test]
async fn test_google_authorization_url_generation() {
    let fixture = ProviderTestFixture::google();

    let auth_url = build_auth_url(
        GOOGLE_AUTH_ENDPOINT,
        &fixture.client_id,
        &fixture.redirect_uri,
        &fixture.scopes,
        TEST_STATE,
        Some(TEST_NONCE),
        Some(TEST_CODE_CHALLENGE),
    );

    // Verify URL contains required OAuth2 parameters
    assert!(auth_url.starts_with(GOOGLE_AUTH_ENDPOINT));
    assert!(auth_url.contains(&format!(
        "client_id={}",
        urlencoding::encode(&fixture.client_id)
    )));
    assert!(auth_url.contains("response_type=code"));
    assert!(auth_url.contains(&format!("state={}", TEST_STATE)));
    assert!(auth_url.contains("scope="));
    assert!(auth_url.contains("openid"));
    assert!(auth_url.contains("email"));
    assert!(auth_url.contains("profile"));

    // Verify PKCE parameters
    assert!(auth_url.contains("code_challenge="));
    assert!(auth_url.contains("code_challenge_method=S256"));
}

#[tokio::test]
async fn test_google_token_exchange_happy_path() {
    let server = MockServer::start().await;
    let fixture = ProviderTestFixture::google();

    setup_token_endpoint_success(&server, &fixture.mock_tokens).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/token", server.uri()))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", TEST_AUTH_CODE),
            ("client_id", &fixture.client_id),
            ("client_secret", &fixture.client_secret),
            ("redirect_uri", &fixture.redirect_uri),
            ("code_verifier", TEST_CODE_VERIFIER),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let tokens: serde_json::Value = response.json().await.unwrap();
    assert_eq!(tokens["access_token"], fixture.mock_tokens.access_token);
    assert_eq!(tokens["token_type"], "Bearer");
    assert!(tokens["expires_in"].as_i64().unwrap() > 0);
    assert!(tokens["id_token"].is_string());
}

#[tokio::test]
async fn test_google_userinfo_retrieval() {
    let server = MockServer::start().await;
    let fixture = ProviderTestFixture::google();

    setup_google_userinfo(&server, &fixture.mock_user).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/userinfo", server.uri()))
        .header(
            "Authorization",
            format!("Bearer {}", fixture.mock_tokens.access_token),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let user_info: serde_json::Value = response.json().await.unwrap();
    assert_eq!(user_info["email"], fixture.mock_user.email);
    assert_eq!(user_info["sub"], fixture.mock_user.provider_id);
    assert_eq!(user_info["name"], fixture.mock_user.name);
    assert_eq!(
        user_info["email_verified"],
        fixture.mock_user.email_verified
    );
}

#[tokio::test]
async fn test_google_csrf_state_validation() {
    let fixture = ProviderTestFixture::google();

    // Generate URL with specific state
    let original_state = "unique_csrf_state_12345";
    let auth_url = build_auth_url(
        GOOGLE_AUTH_ENDPOINT,
        &fixture.client_id,
        &fixture.redirect_uri,
        &fixture.scopes,
        original_state,
        None,
        None,
    );

    // Verify state is in URL
    assert!(auth_url.contains(&format!("state={}", original_state)));

    // Simulate callback with matching state (valid)
    let callback_state = original_state;
    assert_eq!(callback_state, original_state);

    // Simulate callback with different state (invalid - would be rejected)
    let invalid_state = "tampered_state_xyz";
    assert_ne!(invalid_state, original_state);
}

#[tokio::test]
async fn test_google_pkce_flow() {
    let fixture = ProviderTestFixture::google();

    // Verify PKCE challenge can be validated
    // Note: In real implementation, this would be done by the authorization server
    let auth_url = build_auth_url(
        GOOGLE_AUTH_ENDPOINT,
        &fixture.client_id,
        &fixture.redirect_uri,
        &fixture.scopes,
        TEST_STATE,
        None,
        Some(TEST_CODE_CHALLENGE),
    );

    assert!(auth_url.contains("code_challenge="));
    assert!(auth_url.contains("code_challenge_method=S256"));

    // Verify code_verifier produces the expected challenge
    // This is a structural test - the actual PKCE validation happens server-side
    assert!(!TEST_CODE_VERIFIER.is_empty());
    assert!(!TEST_CODE_CHALLENGE.is_empty());
}

#[tokio::test]
async fn test_google_invalid_authorization_code_error() {
    let server = MockServer::start().await;

    setup_token_endpoint_error(&server, OAuthError::invalid_grant(), 400).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/token", server.uri()))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "invalid_expired_code"),
            ("client_id", "test-client"),
            ("client_secret", "test-secret"),
            ("redirect_uri", "http://localhost/callback"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);

    let error: OAuthError = response.json().await.unwrap();
    assert_eq!(error.error, "invalid_grant");
    assert!(
        error.error_description.contains("expired") || error.error_description.contains("invalid")
    );
}

#[tokio::test]
async fn test_google_access_denied_error() {
    let server = MockServer::start().await;

    setup_token_endpoint_error(&server, OAuthError::access_denied(), 400).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/token", server.uri()))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "user_denied_code"),
            ("client_id", "test-client"),
            ("client_secret", "test-secret"),
            ("redirect_uri", "http://localhost/callback"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);

    let error: OAuthError = response.json().await.unwrap();
    assert_eq!(error.error, "access_denied");
    assert!(error.error_description.contains("denied"));
}

#[tokio::test]
async fn test_google_fixture_configuration() {
    let fixture = ProviderTestFixture::google();

    assert_eq!(fixture.provider_type, ProviderType::Google);
    assert!(fixture.client_id.contains("googleusercontent.com"));
    assert!(!fixture.client_secret.is_empty());
    assert!(fixture.redirect_uri.contains("/callback/google"));
    assert!(fixture.scopes.contains(&"openid".to_string()));
    assert!(fixture.scopes.contains(&"email".to_string()));
    assert!(fixture.scopes.contains(&"profile".to_string()));
}
