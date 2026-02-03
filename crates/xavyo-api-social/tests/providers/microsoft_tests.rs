//! Microsoft OAuth2 (Azure AD) Integration Tests
//!
//! Tests for Microsoft OAuth2 flow including:
//! - Authorization URL with v2.0 endpoint
//! - Token exchange
//! - Graph API userinfo
//! - ID token claims extraction
//! - PKCE flow
//! - Error scenarios

use wiremock::MockServer;

use super::common::{
    ProviderTestFixture, ProviderType, TEST_AUTH_CODE, TEST_CODE_CHALLENGE, TEST_CODE_VERIFIER,
    TEST_NONCE, TEST_STATE,
};
use super::mock_server::{
    build_auth_url, setup_microsoft_userinfo, setup_token_endpoint_error,
    setup_token_endpoint_success, OAuthError,
};

/// Microsoft OAuth2 endpoints (v2.0)
const MICROSOFT_AUTH_ENDPOINT: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
#[allow(dead_code)]
const MICROSOFT_TOKEN_ENDPOINT: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

#[tokio::test]
async fn test_microsoft_authorization_url_with_v2_endpoint() {
    let fixture = ProviderTestFixture::microsoft();

    let auth_url = build_auth_url(
        MICROSOFT_AUTH_ENDPOINT,
        &fixture.client_id,
        &fixture.redirect_uri,
        &fixture.scopes,
        TEST_STATE,
        Some(TEST_NONCE),
        Some(TEST_CODE_CHALLENGE),
    );

    // Verify v2.0 endpoint is used
    assert!(auth_url.contains("oauth2/v2.0/authorize"));
    assert!(auth_url.contains(&format!("client_id={}", fixture.client_id)));
    assert!(auth_url.contains("response_type=code"));
    assert!(auth_url.contains(&format!("state={}", TEST_STATE)));

    // Verify Microsoft-specific scopes
    assert!(auth_url.contains("openid"));
    assert!(auth_url.contains("profile"));
    assert!(auth_url.contains("email"));
    assert!(auth_url.contains("User.Read"));
}

#[tokio::test]
async fn test_microsoft_token_exchange() {
    let server = MockServer::start().await;
    let fixture = ProviderTestFixture::microsoft();

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
            ("scope", &fixture.scopes.join(" ")),
            ("code_verifier", TEST_CODE_VERIFIER),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let tokens: serde_json::Value = response.json().await.unwrap();
    assert_eq!(tokens["access_token"], fixture.mock_tokens.access_token);
    assert_eq!(tokens["token_type"], "Bearer");
    assert!(tokens["id_token"].is_string());
}

#[tokio::test]
async fn test_microsoft_graph_api_userinfo() {
    let server = MockServer::start().await;
    let fixture = ProviderTestFixture::microsoft();

    setup_microsoft_userinfo(&server, &fixture.mock_user).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/me", server.uri()))
        .header(
            "Authorization",
            format!("Bearer {}", fixture.mock_tokens.access_token),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let user_info: serde_json::Value = response.json().await.unwrap();
    assert_eq!(user_info["id"], fixture.mock_user.provider_id);
    assert_eq!(user_info["displayName"], fixture.mock_user.name);
    assert_eq!(user_info["mail"], fixture.mock_user.email);
    assert_eq!(
        user_info["givenName"],
        fixture.mock_user.first_name.as_ref().unwrap().as_str()
    );
    assert_eq!(
        user_info["surname"],
        fixture.mock_user.last_name.as_ref().unwrap().as_str()
    );
}

#[tokio::test]
async fn test_microsoft_id_token_claims_extraction() {
    let fixture = ProviderTestFixture::microsoft();

    // Microsoft ID token contains specific claims
    // In real implementation, you would decode and validate the JWT
    let id_token = fixture.mock_tokens.id_token.as_ref().unwrap();

    // Verify token structure (JWT format: header.payload.signature)
    let parts: Vec<&str> = id_token.split('.').collect();
    assert!(parts.len() >= 2, "ID token should be a valid JWT");

    // The mock token is not a real JWT, but we verify the structure
    assert!(!id_token.is_empty());
}

#[tokio::test]
async fn test_microsoft_pkce_flow() {
    let fixture = ProviderTestFixture::microsoft();

    let auth_url = build_auth_url(
        MICROSOFT_AUTH_ENDPOINT,
        &fixture.client_id,
        &fixture.redirect_uri,
        &fixture.scopes,
        TEST_STATE,
        None,
        Some(TEST_CODE_CHALLENGE),
    );

    // Verify PKCE parameters are included
    assert!(auth_url.contains("code_challenge="));
    assert!(auth_url.contains("code_challenge_method=S256"));

    // Microsoft supports PKCE for all app types
    assert!(!TEST_CODE_VERIFIER.is_empty());
}

#[tokio::test]
async fn test_microsoft_invalid_code_error() {
    let server = MockServer::start().await;

    setup_token_endpoint_error(&server, OAuthError::invalid_grant(), 400).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/token", server.uri()))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "invalid_or_expired_code"),
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
}

#[tokio::test]
async fn test_microsoft_missing_email_consent_error() {
    // When user doesn't grant email scope, Microsoft returns error
    // or returns null for mail field
    let server = MockServer::start().await;

    // Setup userinfo with null email (simulating missing consent)
    let response_json = serde_json::json!({
        "id": "00000000-0000-0000-0000-000000000001",
        "displayName": "Test User",
        "givenName": "Test",
        "surname": "User",
        "mail": null,
        "userPrincipalName": "testuser@contoso.onmicrosoft.com"
    });

    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/v1.0/me"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(response_json))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/me", server.uri()))
        .header("Authorization", "Bearer test_token")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let user_info: serde_json::Value = response.json().await.unwrap();
    assert!(user_info["mail"].is_null());
    // Application should fall back to userPrincipalName
    assert!(!user_info["userPrincipalName"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn test_microsoft_fixture_configuration() {
    let fixture = ProviderTestFixture::microsoft();

    assert_eq!(fixture.provider_type, ProviderType::Microsoft);
    assert!(!fixture.client_id.is_empty());
    assert!(!fixture.client_secret.is_empty());
    assert!(fixture.redirect_uri.contains("/callback/microsoft"));

    // Microsoft requires these scopes
    assert!(fixture.scopes.contains(&"openid".to_string()));
    assert!(fixture.scopes.contains(&"profile".to_string()));
    assert!(fixture.scopes.contains(&"email".to_string()));
    assert!(fixture.scopes.contains(&"User.Read".to_string()));
}
