//! GitHub `OAuth2` Integration Tests
//!
//! Tests for GitHub `OAuth2` flow including:
//! - Authorization URL generation
//! - Token exchange
//! - User API retrieval
//! - Emails API for primary verified email
//! - Private email fallback (noreply)
//! - Error scenarios

use wiremock::MockServer;

use super::common::{MockUser, ProviderTestFixture, ProviderType, TEST_AUTH_CODE, TEST_STATE};
use super::mock_server::{
    build_auth_url, setup_github_emails, setup_github_rate_limit, setup_github_user,
    setup_token_endpoint_error, setup_token_endpoint_success, OAuthError,
};

/// GitHub `OAuth2` endpoints
const GITHUB_AUTH_ENDPOINT: &str = "https://github.com/login/oauth/authorize";
#[allow(dead_code)]
const GITHUB_TOKEN_ENDPOINT: &str = "https://github.com/login/oauth/access_token";
#[allow(dead_code)]
const GITHUB_USER_ENDPOINT: &str = "https://api.github.com/user";
#[allow(dead_code)]
const GITHUB_EMAILS_ENDPOINT: &str = "https://api.github.com/user/emails";

#[tokio::test]
async fn test_github_authorization_url_generation() {
    let fixture = ProviderTestFixture::github();

    let auth_url = build_auth_url(
        GITHUB_AUTH_ENDPOINT,
        &fixture.client_id,
        &fixture.redirect_uri,
        &fixture.scopes,
        TEST_STATE,
        None, // GitHub doesn't use nonce
        None, // GitHub doesn't support PKCE
    );

    // Verify URL contains required OAuth2 parameters
    assert!(auth_url.starts_with(GITHUB_AUTH_ENDPOINT));
    assert!(auth_url.contains(&format!("client_id={}", fixture.client_id)));
    assert!(auth_url.contains("response_type=code"));
    assert!(auth_url.contains(&format!("state={TEST_STATE}")));

    // Verify GitHub scopes
    assert!(auth_url.contains("user%3Aemail") || auth_url.contains("user:email"));
    assert!(auth_url.contains("read%3Auser") || auth_url.contains("read:user"));
}

#[tokio::test]
async fn test_github_token_exchange() {
    let server = MockServer::start().await;
    let fixture = ProviderTestFixture::github();

    setup_token_endpoint_success(&server, &fixture.mock_tokens).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/token", server.uri()))
        .header("Accept", "application/json")
        .form(&[
            ("client_id", fixture.client_id.as_str()),
            ("client_secret", fixture.client_secret.as_str()),
            ("code", TEST_AUTH_CODE),
            ("redirect_uri", fixture.redirect_uri.as_str()),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let tokens: serde_json::Value = response.json().await.unwrap();
    assert_eq!(tokens["access_token"], fixture.mock_tokens.access_token);
    assert_eq!(tokens["token_type"], "bearer"); // GitHub uses lowercase

    // GitHub tokens don't have id_token (not OIDC)
    assert!(
        tokens["id_token"].is_null()
            || !tokens.as_object().unwrap().contains_key("id_token")
            || tokens["id_token"].as_str().is_none()
    );
}

#[tokio::test]
async fn test_github_user_api_retrieval() {
    let server = MockServer::start().await;
    let fixture = ProviderTestFixture::github();

    setup_github_user(&server, &fixture.mock_user).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/user", server.uri()))
        .header(
            "Authorization",
            format!("Bearer {}", fixture.mock_tokens.access_token),
        )
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let user_info: serde_json::Value = response.json().await.unwrap();
    assert_eq!(user_info["id"].to_string(), fixture.mock_user.provider_id);
    assert_eq!(user_info["name"], fixture.mock_user.name);
    assert_eq!(user_info["login"], "testuser");
    assert!(user_info["avatar_url"].is_string());
}

#[tokio::test]
async fn test_github_emails_api_for_primary_verified_email() {
    let server = MockServer::start().await;
    let fixture = ProviderTestFixture::github();

    setup_github_emails(&server, &fixture.mock_user).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/user/emails", server.uri()))
        .header(
            "Authorization",
            format!("Bearer {}", fixture.mock_tokens.access_token),
        )
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let emails: Vec<serde_json::Value> = response.json().await.unwrap();

    // Find primary verified email
    let primary_email = emails
        .iter()
        .find(|e| e["primary"].as_bool() == Some(true) && e["verified"].as_bool() == Some(true));

    assert!(
        primary_email.is_some(),
        "Should have a primary verified email"
    );
    assert_eq!(primary_email.unwrap()["email"], fixture.mock_user.email);
}

#[tokio::test]
async fn test_github_private_email_fallback_noreply() {
    let server = MockServer::start().await;
    let private_user = MockUser::github_private_email();

    setup_github_user(&server, &private_user).await;
    setup_github_emails(&server, &private_user).await;

    let client = reqwest::Client::new();

    // User API returns null email for private users
    let user_response = client
        .get(format!("{}/user", server.uri()))
        .header("Authorization", "Bearer test_token")
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();

    let user_info: serde_json::Value = user_response.json().await.unwrap();
    assert!(
        user_info["email"].is_null(),
        "Private user should have null email in /user"
    );

    // Must use emails API to get noreply email
    let emails_response = client
        .get(format!("{}/user/emails", server.uri()))
        .header("Authorization", "Bearer test_token")
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();

    let emails: Vec<serde_json::Value> = emails_response.json().await.unwrap();
    let primary_email = emails.iter().find(|e| e["primary"].as_bool() == Some(true));

    assert!(primary_email.is_some());
    let email = primary_email.unwrap()["email"].as_str().unwrap();
    assert!(
        email.contains("noreply.github.com"),
        "Private user should have noreply email"
    );
}

#[tokio::test]
async fn test_github_invalid_code_error() {
    let server = MockServer::start().await;

    setup_token_endpoint_error(&server, OAuthError::invalid_grant(), 400).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/token", server.uri()))
        .header("Accept", "application/json")
        .form(&[
            ("client_id", "test-client"),
            ("client_secret", "test-secret"),
            ("code", "invalid_or_expired_code"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);

    let error: OAuthError = response.json().await.unwrap();
    assert_eq!(error.error, "invalid_grant");
}

#[tokio::test]
async fn test_github_rate_limit_error() {
    let server = MockServer::start().await;

    setup_github_rate_limit(&server).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/user", server.uri()))
        .header("Authorization", "Bearer test_token")
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 429);

    // Check rate limit headers
    assert_eq!(
        response
            .headers()
            .get("X-RateLimit-Remaining")
            .map(|v| v.to_str().unwrap()),
        Some("0")
    );

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["message"].as_str().unwrap().contains("rate limit"));
}

#[tokio::test]
async fn test_github_fixture_configuration() {
    let fixture = ProviderTestFixture::github();

    assert_eq!(fixture.provider_type, ProviderType::GitHub);
    assert!(!fixture.client_id.is_empty());
    assert!(!fixture.client_secret.is_empty());
    assert!(fixture.redirect_uri.contains("/callback/github"));

    // GitHub scopes
    assert!(fixture.scopes.contains(&"user:email".to_string()));
    assert!(fixture.scopes.contains(&"read:user".to_string()));

    // GitHub doesn't use OIDC
    assert!(fixture.mock_tokens.id_token.is_none());
}
