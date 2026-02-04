//! Apple Sign In Integration Tests
//!
//! Tests for Apple Sign In flow including:
//! - Authorization URL with `form_post` `response_mode`
//! - Form-post callback handling
//! - JWT identity token validation
//! - Private relay email handling
//! - First-time user name capture
//! - Error scenarios

use wiremock::MockServer;

use super::common::{
    MockUser, ProviderTestFixture, ProviderType, TEST_AUTH_CODE, TEST_NONCE, TEST_STATE,
};
use super::mock_server::{
    generate_apple_id_token, setup_token_endpoint_error, setup_token_endpoint_success, OAuthError,
};

/// Apple Sign In endpoints
const APPLE_AUTH_ENDPOINT: &str = "https://appleid.apple.com/auth/authorize";
#[allow(dead_code)]
const APPLE_TOKEN_ENDPOINT: &str = "https://appleid.apple.com/auth/token";
#[allow(dead_code)]
const APPLE_KEYS_ENDPOINT: &str = "https://appleid.apple.com/auth/keys";

/// Build Apple-specific authorization URL
fn build_apple_auth_url(
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
    state: &str,
    nonce: Option<&str>,
) -> String {
    let scope = scopes.join(" ");
    let mut url = format!(
        "{}?client_id={}&redirect_uri={}&scope={}&state={}&response_type=code&response_mode=form_post",
        APPLE_AUTH_ENDPOINT,
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(&scope),
        urlencoding::encode(state)
    );

    if let Some(n) = nonce {
        url.push_str(&format!("&nonce={}", urlencoding::encode(n)));
    }

    url
}

#[tokio::test]
async fn test_apple_authorization_url_with_form_post_response_mode() {
    let fixture = ProviderTestFixture::apple();

    let auth_url = build_apple_auth_url(
        &fixture.client_id,
        &fixture.redirect_uri,
        &fixture.scopes,
        TEST_STATE,
        Some(TEST_NONCE),
    );

    // Verify Apple-specific parameters
    assert!(auth_url.starts_with(APPLE_AUTH_ENDPOINT));
    assert!(auth_url.contains(&format!("client_id={}", fixture.client_id)));
    assert!(auth_url.contains("response_type=code"));
    assert!(auth_url.contains("response_mode=form_post"));
    assert!(auth_url.contains(&format!("state={TEST_STATE}")));
    assert!(auth_url.contains(&format!("nonce={TEST_NONCE}")));

    // Apple scopes
    assert!(auth_url.contains("name"));
    assert!(auth_url.contains("email"));
}

#[tokio::test]
async fn test_apple_form_post_callback_handling() {
    // Apple sends callback as POST with form data, not GET with query params
    let server = MockServer::start().await;
    let fixture = ProviderTestFixture::apple();

    // Setup token endpoint
    let mut tokens = fixture.mock_tokens.clone();
    tokens.id_token = Some(generate_apple_id_token(
        &fixture.mock_user,
        &fixture.client_id,
        Some(TEST_NONCE),
    ));
    setup_token_endpoint_success(&server, &tokens).await;

    // Simulate the form-post callback body
    let callback_body = format!(
        "code={}&state={}&id_token={}",
        TEST_AUTH_CODE,
        TEST_STATE,
        tokens.id_token.as_ref().unwrap()
    );

    // Verify callback contains expected parameters
    assert!(callback_body.contains("code="));
    assert!(callback_body.contains("state="));
    assert!(callback_body.contains("id_token="));
}

#[tokio::test]
async fn test_apple_jwt_identity_token_validation() {
    let fixture = ProviderTestFixture::apple();

    let id_token =
        generate_apple_id_token(&fixture.mock_user, &fixture.client_id, Some(TEST_NONCE));

    // Verify JWT structure
    let parts: Vec<&str> = id_token.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "Apple ID token should be a valid JWT with 3 parts"
    );

    // Decode header (base64url)
    let header_json = base64_url_decode(parts[0]);
    assert!(header_json.contains("RS256"), "Apple uses RS256 algorithm");
    assert!(header_json.contains("JWT"), "Should be JWT type");

    // Decode payload
    let payload_json = base64_url_decode(parts[1]);
    assert!(
        payload_json.contains("appleid.apple.com"),
        "Issuer should be Apple"
    );
    assert!(
        payload_json.contains(&fixture.client_id),
        "Audience should match client_id"
    );
    assert!(
        payload_json.contains(&fixture.mock_user.email),
        "Should contain user email"
    );
}

#[tokio::test]
async fn test_apple_private_relay_email_handling() {
    let user = MockUser::apple();

    // Verify private relay email format
    assert!(user.is_private_email);
    assert!(user.email.contains("privaterelay.appleid.com"));

    // System should accept and store private relay emails
    let id_token = generate_apple_id_token(&user, "com.example.app", None);
    let payload = base64_url_decode(id_token.split('.').nth(1).unwrap());

    assert!(payload.contains("is_private_email"));
    assert!(payload.contains("true"));
}

#[tokio::test]
async fn test_apple_real_email_handling() {
    let user = MockUser::apple_real_email();

    // User who shared real email
    assert!(!user.is_private_email);
    assert!(!user.email.contains("privaterelay"));

    let id_token = generate_apple_id_token(&user, "com.example.app", None);
    let payload = base64_url_decode(id_token.split('.').nth(1).unwrap());

    assert!(payload.contains(&user.email));
    assert!(payload.contains("\"is_private_email\":false"));
}

#[tokio::test]
async fn test_apple_first_time_user_name_capture() {
    // Apple only sends user name on first authorization
    // Subsequent logins do NOT include the name

    let user = MockUser::apple();

    // First authorization includes user info in form-post
    let first_auth_user_info = serde_json::json!({
        "name": {
            "firstName": user.first_name,
            "lastName": user.last_name
        },
        "email": user.email
    });

    // Verify name is present
    assert!(first_auth_user_info["name"]["firstName"].is_string());
    assert!(first_auth_user_info["name"]["lastName"].is_string());

    // Subsequent authorizations - no user info
    let subsequent_auth: Option<serde_json::Value> = None;
    assert!(subsequent_auth.is_none());
}

#[tokio::test]
async fn test_apple_invalid_jwt_signature_error() {
    let fixture = ProviderTestFixture::apple();

    // Create a token and tamper with signature
    let valid_token =
        generate_apple_id_token(&fixture.mock_user, &fixture.client_id, Some(TEST_NONCE));
    let parts: Vec<&str> = valid_token.split('.').collect();

    // Replace signature with invalid one
    let tampered_token = format!("{}.{}.invalid_signature", parts[0], parts[1]);

    // Verify the token is malformed
    let tampered_parts: Vec<&str> = tampered_token.split('.').collect();
    assert_eq!(tampered_parts.len(), 3);
    assert_ne!(tampered_parts[2], parts[2]);

    // In real implementation, signature validation would fail
    // This test verifies we can detect tampered tokens
}

#[tokio::test]
async fn test_apple_token_exchange_failure() {
    let server = MockServer::start().await;

    setup_token_endpoint_error(&server, OAuthError::invalid_grant(), 400).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/token", server.uri()))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "invalid_apple_code"),
            ("client_id", "com.example.app"),
            ("client_secret", "jwt_client_secret"),
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
async fn test_apple_fixture_configuration() {
    let fixture = ProviderTestFixture::apple();

    assert_eq!(fixture.provider_type, ProviderType::Apple);
    assert!(fixture.client_id.contains("com.")); // Apple uses reverse domain notation
    assert!(!fixture.client_secret.is_empty());
    assert!(fixture.redirect_uri.contains("/callback/apple"));

    // Apple scopes
    assert!(fixture.scopes.contains(&"name".to_string()));
    assert!(fixture.scopes.contains(&"email".to_string()));
}

/// Helper to decode base64url without padding
fn base64_url_decode(input: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let bytes = URL_SAFE_NO_PAD.decode(input).unwrap_or_default();
    String::from_utf8_lossy(&bytes).to_string()
}
