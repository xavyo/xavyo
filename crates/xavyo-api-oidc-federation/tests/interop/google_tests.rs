//! Google Workspace OIDC Interoperability Tests
//!
//! Tests verifying correct handling of Google token formats and the HD (hosted domain)
//! claim for distinguishing Workspace users from personal Gmail accounts.

use super::common::*;
use serde_json::json;
use xavyo_api_oidc_federation::error::FederationError;
use xavyo_api_oidc_federation::services::VerificationConfig;

/// Google-specific test fixtures
mod google_fixtures {
    use super::*;

    /// Google issuer (always the same)
    pub const ISSUER: &str = "https://accounts.google.com";

    /// Google discovery document
    #[allow(dead_code)]
    pub fn discovery_document(jwks_uri: &str) -> serde_json::Value {
        json!({
            "issuer": ISSUER,
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "device_authorization_endpoint": "https://oauth2.googleapis.com/device/code",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
            "revocation_endpoint": "https://oauth2.googleapis.com/revoke",
            "jwks_uri": jwks_uri,
            "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token", "none"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "email", "profile"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "claims_supported": ["aud", "email", "email_verified", "exp", "family_name", "given_name", "iat", "iss", "locale", "name", "picture", "sub", "hd"],
            "code_challenge_methods_supported": ["plain", "S256"],
            "grant_types_supported": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:jwt-bearer"]
        })
    }

    /// Google JWKS response
    pub fn jwks(kid: &str) -> serde_json::Value {
        json!({
            "keys": [test_public_key_jwk(kid)]
        })
    }

    /// Create Google Workspace claims with HD (hosted domain)
    pub fn workspace_claims(sub: &str, email: &str, hosted_domain: &str) -> TestClaims {
        TestClaims::new(
            sub,
            ISSUER,
            vec!["client-id.apps.googleusercontent.com".to_string()],
        )
        .with_email(email)
        .with_claim("hd", json!(hosted_domain))
        .with_claim("email_verified", json!(true))
    }

    /// Create personal Gmail claims (no HD claim)
    pub fn gmail_claims(sub: &str, email: &str) -> TestClaims {
        TestClaims::new(
            sub,
            ISSUER,
            vec!["client-id.apps.googleusercontent.com".to_string()],
        )
        .with_email(email)
        .with_claim("email_verified", json!(true))
        // No hd claim for personal accounts
    }
}

#[tokio::test]
async fn test_google_valid_token_verification() {
    let mock = IdpMockServer::new().await;
    let kid = "google-key-1";

    mock.mount_jwks(google_fixtures::jwks(kid)).await;

    let claims = TestClaims::new(
        "118234567890123456789",
        google_fixtures::ISSUER,
        vec!["client-id.apps.googleusercontent.com".to_string()],
    )
    .with_email("user@gmail.com");
    let token = create_test_token(&claims, kid);

    let verifier = mock.verifier(VerificationConfig::default());
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(
        result.is_ok(),
        "Token verification failed: {:?}",
        result.err()
    );
    let verified = result.unwrap();
    assert_eq!(verified.issuer, google_fixtures::ISSUER);
}

#[tokio::test]
async fn test_google_workspace_hd_claim() {
    let mock = IdpMockServer::new().await;
    let kid = "google-key-1";

    mock.mount_jwks(google_fixtures::jwks(kid)).await;

    // Workspace user with HD claim
    let claims = google_fixtures::workspace_claims(
        "118234567890123456789",
        "user@company.com",
        "company.com",
    );
    let token = create_test_token_with_custom_claims(&claims, kid);

    let verifier = mock.verifier(VerificationConfig::default());
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(
        result.is_ok(),
        "Token verification failed: {:?}",
        result.err()
    );
    // HD claim is present in the token, verification succeeded
}

#[tokio::test]
async fn test_google_personal_account_no_hd() {
    let mock = IdpMockServer::new().await;
    let kid = "google-key-1";

    mock.mount_jwks(google_fixtures::jwks(kid)).await;

    // Personal Gmail account (no HD claim)
    let claims = google_fixtures::gmail_claims("118234567890123456789", "user@gmail.com");
    let token = create_test_token_with_custom_claims(&claims, kid);

    let verifier = mock.verifier(VerificationConfig::default());
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(
        result.is_ok(),
        "Token verification failed: {:?}",
        result.err()
    );
    // Token verifies successfully, but has no HD claim
    // Application logic would need to check for HD claim presence
}

#[tokio::test]
async fn test_google_invalid_signature_rejected() {
    let mock = IdpMockServer::new().await;
    let kid = "google-key-1";

    mock.mount_jwks(google_fixtures::jwks(kid)).await;

    let claims = TestClaims::new(
        "118234567890123456789",
        google_fixtures::ISSUER,
        vec!["client-id.apps.googleusercontent.com".to_string()],
    );
    let token = create_invalid_signature_token(&claims, kid);

    let verifier = mock.verifier(VerificationConfig::default());
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            FederationError::TokenVerificationFailed(_)
        ),
        "Expected TokenVerificationFailed error"
    );
}

#[tokio::test]
async fn test_google_expired_token_rejected() {
    let mock = IdpMockServer::new().await;
    let kid = "google-key-1";

    mock.mount_jwks(google_fixtures::jwks(kid)).await;

    // Expired token
    let claims = TestClaims::with_exp_offset(
        "118234567890123456789",
        google_fixtures::ISSUER,
        vec!["client-id.apps.googleusercontent.com".to_string()],
        -3600,
    );
    let token = create_test_token(&claims, kid);

    let verifier = mock.verifier(VerificationConfig::default());
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), FederationError::TokenExpired),
        "Expected TokenExpired error"
    );
}

#[tokio::test]
async fn test_google_issuer_always_accounts_google() {
    let mock = IdpMockServer::new().await;
    let kid = "google-key-1";

    mock.mount_jwks(google_fixtures::jwks(kid)).await;

    let claims = TestClaims::new(
        "user123",
        google_fixtures::ISSUER,
        vec!["client-id.apps.googleusercontent.com".to_string()],
    );
    let token = create_test_token(&claims, kid);

    // Verify with expected Google issuer
    let verifier = mock.verifier(VerificationConfig::default().issuer(google_fixtures::ISSUER));
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(
        result.is_ok(),
        "Token verification failed: {:?}",
        result.err()
    );
    let verified = result.unwrap();
    assert_eq!(verified.issuer, "https://accounts.google.com");
}
