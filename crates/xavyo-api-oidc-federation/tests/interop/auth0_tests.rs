//! Auth0 OIDC Interoperability Tests
//!
//! Tests verifying correct handling of Auth0 token formats, including
//! tenant-specific issuers (with trailing slash) and namespaced custom claims.

use super::common::*;
use serde_json::json;
use xavyo_api_oidc_federation::error::FederationError;
use xavyo_api_oidc_federation::services::{TokenVerifierService, VerificationConfig};

/// Auth0-specific test fixtures
mod auth0_fixtures {
    use super::*;

    /// Auth0 issuer pattern (note trailing slash)
    pub fn issuer(base_url: &str, tenant: &str) -> String {
        // In production: https://{tenant}.auth0.com/
        // Note: Auth0 issuers have a trailing slash
        format!("{}/{}/", base_url, tenant)
    }

    /// Auth0 discovery document
    #[allow(dead_code)]
    pub fn discovery_document(base_url: &str, tenant: &str) -> serde_json::Value {
        let issuer = issuer(base_url, tenant);
        json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{}authorize", issuer),
            "token_endpoint": format!("{}oauth/token", issuer),
            "device_authorization_endpoint": format!("{}oauth/device/code", issuer),
            "userinfo_endpoint": format!("{}userinfo", issuer),
            "mfa_challenge_endpoint": format!("{}mfa/challenge", issuer),
            "jwks_uri": format!("{}/.well-known/jwks.json", base_url),
            "registration_endpoint": format!("{}oidc/register", issuer),
            "revocation_endpoint": format!("{}oauth/revoke", issuer),
            "scopes_supported": ["openid", "profile", "offline_access", "name", "given_name", "family_name", "nickname", "email", "email_verified", "picture", "created_at", "identities", "phone", "address"],
            "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "response_modes_supported": ["query", "fragment", "form_post"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["HS256", "RS256", "PS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
            "claims_supported": ["aud", "auth_time", "created_at", "email", "email_verified", "exp", "family_name", "given_name", "iat", "identities", "iss", "name", "nickname", "phone_number", "picture", "sub"],
            "request_uri_parameter_supported": false,
            "request_parameter_supported": false,
            "token_endpoint_auth_signing_alg_values_supported": ["RS256", "RS384", "PS256"]
        })
    }

    /// Auth0 JWKS
    pub fn jwks(kid: &str) -> serde_json::Value {
        json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "kid": kid,
                "alg": "RS256",
                "n": "uOs2bjkrVK1Vi6uSrZAGjy_YTQlC0eMz4YLJHVDgdXPm8UYjonBBykwbKm-C0p4syG93yBDeV7lC-U8zgSk94QHP4CilO9VShORDHG37iy1cU6o9PCto-z8wgoc88nWRowFn4rJ3QEnkDyCdRzNy4d1YV2q97sMW6U9iqsefQu0g6Qkx7GcLy1TLqchIi_tfKxSO7w75Zx8bqBuXZBmYcmay3ysdQN3l-PVIm4ic_CpuFLW0XmeTvlUp3R2JoSxVySh3faTq-18cspk7nBiW5mTpko2924GiIWMh_graaMU7agn1ItpBwmXQtXBhfd1J6i5jSKu53NGG4SSXPvu9jQ",
                "e": "AQAB",
                "x5c": [],  // Auth0 may include certificate chain
                "x5t": kid
            }]
        })
    }

    /// Create Auth0 claims with namespaced custom claims
    pub fn claims_with_namespace(
        sub: &str,
        issuer: &str,
        namespace: &str,
        roles: Vec<&str>,
        permissions: Vec<&str>,
    ) -> TestClaims {
        TestClaims::new(sub, issuer, vec!["https://api.myapp.com".to_string()])
            .with_email(&format!("{}@example.com", sub))
            .with_claim(&format!("{}/roles", namespace), json!(roles))
            .with_claim(&format!("{}/permissions", namespace), json!(permissions))
    }
}

#[tokio::test]
async fn test_auth0_valid_token_verification() {
    let mock = IdpMockServer::new().await;
    let tenant = "myapp";
    let issuer = auth0_fixtures::issuer(&mock.base_url(), tenant);
    let kid = "auth0-key-1";

    mock.mount_jwks(auth0_fixtures::jwks(kid)).await;

    let claims = TestClaims::new(
        "auth0|user123",
        &issuer,
        vec!["https://api.myapp.com".to_string()],
    )
    .with_email("user@example.com");
    let token = create_test_token(&claims, kid);

    let verifier = TokenVerifierService::new(VerificationConfig::default());
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(
        result.is_ok(),
        "Token verification failed: {:?}",
        result.err()
    );
    let verified = result.unwrap();
    assert_eq!(verified.claims.sub, "auth0|user123");
}

#[tokio::test]
async fn test_auth0_namespaced_claims() {
    let mock = IdpMockServer::new().await;
    let tenant = "myapp";
    let issuer = auth0_fixtures::issuer(&mock.base_url(), tenant);
    let kid = "auth0-key-1";

    mock.mount_jwks(auth0_fixtures::jwks(kid)).await;

    // Create token with Auth0 namespaced claims
    let claims = auth0_fixtures::claims_with_namespace(
        "auth0|user123",
        &issuer,
        "https://myapp.com",
        vec!["admin", "user"],
        vec!["read:users", "write:users"],
    );
    let token = create_test_token_with_custom_claims(&claims, kid);

    let verifier = TokenVerifierService::new(VerificationConfig::default());
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(
        result.is_ok(),
        "Token verification failed: {:?}",
        result.err()
    );
    // Token verifies successfully with namespaced claims embedded
}

#[tokio::test]
async fn test_auth0_trailing_slash_issuer() {
    let mock = IdpMockServer::new().await;
    let tenant = "myapp";
    let issuer = auth0_fixtures::issuer(&mock.base_url(), tenant);
    let kid = "auth0-key-1";

    mock.mount_jwks(auth0_fixtures::jwks(kid)).await;

    // Auth0 issuers have a trailing slash
    assert!(issuer.ends_with('/'), "Auth0 issuer should end with /");

    let claims = TestClaims::new(
        "auth0|user123",
        &issuer,
        vec!["https://api.myapp.com".to_string()],
    );
    let token = create_test_token(&claims, kid);

    // Verify with expected issuer including trailing slash
    let verifier = TokenVerifierService::new(VerificationConfig::default().issuer(&issuer));
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(
        result.is_ok(),
        "Token verification failed: {:?}",
        result.err()
    );
    let verified = result.unwrap();
    assert!(verified.issuer.ends_with('/'));
}

#[tokio::test]
async fn test_auth0_invalid_signature_rejected() {
    let mock = IdpMockServer::new().await;
    let tenant = "myapp";
    let issuer = auth0_fixtures::issuer(&mock.base_url(), tenant);
    let kid = "auth0-key-1";

    mock.mount_jwks(auth0_fixtures::jwks(kid)).await;

    let claims = TestClaims::new(
        "auth0|user123",
        &issuer,
        vec!["https://api.myapp.com".to_string()],
    );
    let token = create_invalid_signature_token(&claims, kid);

    let verifier = TokenVerifierService::new(VerificationConfig::default());
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
async fn test_auth0_expired_token_rejected() {
    let mock = IdpMockServer::new().await;
    let tenant = "myapp";
    let issuer = auth0_fixtures::issuer(&mock.base_url(), tenant);
    let kid = "auth0-key-1";

    mock.mount_jwks(auth0_fixtures::jwks(kid)).await;

    let claims = TestClaims::with_exp_offset(
        "auth0|user123",
        &issuer,
        vec!["https://api.myapp.com".to_string()],
        -3600,
    );
    let token = create_test_token(&claims, kid);

    let verifier = TokenVerifierService::new(VerificationConfig::default());
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), FederationError::TokenExpired),
        "Expected TokenExpired error"
    );
}

#[tokio::test]
async fn test_auth0_subject_format() {
    let mock = IdpMockServer::new().await;
    let tenant = "myapp";
    let issuer = auth0_fixtures::issuer(&mock.base_url(), tenant);
    let kid = "auth0-key-1";

    mock.mount_jwks(auth0_fixtures::jwks(kid)).await;

    // Auth0 subjects typically have format: {connection}|{user_id}
    let sub = "auth0|abc123def456";
    let claims = TestClaims::new(sub, &issuer, vec!["https://api.myapp.com".to_string()]);
    let token = create_test_token(&claims, kid);

    let verifier = TokenVerifierService::new(VerificationConfig::default());
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(
        result.is_ok(),
        "Token verification failed: {:?}",
        result.err()
    );
    let verified = result.unwrap();
    assert_eq!(verified.claims.sub, sub);
    assert!(verified.claims.sub.contains('|'));
}
