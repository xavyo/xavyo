//! Ping Identity OIDC Interoperability Tests
//!
//! Tests verifying correct handling of Ping Identity (PingOne/PingFederate)
//! token formats and JWKS responses.

use super::common::*;
use serde_json::json;
use xavyo_api_oidc_federation::error::FederationError;
use xavyo_api_oidc_federation::services::VerificationConfig;

/// Ping Identity-specific test fixtures
mod ping_fixtures {
    use super::*;

    /// `PingOne` issuer pattern
    pub fn issuer(base_url: &str, environment_id: &str) -> String {
        format!("{base_url}/{environment_id}/as")
    }

    /// Ping Identity discovery document
    #[allow(dead_code)]
    pub fn discovery_document(base_url: &str, environment_id: &str) -> serde_json::Value {
        let issuer = issuer(base_url, environment_id);
        json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{}/authorize", issuer),
            "token_endpoint": format!("{}/token", issuer),
            "userinfo_endpoint": format!("{}/userinfo", issuer),
            "jwks_uri": format!("{}/.well-known/jwks.json", base_url),
            "end_session_endpoint": format!("{}/signoff", issuer),
            "check_session_iframe": format!("{}/session/check", issuer),
            "revocation_endpoint": format!("{}/revoke", issuer),
            "introspection_endpoint": format!("{}/introspect", issuer),
            "response_types_supported": ["code", "token", "id_token", "code id_token", "code token", "token id_token", "code token id_token"],
            "response_modes_supported": ["query", "fragment", "form_post"],
            "grant_types_supported": ["authorization_code", "implicit", "client_credentials", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "RS384", "RS512"],
            "userinfo_signing_alg_values_supported": ["RS256", "RS384", "RS512"],
            "request_object_signing_alg_values_supported": ["RS256", "RS384", "RS512"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["RS256", "RS384", "RS512"],
            "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "acr", "amr", "azp", "name", "email", "email_verified", "phone_number", "phone_number_verified", "address", "updated_at"],
            "scopes_supported": ["openid", "profile", "email", "address", "phone"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "claim_types_supported": ["normal"]
        })
    }

    /// Ping Identity JWKS
    pub fn jwks(kid: &str) -> serde_json::Value {
        json!({
            "keys": [test_public_key_jwk(kid)]
        })
    }

    /// Create Ping Identity claims
    pub fn claims(sub: &str, issuer: &str) -> TestClaims {
        TestClaims::new(sub, issuer, vec!["app-client-id".to_string()])
            .with_email(&format!("{sub}@example.com"))
            .with_name("Test User")
    }
}

#[tokio::test]
async fn test_ping_valid_token_verification() {
    let mock = IdpMockServer::new().await;
    let environment_id = "e2a8b4c6-1234-5678-9abc-def012345678";
    let issuer = ping_fixtures::issuer(&mock.base_url(), environment_id);
    let kid = "ping-key-1";

    mock.mount_jwks(ping_fixtures::jwks(kid)).await;

    let claims = ping_fixtures::claims("user123", &issuer);
    let token = create_test_token(&claims, kid);

    let verifier = mock.verifier(VerificationConfig::default());
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(
        result.is_ok(),
        "Token verification failed: {:?}",
        result.err()
    );
    let verified = result.unwrap();
    assert_eq!(verified.claims.sub, "user123");
    assert!(verified.issuer.contains("/as"));
}

#[tokio::test]
async fn test_ping_key_selection_by_kid() {
    let mock = IdpMockServer::new().await;
    let environment_id = "e2a8b4c6-1234-5678-9abc-def012345678";
    let issuer = ping_fixtures::issuer(&mock.base_url(), environment_id);

    // Mount JWKS with multiple keys
    mock.mount_jwks(multi_key_jwks(&["ping-key-1", "ping-key-2", "ping-key-3"]))
        .await;

    // Sign with the middle key
    let claims = ping_fixtures::claims("user123", &issuer);
    let token = create_test_token(&claims, "ping-key-2");

    let verifier = mock.verifier(VerificationConfig::default());
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(
        result.is_ok(),
        "Token verification failed: {:?}",
        result.err()
    );
    let verified = result.unwrap();
    assert_eq!(verified.kid, Some("ping-key-2".to_string()));
}

#[tokio::test]
async fn test_ping_invalid_signature_rejected() {
    let mock = IdpMockServer::new().await;
    let environment_id = "e2a8b4c6-1234-5678-9abc-def012345678";
    let issuer = ping_fixtures::issuer(&mock.base_url(), environment_id);
    let kid = "ping-key-1";

    mock.mount_jwks(ping_fixtures::jwks(kid)).await;

    let claims = ping_fixtures::claims("user123", &issuer);
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
async fn test_ping_expired_token_rejected() {
    let mock = IdpMockServer::new().await;
    let environment_id = "e2a8b4c6-1234-5678-9abc-def012345678";
    let issuer = ping_fixtures::issuer(&mock.base_url(), environment_id);
    let kid = "ping-key-1";

    mock.mount_jwks(ping_fixtures::jwks(kid)).await;

    let claims =
        TestClaims::with_exp_offset("user123", &issuer, vec!["app-client-id".to_string()], -3600);
    let token = create_test_token(&claims, kid);

    let verifier = mock.verifier(VerificationConfig::default());
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), FederationError::TokenExpired),
        "Expected TokenExpired error"
    );
}
