//! Integration tests for OIDC Discovery endpoints.
//!
//! These tests verify the /.well-known/openid-configuration and
//! /.well-known/jwks.json endpoints work correctly.

use axum::{body::Body, http::Request};
use tower::ServiceExt;
use xavyo_api_oauth::models::{JwkSet, OpenIdConfiguration};
use xavyo_api_oauth::router::well_known_router;

mod common;
use common::create_test_state;

/// Test that the discovery endpoint returns valid OIDC configuration.
#[tokio::test]
async fn test_discovery_endpoint_returns_valid_configuration() {
    let state = create_test_state();
    let app = well_known_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let config: OpenIdConfiguration = serde_json::from_slice(&body).unwrap();

    // Verify issuer
    assert_eq!(config.issuer, "https://idp.test.xavyo.com");

    // Verify endpoints
    assert_eq!(
        config.authorization_endpoint,
        "https://idp.test.xavyo.com/oauth/authorize"
    );
    assert_eq!(
        config.token_endpoint,
        "https://idp.test.xavyo.com/oauth/token"
    );
    assert_eq!(
        config.userinfo_endpoint,
        "https://idp.test.xavyo.com/oauth/userinfo"
    );
    assert_eq!(
        config.jwks_uri,
        "https://idp.test.xavyo.com/.well-known/jwks.json"
    );
}

/// Test that the discovery endpoint returns required OIDC fields.
#[tokio::test]
async fn test_discovery_endpoint_returns_required_oidc_fields() {
    let state = create_test_state();
    let app = well_known_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let config: OpenIdConfiguration = serde_json::from_slice(&body).unwrap();

    // Verify required response types
    assert!(config
        .response_types_supported
        .contains(&"code".to_string()));

    // Verify required grant types
    assert!(config
        .grant_types_supported
        .contains(&"authorization_code".to_string()));
    assert!(config
        .grant_types_supported
        .contains(&"refresh_token".to_string()));

    // Verify PKCE support (S256 only)
    assert!(config
        .code_challenge_methods_supported
        .contains(&"S256".to_string()));
    assert!(!config
        .code_challenge_methods_supported
        .contains(&"plain".to_string()));

    // Verify signing algorithm
    assert!(config
        .id_token_signing_alg_values_supported
        .contains(&"RS256".to_string()));

    // Verify required scopes
    assert!(config.scopes_supported.contains(&"openid".to_string()));
}

/// Test that the JWKS endpoint returns valid JSON.
#[tokio::test]
async fn test_jwks_endpoint_returns_valid_json() {
    let state = create_test_state();
    let app = well_known_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let jwks: JwkSet = serde_json::from_slice(&body).unwrap();

    // With a valid test key, we should have exactly one key
    assert!(
        !jwks.keys.is_empty(),
        "JWKS should contain at least one key"
    );

    // Verify key properties
    let key = &jwks.keys[0];
    assert_eq!(key.kty, "RSA");
    assert_eq!(key.key_use, "sig");
    assert_eq!(key.alg, "RS256");
    assert_eq!(key.kid, "test-key-1");
    assert!(!key.n.is_empty(), "Modulus should not be empty");
    assert!(!key.e.is_empty(), "Exponent should not be empty");
}

/// Test that JWKS key ID matches configuration.
#[tokio::test]
async fn test_jwks_key_id_matches_configuration() {
    let state = create_test_state();
    let key_id = state.key_id.clone();
    let app = well_known_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let jwks: JwkSet = serde_json::from_slice(&body).unwrap();

    assert!(!jwks.keys.is_empty());
    assert_eq!(jwks.keys[0].kid, key_id);
}
