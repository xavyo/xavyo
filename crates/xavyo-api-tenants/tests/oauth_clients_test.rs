//! Integration tests for OAuth client management handlers.
//!
//! F-SECRET-ROTATE: Tests for OAuth client secret rotation functionality.

use chrono::Utc;
use uuid::Uuid;
use xavyo_api_tenants::models::{
    OAuthClientDetails, OAuthClientListResponse, RotateOAuthSecretRequest,
    RotateOAuthSecretResponse,
};

/// Test that the RotateOAuthSecretRequest can be created with defaults.
#[test]
fn test_rotate_oauth_secret_request_default() {
    let request = RotateOAuthSecretRequest::default();
    // The request is valid with defaults (no options currently)
    let _ = request;
}

/// Test response serialization for RotateOAuthSecretResponse.
#[test]
fn test_rotate_oauth_secret_response_serialization() {
    let response = RotateOAuthSecretResponse {
        client_id: Uuid::new_v4(),
        public_client_id: "my_app_client_123".to_string(),
        new_client_secret: "secret_abcdef1234567890".to_string(),
        rotated_at: Utc::now(),
        refresh_tokens_revoked: true,
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("client_id"));
    assert!(json.contains("public_client_id"));
    assert!(json.contains("new_client_secret"));
    assert!(json.contains("rotated_at"));
    assert!(json.contains("\"refresh_tokens_revoked\":true"));
}

/// Test response serialization for OAuthClientDetails.
#[test]
fn test_oauth_client_details_serialization() {
    let details = OAuthClientDetails {
        id: Uuid::new_v4(),
        client_id: "webapp_client".to_string(),
        name: "Web Application".to_string(),
        client_type: "confidential".to_string(),
        redirect_uris: vec![
            "https://app.example.com/callback".to_string(),
            "https://app.example.com/oauth".to_string(),
        ],
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        is_active: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let json = serde_json::to_string(&details).unwrap();
    assert!(json.contains("Web Application"));
    assert!(json.contains("confidential"));
    assert!(json.contains("authorization_code"));
    assert!(json.contains("openid"));
    assert!(json.contains("\"is_active\":true"));
}

#[test]
fn test_oauth_client_details_public_client() {
    let details = OAuthClientDetails {
        id: Uuid::new_v4(),
        client_id: "spa_client".to_string(),
        name: "Single Page App".to_string(),
        client_type: "public".to_string(),
        redirect_uris: vec!["http://localhost:3000/callback".to_string()],
        grant_types: vec!["authorization_code".to_string()],
        scopes: vec!["openid".to_string()],
        is_active: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let json = serde_json::to_string(&details).unwrap();
    assert!(json.contains("public"));
    assert!(json.contains("spa_client"));
}

/// Test response serialization for OAuthClientListResponse.
#[test]
fn test_oauth_client_list_response_serialization() {
    let response = OAuthClientListResponse {
        oauth_clients: vec![
            OAuthClientDetails {
                id: Uuid::new_v4(),
                client_id: "client_1".to_string(),
                name: "Client 1".to_string(),
                client_type: "confidential".to_string(),
                redirect_uris: vec!["https://example.com/cb".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                scopes: vec!["openid".to_string()],
                is_active: true,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            OAuthClientDetails {
                id: Uuid::new_v4(),
                client_id: "client_2".to_string(),
                name: "Client 2".to_string(),
                client_type: "public".to_string(),
                redirect_uris: vec!["http://localhost:8080/cb".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                scopes: vec!["openid".to_string(), "profile".to_string()],
                is_active: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ],
        total: 2,
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"total\":2"));
    assert!(json.contains("Client 1"));
    assert!(json.contains("Client 2"));
    assert!(json.contains("client_1"));
    assert!(json.contains("client_2"));
}

#[test]
fn test_oauth_client_list_response_empty() {
    let response = OAuthClientListResponse {
        oauth_clients: vec![],
        total: 0,
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"total\":0"));
    assert!(json.contains("\"oauth_clients\":[]"));
}
