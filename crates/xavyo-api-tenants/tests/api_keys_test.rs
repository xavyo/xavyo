//! Integration tests for API key management handlers.
//!
//! F-KEY-ROTATE: Tests for API key rotation functionality.

use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_api_tenants::models::{
    ApiKeyInfo, ApiKeyListResponse, RotateApiKeyRequest, RotateApiKeyResponse,
};

/// Test that the RotateApiKeyRequest validation works correctly.
#[test]
fn test_rotate_request_validation_valid_defaults() {
    let request = RotateApiKeyRequest {
        deactivate_old_immediately: None,
        grace_period_hours: None,
        expires_at: None,
    };
    assert!(request.validate().is_none());
}

#[test]
fn test_rotate_request_validation_valid_immediate_deactivation() {
    let request = RotateApiKeyRequest {
        deactivate_old_immediately: Some(true),
        grace_period_hours: None,
        expires_at: None,
    };
    assert!(request.validate().is_none());
}

#[test]
fn test_rotate_request_validation_valid_with_grace_period() {
    let request = RotateApiKeyRequest {
        deactivate_old_immediately: Some(false),
        grace_period_hours: Some(48),
        expires_at: None,
    };
    assert!(request.validate().is_none());
}

#[test]
fn test_rotate_request_validation_valid_max_grace_period() {
    let request = RotateApiKeyRequest {
        deactivate_old_immediately: Some(false),
        grace_period_hours: Some(720), // 30 days max
        expires_at: None,
    };
    assert!(request.validate().is_none());
}

#[test]
fn test_rotate_request_validation_invalid_zero_grace_period() {
    let request = RotateApiKeyRequest {
        deactivate_old_immediately: Some(false),
        grace_period_hours: Some(0),
        expires_at: None,
    };
    let error = request.validate();
    assert!(error.is_some());
    assert!(error.unwrap().contains("at least 1"));
}

#[test]
fn test_rotate_request_validation_invalid_too_long_grace_period() {
    let request = RotateApiKeyRequest {
        deactivate_old_immediately: Some(false),
        grace_period_hours: Some(721), // More than 30 days
        expires_at: None,
    };
    let error = request.validate();
    assert!(error.is_some());
    assert!(error.unwrap().contains("720"));
}

#[test]
fn test_rotate_request_with_expiration() {
    let request = RotateApiKeyRequest {
        deactivate_old_immediately: Some(false),
        grace_period_hours: Some(24),
        expires_at: Some(Utc::now() + Duration::days(365)),
    };
    assert!(request.validate().is_none());
}

/// Test response serialization for RotateApiKeyResponse.
#[test]
fn test_rotate_response_serialization() {
    let response = RotateApiKeyResponse {
        new_key_id: Uuid::new_v4(),
        new_key_prefix: "xavyo_sk_live_".to_string(),
        new_api_key: "xavyo_sk_live_abcdef1234567890".to_string(),
        old_key_id: Uuid::new_v4(),
        old_key_status: "active until 2024-01-02T12:00:00Z (grace period: 24 hours)".to_string(),
        rotated_at: Utc::now(),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("new_key_id"));
    assert!(json.contains("new_api_key"));
    assert!(json.contains("xavyo_sk_live_"));
    assert!(json.contains("old_key_status"));
    assert!(json.contains("grace period"));
}

/// Test response serialization for ApiKeyInfo.
#[test]
fn test_api_key_info_serialization() {
    let info = ApiKeyInfo {
        id: Uuid::new_v4(),
        name: "Production API Key".to_string(),
        key_prefix: "xavyo_sk_live_".to_string(),
        scopes: vec!["read".to_string(), "write".to_string()],
        is_active: true,
        last_used_at: Some(Utc::now()),
        expires_at: None,
        created_at: Utc::now() - Duration::days(30),
    };

    let json = serde_json::to_string(&info).unwrap();
    assert!(json.contains("Production API Key"));
    assert!(json.contains("xavyo_sk_live_"));
    assert!(json.contains("\"is_active\":true"));
    assert!(json.contains("last_used_at"));
    // expires_at should be omitted when None
    assert!(!json.contains("expires_at"));
}

#[test]
fn test_api_key_info_serialization_with_expiration() {
    let info = ApiKeyInfo {
        id: Uuid::new_v4(),
        name: "Expiring Key".to_string(),
        key_prefix: "xavyo_sk_live_".to_string(),
        scopes: vec![],
        is_active: true,
        last_used_at: None,
        expires_at: Some(Utc::now() + Duration::days(90)),
        created_at: Utc::now(),
    };

    let json = serde_json::to_string(&info).unwrap();
    assert!(json.contains("expires_at"));
    // last_used_at should be omitted when None
    assert!(!json.contains("last_used_at"));
}

/// Test response serialization for ApiKeyListResponse.
#[test]
fn test_api_key_list_response_serialization() {
    let response = ApiKeyListResponse {
        api_keys: vec![
            ApiKeyInfo {
                id: Uuid::new_v4(),
                name: "Key 1".to_string(),
                key_prefix: "xavyo_sk_live_".to_string(),
                scopes: vec![],
                is_active: true,
                last_used_at: None,
                expires_at: None,
                created_at: Utc::now(),
            },
            ApiKeyInfo {
                id: Uuid::new_v4(),
                name: "Key 2".to_string(),
                key_prefix: "xavyo_sk_live_".to_string(),
                scopes: vec!["admin".to_string()],
                is_active: false,
                last_used_at: Some(Utc::now()),
                expires_at: None,
                created_at: Utc::now() - Duration::days(7),
            },
        ],
        total: 2,
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"total\":2"));
    assert!(json.contains("Key 1"));
    assert!(json.contains("Key 2"));
}

#[test]
fn test_api_key_list_response_empty() {
    let response = ApiKeyListResponse {
        api_keys: vec![],
        total: 0,
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"total\":0"));
    assert!(json.contains("\"api_keys\":[]"));
}
