//! Integration tests for tenant settings API.
//!
//! F-SETTINGS-API: Tests for tenant settings update and retrieval.

use xavyo_api_tenants::models::{
    GetSettingsResponse, UpdateSettingsRequest, UpdateSettingsResponse,
};

/// Test UpdateSettingsRequest validation with valid settings.
#[test]
fn test_validate_valid_settings() {
    let request = UpdateSettingsRequest {
        settings: serde_json::json!({
            "limits": {
                "max_mau": 1000,
                "max_api_calls": 500000
            }
        }),
    };
    assert!(request.validate().is_none());
}

/// Test UpdateSettingsRequest validation with null limits.
#[test]
fn test_validate_null_limits() {
    let request = UpdateSettingsRequest {
        settings: serde_json::json!({
            "limits": {
                "max_mau": null
            }
        }),
    };
    assert!(request.validate().is_none());
}

/// Test UpdateSettingsRequest validation with empty object.
#[test]
fn test_validate_empty_object() {
    let request = UpdateSettingsRequest {
        settings: serde_json::json!({}),
    };
    assert!(request.validate().is_none());
}

/// Test UpdateSettingsRequest validation with non-object.
#[test]
fn test_validate_non_object() {
    let request = UpdateSettingsRequest {
        settings: serde_json::json!("string"),
    };
    assert_eq!(
        request.validate(),
        Some("settings must be a JSON object".to_string())
    );
}

/// Test UpdateSettingsRequest validation with non-object limits.
#[test]
fn test_validate_limits_not_object() {
    let request = UpdateSettingsRequest {
        settings: serde_json::json!({
            "limits": "not an object"
        }),
    };
    assert_eq!(
        request.validate(),
        Some("limits must be a JSON object".to_string())
    );
}

/// Test UpdateSettingsRequest validation with negative limit.
#[test]
fn test_validate_negative_limit() {
    let request = UpdateSettingsRequest {
        settings: serde_json::json!({
            "limits": {
                "max_mau": -100
            }
        }),
    };
    assert_eq!(
        request.validate(),
        Some("limits.max_mau must be a positive integer".to_string())
    );
}

/// Test UpdateSettingsRequest validation with string limit.
#[test]
fn test_validate_string_limit() {
    let request = UpdateSettingsRequest {
        settings: serde_json::json!({
            "limits": {
                "max_mau": "not a number"
            }
        }),
    };
    assert_eq!(
        request.validate(),
        Some("limits.max_mau must be a positive integer or null".to_string())
    );
}

/// Test UpdateSettingsRequest validation with features object.
#[test]
fn test_validate_features_object() {
    let request = UpdateSettingsRequest {
        settings: serde_json::json!({
            "features": {
                "mfa_required": true,
                "sso_enabled": false
            }
        }),
    };
    assert!(request.validate().is_none());
}

/// Test UpdateSettingsRequest validation with mixed valid settings.
#[test]
fn test_validate_mixed_valid_settings() {
    let request = UpdateSettingsRequest {
        settings: serde_json::json!({
            "limits": {
                "max_mau": 1000,
                "max_api_calls": 500000,
                "max_agent_invocations": 10000
            },
            "features": {
                "mfa_required": true,
                "sso_enabled": true
            },
            "custom": {
                "some_key": "some_value"
            }
        }),
    };
    assert!(request.validate().is_none());
}

/// Test UpdateSettingsResponse serialization.
#[test]
fn test_update_response_serialization() {
    let response = UpdateSettingsResponse {
        tenant_id: uuid::Uuid::new_v4(),
        settings: serde_json::json!({
            "limits": {"max_mau": 1000}
        }),
        updated_at: chrono::Utc::now(),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("tenant_id"));
    assert!(json.contains("settings"));
    assert!(json.contains("updated_at"));
    assert!(json.contains("max_mau"));
}

/// Test UpdateSettingsResponse deserialization.
#[test]
fn test_update_response_deserialization() {
    let json = r#"{
        "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
        "settings": {"limits": {"max_mau": 1000}},
        "updated_at": "2024-01-15T10:00:00Z"
    }"#;

    let response: UpdateSettingsResponse = serde_json::from_str(json).unwrap();
    assert_eq!(
        response.tenant_id.to_string(),
        "550e8400-e29b-41d4-a716-446655440000"
    );
    assert_eq!(response.settings["limits"]["max_mau"], 1000);
}

/// Test GetSettingsResponse serialization.
#[test]
fn test_get_response_serialization() {
    let response = GetSettingsResponse {
        tenant_id: uuid::Uuid::new_v4(),
        settings: serde_json::json!({
            "limits": {"max_mau": 500},
            "features": {"mfa_required": false}
        }),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("tenant_id"));
    assert!(json.contains("settings"));
    assert!(json.contains("max_mau"));
    assert!(json.contains("mfa_required"));
}

/// Test GetSettingsResponse deserialization.
#[test]
fn test_get_response_deserialization() {
    let json = r#"{
        "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
        "settings": {"limits": {"max_mau": 500, "max_api_calls": 100000}}
    }"#;

    let response: GetSettingsResponse = serde_json::from_str(json).unwrap();
    assert_eq!(
        response.tenant_id.to_string(),
        "550e8400-e29b-41d4-a716-446655440000"
    );
    assert_eq!(response.settings["limits"]["max_mau"], 500);
    assert_eq!(response.settings["limits"]["max_api_calls"], 100000);
}

/// Test UpdateSettingsRequest serialization.
#[test]
fn test_request_serialization() {
    let request = UpdateSettingsRequest {
        settings: serde_json::json!({
            "limits": {"max_mau": 2000}
        }),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("settings"));
    assert!(json.contains("max_mau"));
    assert!(json.contains("2000"));
}

/// Test UpdateSettingsRequest deserialization.
#[test]
fn test_request_deserialization() {
    let json = r#"{"settings": {"limits": {"max_mau": 3000}}}"#;

    let request: UpdateSettingsRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.settings["limits"]["max_mau"], 3000);
}

/// Test validation with zero limit value (valid - zero is a positive integer).
#[test]
fn test_validate_zero_limit() {
    let request = UpdateSettingsRequest {
        settings: serde_json::json!({
            "limits": {
                "max_mau": 0
            }
        }),
    };
    // Zero is technically valid (0 >= 0)
    assert!(request.validate().is_none());
}

/// Test validation with float limit value.
#[test]
fn test_validate_float_limit() {
    let request = UpdateSettingsRequest {
        settings: serde_json::json!({
            "limits": {
                "max_mau": 100.5
            }
        }),
    };
    // Float values are not valid integers
    assert_eq!(
        request.validate(),
        Some("limits.max_mau must be a positive integer or null".to_string())
    );
}

/// Test validation with boolean limit value.
#[test]
fn test_validate_boolean_limit() {
    let request = UpdateSettingsRequest {
        settings: serde_json::json!({
            "limits": {
                "max_mau": true
            }
        }),
    };
    assert_eq!(
        request.validate(),
        Some("limits.max_mau must be a positive integer or null".to_string())
    );
}

/// Test validation with array limit value.
#[test]
fn test_validate_array_limit() {
    let request = UpdateSettingsRequest {
        settings: serde_json::json!({
            "limits": {
                "max_mau": [1, 2, 3]
            }
        }),
    };
    assert_eq!(
        request.validate(),
        Some("limits.max_mau must be a positive integer or null".to_string())
    );
}

/// Test validation with nested object limit value.
#[test]
fn test_validate_nested_object_limit() {
    let request = UpdateSettingsRequest {
        settings: serde_json::json!({
            "limits": {
                "max_mau": {"value": 1000}
            }
        }),
    };
    assert_eq!(
        request.validate(),
        Some("limits.max_mau must be a positive integer or null".to_string())
    );
}
