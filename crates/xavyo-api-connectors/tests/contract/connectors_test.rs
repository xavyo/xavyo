//! Unit tests for connector test/activate/deactivate models.

use chrono::Utc;
use serde_json::json;
use xavyo_api_connectors::ConnectionTestResponse;

/// Test: ConnectionTestResponse success serializes correctly
#[test]
fn test_connection_test_response_success() {
    let response = ConnectionTestResponse {
        success: true,
        error: None,
        tested_at: Utc::now(),
    };

    let json = serde_json::to_value(&response).unwrap();

    assert_eq!(json["success"], true);
    assert!(json.get("error").is_none()); // Should be skipped when None
    assert!(json["tested_at"].is_string());
}

/// Test: ConnectionTestResponse failure serializes correctly
#[test]
fn test_connection_test_response_failure() {
    let response = ConnectionTestResponse {
        success: false,
        error: Some("Connection refused: ldap.example.com:389".to_string()),
        tested_at: Utc::now(),
    };

    let json = serde_json::to_value(&response).unwrap();

    assert_eq!(json["success"], false);
    assert_eq!(json["error"], "Connection refused: ldap.example.com:389");
    assert!(json["tested_at"].is_string());
}

/// Test: ConnectionTestResponse deserializes correctly
#[test]
fn test_connection_test_response_deserialization() {
    let json = json!({
        "success": true,
        "tested_at": "2024-01-15T10:30:00Z"
    });

    let response: ConnectionTestResponse = serde_json::from_value(json).unwrap();

    assert!(response.success);
    assert!(response.error.is_none());
}

/// Test: ConnectionTestResponse with error deserializes correctly
#[test]
fn test_connection_test_response_with_error_deserialization() {
    let json = json!({
        "success": false,
        "error": "Authentication failed",
        "tested_at": "2024-01-15T10:30:00Z"
    });

    let response: ConnectionTestResponse = serde_json::from_value(json).unwrap();

    assert!(!response.success);
    assert_eq!(response.error, Some("Authentication failed".to_string()));
}

/// Test: Various error messages in ConnectionTestResponse
#[test]
fn test_connection_test_various_errors() {
    let error_messages = vec![
        "Connection timeout after 30 seconds",
        "SSL certificate verification failed",
        "Invalid credentials",
        "Host unreachable",
        "Port 389 is blocked",
        "LDAP bind failed: invalid DN",
        "Database connection refused",
        "REST API returned 401 Unauthorized",
    ];

    for error in error_messages {
        let response = ConnectionTestResponse {
            success: false,
            error: Some(error.to_string()),
            tested_at: Utc::now(),
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["error"], error);
    }
}
