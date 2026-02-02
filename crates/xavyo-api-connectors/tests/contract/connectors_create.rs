//! Unit tests for connector creation request/response models.

use serde_json::json;
use xavyo_api_connectors::{ConnectorResponse, CreateConnectorRequest, UpdateConnectorRequest};
use xavyo_db::models::{ConnectorStatus, ConnectorType};

/// Test: CreateConnectorRequest deserializes correctly for LDAP
#[test]
fn test_create_ldap_connector_request_deserialization() {
    let json = json!({
        "name": "Test LDAP Connector",
        "connector_type": "ldap",
        "description": "Test connector for unit tests",
        "config": {
            "host": "ldap.example.com",
            "port": 389,
            "base_dn": "dc=example,dc=com",
            "bind_dn": "cn=admin,dc=example,dc=com",
            "use_ssl": false
        },
        "credentials": {
            "password": "secret123"
        }
    });

    let request: CreateConnectorRequest = serde_json::from_value(json).unwrap();

    assert_eq!(request.name, "Test LDAP Connector");
    assert_eq!(request.connector_type, ConnectorType::Ldap);
    assert_eq!(
        request.description,
        Some("Test connector for unit tests".to_string())
    );
    assert_eq!(request.config["host"], "ldap.example.com");
    assert_eq!(request.credentials["password"], "secret123");
}

/// Test: CreateConnectorRequest deserializes correctly for Database
#[test]
fn test_create_database_connector_request_deserialization() {
    let json = json!({
        "name": "Test Database Connector",
        "connector_type": "database",
        "config": {
            "driver": "postgresql",
            "host": "db.example.com",
            "port": 5432,
            "database": "identities",
            "username": "app_user"
        },
        "credentials": {
            "password": "db_secret"
        }
    });

    let request: CreateConnectorRequest = serde_json::from_value(json).unwrap();

    assert_eq!(request.name, "Test Database Connector");
    assert_eq!(request.connector_type, ConnectorType::Database);
    assert_eq!(request.config["driver"], "postgresql");
}

/// Test: CreateConnectorRequest deserializes correctly for REST
#[test]
fn test_create_rest_connector_request_deserialization() {
    let json = json!({
        "name": "Test REST Connector",
        "connector_type": "rest",
        "config": {
            "base_url": "https://api.example.com/v1",
            "auth_type": "api_key",
            "auth_header": "X-API-Key"
        },
        "credentials": {
            "api_key": "sk-test-12345"
        }
    });

    let request: CreateConnectorRequest = serde_json::from_value(json).unwrap();

    assert_eq!(request.name, "Test REST Connector");
    assert_eq!(request.connector_type, ConnectorType::Rest);
    assert_eq!(request.config["base_url"], "https://api.example.com/v1");
}

/// Test: CreateConnectorRequest fails without name
#[test]
fn test_create_connector_request_missing_name() {
    let json = json!({
        "connector_type": "ldap",
        "config": {},
        "credentials": {}
    });

    let result: Result<CreateConnectorRequest, _> = serde_json::from_value(json);
    assert!(result.is_err());
}

/// Test: CreateConnectorRequest fails with invalid connector type
#[test]
fn test_create_connector_request_invalid_type() {
    let json = json!({
        "name": "Invalid Connector",
        "connector_type": "invalid_type",
        "config": {},
        "credentials": {}
    });

    let result: Result<CreateConnectorRequest, _> = serde_json::from_value(json);
    assert!(result.is_err());
}

/// Test: UpdateConnectorRequest deserializes with partial fields
#[test]
fn test_update_connector_request_partial() {
    let json = json!({
        "name": "Updated Name"
    });

    let request: UpdateConnectorRequest = serde_json::from_value(json).unwrap();

    assert_eq!(request.name, Some("Updated Name".to_string()));
    assert!(request.description.is_none());
    assert!(request.config.is_none());
    assert!(request.credentials.is_none());
}

/// Test: UpdateConnectorRequest deserializes all fields
#[test]
fn test_update_connector_request_full() {
    let json = json!({
        "name": "Updated Name",
        "description": "New description",
        "config": {
            "host": "new-host.example.com"
        },
        "credentials": {
            "password": "new_password"
        }
    });

    let request: UpdateConnectorRequest = serde_json::from_value(json).unwrap();

    assert_eq!(request.name, Some("Updated Name".to_string()));
    assert_eq!(request.description, Some("New description".to_string()));
    assert!(request.config.is_some());
    assert!(request.credentials.is_some());
}

/// Test: ConnectorResponse serializes correctly
#[test]
fn test_connector_response_serialization() {
    use chrono::Utc;
    use uuid::Uuid;

    let response = ConnectorResponse {
        id: Uuid::new_v4(),
        name: "My Connector".to_string(),
        connector_type: ConnectorType::Ldap,
        description: Some("A test connector".to_string()),
        config: json!({"host": "ldap.example.com"}),
        status: ConnectorStatus::Active,
        last_connection_test: Some(Utc::now()),
        last_error: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let json = serde_json::to_value(&response).unwrap();

    assert!(json["id"].is_string());
    assert_eq!(json["name"], "My Connector");
    assert_eq!(json["connector_type"], "ldap");
    assert_eq!(json["status"], "active");
    assert!(json["config"].is_object());
    // Credentials should NOT be in the response
    assert!(json.get("credentials").is_none());
}

/// Test: ConnectorResponse without optional fields
#[test]
fn test_connector_response_minimal() {
    use chrono::Utc;
    use uuid::Uuid;

    let response = ConnectorResponse {
        id: Uuid::new_v4(),
        name: "Minimal Connector".to_string(),
        connector_type: ConnectorType::Database,
        description: None,
        config: json!({}),
        status: ConnectorStatus::Inactive,
        last_connection_test: None,
        last_error: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let json = serde_json::to_value(&response).unwrap();

    assert_eq!(json["name"], "Minimal Connector");
    assert_eq!(json["status"], "inactive");
    // Optional fields should be skipped
    assert!(json.get("description").is_none());
    assert!(json.get("last_connection_test").is_none());
    assert!(json.get("last_error").is_none());
}
