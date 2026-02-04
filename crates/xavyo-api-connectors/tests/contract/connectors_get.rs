//! Unit tests for connector list/get request/response models.

use serde_json::json;
use xavyo_api_connectors::{ConnectorListResponse, ConnectorSummaryResponse, ListConnectorsQuery};
use xavyo_db::models::{ConnectorStatus, ConnectorType};

/// Test: `ListConnectorsQuery` deserializes with defaults
#[test]
fn test_list_connectors_query_defaults() {
    let json = json!({});
    let query: ListConnectorsQuery = serde_json::from_value(json).unwrap();

    assert!(query.connector_type.is_none());
    assert!(query.status.is_none());
    assert!(query.name_contains.is_none());
    assert_eq!(query.limit, 20); // default
    assert_eq!(query.offset, 0); // default
}

/// Test: `ListConnectorsQuery` deserializes with all filters
#[test]
fn test_list_connectors_query_with_filters() {
    let json = json!({
        "connector_type": "ldap",
        "status": "active",
        "name_contains": "prod",
        "limit": 50,
        "offset": 10
    });

    let query: ListConnectorsQuery = serde_json::from_value(json).unwrap();

    assert_eq!(query.connector_type, Some(ConnectorType::Ldap));
    assert_eq!(query.status, Some(ConnectorStatus::Active));
    assert_eq!(query.name_contains, Some("prod".to_string()));
    assert_eq!(query.limit, 50);
    assert_eq!(query.offset, 10);
}

/// Test: `ConnectorSummaryResponse` serializes correctly
#[test]
fn test_connector_summary_response() {
    use chrono::Utc;
    use uuid::Uuid;

    let summary = ConnectorSummaryResponse {
        id: Uuid::new_v4(),
        name: "Production LDAP".to_string(),
        connector_type: ConnectorType::Ldap,
        status: ConnectorStatus::Active,
        last_connection_test: Some(Utc::now()),
        created_at: Utc::now(),
    };

    let json = serde_json::to_value(&summary).unwrap();

    assert!(json["id"].is_string());
    assert_eq!(json["name"], "Production LDAP");
    assert_eq!(json["connector_type"], "ldap");
    assert_eq!(json["status"], "active");
    // Summary should not have config or description
    assert!(json.get("config").is_none());
    assert!(json.get("description").is_none());
}

/// Test: `ConnectorListResponse` serializes correctly
#[test]
fn test_connector_list_response() {
    use chrono::Utc;
    use uuid::Uuid;

    let response = ConnectorListResponse {
        items: vec![
            ConnectorSummaryResponse {
                id: Uuid::new_v4(),
                name: "Connector 1".to_string(),
                connector_type: ConnectorType::Ldap,
                status: ConnectorStatus::Active,
                last_connection_test: None,
                created_at: Utc::now(),
            },
            ConnectorSummaryResponse {
                id: Uuid::new_v4(),
                name: "Connector 2".to_string(),
                connector_type: ConnectorType::Database,
                status: ConnectorStatus::Inactive,
                last_connection_test: None,
                created_at: Utc::now(),
            },
        ],
        total: 10,
        limit: 20,
        offset: 0,
    };

    let json = serde_json::to_value(&response).unwrap();

    assert_eq!(json["items"].as_array().unwrap().len(), 2);
    assert_eq!(json["total"], 10);
    assert_eq!(json["limit"], 20);
    assert_eq!(json["offset"], 0);
    assert_eq!(json["items"][0]["name"], "Connector 1");
    assert_eq!(json["items"][1]["name"], "Connector 2");
}

/// Test: Empty `ConnectorListResponse`
#[test]
fn test_connector_list_response_empty() {
    let response = ConnectorListResponse {
        items: vec![],
        total: 0,
        limit: 20,
        offset: 0,
    };

    let json = serde_json::to_value(&response).unwrap();

    assert_eq!(json["items"].as_array().unwrap().len(), 0);
    assert_eq!(json["total"], 0);
}

/// Test: `ListConnectorsQuery` with database filter
#[test]
fn test_list_connectors_query_database_filter() {
    let json = json!({
        "connector_type": "database"
    });

    let query: ListConnectorsQuery = serde_json::from_value(json).unwrap();
    assert_eq!(query.connector_type, Some(ConnectorType::Database));
}

/// Test: `ListConnectorsQuery` with REST filter
#[test]
fn test_list_connectors_query_rest_filter() {
    let json = json!({
        "connector_type": "rest"
    });

    let query: ListConnectorsQuery = serde_json::from_value(json).unwrap();
    assert_eq!(query.connector_type, Some(ConnectorType::Rest));
}

/// Test: `ListConnectorsQuery` with error status filter
#[test]
fn test_list_connectors_query_error_status() {
    let json = json!({
        "status": "error"
    });

    let query: ListConnectorsQuery = serde_json::from_value(json).unwrap();
    assert_eq!(query.status, Some(ConnectorStatus::Error));
}
