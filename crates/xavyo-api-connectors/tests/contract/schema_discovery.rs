//! Contract tests for schema discovery API endpoints.
//!
//! Tests verify request/response serialization for F046 Schema Discovery feature.

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use xavyo_api_connectors::handlers::schemas::{
    AttributeListResponse, AttributeWithSource, DiffSchemaQuery, DiscoverSchemaRequest,
    DiscoveryStatusResponse, GetSchemaQuery, ListAttributesQuery, ListVersionsQuery,
    ObjectClassListResponse, ObjectClassSummary, RefreshScheduleRequest, RefreshScheduleResponse,
    SchemaDiffResponse, SchemaVersionListResponse,
};
use xavyo_db::models::{ScheduleType, SchemaVersionSummary};

// =============================================================================
// POST /connectors/{id}/schema/discover (T012)
// =============================================================================

/// Test: DiscoverSchemaRequest deserializes with defaults
#[test]
fn test_discover_schema_request_defaults() {
    let json = json!({});
    let request: DiscoverSchemaRequest = serde_json::from_value(json).unwrap();

    assert!(!request.force_refresh);
    assert!(!request.include_operational);
}

/// Test: DiscoverSchemaRequest deserializes with all options
#[test]
fn test_discover_schema_request_with_options() {
    let json = json!({
        "force_refresh": true,
        "include_operational": true
    });

    let request: DiscoverSchemaRequest = serde_json::from_value(json).unwrap();

    assert!(request.force_refresh);
    assert!(request.include_operational);
}

/// Test: DiscoveryStatusResponse serializes correctly for in_progress state
#[test]
fn test_discovery_status_response_in_progress() {
    let now = Utc::now();
    let connector_id = Uuid::new_v4();

    let response = DiscoveryStatusResponse {
        connector_id,
        state: "in_progress".to_string(),
        started_at: Some(now),
        completed_at: None,
        progress_percent: Some(45),
        current_object_class: Some("inetOrgPerson".to_string()),
        error: None,
        version: None,
    };

    let json = serde_json::to_value(&response).unwrap();

    assert_eq!(json["state"], "in_progress");
    assert!(json["started_at"].is_string());
    assert!(json.get("completed_at").is_none());
    assert_eq!(json["progress_percent"], 45);
    assert_eq!(json["current_object_class"], "inetOrgPerson");
    assert!(json.get("error").is_none());
    assert!(json.get("version").is_none());
}

/// Test: DiscoveryStatusResponse serializes correctly for completed state
#[test]
fn test_discovery_status_response_completed() {
    let now = Utc::now();
    let connector_id = Uuid::new_v4();

    let response = DiscoveryStatusResponse {
        connector_id,
        state: "completed".to_string(),
        started_at: Some(now),
        completed_at: Some(now),
        progress_percent: Some(100),
        current_object_class: None,
        error: None,
        version: Some(3),
    };

    let json = serde_json::to_value(&response).unwrap();

    assert_eq!(json["state"], "completed");
    assert!(json["completed_at"].is_string());
    assert_eq!(json["progress_percent"], 100);
    assert_eq!(json["version"], 3);
}

/// Test: DiscoveryStatusResponse serializes correctly for failed state
#[test]
fn test_discovery_status_response_failed() {
    let now = Utc::now();
    let connector_id = Uuid::new_v4();

    let response = DiscoveryStatusResponse {
        connector_id,
        state: "failed".to_string(),
        started_at: Some(now),
        completed_at: Some(now),
        progress_percent: Some(25),
        current_object_class: None,
        error: Some("Connection refused".to_string()),
        version: None,
    };

    let json = serde_json::to_value(&response).unwrap();

    assert_eq!(json["state"], "failed");
    assert_eq!(json["error"], "Connection refused");
}

/// Test: DiscoveryStatusResponse serializes correctly for idle state
#[test]
fn test_discovery_status_response_idle() {
    let connector_id = Uuid::new_v4();

    let response = DiscoveryStatusResponse {
        connector_id,
        state: "idle".to_string(),
        started_at: None,
        completed_at: None,
        progress_percent: None,
        current_object_class: None,
        error: None,
        version: None,
    };

    let json = serde_json::to_value(&response).unwrap();

    assert_eq!(json["state"], "idle");
    // None fields should not be serialized
    assert!(json.get("started_at").is_none());
    assert!(json.get("progress_percent").is_none());
}

// =============================================================================
// GET /connectors/{id}/schema/status (T013)
// =============================================================================

// Status endpoint uses DiscoveryStatusResponse - tests covered above

// =============================================================================
// GET /connectors/{id}/schema (T026)
// =============================================================================

/// Test: GetSchemaQuery deserializes with defaults
#[test]
fn test_get_schema_query_defaults() {
    let json = json!({});
    let query: GetSchemaQuery = serde_json::from_value(json).unwrap();

    assert!(query.version.is_none());
}

/// Test: GetSchemaQuery deserializes with specific version
#[test]
fn test_get_schema_query_with_version() {
    let json = json!({
        "version": 5
    });

    let query: GetSchemaQuery = serde_json::from_value(json).unwrap();

    assert_eq!(query.version, Some(5));
}

// =============================================================================
// GET /connectors/{id}/schema/versions (T027)
// =============================================================================

/// Test: ListVersionsQuery deserializes with defaults
#[test]
fn test_list_versions_query_defaults() {
    let json = json!({});
    let query: ListVersionsQuery = serde_json::from_value(json).unwrap();

    assert_eq!(query.limit, 50); // default
    assert_eq!(query.offset, 0); // default
}

/// Test: ListVersionsQuery deserializes with pagination
#[test]
fn test_list_versions_query_with_pagination() {
    let json = json!({
        "limit": 25,
        "offset": 50
    });

    let query: ListVersionsQuery = serde_json::from_value(json).unwrap();

    assert_eq!(query.limit, 25);
    assert_eq!(query.offset, 50);
}

/// Test: SchemaVersionListResponse serializes correctly
#[test]
fn test_schema_version_list_response() {
    let response = SchemaVersionListResponse {
        versions: vec![
            SchemaVersionSummary {
                version: 3,
                discovered_at: Utc::now(),
                discovery_duration_ms: 1500,
                object_class_count: 10,
                attribute_count: 85,
                triggered_by: "manual".to_string(),
                triggered_by_user: Some(Uuid::new_v4()),
            },
            SchemaVersionSummary {
                version: 2,
                discovered_at: Utc::now(),
                discovery_duration_ms: 1200,
                object_class_count: 9,
                attribute_count: 80,
                triggered_by: "scheduled".to_string(),
                triggered_by_user: None,
            },
        ],
        total: 3,
        limit: 50,
        offset: 0,
    };

    let json = serde_json::to_value(&response).unwrap();

    assert_eq!(json["versions"].as_array().unwrap().len(), 2);
    assert_eq!(json["total"], 3);
    assert_eq!(json["limit"], 50);
    assert_eq!(json["versions"][0]["version"], 3);
    assert_eq!(json["versions"][0]["triggered_by"], "manual");
    assert_eq!(json["versions"][1]["triggered_by"], "scheduled");
}

// =============================================================================
// GET /connectors/{id}/schema/diff (T046)
// =============================================================================

/// Test: DiffSchemaQuery deserializes correctly
#[test]
fn test_diff_schema_query() {
    let json = json!({
        "from_version": 1,
        "to_version": 3
    });

    let query: DiffSchemaQuery = serde_json::from_value(json).unwrap();

    assert_eq!(query.from_version, 1);
    assert_eq!(query.to_version, 3);
}

/// Test: SchemaDiffResponse serializes correctly
#[test]
fn test_schema_diff_response() {
    use std::collections::HashMap;
    use xavyo_connector::schema::{AttributeChanges, DiffSummary, ObjectClassChanges};

    let response = SchemaDiffResponse {
        from_version: 1,
        to_version: 2,
        from_discovered_at: Some(Utc::now()),
        to_discovered_at: Some(Utc::now()),
        summary: DiffSummary {
            object_classes_added: 1,
            object_classes_removed: 0,
            attributes_added: 5,
            attributes_removed: 1,
            attributes_modified: 2,
            has_breaking_changes: false,
        },
        object_class_changes: ObjectClassChanges {
            added: vec!["posixAccount".to_string()],
            removed: vec![],
        },
        attribute_changes: HashMap::new(),
    };

    let json = serde_json::to_value(&response).unwrap();

    assert_eq!(json["from_version"], 1);
    assert_eq!(json["to_version"], 2);
    assert_eq!(json["summary"]["object_classes_added"], 1);
    assert_eq!(json["summary"]["attributes_added"], 5);
    assert_eq!(json["summary"]["has_breaking_changes"], false);
    assert_eq!(json["object_class_changes"]["added"][0], "posixAccount");
}

// =============================================================================
// GET /connectors/{id}/schema/object-classes (T036)
// =============================================================================

/// Test: ObjectClassListResponse serializes correctly
#[test]
fn test_object_class_list_response() {
    let response = ObjectClassListResponse {
        object_classes: vec![
            ObjectClassSummary {
                name: "user".to_string(),
                native_name: "inetOrgPerson".to_string(),
                display_name: Some("User".to_string()),
                object_class_type: Some("structural".to_string()),
                attribute_count: 25,
                parent_classes: vec!["organizationalPerson".to_string(), "person".to_string()],
            },
            ObjectClassSummary {
                name: "group".to_string(),
                native_name: "groupOfNames".to_string(),
                display_name: None,
                object_class_type: Some("structural".to_string()),
                attribute_count: 5,
                parent_classes: vec!["top".to_string()],
            },
        ],
        total: 2,
    };

    let json = serde_json::to_value(&response).unwrap();

    assert_eq!(json["total"], 2);
    assert_eq!(json["object_classes"].as_array().unwrap().len(), 2);
    assert_eq!(json["object_classes"][0]["name"], "user");
    assert_eq!(
        json["object_classes"][0]["parent_classes"][0],
        "organizationalPerson"
    );
}

// =============================================================================
// GET /connectors/{id}/schema/object-classes/{name}/attributes (T038)
// =============================================================================

/// Test: ListAttributesQuery deserializes with defaults
#[test]
fn test_list_attributes_query_defaults() {
    let json = json!({});
    let query: ListAttributesQuery = serde_json::from_value(json).unwrap();

    assert!(query.include_inherited); // default true
}

/// Test: ListAttributesQuery with include_inherited false
#[test]
fn test_list_attributes_query_no_inherited() {
    let json = json!({
        "include_inherited": false
    });

    let query: ListAttributesQuery = serde_json::from_value(json).unwrap();

    assert!(!query.include_inherited);
}

/// Test: AttributeListResponse serializes correctly
#[test]
fn test_attribute_list_response() {
    let response = AttributeListResponse {
        attributes: vec![
            AttributeWithSource {
                name: "uid".to_string(),
                native_name: "uid".to_string(),
                data_type: "string".to_string(),
                multi_valued: false,
                required: true,
                readable: true,
                writable: true,
                source: "direct".to_string(),
                source_class: None,
            },
            AttributeWithSource {
                name: "cn".to_string(),
                native_name: "cn".to_string(),
                data_type: "string".to_string(),
                multi_valued: false,
                required: true,
                readable: true,
                writable: true,
                source: "inherited".to_string(),
                source_class: Some("person".to_string()),
            },
        ],
        total: 2,
    };

    let json = serde_json::to_value(&response).unwrap();

    assert_eq!(json["total"], 2);
    assert_eq!(json["attributes"][0]["source"], "direct");
    assert!(json["attributes"][0].get("source_class").is_none());
    assert_eq!(json["attributes"][1]["source"], "inherited");
    assert_eq!(json["attributes"][1]["source_class"], "person");
}

// =============================================================================
// Schema Schedule Endpoints (T060-T062)
// =============================================================================

/// Test: RefreshScheduleRequest deserializes interval schedule
#[test]
fn test_refresh_schedule_request_interval() {
    let json = json!({
        "enabled": true,
        "schedule_type": "interval",
        "interval_hours": 24,
        "notify_on_changes": true,
        "notify_email": "admin@example.com"
    });

    let request: RefreshScheduleRequest = serde_json::from_value(json).unwrap();

    assert!(request.enabled);
    assert_eq!(request.schedule_type, ScheduleType::Interval);
    assert_eq!(request.interval_hours, Some(24));
    assert!(request.cron_expression.is_none());
    assert!(request.notify_on_changes);
    assert_eq!(request.notify_email, Some("admin@example.com".to_string()));
}

/// Test: RefreshScheduleRequest deserializes cron schedule
#[test]
fn test_refresh_schedule_request_cron() {
    let json = json!({
        "schedule_type": "cron",
        "cron_expression": "0 2 * * 0"
    });

    let request: RefreshScheduleRequest = serde_json::from_value(json).unwrap();

    assert!(request.enabled); // default true
    assert_eq!(request.schedule_type, ScheduleType::Cron);
    assert!(request.interval_hours.is_none());
    assert_eq!(request.cron_expression, Some("0 2 * * 0".to_string()));
    assert!(!request.notify_on_changes); // default false
}

/// Test: RefreshScheduleResponse serializes correctly
#[test]
fn test_refresh_schedule_response() {
    let now = Utc::now();

    let response = RefreshScheduleResponse {
        id: Uuid::new_v4(),
        connector_id: Uuid::new_v4(),
        enabled: true,
        schedule_type: "interval".to_string(),
        interval_hours: Some(24),
        cron_expression: None,
        last_run_at: Some(now),
        next_run_at: Some(now),
        last_error: None,
        notify_on_changes: true,
        notify_email: Some("admin@example.com".to_string()),
    };

    let json = serde_json::to_value(&response).unwrap();

    assert!(json["id"].is_string());
    assert!(json["connector_id"].is_string());
    assert_eq!(json["enabled"], true);
    assert_eq!(json["schedule_type"], "interval");
    assert_eq!(json["interval_hours"], 24);
    assert!(json.get("cron_expression").is_none());
    assert!(json["last_run_at"].is_string());
    assert!(json.get("last_error").is_none());
    assert_eq!(json["notify_on_changes"], true);
    assert_eq!(json["notify_email"], "admin@example.com");
}

/// Test: RefreshScheduleResponse with cron and error
#[test]
fn test_refresh_schedule_response_with_error() {
    let response = RefreshScheduleResponse {
        id: Uuid::new_v4(),
        connector_id: Uuid::new_v4(),
        enabled: true,
        schedule_type: "cron".to_string(),
        interval_hours: None,
        cron_expression: Some("0 2 * * 0".to_string()),
        last_run_at: None,
        next_run_at: None,
        last_error: Some("Previous run failed: timeout".to_string()),
        notify_on_changes: false,
        notify_email: None,
    };

    let json = serde_json::to_value(&response).unwrap();

    assert_eq!(json["schedule_type"], "cron");
    assert_eq!(json["cron_expression"], "0 2 * * 0");
    assert!(json.get("interval_hours").is_none());
    assert_eq!(json["last_error"], "Previous run failed: timeout");
}
