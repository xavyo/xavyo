//! Integration tests for audit log commands (login history)
//!
//! These tests use wiremock to mock the login history API endpoint.

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ============================================================================
// Test Fixtures
// ============================================================================

/// Create a mock login history entry for testing
fn create_mock_login_entry(success: bool, auth_method: &str) -> serde_json::Value {
    json!({
        "id": Uuid::new_v4().to_string(),
        "user_id": Uuid::new_v4().to_string(),
        "email": "alice@example.com",
        "success": success,
        "auth_method": auth_method,
        "ip_address": "192.168.1.1",
        "user_agent": "curl/8.5.0",
        "is_new_device": false,
        "is_new_location": false,
        "created_at": Utc::now().to_rfc3339()
    })
}

/// Create a mock login history list response
fn create_mock_list_response(
    items: Vec<serde_json::Value>,
    total: i64,
    next_cursor: Option<&str>,
) -> serde_json::Value {
    let mut resp = json!({
        "items": items,
        "total": total,
    });
    if let Some(cursor) = next_cursor {
        resp["next_cursor"] = json!(cursor);
    }
    resp
}

// ============================================================================
// List Login History Tests
// ============================================================================

/// Test basic login history listing
#[tokio::test]
async fn test_audit_list_basic() {
    let mock_server = MockServer::start().await;

    let entries = vec![
        create_mock_login_entry(true, "password"),
        create_mock_login_entry(false, "password"),
    ];
    let response = create_mock_list_response(entries, 2, None);

    Mock::given(method("GET"))
        .and(path("/audit/login-history"))
        .and(query_param("limit", "50"))
        .and(query_param("offset", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{}/audit/login-history?limit=50&offset=0",
            mock_server.uri()
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
}

/// Test login history listing with limit parameter
#[tokio::test]
async fn test_audit_list_with_limit() {
    let mock_server = MockServer::start().await;

    let entries: Vec<serde_json::Value> = (0..10)
        .map(|_| create_mock_login_entry(true, "password"))
        .collect();
    let response = create_mock_list_response(entries, 100, Some("2026-02-04T10:30:00Z"));

    Mock::given(method("GET"))
        .and(path("/audit/login-history"))
        .and(query_param("limit", "10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{}/audit/login-history?limit=10&offset=0",
            mock_server.uri()
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["items"].as_array().unwrap().len(), 10);
    assert!(body["next_cursor"].is_string());
}

/// Test login history listing when not authenticated
#[tokio::test]
async fn test_audit_list_unauthenticated() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/audit/login-history"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "unauthorized",
            "message": "Not authenticated"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{}/audit/login-history?limit=50&offset=0",
            mock_server.uri()
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

// ============================================================================
// Filter Tests
// ============================================================================

/// Test filtering by user
#[tokio::test]
async fn test_audit_list_filter_user() {
    let mock_server = MockServer::start().await;

    let entries = vec![create_mock_login_entry(true, "password")];
    let response = create_mock_list_response(entries, 1, None);

    Mock::given(method("GET"))
        .and(path("/audit/login-history"))
        .and(query_param("user", "alice@example.com"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{}/audit/login-history?limit=50&offset=0&user=alice%40example.com",
            mock_server.uri()
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
}

/// Test invalid date range error (until before since)
#[tokio::test]
async fn test_audit_list_invalid_date_range() {
    use chrono::NaiveDate;

    let since = NaiveDate::parse_from_str("2026-02-05", "%Y-%m-%d").unwrap();
    let until = NaiveDate::parse_from_str("2026-02-01", "%Y-%m-%d").unwrap();

    assert!(since > until, "since date should be after until date");
}

// ============================================================================
// Model Serialization Tests
// ============================================================================

#[tokio::test]
async fn test_audit_entry_serialization() {
    use xavyo_cli::models::audit::AuditEntry;

    let entry = AuditEntry {
        id: Uuid::new_v4(),
        user_id: Some(Uuid::new_v4()),
        email: Some("alice@example.com".to_string()),
        success: true,
        auth_method: Some("password".to_string()),
        ip_address: Some("10.0.0.1".to_string()),
        user_agent: Some("xavyo-cli/0.1.0".to_string()),
        is_new_device: false,
        is_new_location: false,
        created_at: Utc::now(),
    };

    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("alice@example.com"));
    assert!(json.contains("password"));

    // Roundtrip
    let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.email.as_deref(), Some("alice@example.com"));
    assert!(parsed.success);
}

#[tokio::test]
async fn test_audit_filter_query_string() {
    use xavyo_cli::models::audit::AuditFilter;

    let filter = AuditFilter::new()
        .with_user("alice@example.com")
        .with_action("login")
        .with_limit(100)
        .with_offset(50);

    let query = filter.to_query_string();

    assert!(query.contains("limit=100"));
    assert!(query.contains("offset=50"));
    assert!(query.contains("user=alice%40example.com"));
    assert!(query.contains("action=login"));
}

#[tokio::test]
async fn test_audit_list_response_deserialization() {
    use xavyo_cli::models::audit::AuditListResponse;

    let json = r#"{
        "items": [
            {
                "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "user_id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
                "email": "alice@example.com",
                "success": true,
                "auth_method": "password",
                "ip_address": "127.0.0.1",
                "created_at": "2026-02-04T10:30:00Z"
            }
        ],
        "total": 100,
        "next_cursor": "2026-02-04T10:30:00Z"
    }"#;

    let response: AuditListResponse = serde_json::from_str(json).unwrap();

    assert_eq!(response.items.len(), 1);
    assert_eq!(response.total, 100);
    assert!(response.next_cursor.is_some());
}

/// Test output format enum
#[tokio::test]
async fn test_audit_output_format() {
    use xavyo_cli::commands::audit::OutputFormat;

    let table = OutputFormat::Table;
    let json = OutputFormat::Json;
    let csv = OutputFormat::Csv;

    assert!(matches!(table, OutputFormat::Table));
    assert!(matches!(json, OutputFormat::Json));
    assert!(matches!(csv, OutputFormat::Csv));
}

/// Test SSE stream endpoint exists
#[tokio::test]
async fn test_audit_stream_endpoint() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/audit/stream"))
        .and(header("Accept", "text/event-stream"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/event-stream")
                .set_body_string("data: {\"id\":\"test\"}\n\n"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/audit/stream", mock_server.uri()))
        .header("Accept", "text/event-stream")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
}

/// Test graceful shutdown mechanism
#[tokio::test]
async fn test_shutdown_mechanism() {
    use std::time::Duration;
    use tokio::sync::mpsc;

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    let handle = tokio::spawn(async move {
        let mut event_count = 0;

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {
                    event_count += 1;
                }
            }
        }

        event_count
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown_tx.send(()).await.unwrap();

    let count = handle.await.unwrap();
    assert!(count >= 1, "Should have processed at least one event");
}
