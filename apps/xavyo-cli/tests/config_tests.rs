//! Integration tests for configuration apply and export
//!
//! Tests cover:
//! - Apply with valid YAML
//! - Apply with invalid YAML syntax
//! - Apply with invalid schema
//! - Export returns valid YAML
//! - Apply→Export round-trip
//! - Dry-run mode
//! - Format options
//! - Partial configuration

mod common;

use common::TestContext;
use serde_json::json;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

// =========================================================================
// T043: Test apply with valid YAML configuration
// =========================================================================

#[tokio::test]
async fn test_config_apply_valid_yaml() {
    let ctx = TestContext::new().await;

    ctx.mock_config_apply().await;

    let valid_yaml = r#"
version: "1.0"
agents:
  - name: test-agent
    description: Test agent
    agent_type: service_account
tools:
  - name: test-tool
    description: Test tool
    tool_type: api
    endpoint: https://example.com/api
"#;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/config/apply", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .header("Content-Type", "application/x-yaml")
        .body(valid_yaml)
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["status"], "applied");
    assert!(body["changes"]["agents_created"].as_i64().unwrap() >= 0);
}

// =========================================================================
// T044: Test apply with invalid YAML syntax
// =========================================================================

#[tokio::test]
async fn test_config_apply_invalid_yaml_syntax() {
    let ctx = TestContext::new().await;

    Mock::given(method("POST"))
        .and(path("/config/apply"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "parse_error",
            "message": "Invalid YAML syntax: unexpected end of document"
        })))
        .mount(&ctx.server)
        .await;

    let invalid_yaml = r#"
version: "1.0"
agents:
  - name: test-agent
    description: Missing closing bracket
    tags: [one, two
"#;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/config/apply", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .header("Content-Type", "application/x-yaml")
        .body(invalid_yaml)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "parse_error");
}

// =========================================================================
// T045: Test apply with invalid schema
// =========================================================================

#[tokio::test]
async fn test_config_apply_invalid_schema() {
    let ctx = TestContext::new().await;

    Mock::given(method("POST"))
        .and(path("/config/apply"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "validation_error",
            "message": "Invalid schema: 'agent_type' must be one of: service_account, user_agent"
        })))
        .mount(&ctx.server)
        .await;

    let invalid_schema_yaml = r#"
version: "1.0"
agents:
  - name: test-agent
    description: Test agent
    agent_type: invalid_type
"#;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/config/apply", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .header("Content-Type", "application/x-yaml")
        .body(invalid_schema_yaml)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "validation_error");
    assert!(body["message"].as_str().unwrap().contains("agent_type"));
}

// =========================================================================
// T046: Test export returns valid YAML
// =========================================================================

#[tokio::test]
async fn test_config_export_valid_yaml() {
    let ctx = TestContext::new().await;

    let expected_yaml = r#"version: "1.0"
agents:
  - name: exported-agent
    description: Exported agent
    agent_type: service_account
tools:
  - name: exported-tool
    description: Exported tool
    tool_type: api
"#;

    ctx.mock_config_export(expected_yaml).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/config/export", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .header("Accept", "application/x-yaml")
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    // Check content type contains yaml
    let content_type = response
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("");
    assert!(
        content_type.contains("yaml") || content_type.contains("text"),
        "Expected yaml content type, got: {}",
        content_type
    );

    let body = response.text().await.expect("Failed to get body");
    assert!(body.contains("version:"));
    assert!(body.contains("agents:"));
    assert!(body.contains("exported-agent"));
}

// =========================================================================
// T047: Test apply→export round-trip preserves data
// =========================================================================

#[tokio::test]
async fn test_config_apply_export_roundtrip() {
    let ctx = TestContext::new().await;

    // Mock apply
    ctx.mock_config_apply().await;

    // Mock export to return same data
    let config_yaml = r#"version: "1.0"
agents:
  - name: roundtrip-agent
    description: Roundtrip test agent
    agent_type: service_account
"#;
    ctx.mock_config_export(config_yaml).await;

    let client = reqwest::Client::new();

    // Step 1: Apply config
    let apply_response = client
        .post(format!("{}/config/apply", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .header("Content-Type", "application/x-yaml")
        .body(config_yaml)
        .send()
        .await
        .expect("Apply request failed");

    assert!(apply_response.status().is_success());

    // Step 2: Export config
    let export_response = client
        .get(format!("{}/config/export", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Export request failed");

    assert!(export_response.status().is_success());

    let exported = export_response.text().await.expect("Failed to get body");
    assert!(exported.contains("roundtrip-agent"));
}

// =========================================================================
// T048: Test apply with dry-run flag
// =========================================================================

#[tokio::test]
async fn test_config_apply_dry_run() {
    let ctx = TestContext::new().await;

    Mock::given(method("POST"))
        .and(path("/config/apply"))
        .and(query_param("dry_run", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "dry_run",
            "would_apply": {
                "agents_to_create": 1,
                "agents_to_update": 0,
                "agents_to_delete": 0,
                "tools_to_create": 2,
                "tools_to_update": 1,
                "tools_to_delete": 0
            }
        })))
        .mount(&ctx.server)
        .await;

    let yaml = r#"
version: "1.0"
agents:
  - name: dry-run-agent
"#;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/config/apply?dry_run=true", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .header("Content-Type", "application/x-yaml")
        .body(yaml)
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["status"], "dry_run");
    assert!(body["would_apply"]["agents_to_create"].as_i64().unwrap() >= 0);
}

// =========================================================================
// T049: Test export with format options
// =========================================================================

#[tokio::test]
async fn test_config_export_json_format() {
    let ctx = TestContext::new().await;

    Mock::given(method("GET"))
        .and(path("/config/export"))
        .and(query_param("format", "json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "version": "1.0",
                    "agents": [
                        {"name": "json-agent", "agent_type": "service_account"}
                    ],
                    "tools": []
                }))
                .insert_header("Content-Type", "application/json"),
        )
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/config/export?format=json", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["version"], "1.0");
    assert!(body["agents"].as_array().is_some());
}

// =========================================================================
// T050: Test apply with partial configuration
// =========================================================================

#[tokio::test]
async fn test_config_apply_partial() {
    let ctx = TestContext::new().await;

    Mock::given(method("POST"))
        .and(path("/config/apply"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "applied",
            "changes": {
                "agents_created": 0,
                "agents_updated": 1,
                "agents_deleted": 0,
                "tools_created": 0,
                "tools_updated": 0,
                "tools_deleted": 0
            }
        })))
        .mount(&ctx.server)
        .await;

    // Only update agents, no tools section
    let partial_yaml = r#"
version: "1.0"
agents:
  - name: partial-update-agent
    description: Updated description only
"#;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/config/apply", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .header("Content-Type", "application/x-yaml")
        .body(partial_yaml)
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["status"], "applied");
}

// =========================================================================
// Additional config tests
// =========================================================================

#[tokio::test]
async fn test_config_apply_unauthorized() {
    let ctx = TestContext::new().await;

    Mock::given(method("POST"))
        .and(path("/config/apply"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "unauthorized",
            "message": "Authentication required"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/config/apply", ctx.base_url()))
        .header("Content-Type", "application/x-yaml")
        .body("version: '1.0'")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn test_config_export_empty() {
    let ctx = TestContext::new().await;

    let empty_yaml = r#"version: "1.0"
agents: []
tools: []
"#;
    ctx.mock_config_export(empty_yaml).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/config/export", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body = response.text().await.expect("Failed to get body");
    assert!(body.contains("agents: []"));
    assert!(body.contains("tools: []"));
}
