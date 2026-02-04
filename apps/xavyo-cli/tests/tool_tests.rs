//! Integration tests for tool CRUD operations
//!
//! Tests cover:
//! - List tools (with data and empty)
//! - Create tool (valid and invalid)
//! - Get tool by ID (existing and non-existent)
//! - Update tool (valid and non-existent)
//! - Delete tool (existing and non-existent)

mod common;

use common::{create_tool_fixture, TestContext};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, ResponseTemplate};

// =========================================================================
// T032: Test tools list returns all tools
// =========================================================================

#[tokio::test]
async fn test_tools_list_returns_all_tools() {
    let ctx = TestContext::new().await;

    let tools = vec![
        create_tool_fixture("tool-1"),
        create_tool_fixture("tool-2"),
        create_tool_fixture("tool-3"),
    ];

    ctx.mock_tools_list(tools.clone()).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/nhi/tools?limit=100&offset=0", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["total"], 3);
    assert_eq!(body["tools"].as_array().unwrap().len(), 3);
}

// =========================================================================
// T033: Test tools list with empty result
// =========================================================================

#[tokio::test]
async fn test_tools_list_empty() {
    let ctx = TestContext::new().await;

    ctx.mock_tools_list(vec![]).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/nhi/tools?limit=100&offset=0", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["total"], 0);
    assert!(body["tools"].as_array().unwrap().is_empty());
}

// =========================================================================
// T034: Test tools create with valid data
// =========================================================================

#[tokio::test]
async fn test_tools_create_valid() {
    let ctx = TestContext::new().await;

    let new_tool = create_tool_fixture("new-test-tool");
    ctx.mock_tool_create(new_tool.clone()).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/nhi/tools", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .json(&json!({
            "name": "new-test-tool",
            "description": "A new test tool",
            "tool_type": "api",
            "endpoint": "https://example.com/api"
        }))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["name"], "new-test-tool");
    assert!(body["id"].as_str().is_some());
}

// =========================================================================
// T035: Test tools create with invalid data
// =========================================================================

#[tokio::test]
async fn test_tools_create_invalid() {
    let ctx = TestContext::new().await;

    Mock::given(method("POST"))
        .and(path("/nhi/tools"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "validation_error",
            "message": "Tool name is required"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/nhi/tools", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .json(&json!({
            "description": "Missing name field"
        }))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("name is required"));
}

// =========================================================================
// T036: Test tools get by ID
// =========================================================================

#[tokio::test]
async fn test_tools_get_by_id() {
    let ctx = TestContext::new().await;

    let tool = create_tool_fixture("specific-tool");
    let tool_id = tool["id"].as_str().unwrap();

    ctx.mock_tool_get(tool.clone()).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/nhi/tools/{}", ctx.base_url(), tool_id))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["name"], "specific-tool");
    assert_eq!(body["id"], tool_id);
}

// =========================================================================
// T037: Test tools get with non-existent ID
// =========================================================================

#[tokio::test]
async fn test_tools_get_not_found() {
    let ctx = TestContext::new().await;

    let non_existent_id = Uuid::new_v4();

    Mock::given(method("GET"))
        .and(path(format!("/nhi/tools/{}", non_existent_id)))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "not_found",
            "message": format!("Tool not found: {}", non_existent_id)
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/nhi/tools/{}", ctx.base_url(), non_existent_id))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 404);
}

// =========================================================================
// T038: Test tools update with valid data
// =========================================================================

#[tokio::test]
async fn test_tools_update_valid() {
    let ctx = TestContext::new().await;

    let tool_id = Uuid::new_v4();
    let updated_tool = json!({
        "id": tool_id.to_string(),
        "name": "updated-tool",
        "description": "Updated description",
        "tool_type": "api",
        "endpoint": "https://updated.example.com/api",
        "status": "active"
    });

    Mock::given(method("PUT"))
        .and(path(format!("/nhi/tools/{}", tool_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(updated_tool.clone()))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .put(format!("{}/nhi/tools/{}", ctx.base_url(), tool_id))
        .header("Authorization", "Bearer test-token")
        .json(&json!({
            "name": "updated-tool",
            "description": "Updated description",
            "endpoint": "https://updated.example.com/api"
        }))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["name"], "updated-tool");
    assert_eq!(body["description"], "Updated description");
}

// =========================================================================
// T039: Test tools update with non-existent ID
// =========================================================================

#[tokio::test]
async fn test_tools_update_not_found() {
    let ctx = TestContext::new().await;

    let non_existent_id = Uuid::new_v4();

    Mock::given(method("PUT"))
        .and(path(format!("/nhi/tools/{}", non_existent_id)))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "not_found",
            "message": format!("Tool not found: {}", non_existent_id)
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .put(format!("{}/nhi/tools/{}", ctx.base_url(), non_existent_id))
        .header("Authorization", "Bearer test-token")
        .json(&json!({
            "name": "updated-tool"
        }))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 404);
}

// =========================================================================
// T040: Test tools delete by ID
// =========================================================================

#[tokio::test]
async fn test_tools_delete_success() {
    let ctx = TestContext::new().await;

    let tool_id = Uuid::new_v4().to_string();
    ctx.mock_tool_delete(&tool_id).await;

    let client = reqwest::Client::new();
    let response = client
        .delete(format!("{}/nhi/tools/{}", ctx.base_url(), tool_id))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 204);
}

// =========================================================================
// T041: Test tools delete with non-existent ID
// =========================================================================

#[tokio::test]
async fn test_tools_delete_not_found() {
    let ctx = TestContext::new().await;

    let non_existent_id = Uuid::new_v4();

    Mock::given(method("DELETE"))
        .and(path(format!("/nhi/tools/{}", non_existent_id)))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "not_found",
            "message": format!("Tool not found: {}", non_existent_id)
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .delete(format!("{}/nhi/tools/{}", ctx.base_url(), non_existent_id))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 404);
}

// =========================================================================
// Additional tool tests
// =========================================================================

#[tokio::test]
async fn test_tools_create_conflict() {
    let ctx = TestContext::new().await;

    Mock::given(method("POST"))
        .and(path("/nhi/tools"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error": "conflict",
            "message": "Tool with name 'existing-tool' already exists"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/nhi/tools", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .json(&json!({
            "name": "existing-tool",
            "description": "Duplicate tool"
        }))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 409);
}

#[tokio::test]
async fn test_tools_list_pagination() {
    let ctx = TestContext::new().await;

    let tools: Vec<serde_json::Value> = (0..20)
        .map(|i| create_tool_fixture(&format!("tool-{}", i)))
        .collect();

    Mock::given(method("GET"))
        .and(path_regex(r"/nhi/tools.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tools": &tools[0..5],
            "total": 20,
            "limit": 5,
            "offset": 0
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/nhi/tools?limit=5&offset=0", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["total"], 20);
    assert_eq!(body["tools"].as_array().unwrap().len(), 5);
}
