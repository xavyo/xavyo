//! Integration tests for agent CRUD operations
//!
//! Tests cover:
//! - List agents (with data and empty)
//! - Create agent (valid and invalid)
//! - Get agent by ID (existing and non-existent)
//! - Update agent (valid and non-existent)
//! - Delete agent (existing and non-existent)
//! - Credential rotation

mod common;

use common::{create_agent_fixture, TestContext};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, ResponseTemplate};

// =========================================================================
// T020: Test agents list returns all agents
// =========================================================================

#[tokio::test]
async fn test_agents_list_returns_all_agents() {
    let ctx = TestContext::new().await;

    // Create test agents
    let agents = vec![
        create_agent_fixture("agent-1"),
        create_agent_fixture("agent-2"),
        create_agent_fixture("agent-3"),
    ];

    ctx.mock_agents_list(agents.clone()).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/nhi/agents?limit=100&offset=0", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["total"], 3);
    assert_eq!(body["agents"].as_array().unwrap().len(), 3);
}

// =========================================================================
// T021: Test agents list with empty result
// =========================================================================

#[tokio::test]
async fn test_agents_list_empty() {
    let ctx = TestContext::new().await;

    ctx.mock_agents_list(vec![]).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/nhi/agents?limit=100&offset=0", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["total"], 0);
    assert!(body["agents"].as_array().unwrap().is_empty());
}

// =========================================================================
// T022: Test agents create with valid data
// =========================================================================

#[tokio::test]
async fn test_agents_create_valid() {
    let ctx = TestContext::new().await;

    let new_agent = create_agent_fixture("new-test-agent");
    ctx.mock_agent_create(new_agent.clone()).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/nhi/agents", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .json(&json!({
            "name": "new-test-agent",
            "description": "A new test agent",
            "agent_type": "service_account"
        }))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["name"], "new-test-agent");
    assert!(body["id"].as_str().is_some());
}

// =========================================================================
// T023: Test agents create with invalid data
// =========================================================================

#[tokio::test]
async fn test_agents_create_invalid() {
    let ctx = TestContext::new().await;

    // Mock validation error
    Mock::given(method("POST"))
        .and(path("/nhi/agents"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "validation_error",
            "message": "Agent name is required"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/nhi/agents", ctx.base_url()))
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
// T024: Test agents get by ID
// =========================================================================

#[tokio::test]
async fn test_agents_get_by_id() {
    let ctx = TestContext::new().await;

    let agent = create_agent_fixture("specific-agent");
    let agent_id = agent["id"].as_str().unwrap();

    ctx.mock_agent_get(agent.clone()).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/nhi/agents/{}", ctx.base_url(), agent_id))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["name"], "specific-agent");
    assert_eq!(body["id"], agent_id);
}

// =========================================================================
// T025: Test agents get with non-existent ID
// =========================================================================

#[tokio::test]
async fn test_agents_get_not_found() {
    let ctx = TestContext::new().await;

    let non_existent_id = Uuid::new_v4();

    Mock::given(method("GET"))
        .and(path(format!("/nhi/agents/{}", non_existent_id)))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "not_found",
            "message": format!("Agent not found: {}", non_existent_id)
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/nhi/agents/{}", ctx.base_url(), non_existent_id))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 404);
}

// =========================================================================
// T026: Test agents update with valid data
// =========================================================================

#[tokio::test]
async fn test_agents_update_valid() {
    let ctx = TestContext::new().await;

    let agent_id = Uuid::new_v4();
    let updated_agent = json!({
        "id": agent_id.to_string(),
        "name": "updated-agent",
        "description": "Updated description",
        "agent_type": "service_account",
        "status": "active"
    });

    Mock::given(method("PUT"))
        .and(path(format!("/nhi/agents/{}", agent_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(updated_agent.clone()))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .put(format!("{}/nhi/agents/{}", ctx.base_url(), agent_id))
        .header("Authorization", "Bearer test-token")
        .json(&json!({
            "name": "updated-agent",
            "description": "Updated description"
        }))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["name"], "updated-agent");
    assert_eq!(body["description"], "Updated description");
}

// =========================================================================
// T027: Test agents update with non-existent ID
// =========================================================================

#[tokio::test]
async fn test_agents_update_not_found() {
    let ctx = TestContext::new().await;

    let non_existent_id = Uuid::new_v4();

    Mock::given(method("PUT"))
        .and(path(format!("/nhi/agents/{}", non_existent_id)))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "not_found",
            "message": format!("Agent not found: {}", non_existent_id)
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .put(format!("{}/nhi/agents/{}", ctx.base_url(), non_existent_id))
        .header("Authorization", "Bearer test-token")
        .json(&json!({
            "name": "updated-agent"
        }))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 404);
}

// =========================================================================
// T028: Test agents delete by ID
// =========================================================================

#[tokio::test]
async fn test_agents_delete_success() {
    let ctx = TestContext::new().await;

    let agent_id = Uuid::new_v4().to_string();
    ctx.mock_agent_delete(&agent_id).await;

    let client = reqwest::Client::new();
    let response = client
        .delete(format!("{}/nhi/agents/{}", ctx.base_url(), agent_id))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 204);
}

// =========================================================================
// T029: Test agents delete with non-existent ID
// =========================================================================

#[tokio::test]
async fn test_agents_delete_not_found() {
    let ctx = TestContext::new().await;

    let non_existent_id = Uuid::new_v4();

    Mock::given(method("DELETE"))
        .and(path(format!("/nhi/agents/{}", non_existent_id)))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "not_found",
            "message": format!("Agent not found: {}", non_existent_id)
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .delete(format!("{}/nhi/agents/{}", ctx.base_url(), non_existent_id))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 404);
}

// =========================================================================
// T030: Test agents credentials rotate
// =========================================================================

#[tokio::test]
async fn test_agents_credentials_rotate() {
    let ctx = TestContext::new().await;

    let agent_id = Uuid::new_v4();
    let credential_id = Uuid::new_v4();

    Mock::given(method("POST"))
        .and(path(format!("/nhi/agents/{}/credentials/rotate", agent_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credential_id": credential_id.to_string(),
            "client_id": format!("agent-{}", agent_id),
            "client_secret": "new-secret-xyz123",
            "created_at": "2026-02-04T12:00:00Z",
            "expires_at": "2027-02-04T12:00:00Z"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "{}/nhi/agents/{}/credentials/rotate",
            ctx.base_url(),
            agent_id
        ))
        .header("Authorization", "Bearer test-token")
        .json(&json!({
            "revoke_existing": true,
            "expires_in_days": 365
        }))
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert!(body["credential_id"].as_str().is_some());
    assert!(body["client_secret"].as_str().is_some());
}

// =========================================================================
// Additional agent tests
// =========================================================================

#[tokio::test]
async fn test_agents_create_conflict() {
    let ctx = TestContext::new().await;

    Mock::given(method("POST"))
        .and(path("/nhi/agents"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error": "conflict",
            "message": "Agent with name 'existing-agent' already exists"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/nhi/agents", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .json(&json!({
            "name": "existing-agent",
            "description": "Duplicate agent"
        }))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 409);
}

#[tokio::test]
async fn test_agents_list_pagination() {
    let ctx = TestContext::new().await;

    // Create many agents for pagination test
    let agents: Vec<serde_json::Value> = (0..25)
        .map(|i| create_agent_fixture(&format!("agent-{}", i)))
        .collect();

    Mock::given(method("GET"))
        .and(path_regex(r"/nhi/agents.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "agents": &agents[0..10],
            "total": 25,
            "limit": 10,
            "offset": 0
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/nhi/agents?limit=10&offset=0", ctx.base_url()))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["total"], 25);
    assert_eq!(body["agents"].as_array().unwrap().len(), 10);
    assert_eq!(body["limit"], 10);
    assert_eq!(body["offset"], 0);
}
