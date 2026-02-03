//! Integration tests for delta sync token management.

#![cfg(feature = "integration")]

mod common;

use common::*;
use serde_json::json;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, ResponseTemplate};

/// Tests that first sync returns a delta link.
#[tokio::test]
async fn test_first_sync_returns_delta_link() {
    let mock = MockGraphServer::new().await;
    let users = generate_test_users(3);

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_users_endpoint(users, 10).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/users", mock.url()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    let delta_link = body["@odata.deltaLink"].as_str().unwrap();

    assert!(delta_link.contains("deltatoken"));
    assert!(delta_link.contains("delta"));
}

/// Tests that delta sync with no changes returns empty value array.
#[tokio::test]
async fn test_delta_sync_with_no_changes() {
    let mock = MockGraphServer::new().await;

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_delta_endpoint(vec![], "token-2").await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/v1.0/users/delta?$deltatoken=token-1",
            mock.url()
        ))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();

    assert!(body["value"].as_array().unwrap().is_empty());
    assert!(body["@odata.deltaLink"].is_string());
}

/// Tests that delta sync detects created users.
#[tokio::test]
async fn test_delta_sync_detects_created_user() {
    let mock = MockGraphServer::new().await;
    let new_user = create_test_user("new-user-123", "newuser");

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_delta_endpoint(vec![new_user.clone()], "token-2")
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/v1.0/users/delta?$deltatoken=token-1",
            mock.url()
        ))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    let changes = body["value"].as_array().unwrap();

    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["id"], "new-user-123");
    // No @removed means it's a create or update
    assert!(changes[0].get("@removed").is_none());
}

/// Tests that delta sync detects updated users.
#[tokio::test]
async fn test_delta_sync_detects_updated_user() {
    let mock = MockGraphServer::new().await;
    let mut updated_user = create_test_user("existing-user", "existinguser");
    updated_user["displayName"] = json!("Updated Display Name");

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_delta_endpoint(vec![updated_user.clone()], "token-2")
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/v1.0/users/delta?$deltatoken=token-1",
            mock.url()
        ))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    let changes = body["value"].as_array().unwrap();

    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["displayName"], "Updated Display Name");
}

/// Tests that delta sync detects deleted users with @removed marker.
#[tokio::test]
async fn test_delta_sync_detects_deleted_user() {
    let mock = MockGraphServer::new().await;
    let deleted_item = create_deleted_item("deleted-user-123");

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_delta_endpoint(vec![deleted_item], "token-2")
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/v1.0/users/delta?$deltatoken=token-1",
            mock.url()
        ))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    let changes = body["value"].as_array().unwrap();

    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["id"], "deleted-user-123");
    assert!(changes[0]["@removed"].is_object());
    assert_eq!(changes[0]["@removed"]["reason"], "deleted");
}

/// Tests that delta sync handles mixed changes (create, update, delete).
#[tokio::test]
async fn test_delta_sync_handles_mixed_changes() {
    let mock = MockGraphServer::new().await;

    let new_user = create_test_user("new-user", "newuser");
    let mut updated_user = create_test_user("updated-user", "updateduser");
    updated_user["displayName"] = json!("Modified Name");
    let deleted_item = create_deleted_item("deleted-user");

    let changes = vec![new_user, updated_user, deleted_item];

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_delta_endpoint(changes, "token-2").await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/v1.0/users/delta?$deltatoken=token-1",
            mock.url()
        ))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    let changes = body["value"].as_array().unwrap();

    assert_eq!(changes.len(), 3);

    // Verify mixed types
    let has_deleted = changes.iter().any(|c| c.get("@removed").is_some());
    let has_regular = changes.iter().any(|c| c.get("@removed").is_none());

    assert!(has_deleted);
    assert!(has_regular);
}

/// Tests that invalid delta token triggers appropriate error.
#[tokio::test]
async fn test_invalid_delta_token_returns_error() {
    let mock = MockGraphServer::new().await;

    // Set up mock to return 410 Gone for invalid token
    Mock::given(method("GET"))
        .and(path_regex(r"/v1\.0/users/delta.*"))
        .respond_with(ResponseTemplate::new(410).set_body_json(create_odata_error(
            "InvalidDeltaToken",
            "The delta token is expired or invalid",
        )))
        .mount(&mock.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/v1.0/users/delta?$deltatoken=invalid",
            mock.url()
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 410);
}

/// Tests that delta sync returns a new token for subsequent syncs.
#[tokio::test]
async fn test_delta_sync_returns_new_token() {
    let mock = MockGraphServer::new().await;

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_delta_endpoint(vec![], "new-token-123").await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/v1.0/users/delta?$deltatoken=old-token",
            mock.url()
        ))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    let delta_link = body["@odata.deltaLink"].as_str().unwrap();

    assert!(delta_link.contains("new-token-123"));
}

/// Tests that delta sync handles pagination.
#[tokio::test]
async fn test_delta_sync_handles_pagination() {
    let mock = MockGraphServer::new().await;

    // Set up paginated delta response
    let page1_users = generate_test_users(5);
    let page1_response = json!({
        "value": page1_users,
        "@odata.nextLink": format!("{}/v1.0/users/delta?$skiptoken=page2", mock.url())
    });

    Mock::given(method("GET"))
        .and(path_regex(r"/v1\.0/users/delta.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page1_response))
        .mount(&mock.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/v1.0/users/delta?$deltatoken=token-1",
            mock.url()
        ))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();

    assert_eq!(body["value"].as_array().unwrap().len(), 5);
    assert!(body["@odata.nextLink"].is_string());
}

/// Tests delta sync token progression over multiple syncs.
#[tokio::test]
async fn test_delta_token_progression() {
    let mock = MockGraphServer::new().await;
    mock.mock_token_endpoint("test-tenant").await;

    // First sync - returns token-1
    let users = generate_test_users(2);
    mock.mock_users_endpoint(users, 10).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/users", mock.url()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["@odata.deltaLink"].is_string());

    // The delta link should be usable for the next sync
    let delta_link = body["@odata.deltaLink"].as_str().unwrap();
    assert!(delta_link.contains("deltatoken"));
}
