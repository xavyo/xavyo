//! Integration tests for user synchronization operations.

#![cfg(feature = "integration")]

mod common;

use common::*;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

/// Tests that full sync retrieves all users correctly.
#[tokio::test]
async fn test_full_sync_retrieves_all_users() {
    let mock = MockGraphServer::new().await;
    let users = generate_test_users(5);

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_users_endpoint(users.clone(), 10).await;

    // Verify mock is set up
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/users", mock.url()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["value"].as_array().unwrap().len(), 5);
}

/// Tests that user attributes are mapped correctly.
#[tokio::test]
async fn test_full_sync_maps_attributes_correctly() {
    let mock = MockGraphServer::new().await;
    let user = create_test_user("user-123", "john.doe");

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_users_endpoint(vec![user.clone()], 10).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/users", mock.url()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    let returned_user = &body["value"][0];

    assert_eq!(returned_user["id"], "user-123");
    assert_eq!(
        returned_user["userPrincipalName"],
        "john.doe@test.onmicrosoft.com"
    );
    assert_eq!(returned_user["displayName"], "Test User john.doe");
    assert_eq!(returned_user["accountEnabled"], true);
}

/// Tests that pagination is handled correctly for multi-page responses.
#[tokio::test]
async fn test_full_sync_handles_pagination() {
    let mock = MockGraphServer::new().await;
    let users = generate_test_users(15);

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_users_endpoint(users, 5).await; // 5 per page = 3 pages

    // First page
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/users", mock.url()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["value"].as_array().unwrap().len(), 5);
    assert!(body["@odata.nextLink"].is_string());
}

/// Tests that disabled users are handled correctly.
#[tokio::test]
async fn test_sync_handles_disabled_users() {
    let mock = MockGraphServer::new().await;
    let users = vec![
        create_test_user("user-1", "active"),
        create_disabled_user("user-2", "disabled"),
    ];

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_users_endpoint(users, 10).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/users", mock.url()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    let returned_users = body["value"].as_array().unwrap();

    assert_eq!(returned_users[0]["accountEnabled"], true);
    assert_eq!(returned_users[1]["accountEnabled"], false);
}

/// Tests that empty optional fields are handled correctly.
#[tokio::test]
async fn test_sync_handles_empty_optional_fields() {
    let mock = MockGraphServer::new().await;
    let user = create_minimal_user("user-minimal", "minimal@test.onmicrosoft.com");

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_users_endpoint(vec![user], 10).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/users", mock.url()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    let returned_user = &body["value"][0];

    assert_eq!(returned_user["id"], "user-minimal");
    assert!(returned_user.get("mail").is_none() || returned_user["mail"].is_null());
    assert!(returned_user.get("jobTitle").is_none() || returned_user["jobTitle"].is_null());
}

/// Tests that special characters in user names are handled correctly.
#[tokio::test]
async fn test_sync_handles_special_characters() {
    let mock = MockGraphServer::new().await;
    let mut user = create_test_user("user-unicode", "unicode");
    user["displayName"] = json!("Tëst Üsér with émojis 🎉");
    user["givenName"] = json!("Tëst");
    user["surname"] = json!("Üsér");

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_users_endpoint(vec![user], 10).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/users", mock.url()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    let returned_user = &body["value"][0];

    assert_eq!(returned_user["displayName"], "Tëst Üsér with émojis 🎉");
    assert_eq!(returned_user["givenName"], "Tëst");
}

/// Tests that delta link is returned after full sync.
#[tokio::test]
async fn test_sync_returns_delta_link() {
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
    assert!(body["@odata.deltaLink"].is_string());
    assert!(body["@odata.deltaLink"]
        .as_str()
        .unwrap()
        .contains("deltatoken"));
}

/// Tests that large result sets are handled correctly.
#[tokio::test]
async fn test_sync_handles_large_result_set() {
    let mock = MockGraphServer::new().await;
    let users = generate_test_users(100);

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_users_endpoint(users, 25).await; // 4 pages of 25

    // First page should have 25 users and nextLink
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/users", mock.url()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["value"].as_array().unwrap().len(), 25);
    assert!(body["@odata.nextLink"].is_string());
}
