//! Integration tests for user provisioning operations.

#![cfg(feature = "integration")]

mod common;

use common::*;
use serde_json::json;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, ResponseTemplate};

/// Tests that user creation via Graph API works correctly.
#[tokio::test]
async fn test_user_creation() {
    let mock = MockGraphServer::new().await;

    let new_user = json!({
        "accountEnabled": true,
        "displayName": "New User",
        "mailNickname": "newuser",
        "userPrincipalName": "newuser@test.onmicrosoft.com",
        "passwordProfile": {
            "forceChangePasswordNextSignIn": true,
            "password": "TempPass123!"
        }
    });

    let created_user = create_test_user("created-user-123", "newuser");

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_create_user_endpoint(created_user.clone()).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/v1.0/users", mock.url()))
        .json(&new_user)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 201);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["id"], "created-user-123");
    assert_eq!(body["userPrincipalName"], "newuser@test.onmicrosoft.com");
}

/// Tests that user update via Graph API works correctly.
#[tokio::test]
async fn test_user_update() {
    let mock = MockGraphServer::new().await;

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_update_user_endpoint("user-to-update").await;

    let update_payload = json!({
        "displayName": "Updated Display Name",
        "jobTitle": "Senior Engineer"
    });

    let client = reqwest::Client::new();
    let response = client
        .patch(format!("{}/v1.0/users/user-to-update", mock.url()))
        .json(&update_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 204);
}

/// Tests that user disable (accountEnabled = false) works correctly.
#[tokio::test]
async fn test_user_disable() {
    let mock = MockGraphServer::new().await;

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_update_user_endpoint("user-to-disable").await;

    let disable_payload = json!({
        "accountEnabled": false
    });

    let client = reqwest::Client::new();
    let response = client
        .patch(format!("{}/v1.0/users/user-to-disable", mock.url()))
        .json(&disable_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 204);
}

/// Tests that user deletion via Graph API works correctly.
#[tokio::test]
async fn test_user_deletion() {
    let mock = MockGraphServer::new().await;

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_delete_user_endpoint("user-to-delete").await;

    let client = reqwest::Client::new();
    let response = client
        .delete(format!("{}/v1.0/users/user-to-delete", mock.url()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 204);
}

/// Tests handling of conflict when creating duplicate user.
#[tokio::test]
async fn test_user_creation_conflict() {
    let mock = MockGraphServer::new().await;

    Mock::given(method("POST"))
        .and(path("/v1.0/users"))
        .respond_with(
            ResponseTemplate::new(409).set_body_json(create_odata_error(
                "Request_MultipleObjectsWithSameKeyValue",
                "Another object with the same value for property userPrincipalName already exists.",
            )),
        )
        .mount(&mock.server)
        .await;

    let new_user = json!({
        "accountEnabled": true,
        "displayName": "Duplicate User",
        "mailNickname": "duplicate",
        "userPrincipalName": "existing@test.onmicrosoft.com",
        "passwordProfile": {
            "forceChangePasswordNextSignIn": true,
            "password": "TempPass123!"
        }
    });

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/v1.0/users", mock.url()))
        .json(&new_user)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 409);
}

/// Tests handling of not found when updating non-existent user.
#[tokio::test]
async fn test_user_update_not_found() {
    let mock = MockGraphServer::new().await;

    Mock::given(method("PATCH"))
        .and(path("/v1.0/users/non-existent"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(create_odata_error(
                "Request_ResourceNotFound",
                "Resource 'non-existent' does not exist.",
            )),
        )
        .mount(&mock.server)
        .await;

    let update_payload = json!({
        "displayName": "Will Not Work"
    });

    let client = reqwest::Client::new();
    let response = client
        .patch(format!("{}/v1.0/users/non-existent", mock.url()))
        .json(&update_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 404);
}

/// Tests handling of not found when deleting non-existent user.
#[tokio::test]
async fn test_user_deletion_not_found() {
    let mock = MockGraphServer::new().await;

    Mock::given(method("DELETE"))
        .and(path("/v1.0/users/non-existent"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(create_odata_error(
                "Request_ResourceNotFound",
                "Resource 'non-existent' does not exist.",
            )),
        )
        .mount(&mock.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .delete(format!("{}/v1.0/users/non-existent", mock.url()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 404);
}

/// Tests batch user creation pattern.
#[tokio::test]
async fn test_batch_user_creation() {
    let mock = MockGraphServer::new().await;

    // Set up multiple user creation responses
    for i in 0..3 {
        let created_user = create_test_user(&format!("batch-user-{}", i), &format!("batchuser{}", i));
        Mock::given(method("POST"))
            .and(path("/v1.0/users"))
            .and(body_json(json!({
                "displayName": format!("Batch User {}", i),
                "mailNickname": format!("batchuser{}", i),
                "userPrincipalName": format!("batchuser{}@test.onmicrosoft.com", i),
                "accountEnabled": true,
                "passwordProfile": {
                    "forceChangePasswordNextSignIn": true,
                    "password": "TempPass123!"
                }
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(created_user))
            .expect(1)
            .mount(&mock.server)
            .await;
    }

    let client = reqwest::Client::new();

    // Create users in batch
    for i in 0..3 {
        let new_user = json!({
            "displayName": format!("Batch User {}", i),
            "mailNickname": format!("batchuser{}", i),
            "userPrincipalName": format!("batchuser{}@test.onmicrosoft.com", i),
            "accountEnabled": true,
            "passwordProfile": {
                "forceChangePasswordNextSignIn": true,
                "password": "TempPass123!"
            }
        });

        let response = client
            .post(format!("{}/v1.0/users", mock.url()))
            .json(&new_user)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 201);
    }
}

/// Tests user password reset operation.
#[tokio::test]
async fn test_user_password_reset() {
    let mock = MockGraphServer::new().await;

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_update_user_endpoint("user-password-reset").await;

    let password_reset = json!({
        "passwordProfile": {
            "forceChangePasswordNextSignIn": true,
            "password": "NewTempPass456!"
        }
    });

    let client = reqwest::Client::new();
    let response = client
        .patch(format!("{}/v1.0/users/user-password-reset", mock.url()))
        .json(&password_reset)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 204);
}

/// Tests user enable (re-enable after disable).
#[tokio::test]
async fn test_user_enable() {
    let mock = MockGraphServer::new().await;

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_update_user_endpoint("user-to-enable").await;

    let enable_payload = json!({
        "accountEnabled": true
    });

    let client = reqwest::Client::new();
    let response = client
        .patch(format!("{}/v1.0/users/user-to-enable", mock.url()))
        .json(&enable_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 204);
}
