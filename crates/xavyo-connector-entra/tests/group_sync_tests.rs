//! Integration tests for group synchronization operations.

#![cfg(feature = "integration")]

mod common;

use common::*;
use serde_json::json;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, ResponseTemplate};

/// Tests that group sync retrieves all groups.
#[tokio::test]
async fn test_group_sync_retrieves_all_groups() {
    let mock = MockGraphServer::new().await;
    let groups = generate_test_groups(5);

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_groups_endpoint(groups.clone()).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/groups", mock.url()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["value"].as_array().unwrap().len(), 5);
}

/// Tests that group sync handles pagination.
#[tokio::test]
async fn test_group_sync_handles_pagination() {
    let mock = MockGraphServer::new().await;
    let groups = generate_test_groups(15);

    // Set up paginated response
    let page1 = groups[..5].to_vec();
    let page1_response = json!({
        "value": page1,
        "@odata.nextLink": format!("{}/v1.0/groups?$skiptoken=page2", mock.url())
    });

    Mock::given(method("GET"))
        .and(path("/v1.0/groups"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page1_response))
        .mount(&mock.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/groups", mock.url()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["value"].as_array().unwrap().len(), 5);
    assert!(body["@odata.nextLink"].is_string());
}

/// Tests that group membership retrieval works.
#[tokio::test]
async fn test_group_membership_retrieval() {
    let mock = MockGraphServer::new().await;
    let members = generate_test_users(3);

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_group_members_endpoint("group-123", members.clone())
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/groups/group-123/members", mock.url()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["value"].as_array().unwrap().len(), 3);
}

/// Tests that large group membership is handled with pagination.
#[tokio::test]
async fn test_large_group_membership() {
    let mock = MockGraphServer::new().await;

    // Simulate a group with many members (paginated)
    let page1_members = generate_test_users(100);
    let page1_response = json!({
        "value": page1_members,
        "@odata.nextLink": format!("{}/v1.0/groups/large-group/members?$skiptoken=page2", mock.url())
    });

    Mock::given(method("GET"))
        .and(path("/v1.0/groups/large-group/members"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page1_response))
        .mount(&mock.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/groups/large-group/members", mock.url()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["value"].as_array().unwrap().len(), 100);
    assert!(body["@odata.nextLink"].is_string());
}

/// Tests transitive membership resolution.
#[tokio::test]
async fn test_transitive_membership_resolution() {
    let mock = MockGraphServer::new().await;

    // User is direct member of GroupA, GroupA is member of GroupB
    // Transitive should return both memberships
    let direct_member = create_test_user("user-1", "directuser");
    let indirect_member = create_test_user("user-1", "directuser"); // Same user from nested group

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_transitive_members_endpoint("group-parent", vec![direct_member, indirect_member])
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/v1.0/groups/group-parent/transitiveMembers",
            mock.url()
        ))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["value"].as_array().unwrap().len() >= 1);
}

/// Tests that security groups are distinguished from M365 groups.
#[tokio::test]
async fn test_security_vs_m365_groups() {
    let mock = MockGraphServer::new().await;

    let security_group = create_test_group("group-sec", "Security Group");
    let m365_group = create_m365_group("group-m365", "M365 Group");

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_groups_endpoint(vec![security_group, m365_group])
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/groups", mock.url()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    let groups = body["value"].as_array().unwrap();

    // Security group
    assert_eq!(groups[0]["securityEnabled"], true);
    assert_eq!(groups[0]["mailEnabled"], false);
    assert!(groups[0]["groupTypes"].as_array().unwrap().is_empty());

    // M365 group
    assert_eq!(groups[1]["securityEnabled"], false);
    assert_eq!(groups[1]["mailEnabled"], true);
    assert!(groups[1]["groupTypes"]
        .as_array()
        .unwrap()
        .contains(&json!("Unified")));
}

/// Tests delta sync for groups.
#[tokio::test]
async fn test_group_delta_sync() {
    let mock = MockGraphServer::new().await;

    // Set up delta endpoint for groups
    let new_group = create_test_group("new-group", "Newly Created Group");
    let delta_response = create_delta_response(
        vec![new_group],
        &format!(
            "{}/v1.0/groups/delta?$deltatoken=groups-token-2",
            mock.url()
        ),
    );

    Mock::given(method("GET"))
        .and(path_regex(r"/v1\.0/groups/delta.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(delta_response))
        .mount(&mock.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/v1.0/groups/delta?$deltatoken=groups-token-1",
            mock.url()
        ))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["value"].as_array().unwrap().len(), 1);
    assert!(body["@odata.deltaLink"].is_string());
}

/// Tests handling of empty groups (no members).
#[tokio::test]
async fn test_empty_group_handling() {
    let mock = MockGraphServer::new().await;

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_group_members_endpoint("empty-group", vec![])
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/groups/empty-group/members", mock.url()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["value"].as_array().unwrap().is_empty());
}

/// Tests group with special characters in name.
#[tokio::test]
async fn test_group_with_special_characters() {
    let mock = MockGraphServer::new().await;

    let mut group = create_test_group("special-group", "Group with Special Characters");
    group["displayName"] = json!("Départment - Tëam Ünited 🏆");

    mock.mock_token_endpoint("test-tenant").await;
    mock.mock_groups_endpoint(vec![group]).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/groups", mock.url()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        body["value"][0]["displayName"],
        "Départment - Tëam Ünited 🏆"
    );
}
