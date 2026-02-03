//! Comprehensive pagination tests for large dataset handling.
//!
//! These tests verify pagination behavior with large datasets including:
//! - Large group memberships (1000+ members)
//! - Edge cases (empty pages, single items)
//! - Pagination with various page sizes

#![cfg(feature = "integration")]

mod common;

use common::*;
use serde_json::json;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

/// Custom responder for paginated responses.
struct PaginatedResponder {
    pages: Vec<serde_json::Value>,
    current_page: Arc<AtomicU32>,
}

impl Respond for PaginatedResponder {
    fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
        let page_idx = self.current_page.fetch_add(1, Ordering::SeqCst) as usize;
        if page_idx < self.pages.len() {
            ResponseTemplate::new(200).set_body_json(self.pages[page_idx].clone())
        } else {
            // Return empty on extra requests
            ResponseTemplate::new(200).set_body_json(json!({"value": []}))
        }
    }
}

/// Tests pagination with 1000+ members in a group.
#[tokio::test]
async fn test_large_group_membership_1000_plus() {
    let server = MockServer::start().await;

    // Generate 1000+ members across multiple pages
    let total_members = 1050;
    let page_size = 100;
    let num_pages = (total_members + page_size - 1) / page_size; // 11 pages

    // Build all pages
    let mut pages = Vec::new();
    for page_num in 0..num_pages {
        let start = page_num * page_size;
        let end = std::cmp::min(start + page_size, total_members);
        let members: Vec<_> = (start..end)
            .map(|i| create_test_user(&format!("member-{}", i), &format!("member{}", i)))
            .collect();

        let next_link = if page_num < num_pages - 1 {
            Some(format!(
                "{}/v1.0/groups/large-group/members?skiptoken=page{}",
                server.uri(),
                page_num + 1
            ))
        } else {
            None
        };

        pages.push(create_odata_response(members, next_link.as_deref(), None));
    }

    let responder = PaginatedResponder {
        pages,
        current_page: Arc::new(AtomicU32::new(0)),
    };

    Mock::given(method("GET"))
        .and(path("/v1.0/groups/large-group/members"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let mut all_members = Vec::new();
    let mut url = format!("{}/v1.0/groups/large-group/members", server.uri());

    // Fetch all pages
    loop {
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), 200);

        let body: serde_json::Value = response.json().await.unwrap();
        let members = body["value"].as_array().unwrap();
        all_members.extend(members.clone());

        if let Some(next) = body["@odata.nextLink"].as_str() {
            url = next.to_string();
        } else {
            break;
        }
    }

    assert_eq!(all_members.len(), total_members);
}

/// Tests empty page handling in pagination.
#[tokio::test]
async fn test_pagination_empty_page() {
    let server = MockServer::start().await;

    // Response with empty value array but delta link (common in delta sync)
    let response = json!({
        "value": [],
        "@odata.deltaLink": format!("{}/v1.0/users/delta?deltatoken=empty", server.uri())
    });

    Mock::given(method("GET"))
        .and(path("/v1.0/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/users", server.uri()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["value"].as_array().unwrap().is_empty());
    assert!(body["@odata.deltaLink"].is_string());
}

/// Tests single item response (no pagination needed).
#[tokio::test]
async fn test_pagination_single_item() {
    let server = MockServer::start().await;

    let user = create_test_user("single-user", "single");
    let response = create_odata_response(vec![user], None, Some("deltalink"));

    Mock::given(method("GET"))
        .and(path("/v1.0/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/users", server.uri()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["value"].as_array().unwrap().len(), 1);
    assert!(body["@odata.nextLink"].is_null() || body.get("@odata.nextLink").is_none());
}

/// Tests pagination with exact page boundary (no partial last page).
#[tokio::test]
async fn test_pagination_exact_boundary() {
    let server = MockServer::start().await;

    // 200 users exactly filling 2 pages of 100
    let page1_users: Vec<_> = (0..100)
        .map(|i| create_test_user(&format!("user-{}", i), &format!("user{}", i)))
        .collect();
    let page2_users: Vec<_> = (100..200)
        .map(|i| create_test_user(&format!("user-{}", i), &format!("user{}", i)))
        .collect();

    let pages = vec![
        json!({
            "value": page1_users,
            "@odata.nextLink": format!("{}/v1.0/users?skiptoken=page2", server.uri())
        }),
        json!({
            "value": page2_users,
            "@odata.deltaLink": format!("{}/v1.0/users/delta?deltatoken=final", server.uri())
        }),
    ];

    let responder = PaginatedResponder {
        pages,
        current_page: Arc::new(AtomicU32::new(0)),
    };

    Mock::given(method("GET"))
        .and(path("/v1.0/users"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let mut all_users = Vec::new();
    let mut url = format!("{}/v1.0/users", server.uri());

    loop {
        let response = client.get(&url).send().await.unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        all_users.extend(body["value"].as_array().unwrap().clone());

        if let Some(next) = body["@odata.nextLink"].as_str() {
            url = next.to_string();
        } else {
            break;
        }
    }

    assert_eq!(all_users.len(), 200);
}

/// Tests pagination with varying page sizes.
#[tokio::test]
async fn test_pagination_varying_page_sizes() {
    let server = MockServer::start().await;

    // Pages with different sizes: 50, 75, 25
    let page1_users: Vec<_> = (0..50)
        .map(|i| create_test_user(&format!("user-{}", i), &format!("user{}", i)))
        .collect();
    let page2_users: Vec<_> = (50..125)
        .map(|i| create_test_user(&format!("user-{}", i), &format!("user{}", i)))
        .collect();
    let page3_users: Vec<_> = (125..150)
        .map(|i| create_test_user(&format!("user-{}", i), &format!("user{}", i)))
        .collect();

    let pages = vec![
        json!({
            "value": page1_users,
            "@odata.nextLink": format!("{}/v1.0/users?skiptoken=page2", server.uri())
        }),
        json!({
            "value": page2_users,
            "@odata.nextLink": format!("{}/v1.0/users?skiptoken=page3", server.uri())
        }),
        create_odata_response(page3_users, None, Some("deltalink")),
    ];

    let responder = PaginatedResponder {
        pages,
        current_page: Arc::new(AtomicU32::new(0)),
    };

    Mock::given(method("GET"))
        .and(path("/v1.0/users"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let mut all_users = Vec::new();
    let mut url = format!("{}/v1.0/users", server.uri());

    loop {
        let response = client.get(&url).send().await.unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        all_users.extend(body["value"].as_array().unwrap().clone());

        if let Some(next) = body["@odata.nextLink"].as_str() {
            url = next.to_string();
        } else {
            break;
        }
    }

    assert_eq!(all_users.len(), 150);
}

/// Tests pagination concurrent access (parallel page fetches).
#[tokio::test]
async fn test_pagination_concurrent_fetches() {
    let server = MockServer::start().await;

    // Set up mock for different group memberships
    for group_id in 1..=3 {
        let members: Vec<_> = (0..10)
            .map(|i| {
                create_test_user(
                    &format!("group{}-member-{}", group_id, i),
                    &format!("g{}m{}", group_id, i),
                )
            })
            .collect();
        let response = create_odata_response(members, None, None);

        Mock::given(method("GET"))
            .and(path(format!("/v1.0/groups/group-{}/members", group_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;
    }

    let client = reqwest::Client::new();

    // Fetch all groups' members concurrently
    let (r1, r2, r3) = tokio::join!(
        client
            .get(format!("{}/v1.0/groups/group-1/members", server.uri()))
            .send(),
        client
            .get(format!("{}/v1.0/groups/group-2/members", server.uri()))
            .send(),
        client
            .get(format!("{}/v1.0/groups/group-3/members", server.uri()))
            .send()
    );

    let body1: serde_json::Value = r1.unwrap().json().await.unwrap();
    let body2: serde_json::Value = r2.unwrap().json().await.unwrap();
    let body3: serde_json::Value = r3.unwrap().json().await.unwrap();

    assert_eq!(body1["value"].as_array().unwrap().len(), 10);
    assert_eq!(body2["value"].as_array().unwrap().len(), 10);
    assert_eq!(body3["value"].as_array().unwrap().len(), 10);
}

/// Tests $top parameter for controlling page size.
#[tokio::test]
async fn test_pagination_top_parameter() {
    let server = MockServer::start().await;

    // Set up response for $top=5 request
    let users = generate_test_users(5);
    let response = json!({
        "value": users,
        "@odata.nextLink": format!("{}/v1.0/users?top=5&skiptoken=more", server.uri())
    });

    Mock::given(method("GET"))
        .and(path("/v1.0/users"))
        .and(query_param("top", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/users?top=5", server.uri()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["value"].as_array().unwrap().len(), 5);
    assert!(body["@odata.nextLink"].is_string());
}

/// Tests pagination with nested group members (transitive).
#[tokio::test]
async fn test_pagination_transitive_members_large() {
    let server = MockServer::start().await;

    // Parent group with 200 transitive members across 2 pages
    let page1_members: Vec<_> = (0..100)
        .map(|i| create_test_user(&format!("trans-member-{}", i), &format!("trans{}", i)))
        .collect();
    let page2_members: Vec<_> = (100..200)
        .map(|i| create_test_user(&format!("trans-member-{}", i), &format!("trans{}", i)))
        .collect();

    let pages = vec![
        json!({
            "value": page1_members,
            "@odata.nextLink": format!("{}/v1.0/groups/parent-group/transitiveMembers?skiptoken=page2", server.uri())
        }),
        create_odata_response(page2_members, None, None),
    ];

    let responder = PaginatedResponder {
        pages,
        current_page: Arc::new(AtomicU32::new(0)),
    };

    Mock::given(method("GET"))
        .and(path("/v1.0/groups/parent-group/transitiveMembers"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let mut all_members = Vec::new();
    let mut url = format!(
        "{}/v1.0/groups/parent-group/transitiveMembers",
        server.uri()
    );

    loop {
        let response = client.get(&url).send().await.unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        all_members.extend(body["value"].as_array().unwrap().clone());

        if let Some(next) = body["@odata.nextLink"].as_str() {
            url = next.to_string();
        } else {
            break;
        }
    }

    assert_eq!(all_members.len(), 200);
}

/// Tests pagination with delta sync tokens.
#[tokio::test]
async fn test_pagination_delta_token_progression() {
    let server = MockServer::start().await;

    // Delta sync returns pages with changes, then final delta link
    let page1_changes: Vec<_> = (0..50)
        .map(|i| {
            let mut user = create_test_user(&format!("changed-{}", i), &format!("changed{}", i));
            user["@odata.type"] = json!("#microsoft.graph.user");
            user
        })
        .collect();

    let page2_changes: Vec<_> = (50..75)
        .map(|i| {
            let mut user = create_test_user(&format!("changed-{}", i), &format!("changed{}", i));
            user["@odata.type"] = json!("#microsoft.graph.user");
            user
        })
        .collect();

    let pages = vec![
        json!({
            "value": page1_changes,
            "@odata.nextLink": format!("{}/v1.0/users/delta?skiptoken=page2", server.uri())
        }),
        json!({
            "value": page2_changes,
            "@odata.deltaLink": format!("{}/v1.0/users/delta?deltatoken=newtoken123", server.uri())
        }),
    ];

    let responder = PaginatedResponder {
        pages,
        current_page: Arc::new(AtomicU32::new(0)),
    };

    Mock::given(method("GET"))
        .and(path("/v1.0/users/delta"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let mut all_changes = Vec::new();
    let mut url = format!("{}/v1.0/users/delta?deltatoken=oldtoken", server.uri());
    let mut final_delta_link = None;

    loop {
        let response = client.get(&url).send().await.unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        all_changes.extend(body["value"].as_array().unwrap().clone());

        if let Some(next) = body["@odata.nextLink"].as_str() {
            url = next.to_string();
        } else if let Some(delta) = body["@odata.deltaLink"].as_str() {
            final_delta_link = Some(delta.to_string());
            break;
        } else {
            break;
        }
    }

    assert_eq!(all_changes.len(), 75);
    assert!(final_delta_link.unwrap().contains("newtoken123"));
}
