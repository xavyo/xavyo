//! Common test utilities for xavyo-connector-entra integration tests.

#![cfg(feature = "integration")]

use serde_json::{json, Value};
use std::sync::Arc;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Test data factory for creating Entra users.
pub fn create_test_user(id: &str, email_prefix: &str) -> Value {
    json!({
        "id": id,
        "userPrincipalName": format!("{}@test.onmicrosoft.com", email_prefix),
        "displayName": format!("Test User {}", email_prefix),
        "givenName": "Test",
        "surname": "User",
        "mail": format!("{}@example.com", email_prefix),
        "accountEnabled": true,
        "jobTitle": "Test Engineer",
        "department": "Testing"
    })
}

/// Test data factory for creating disabled Entra users.
pub fn create_disabled_user(id: &str, email_prefix: &str) -> Value {
    let mut user = create_test_user(id, email_prefix);
    user["accountEnabled"] = json!(false);
    user
}

/// Test data factory for creating Entra users with minimal fields.
pub fn create_minimal_user(id: &str, upn: &str) -> Value {
    json!({
        "id": id,
        "userPrincipalName": upn,
        "displayName": "Minimal User",
        "accountEnabled": true
    })
}

/// Test data factory for creating Entra groups.
pub fn create_test_group(id: &str, name: &str) -> Value {
    json!({
        "id": id,
        "displayName": name,
        "description": format!("Test group: {}", name),
        "securityEnabled": true,
        "mailEnabled": false,
        "groupTypes": []
    })
}

/// Test data factory for creating M365 groups.
pub fn create_m365_group(id: &str, name: &str) -> Value {
    json!({
        "id": id,
        "displayName": name,
        "description": format!("M365 group: {}", name),
        "securityEnabled": false,
        "mailEnabled": true,
        "groupTypes": ["Unified"]
    })
}

/// Wraps items in an OData response format.
pub fn create_odata_response(items: Vec<Value>, next_link: Option<&str>, delta_link: Option<&str>) -> Value {
    let mut response = json!({ "value": items });
    if let Some(link) = next_link {
        response["@odata.nextLink"] = json!(link);
    }
    if let Some(link) = delta_link {
        response["@odata.deltaLink"] = json!(link);
    }
    response
}

/// Creates a delta response with change tracking.
pub fn create_delta_response(items: Vec<Value>, delta_link: &str) -> Value {
    json!({
        "value": items,
        "@odata.deltaLink": delta_link
    })
}

/// Creates a deleted item marker for delta responses.
pub fn create_deleted_item(id: &str) -> Value {
    json!({
        "id": id,
        "@removed": {
            "reason": "deleted"
        }
    })
}

/// Creates an OData error response.
pub fn create_odata_error(code: &str, message: &str) -> Value {
    json!({
        "error": {
            "code": code,
            "message": message
        }
    })
}

/// Creates a mock OAuth token response.
pub fn create_token_response(access_token: &str, expires_in: u64) -> Value {
    json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in
    })
}

/// Mock server wrapper with common setup helpers.
pub struct MockGraphServer {
    pub server: MockServer,
}

impl MockGraphServer {
    /// Creates a new mock Graph API server.
    pub async fn new() -> Self {
        let server = MockServer::start().await;
        Self { server }
    }

    /// Returns the mock server's base URL.
    pub fn url(&self) -> String {
        self.server.uri()
    }

    /// Sets up OAuth token endpoint.
    pub async fn mock_token_endpoint(&self, tenant_id: &str) {
        Mock::given(method("POST"))
            .and(path(format!("/{}/oauth2/v2.0/token", tenant_id)))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(create_token_response("mock-access-token", 3600)),
            )
            .mount(&self.server)
            .await;
    }

    /// Sets up users list endpoint with pagination.
    pub async fn mock_users_endpoint(&self, users: Vec<Value>, page_size: usize) {
        let pages: Vec<Vec<Value>> = users.chunks(page_size).map(|c| c.to_vec()).collect();
        let total_pages = pages.len();

        for (i, page) in pages.into_iter().enumerate() {
            let next_link = if i < total_pages - 1 {
                Some(format!("{}/v1.0/users?$skiptoken=page{}", self.url(), i + 1))
            } else {
                None
            };

            let delta_link = if i == total_pages - 1 {
                Some(format!(
                    "{}/v1.0/users/delta?$deltatoken=initial",
                    self.url()
                ))
            } else {
                None
            };

            let response = create_odata_response(page, next_link.as_deref(), delta_link.as_deref());

            if i == 0 {
                Mock::given(method("GET"))
                    .and(path("/v1.0/users"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(response))
                    .mount(&self.server)
                    .await;
            } else {
                Mock::given(method("GET"))
                    .and(path_regex(format!(r"/v1\.0/users\?.*skiptoken=page{}", i)))
                    .respond_with(ResponseTemplate::new(200).set_body_json(response))
                    .mount(&self.server)
                    .await;
            }
        }
    }

    /// Sets up delta sync endpoint.
    pub async fn mock_delta_endpoint(&self, changes: Vec<Value>, new_delta_token: &str) {
        let response = create_delta_response(
            changes,
            &format!(
                "{}/v1.0/users/delta?$deltatoken={}",
                self.url(),
                new_delta_token
            ),
        );

        Mock::given(method("GET"))
            .and(path_regex(r"/v1\.0/users/delta.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&self.server)
            .await;
    }

    /// Sets up groups list endpoint.
    pub async fn mock_groups_endpoint(&self, groups: Vec<Value>) {
        let response = create_odata_response(groups, None, None);
        Mock::given(method("GET"))
            .and(path("/v1.0/groups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&self.server)
            .await;
    }

    /// Sets up group members endpoint.
    pub async fn mock_group_members_endpoint(&self, group_id: &str, members: Vec<Value>) {
        let response = create_odata_response(members, None, None);
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/groups/{}/members", group_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&self.server)
            .await;
    }

    /// Sets up transitive members endpoint.
    pub async fn mock_transitive_members_endpoint(&self, group_id: &str, members: Vec<Value>) {
        let response = create_odata_response(members, None, None);
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/groups/{}/transitiveMembers", group_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&self.server)
            .await;
    }

    /// Sets up user creation endpoint.
    pub async fn mock_create_user_endpoint(&self, created_user: Value) {
        Mock::given(method("POST"))
            .and(path("/v1.0/users"))
            .respond_with(ResponseTemplate::new(201).set_body_json(created_user))
            .mount(&self.server)
            .await;
    }

    /// Sets up user update endpoint.
    pub async fn mock_update_user_endpoint(&self, user_id: &str) {
        Mock::given(method("PATCH"))
            .and(path(format!("/v1.0/users/{}", user_id)))
            .respond_with(ResponseTemplate::new(204))
            .mount(&self.server)
            .await;
    }

    /// Sets up user delete endpoint.
    pub async fn mock_delete_user_endpoint(&self, user_id: &str) {
        Mock::given(method("DELETE"))
            .and(path(format!("/v1.0/users/{}", user_id)))
            .respond_with(ResponseTemplate::new(204))
            .mount(&self.server)
            .await;
    }

    /// Sets up rate limit response (429).
    pub async fn mock_rate_limit(&self, path_pattern: &str, retry_after: u64) {
        Mock::given(method("GET"))
            .and(path(path_pattern))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", retry_after.to_string()),
            )
            .expect(1)
            .mount(&self.server)
            .await;
    }

    /// Sets up a successful response after rate limit.
    pub async fn mock_success_after_rate_limit(&self, path_pattern: &str, response: Value) {
        Mock::given(method("GET"))
            .and(path(path_pattern))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&self.server)
            .await;
    }
}

/// Generate a sequence of test users.
pub fn generate_test_users(count: usize) -> Vec<Value> {
    (0..count)
        .map(|i| create_test_user(&format!("user-{}", i), &format!("user{}", i)))
        .collect()
}

/// Generate a sequence of test groups.
pub fn generate_test_groups(count: usize) -> Vec<Value> {
    (0..count)
        .map(|i| create_test_group(&format!("group-{}", i), &format!("Test Group {}", i)))
        .collect()
}
