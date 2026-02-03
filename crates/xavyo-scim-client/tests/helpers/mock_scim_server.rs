//! Mock SCIM server using wiremock for integration testing.
//!
//! Provides a configurable mock server that simulates SCIM 2.0 endpoints
//! with various response scenarios (success, errors, rate limiting).

#![allow(dead_code)]

use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use xavyo_scim_client::auth::{ScimAuth, ScimCredentials};
use xavyo_scim_client::client::ScimClient;

/// A mock SCIM server that tracks created resources and supports various test scenarios.
pub struct MockScimServer {
    server: MockServer,
    /// In-memory storage of users keyed by external resource ID.
    users: Arc<RwLock<HashMap<String, Value>>>,
    /// In-memory storage of groups keyed by external resource ID.
    groups: Arc<RwLock<HashMap<String, Value>>>,
    /// Counter for generating unique resource IDs.
    id_counter: Arc<RwLock<u64>>,
}

impl MockScimServer {
    /// Create a new mock SCIM server.
    pub async fn new() -> Self {
        Self {
            server: MockServer::start().await,
            users: Arc::new(RwLock::new(HashMap::new())),
            groups: Arc::new(RwLock::new(HashMap::new())),
            id_counter: Arc::new(RwLock::new(1000)),
        }
    }

    /// Get the base URI of the mock server.
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// Create a ScimClient configured to talk to this mock server.
    pub fn client(&self) -> ScimClient {
        let auth = ScimAuth::new(
            ScimCredentials::Bearer {
                token: "test-token-123".to_string(),
            },
            reqwest::Client::new(),
        );
        ScimClient::with_http_client(self.uri(), auth, reqwest::Client::new())
    }

    /// Create a ScimClient with a specific bearer token.
    pub fn client_with_token(&self, token: &str) -> ScimClient {
        let auth = ScimAuth::new(
            ScimCredentials::Bearer {
                token: token.to_string(),
            },
            reqwest::Client::new(),
        );
        ScimClient::with_http_client(self.uri(), auth, reqwest::Client::new())
    }

    /// Generate a unique external resource ID.
    async fn next_id(&self) -> String {
        let mut counter = self.id_counter.write().await;
        *counter += 1;
        Uuid::new_v4().to_string()
    }

    // =========================================================================
    // ServiceProviderConfig mocks
    // =========================================================================

    /// Mount a mock for successful ServiceProviderConfig discovery.
    pub async fn mock_service_provider_config(&self) {
        Mock::given(method("GET"))
            .and(path("/ServiceProviderConfig"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                "patch": { "supported": true },
                "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
                "filter": { "supported": true, "maxResults": 200 },
                "changePassword": { "supported": false },
                "sort": { "supported": false },
                "etag": { "supported": false },
                "authenticationSchemes": [{
                    "type": "oauthbearertoken",
                    "name": "OAuth Bearer Token",
                    "description": "Authentication using OAuth Bearer Token"
                }]
            })))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for ServiceProviderConfig with PATCH not supported.
    pub async fn mock_service_provider_config_no_patch(&self) {
        Mock::given(method("GET"))
            .and(path("/ServiceProviderConfig"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                "patch": { "supported": false },
                "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
                "filter": { "supported": true, "maxResults": 200 },
                "changePassword": { "supported": false },
                "sort": { "supported": false },
                "etag": { "supported": false },
                "authenticationSchemes": []
            })))
            .mount(&self.server)
            .await;
    }

    // =========================================================================
    // User CRUD mocks
    // =========================================================================

    /// Mount a mock for successful user creation.
    pub async fn mock_create_user_success(&self) {
        let _users = self.users.clone();
        let _id_counter = self.id_counter.clone();

        Mock::given(method("POST"))
            .and(path("/Users"))
            .and(header("Content-Type", "application/scim+json"))
            .respond_with(move |req: &Request| {
                let body: Value = serde_json::from_slice(&req.body).unwrap_or(json!({}));
                let user_name = body
                    .get("userName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let external_id = body
                    .get("externalId")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let emails = body.get("emails").cloned().unwrap_or_else(|| json!([]));
                let groups = body.get("groups").cloned().unwrap_or_else(|| json!([]));

                let resource_id = Uuid::new_v4().to_string();

                let response = json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "id": resource_id,
                    "externalId": external_id,
                    "userName": user_name,
                    "name": body.get("name"),
                    "displayName": body.get("displayName"),
                    "active": body.get("active").and_then(|v| v.as_bool()).unwrap_or(true),
                    "emails": emails,
                    "groups": groups,
                    "meta": {
                        "resourceType": "User",
                        "created": chrono::Utc::now().to_rfc3339(),
                        "lastModified": chrono::Utc::now().to_rfc3339(),
                        "location": format!("/Users/{}", resource_id)
                    }
                });

                ResponseTemplate::new(201).set_body_json(response)
            })
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for user creation that returns 409 Conflict.
    pub async fn mock_create_user_conflict(&self) {
        Mock::given(method("POST"))
            .and(path("/Users"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "detail": "User already exists",
                "status": "409"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for successful user GET.
    pub async fn mock_get_user_success(&self, user_id: &str, user_data: Value) {
        Mock::given(method("GET"))
            .and(path(format!("/Users/{}", user_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_data))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for user GET that returns 404.
    pub async fn mock_get_user_not_found(&self, user_id: &str) {
        Mock::given(method("GET"))
            .and(path(format!("/Users/{}", user_id)))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "detail": "User not found",
                "status": "404"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for successful user PATCH.
    pub async fn mock_patch_user_success(&self, user_id: &str) {
        let uid = user_id.to_string();
        Mock::given(method("PATCH"))
            .and(path(format!("/Users/{}", user_id)))
            .and(header("Content-Type", "application/scim+json"))
            .respond_with(move |_req: &Request| {
                ResponseTemplate::new(200).set_body_json(json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "id": uid,
                    "userName": "updated@example.com",
                    "active": true,
                    "emails": [],
                    "groups": [],
                    "meta": {
                        "resourceType": "User",
                        "created": chrono::Utc::now().to_rfc3339(),
                        "lastModified": chrono::Utc::now().to_rfc3339(),
                        "location": format!("/Users/{}", uid)
                    }
                }))
            })
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for successful user PUT (replace).
    pub async fn mock_replace_user_success(&self, user_id: &str) {
        let uid = user_id.to_string();
        Mock::given(method("PUT"))
            .and(path(format!("/Users/{}", user_id)))
            .and(header("Content-Type", "application/scim+json"))
            .respond_with(move |req: &Request| {
                let body: Value = serde_json::from_slice(&req.body).unwrap_or(json!({}));
                let mut response = body.clone();
                if let Some(obj) = response.as_object_mut() {
                    obj.insert("id".to_string(), json!(uid));
                    // Ensure emails/groups are arrays not null
                    if obj.get("emails").map_or(true, |v| v.is_null()) {
                        obj.insert("emails".to_string(), json!([]));
                    }
                    if obj.get("groups").map_or(true, |v| v.is_null()) {
                        obj.insert("groups".to_string(), json!([]));
                    }
                    obj.insert(
                        "meta".to_string(),
                        json!({
                            "resourceType": "User",
                            "created": chrono::Utc::now().to_rfc3339(),
                            "lastModified": chrono::Utc::now().to_rfc3339(),
                            "location": format!("/Users/{}", uid)
                        }),
                    );
                }
                ResponseTemplate::new(200).set_body_json(response)
            })
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for successful user DELETE.
    pub async fn mock_delete_user_success(&self, user_id: &str) {
        Mock::given(method("DELETE"))
            .and(path(format!("/Users/{}", user_id)))
            .respond_with(ResponseTemplate::new(204))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for user DELETE that returns 404.
    pub async fn mock_delete_user_not_found(&self, user_id: &str) {
        Mock::given(method("DELETE"))
            .and(path(format!("/Users/{}", user_id)))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "detail": "User not found",
                "status": "404"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for listing users (with optional filter support).
    pub async fn mock_list_users(&self, users: Vec<Value>) {
        let total = users.len() as i64;
        Mock::given(method("GET"))
            .and(path("/Users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": total,
                "startIndex": 1,
                "itemsPerPage": total,
                "Resources": users
            })))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for listing users that returns empty results.
    pub async fn mock_list_users_empty(&self) {
        Mock::given(method("GET"))
            .and(path("/Users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": 0,
                "startIndex": 1,
                "itemsPerPage": 0,
                "Resources": []
            })))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for finding user by externalId filter.
    pub async fn mock_find_user_by_external_id(
        &self,
        _external_id: &str,
        user_data: Option<Value>,
    ) {
        let response = match user_data {
            Some(user) => json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": 1,
                "startIndex": 1,
                "itemsPerPage": 1,
                "Resources": [user]
            }),
            None => json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": 0,
                "startIndex": 1,
                "itemsPerPage": 0,
                "Resources": []
            }),
        };

        Mock::given(method("GET"))
            .and(path("/Users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&self.server)
            .await;
    }

    // =========================================================================
    // Group CRUD mocks
    // =========================================================================

    /// Mount a mock for successful group creation.
    pub async fn mock_create_group_success(&self) {
        Mock::given(method("POST"))
            .and(path("/Groups"))
            .and(header("Content-Type", "application/scim+json"))
            .respond_with(move |req: &Request| {
                let body: Value = serde_json::from_slice(&req.body).unwrap_or(json!({}));
                let display_name = body
                    .get("displayName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown Group");
                let external_id = body
                    .get("externalId")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let members = body.get("members").cloned().unwrap_or_else(|| json!([]));

                let resource_id = Uuid::new_v4().to_string();

                ResponseTemplate::new(201).set_body_json(json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                    "id": resource_id,
                    "externalId": external_id,
                    "displayName": display_name,
                    "members": members,
                    "meta": {
                        "resourceType": "Group",
                        "created": chrono::Utc::now().to_rfc3339(),
                        "lastModified": chrono::Utc::now().to_rfc3339(),
                        "location": format!("/Groups/{}", resource_id)
                    }
                }))
            })
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for group creation that returns 409 Conflict.
    pub async fn mock_create_group_conflict(&self) {
        Mock::given(method("POST"))
            .and(path("/Groups"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "detail": "Group already exists",
                "status": "409"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for successful group DELETE.
    pub async fn mock_delete_group_success(&self, group_id: &str) {
        Mock::given(method("DELETE"))
            .and(path(format!("/Groups/{}", group_id)))
            .respond_with(ResponseTemplate::new(204))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for successful group PATCH (member operations).
    pub async fn mock_patch_group_success(&self, group_id: &str) {
        Mock::given(method("PATCH"))
            .and(path(format!("/Groups/{}", group_id)))
            .and(header("Content-Type", "application/scim+json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "id": group_id,
                "displayName": "Updated Group",
                "meta": {
                    "resourceType": "Group",
                    "lastModified": chrono::Utc::now().to_rfc3339()
                }
            })))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for listing groups.
    pub async fn mock_list_groups(&self, groups: Vec<Value>) {
        let total = groups.len() as i64;
        Mock::given(method("GET"))
            .and(path("/Groups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": total,
                "startIndex": 1,
                "itemsPerPage": total,
                "Resources": groups
            })))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for listing groups that returns empty results.
    pub async fn mock_list_groups_empty(&self) {
        Mock::given(method("GET"))
            .and(path("/Groups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": 0,
                "startIndex": 1,
                "itemsPerPage": 0,
                "Resources": []
            })))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock for finding group by externalId filter.
    pub async fn mock_find_group_by_external_id(
        &self,
        _external_id: &str,
        group_data: Option<Value>,
    ) {
        let response = match group_data {
            Some(group) => json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": 1,
                "startIndex": 1,
                "itemsPerPage": 1,
                "Resources": [group]
            }),
            None => json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": 0,
                "startIndex": 1,
                "itemsPerPage": 0,
                "Resources": []
            }),
        };

        Mock::given(method("GET"))
            .and(path("/Groups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&self.server)
            .await;
    }

    // =========================================================================
    // Error response mocks
    // =========================================================================

    /// Mount a mock that returns 401 Unauthorized for all requests.
    pub async fn mock_unauthorized(&self) {
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "detail": "Unauthorized",
                "status": "401"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock that returns 403 Forbidden for all requests.
    pub async fn mock_forbidden(&self) {
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "detail": "Forbidden",
                "status": "403"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock that returns 429 Too Many Requests with Retry-After.
    pub async fn mock_rate_limited(&self, retry_after_secs: u64) {
        Mock::given(wiremock::matchers::any())
            .respond_with(
                ResponseTemplate::new(429)
                    .append_header("Retry-After", retry_after_secs.to_string())
                    .set_body_json(json!({
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                        "detail": "Rate limit exceeded",
                        "status": "429"
                    })),
            )
            .mount(&self.server)
            .await;
    }

    /// Mount a mock that returns 500 Internal Server Error.
    pub async fn mock_server_error(&self) {
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "detail": "Internal server error",
                "status": "500"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock that returns 502 Bad Gateway.
    pub async fn mock_bad_gateway(&self) {
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(502).set_body_string("Bad Gateway"))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock that returns 503 Service Unavailable.
    pub async fn mock_service_unavailable(&self) {
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(503).set_body_json(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "detail": "Service temporarily unavailable",
                "status": "503"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mount a mock with configurable delay (for timeout testing).
    pub async fn mock_slow_response(&self, delay: std::time::Duration) {
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(200).set_delay(delay))
            .mount(&self.server)
            .await;
    }
}

/// Build a standard SCIM user response JSON.
pub fn scim_user_response(
    id: &str,
    user_name: &str,
    external_id: Option<&str>,
    active: bool,
) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": id,
        "externalId": external_id,
        "userName": user_name,
        "displayName": user_name,
        "active": active,
        "emails": [{
            "value": user_name,
            "type": "work",
            "primary": true
        }],
        "groups": [],
        "meta": {
            "resourceType": "User",
            "created": chrono::Utc::now().to_rfc3339(),
            "lastModified": chrono::Utc::now().to_rfc3339(),
            "location": format!("/Users/{}", id)
        }
    })
}

/// Build a standard SCIM group response JSON.
pub fn scim_group_response(
    id: &str,
    display_name: &str,
    external_id: Option<&str>,
    member_ids: &[&str],
) -> Value {
    let members: Vec<Value> = member_ids
        .iter()
        .map(|mid| {
            json!({
                "value": mid,
                "$ref": format!("/Users/{}", mid)
            })
        })
        .collect();

    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": id,
        "externalId": external_id,
        "displayName": display_name,
        "members": members,
        "meta": {
            "resourceType": "Group",
            "created": chrono::Utc::now().to_rfc3339(),
            "lastModified": chrono::Utc::now().to_rfc3339(),
            "location": format!("/Groups/{}", id)
        }
    })
}
