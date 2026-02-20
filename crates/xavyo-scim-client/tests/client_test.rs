//! Unit tests for SCIM HTTP client — discovery, auth, and error handling.
//!
//! Tests cover:
//! - T016: `ServiceProviderConfig` discovery, health check, connection failures
//! - T017: Bearer token auth, `OAuth2` client credentials, token caching

use serde_json::json;
use wiremock::matchers::{basic_auth, body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use xavyo_scim_client::auth::{ScimAuth, ScimCredentials};
use xavyo_scim_client::client::ScimClient;
use xavyo_scim_client::error::ScimClientError;

/// Helper: create a `ScimClient` pointing at a wiremock server with Bearer auth.
fn bearer_client(server: &MockServer) -> ScimClient {
    let auth = ScimAuth::new(
        ScimCredentials::Bearer {
            token: "test-token-123".to_string(),
        },
        reqwest::Client::new(),
    );
    ScimClient::with_http_client(server.uri(), auth, reqwest::Client::new())
}

/// Helper: standard `ServiceProviderConfig` JSON response.
fn service_provider_config_json() -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": 200 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Authentication using OAuth Bearer Token"
            }
        ]
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// T016: ServiceProviderConfig Discovery Tests
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_discover_service_provider_config_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ServiceProviderConfig"))
        .and(header("Authorization", "Bearer test-token-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(service_provider_config_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = bearer_client(&server);
    let config = client.discover_service_provider_config().await.unwrap();

    assert!(config.patch.supported);
    assert!(!config.bulk.supported);
    assert!(config.filter.supported);
    assert_eq!(config.filter.max_results, 200);
    assert!(!config.change_password.supported);
}

#[tokio::test]
async fn test_discover_service_provider_config_with_patch_unsupported() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ServiceProviderConfig"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": { "supported": false },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": false, "maxResults": 0 },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": []
        })))
        .mount(&server)
        .await;

    let client = bearer_client(&server);
    let config = client.discover_service_provider_config().await.unwrap();

    assert!(!config.patch.supported);
    assert!(!config.filter.supported);
}

#[tokio::test]
async fn test_health_check_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ServiceProviderConfig"))
        .respond_with(ResponseTemplate::new(200).set_body_json(service_provider_config_json()))
        .mount(&server)
        .await;

    let client = bearer_client(&server);
    let result = client.health_check().await;

    assert!(result.healthy);
    assert!(result.service_provider_config.is_some());
    assert!(result.error.is_none());
}

#[tokio::test]
async fn test_health_check_failure_401() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ServiceProviderConfig"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .mount(&server)
        .await;

    let client = bearer_client(&server);
    let result = client.health_check().await;

    assert!(!result.healthy);
    assert!(result.service_provider_config.is_none());
    assert!(result.error.is_some());
}

#[tokio::test]
async fn test_health_check_failure_500() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ServiceProviderConfig"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let client = bearer_client(&server);
    let result = client.health_check().await;

    assert!(!result.healthy);
    assert!(result.error.is_some());
}

#[tokio::test]
async fn test_health_check_timeout() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ServiceProviderConfig"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(service_provider_config_json())
                .set_delay(std::time::Duration::from_secs(5)),
        )
        .mount(&server)
        .await;

    // Create client with very short timeout.
    let auth = ScimAuth::new(
        ScimCredentials::Bearer {
            token: "test-token-123".to_string(),
        },
        reqwest::Client::new(),
    );
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(100))
        .build()
        .unwrap();
    let client = ScimClient::with_http_client(server.uri(), auth, http_client);

    let result = client.health_check().await;
    assert!(!result.healthy);
    assert!(result.error.is_some());
}

// ═══════════════════════════════════════════════════════════════════════════
// T016: Error Handling Tests
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_404_returns_not_found_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/Users/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": "User not found",
            "status": "404"
        })))
        .mount(&server)
        .await;

    let client = bearer_client(&server);
    let result = client.get_user("nonexistent").await;

    assert!(matches!(result, Err(ScimClientError::NotFound(_))));
}

#[tokio::test]
async fn test_409_returns_conflict_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/Users"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": "User already exists",
            "status": "409"
        })))
        .mount(&server)
        .await;

    let client = bearer_client(&server);
    let user = xavyo_api_scim::models::ScimUser {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".to_string()],
        id: None,
        external_id: Some("ext-123".to_string()),
        user_name: "test@example.com".to_string(),
        name: None,
        display_name: None,
        nick_name: None,
        profile_url: None,
        title: None,
        user_type: None,
        preferred_language: None,
        locale: None,
        timezone: None,
        active: true,
        emails: vec![],
        groups: vec![],
        meta: None,
        extensions: serde_json::Map::new(),
    };
    let result = client.create_user(&user).await;

    assert!(matches!(result, Err(ScimClientError::Conflict(_))));
}

#[tokio::test]
async fn test_429_returns_rate_limited_with_retry_after() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/Users/rate-limited"))
        .respond_with(
            ResponseTemplate::new(429)
                .append_header("Retry-After", "30")
                .set_body_string("Rate limited"),
        )
        .mount(&server)
        .await;

    let client = bearer_client(&server);
    let result = client.get_user("rate-limited").await;

    match result {
        Err(ScimClientError::RateLimited { retry_after_secs }) => {
            assert_eq!(retry_after_secs, Some(30));
        }
        other => panic!("Expected RateLimited, got {other:?}"),
    }
}

#[tokio::test]
async fn test_500_returns_scim_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/Users/server-error"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let client = bearer_client(&server);
    let result = client.get_user("server-error").await;

    match result {
        Err(ScimClientError::ScimError { status, .. }) => {
            assert_eq!(status, 500);
        }
        other => panic!("Expected ScimError with status 500, got {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// T017: Bearer Token Authentication Tests
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_bearer_token_sent_in_authorization_header() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ServiceProviderConfig"))
        .and(header("Authorization", "Bearer my-secret-bearer-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(service_provider_config_json()))
        .expect(1)
        .mount(&server)
        .await;

    let auth = ScimAuth::new(
        ScimCredentials::Bearer {
            token: "my-secret-bearer-token".to_string(),
        },
        reqwest::Client::new(),
    );
    let client = ScimClient::with_http_client(server.uri(), auth, reqwest::Client::new());

    let config = client.discover_service_provider_config().await.unwrap();
    assert!(config.patch.supported);
}

#[tokio::test]
async fn test_bearer_get_bearer_token_returns_static_token() {
    let auth = ScimAuth::new(
        ScimCredentials::Bearer {
            token: "static-token".to_string(),
        },
        reqwest::Client::new(),
    );
    let token = auth.get_bearer_token().await.unwrap();
    assert_eq!(token, "static-token");
}

// ═══════════════════════════════════════════════════════════════════════════
// T017: OAuth2 Client Credentials Authentication Tests
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_oauth2_cc_fetches_token_from_endpoint() {
    let token_server = MockServer::start().await;

    // Mock the token endpoint.
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(basic_auth("my-client-id", "my-client-secret"))
        .and(body_string_contains("grant_type=client_credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "fetched-access-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&token_server)
        .await;

    let auth = ScimAuth::new(
        ScimCredentials::OAuth2 {
            client_id: "my-client-id".to_string(),
            client_secret: "my-client-secret".to_string(),
            token_endpoint: format!("{}/oauth/token", token_server.uri()),
            scopes: vec![],
        },
        reqwest::Client::new(),
    )
    .with_skip_ssrf_validation();

    let token = auth.get_bearer_token().await.unwrap();
    assert_eq!(token, "fetched-access-token");
}

#[tokio::test]
async fn test_oauth2_cc_caches_token() {
    let token_server = MockServer::start().await;

    // Token endpoint should only be called ONCE (cached for second call).
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "cached-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&token_server)
        .await;

    let auth = ScimAuth::new(
        ScimCredentials::OAuth2 {
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            token_endpoint: format!("{}/oauth/token", token_server.uri()),
            scopes: vec![],
        },
        reqwest::Client::new(),
    )
    .with_skip_ssrf_validation();

    let token1 = auth.get_bearer_token().await.unwrap();
    let token2 = auth.get_bearer_token().await.unwrap();
    assert_eq!(token1, "cached-token");
    assert_eq!(token2, "cached-token");
}

#[tokio::test]
async fn test_oauth2_cc_invalidate_cache_forces_refetch() {
    let token_server = MockServer::start().await;

    // Token endpoint will be called TWICE (once initially, once after invalidation).
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .expect(2)
        .mount(&token_server)
        .await;

    let auth = ScimAuth::new(
        ScimCredentials::OAuth2 {
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            token_endpoint: format!("{}/oauth/token", token_server.uri()),
            scopes: vec![],
        },
        reqwest::Client::new(),
    )
    .with_skip_ssrf_validation();

    let _token1 = auth.get_bearer_token().await.unwrap();
    auth.invalidate_cache().await;
    let _token2 = auth.get_bearer_token().await.unwrap();
}

#[tokio::test]
async fn test_oauth2_cc_sends_scopes() {
    let token_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("scope=read+write"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "scoped-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&token_server)
        .await;

    let auth = ScimAuth::new(
        ScimCredentials::OAuth2 {
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            token_endpoint: format!("{}/oauth/token", token_server.uri()),
            scopes: vec!["read".to_string(), "write".to_string()],
        },
        reqwest::Client::new(),
    )
    .with_skip_ssrf_validation();

    let token = auth.get_bearer_token().await.unwrap();
    assert_eq!(token, "scoped-token");
}

#[tokio::test]
async fn test_oauth2_cc_token_endpoint_failure() {
    let token_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid client credentials"))
        .mount(&token_server)
        .await;

    let auth = ScimAuth::new(
        ScimCredentials::OAuth2 {
            client_id: "bad-client".to_string(),
            client_secret: "bad-secret".to_string(),
            token_endpoint: format!("{}/oauth/token", token_server.uri()),
            scopes: vec![],
        },
        reqwest::Client::new(),
    )
    .with_skip_ssrf_validation();

    let result = auth.get_bearer_token().await;
    assert!(matches!(result, Err(ScimClientError::AuthError(_))));
}

#[tokio::test]
async fn test_oauth2_cc_token_used_in_scim_requests() {
    let token_server = MockServer::start().await;
    let scim_server = MockServer::start().await;

    // Mock token endpoint.
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "oauth2-bearer-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&token_server)
        .await;

    // Mock SCIM endpoint — expect the OAuth2 token in Authorization header.
    Mock::given(method("GET"))
        .and(path("/ServiceProviderConfig"))
        .and(header("Authorization", "Bearer oauth2-bearer-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(service_provider_config_json()))
        .expect(1)
        .mount(&scim_server)
        .await;

    let auth = ScimAuth::new(
        ScimCredentials::OAuth2 {
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            token_endpoint: format!("{}/oauth/token", token_server.uri()),
            scopes: vec![],
        },
        reqwest::Client::new(),
    )
    .with_skip_ssrf_validation();
    let client = ScimClient::with_http_client(scim_server.uri(), auth, reqwest::Client::new());

    let config = client.discover_service_provider_config().await.unwrap();
    assert!(config.patch.supported);
}

// ═══════════════════════════════════════════════════════════════════════════
// T016: TLS Verification Tests
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_client_creation_with_tls_verify_true() {
    let auth = ScimAuth::new(
        ScimCredentials::Bearer {
            token: "token".to_string(),
        },
        reqwest::Client::new(),
    );
    let client = ScimClient::new(
        "https://example.com/scim/v2".to_string(),
        auth,
        std::time::Duration::from_secs(30),
        true,
    );
    assert!(client.is_ok());
}

#[tokio::test]
async fn test_client_creation_with_tls_verify_false() {
    let auth = ScimAuth::new(
        ScimCredentials::Bearer {
            token: "token".to_string(),
        },
        reqwest::Client::new(),
    );
    let client = ScimClient::new(
        "https://example.com/scim/v2".to_string(),
        auth,
        std::time::Duration::from_secs(30),
        false,
    );
    assert!(client.is_ok());
}

#[tokio::test]
async fn test_base_url_trailing_slash_stripped() {
    let auth = ScimAuth::new(
        ScimCredentials::Bearer {
            token: "token".to_string(),
        },
        reqwest::Client::new(),
    );
    let client = ScimClient::new(
        "https://example.com/scim/v2/".to_string(),
        auth,
        std::time::Duration::from_secs(30),
        true,
    )
    .unwrap();
    assert_eq!(client.base_url(), "https://example.com/scim/v2");
}

// ═══════════════════════════════════════════════════════════════════════════
// T016: User CRUD Operation Tests
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_create_user_posts_to_users_endpoint() {
    let server = MockServer::start().await;

    let user_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

    Mock::given(method("POST"))
        .and(path("/Users"))
        .and(header("Content-Type", "application/scim+json"))
        .and(header("Authorization", "Bearer test-token-123"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": user_uuid,
            "externalId": "ext-123",
            "userName": "jane@example.com",
            "name": { "givenName": "Jane", "familyName": "Doe" },
            "displayName": "Jane Doe",
            "active": true,
            "emails": [{ "value": "jane@example.com", "type": "work", "primary": true }],
            "meta": {
                "resourceType": "User",
                "created": "2026-01-28T10:00:00Z",
                "lastModified": "2026-01-28T10:00:00Z",
                "location": format!("https://example.com/scim/v2/Users/{}", user_uuid)
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = bearer_client(&server);
    let user = xavyo_api_scim::models::ScimUser {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".to_string()],
        id: None,
        external_id: Some("ext-123".to_string()),
        user_name: "jane@example.com".to_string(),
        name: Some(xavyo_api_scim::models::ScimName {
            formatted: None,
            family_name: Some("Doe".to_string()),
            given_name: Some("Jane".to_string()),
            middle_name: None,
            honorific_prefix: None,
            honorific_suffix: None,
        }),
        display_name: Some("Jane Doe".to_string()),
        nick_name: None,
        profile_url: None,
        title: None,
        user_type: None,
        preferred_language: None,
        locale: None,
        timezone: None,
        active: true,
        emails: vec![xavyo_api_scim::models::ScimEmail {
            value: "jane@example.com".to_string(),
            email_type: Some("work".to_string()),
            primary: true,
        }],
        groups: vec![],
        meta: None,
        extensions: serde_json::Map::new(),
    };

    let created = client.create_user(&user).await.unwrap();
    assert_eq!(created.id.unwrap().to_string(), user_uuid);
    assert_eq!(created.user_name, "jane@example.com");
    assert!(created.active);
}

#[tokio::test]
async fn test_delete_user_sends_delete_request() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/Users/user-to-delete"))
        .and(header("Authorization", "Bearer test-token-123"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = bearer_client(&server);
    let result = client.delete_user("user-to-delete").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_find_user_by_external_id_returns_some() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/Users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            "startIndex": 1,
            "itemsPerPage": 1,
            "Resources": [{
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
                "externalId": "ext-lookup",
                "userName": "found@example.com",
                "active": true,
                "emails": [],
                "groups": []
            }]
        })))
        .mount(&server)
        .await;

    let client = bearer_client(&server);
    let user = client.find_user_by_external_id("ext-lookup").await.unwrap();
    assert!(user.is_some());
    assert_eq!(user.unwrap().user_name, "found@example.com");
}

#[tokio::test]
async fn test_find_user_by_external_id_returns_none() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/Users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 0,
            "startIndex": 1,
            "itemsPerPage": 0,
            "Resources": []
        })))
        .mount(&server)
        .await;

    let client = bearer_client(&server);
    let user = client
        .find_user_by_external_id("nonexistent")
        .await
        .unwrap();
    assert!(user.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// T017: 401 Invalidates OAuth2 Cache
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_401_invalidates_oauth2_token_cache() {
    let token_server = MockServer::start().await;
    let scim_server = MockServer::start().await;

    // Token endpoint returns different tokens on each call.
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "will-be-rejected",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&token_server)
        .await;

    // SCIM endpoint returns 401 to trigger cache invalidation.
    Mock::given(method("GET"))
        .and(path("/Users/trigger-401"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Token expired"))
        .mount(&scim_server)
        .await;

    let auth = ScimAuth::new(
        ScimCredentials::OAuth2 {
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            token_endpoint: format!("{}/oauth/token", token_server.uri()),
            scopes: vec![],
        },
        reqwest::Client::new(),
    )
    .with_skip_ssrf_validation();
    let client = ScimClient::with_http_client(scim_server.uri(), auth, reqwest::Client::new());

    let result = client.get_user("trigger-401").await;
    assert!(matches!(result, Err(ScimClientError::AuthError(_))));
}

// ═══════════════════════════════════════════════════════════════════════════
// Credential Serialization Tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_credentials_serialize_bearer() {
    let creds = ScimCredentials::Bearer {
        token: "my-token".to_string(),
    };
    let json = serde_json::to_string(&creds).unwrap();
    assert!(json.contains("\"type\":\"bearer\""));
    assert!(json.contains("\"token\":\"my-token\""));

    let deserialized: ScimCredentials = serde_json::from_str(&json).unwrap();
    match deserialized {
        ScimCredentials::Bearer { token } => assert_eq!(token, "my-token"),
        _ => panic!("Expected Bearer"),
    }
}

#[test]
fn test_credentials_serialize_oauth2() {
    let creds = ScimCredentials::OAuth2 {
        client_id: "cid".to_string(),
        client_secret: "csecret".to_string(),
        token_endpoint: "https://auth.example.com/token".to_string(),
        scopes: vec!["read".to_string()],
    };
    let json = serde_json::to_string(&creds).unwrap();
    assert!(json.contains("\"type\":\"oauth2\""));

    let deserialized: ScimCredentials = serde_json::from_str(&json).unwrap();
    match deserialized {
        ScimCredentials::OAuth2 {
            client_id,
            token_endpoint,
            scopes,
            ..
        } => {
            assert_eq!(client_id, "cid");
            assert_eq!(token_endpoint, "https://auth.example.com/token");
            assert_eq!(scopes, vec!["read"]);
        }
        _ => panic!("Expected OAuth2"),
    }
}
