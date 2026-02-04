//! Integration tests for CLI tenant management (multi-tenant switching)
//!
//! Tests tenant list, switch, and current commands using wiremock

mod common;

use chrono::Utc;
use common::TestContext;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

// =============================================================================
// Test Fixtures
// =============================================================================

/// Create a mock tenant info
pub fn create_tenant_fixture(
    name: &str,
    slug: &str,
    role: &str,
    is_current: bool,
) -> serde_json::Value {
    json!({
        "id": Uuid::new_v4().to_string(),
        "name": name,
        "slug": slug,
        "role": role,
        "is_current": is_current
    })
}

/// Create a mock tenant list response
pub fn mock_tenant_list_response(tenants: Vec<serde_json::Value>) -> serde_json::Value {
    json!({
        "tenants": tenants,
        "total": tenants.len(),
        "has_more": false
    })
}

/// Create a mock tenant switch response
pub fn mock_tenant_switch_response(
    tenant_id: &str,
    name: &str,
    slug: &str,
    role: &str,
) -> serde_json::Value {
    json!({
        "tenant_id": tenant_id,
        "tenant_name": name,
        "tenant_slug": slug,
        "role": role
    })
}

// =============================================================================
// Tenant Model Tests
// =============================================================================

#[test]
fn test_tenant_role_serialization() {
    use xavyo_cli::models::tenant::TenantRole;

    // Test all variants serialize correctly
    let owner = TenantRole::Owner;
    let admin = TenantRole::Admin;
    let member = TenantRole::Member;
    let viewer = TenantRole::Viewer;

    assert_eq!(serde_json::to_string(&owner).unwrap(), "\"owner\"");
    assert_eq!(serde_json::to_string(&admin).unwrap(), "\"admin\"");
    assert_eq!(serde_json::to_string(&member).unwrap(), "\"member\"");
    assert_eq!(serde_json::to_string(&viewer).unwrap(), "\"viewer\"");
}

#[test]
fn test_tenant_role_deserialization() {
    use xavyo_cli::models::tenant::TenantRole;

    let owner: TenantRole = serde_json::from_str("\"owner\"").unwrap();
    let admin: TenantRole = serde_json::from_str("\"admin\"").unwrap();
    let member: TenantRole = serde_json::from_str("\"member\"").unwrap();
    let viewer: TenantRole = serde_json::from_str("\"viewer\"").unwrap();

    assert_eq!(owner, TenantRole::Owner);
    assert_eq!(admin, TenantRole::Admin);
    assert_eq!(member, TenantRole::Member);
    assert_eq!(viewer, TenantRole::Viewer);
}

#[test]
fn test_tenant_role_display() {
    use xavyo_cli::models::tenant::TenantRole;

    assert_eq!(TenantRole::Owner.to_string(), "owner");
    assert_eq!(TenantRole::Admin.to_string(), "admin");
    assert_eq!(TenantRole::Member.to_string(), "member");
    assert_eq!(TenantRole::Viewer.to_string(), "viewer");
}

#[test]
fn test_tenant_role_default() {
    use xavyo_cli::models::tenant::TenantRole;

    assert_eq!(TenantRole::default(), TenantRole::Member);
}

#[test]
fn test_tenant_info_deserialization() {
    use xavyo_cli::models::tenant::{TenantInfo, TenantRole};

    let json = r#"{
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "name": "Acme Corporation",
        "slug": "acme-corp",
        "role": "admin",
        "is_current": true
    }"#;

    let info: TenantInfo = serde_json::from_str(json).unwrap();
    assert_eq!(info.name, "Acme Corporation");
    assert_eq!(info.slug, "acme-corp");
    assert_eq!(info.role, TenantRole::Admin);
    assert!(info.is_current);
}

#[test]
fn test_tenant_info_is_current_defaults_to_false() {
    use xavyo_cli::models::tenant::{TenantInfo, TenantRole};

    // is_current should default to false when not present
    let json = r#"{
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "name": "Test Org",
        "slug": "test-org",
        "role": "member"
    }"#;

    let info: TenantInfo = serde_json::from_str(json).unwrap();
    assert!(!info.is_current);
}

#[test]
fn test_tenant_list_response_deserialization() {
    use xavyo_cli::models::tenant::TenantListResponse;

    let json = r#"{
        "tenants": [
            {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "Acme Corp",
                "slug": "acme-corp",
                "role": "admin",
                "is_current": true
            },
            {
                "id": "550e8400-e29b-41d4-a716-446655440001",
                "name": "Beta Inc",
                "slug": "beta-inc",
                "role": "member",
                "is_current": false
            }
        ],
        "total": 2,
        "has_more": false
    }"#;

    let response: TenantListResponse = serde_json::from_str(json).unwrap();
    assert_eq!(response.tenants.len(), 2);
    assert_eq!(response.total, 2);
    assert!(!response.has_more);
    assert!(response.next_cursor.is_none());
}

#[test]
fn test_tenant_list_response_with_pagination() {
    use xavyo_cli::models::tenant::TenantListResponse;

    let json = r#"{
        "tenants": [],
        "total": 100,
        "has_more": true,
        "next_cursor": "eyJsYXN0X2lkIjogIjEyMyJ9"
    }"#;

    let response: TenantListResponse = serde_json::from_str(json).unwrap();
    assert!(response.has_more);
    assert_eq!(
        response.next_cursor,
        Some("eyJsYXN0X2lkIjogIjEyMyJ9".to_string())
    );
}

#[test]
fn test_tenant_switch_request_serialization() {
    use xavyo_cli::models::tenant::TenantSwitchRequest;

    let request = TenantSwitchRequest {
        tenant_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("550e8400-e29b-41d4-a716-446655440000"));
}

#[test]
fn test_tenant_switch_response_deserialization() {
    use xavyo_cli::models::tenant::{TenantRole, TenantSwitchResponse};

    let json = r#"{
        "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
        "tenant_name": "Acme Corp",
        "tenant_slug": "acme-corp",
        "role": "admin"
    }"#;

    let response: TenantSwitchResponse = serde_json::from_str(json).unwrap();
    assert_eq!(response.tenant_name, "Acme Corp");
    assert_eq!(response.tenant_slug, "acme-corp");
    assert_eq!(response.role, TenantRole::Admin);
}

#[test]
fn test_tenant_current_output_serialization() {
    use xavyo_cli::models::tenant::TenantCurrentOutput;

    // With tenant
    let output = TenantCurrentOutput {
        tenant_id: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
        tenant_name: Some("Acme Corp".to_string()),
        tenant_slug: Some("acme-corp".to_string()),
        role: Some("admin".to_string()),
    };

    let json = serde_json::to_string(&output).unwrap();
    assert!(json.contains("Acme Corp"));
    assert!(json.contains("acme-corp"));

    // Without tenant
    let output_none = TenantCurrentOutput {
        tenant_id: None,
        tenant_name: None,
        tenant_slug: None,
        role: None,
    };

    let json_none = serde_json::to_string(&output_none).unwrap();
    assert!(json_none.contains("null"));
}

#[test]
fn test_tenant_switch_output_serialization() {
    use xavyo_cli::models::tenant::TenantSwitchOutput;

    let output = TenantSwitchOutput {
        tenant_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        tenant_name: "Acme Corp".to_string(),
        tenant_slug: "acme-corp".to_string(),
        role: "admin".to_string(),
        switched: true,
    };

    let json = serde_json::to_string(&output).unwrap();
    assert!(json.contains("\"switched\":true"));
}

// =============================================================================
// Session with TenantRole Tests
// =============================================================================

#[test]
fn test_session_set_tenant_with_role() {
    use xavyo_cli::models::tenant::TenantRole;
    use xavyo_cli::models::Session;

    let mut session = Session {
        user_id: Uuid::new_v4(),
        email: "test@example.com".to_string(),
        tenant_id: None,
        tenant_name: None,
        tenant_slug: None,
        tenant_role: None,
    };

    session.set_tenant(
        Uuid::new_v4(),
        "Acme Corp".to_string(),
        "acme-corp".to_string(),
        TenantRole::Admin,
    );

    assert!(session.has_tenant());
    assert_eq!(session.tenant_name.as_deref(), Some("Acme Corp"));
    assert_eq!(session.tenant_slug.as_deref(), Some("acme-corp"));
    assert_eq!(session.tenant_role, Some(TenantRole::Admin));
}

#[test]
fn test_session_serialization_with_tenant_role() {
    use xavyo_cli::models::tenant::TenantRole;
    use xavyo_cli::models::Session;

    let tenant_id = Uuid::new_v4();
    let session = Session {
        user_id: Uuid::new_v4(),
        email: "test@example.com".to_string(),
        tenant_id: Some(tenant_id),
        tenant_name: Some("Test Org".to_string()),
        tenant_slug: Some("test-org".to_string()),
        tenant_role: Some(TenantRole::Owner),
    };

    let json = serde_json::to_string(&session).unwrap();
    assert!(json.contains("\"tenant_role\":\"owner\""));

    // Deserialize and verify
    let deserialized: Session = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.tenant_role, Some(TenantRole::Owner));
}

#[test]
fn test_session_deserialization_without_tenant_role() {
    use xavyo_cli::models::Session;

    // Old session format without tenant_role should still deserialize
    let json = r#"{
        "user_id": "550e8400-e29b-41d4-a716-446655440000",
        "email": "test@example.com",
        "tenant_id": null,
        "tenant_name": null,
        "tenant_slug": null
    }"#;

    let session: Session = serde_json::from_str(json).unwrap();
    assert!(session.tenant_role.is_none());
}

// =============================================================================
// API Mock Tests (Integration)
// =============================================================================

// Note: Full API integration tests require the command module to be implemented.
// These tests verify the mock setup and response handling.

#[tokio::test]
async fn test_tenant_list_mock_setup() {
    let ctx = TestContext::new().await;

    // Setup mock
    let tenants = vec![
        create_tenant_fixture("Acme Corp", "acme-corp", "admin", true),
        create_tenant_fixture("Beta Inc", "beta-inc", "member", false),
    ];

    Mock::given(method("GET"))
        .and(path("/users/me/tenants"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_tenant_list_response(tenants)))
        .mount(&ctx.server)
        .await;

    // Verify mock is working
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/users/me/tenants", ctx.base_url()))
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["tenants"].as_array().unwrap().len(), 2);
    assert_eq!(body["total"], 2);
}

#[tokio::test]
async fn test_tenant_switch_mock_setup() {
    let ctx = TestContext::new().await;
    let tenant_id = Uuid::new_v4().to_string();

    // Setup mock
    Mock::given(method("POST"))
        .and(path("/users/me/tenant"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(mock_tenant_switch_response(
                &tenant_id,
                "Acme Corp",
                "acme-corp",
                "admin",
            )),
        )
        .mount(&ctx.server)
        .await;

    // Verify mock is working
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/users/me/tenant", ctx.base_url()))
        .json(&json!({ "tenant_id": tenant_id }))
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["tenant_name"], "Acme Corp");
    assert_eq!(body["tenant_slug"], "acme-corp");
}

#[tokio::test]
async fn test_tenant_not_found_mock() {
    let ctx = TestContext::new().await;

    Mock::given(method("POST"))
        .and(path("/users/me/tenant"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "not_found",
            "message": "Tenant not found"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/users/me/tenant", ctx.base_url()))
        .json(&json!({ "tenant_id": Uuid::new_v4() }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn test_tenant_access_denied_mock() {
    let ctx = TestContext::new().await;

    Mock::given(method("POST"))
        .and(path("/users/me/tenant"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": "access_denied",
            "message": "You do not have access to this tenant"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/users/me/tenant", ctx.base_url()))
        .json(&json!({ "tenant_id": Uuid::new_v4() }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 403);
}

#[tokio::test]
async fn test_tenant_list_empty_mock() {
    let ctx = TestContext::new().await;

    Mock::given(method("GET"))
        .and(path("/users/me/tenants"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tenants": [],
            "total": 0,
            "has_more": false
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/users/me/tenants", ctx.base_url()))
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["tenants"].as_array().unwrap().len(), 0);
    assert_eq!(body["total"], 0);
}

#[tokio::test]
async fn test_tenant_list_unauthorized_mock() {
    let ctx = TestContext::new().await;

    Mock::given(method("GET"))
        .and(path("/users/me/tenants"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "unauthorized",
            "message": "Authentication required"
        })))
        .mount(&ctx.server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/users/me/tenants", ctx.base_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 401);
}
