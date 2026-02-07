//! Integration tests for CLI tenant management
//!
//! Tests tenant current command model types

use uuid::Uuid;

// =============================================================================
// Tenant Model Tests
// =============================================================================

#[test]
fn test_tenant_role_serialization() {
    use xavyo_cli::models::tenant::TenantRole;

    assert_eq!(
        serde_json::to_string(&TenantRole::Owner).unwrap(),
        "\"owner\""
    );
    assert_eq!(
        serde_json::to_string(&TenantRole::Admin).unwrap(),
        "\"admin\""
    );
    assert_eq!(
        serde_json::to_string(&TenantRole::Member).unwrap(),
        "\"member\""
    );
    assert_eq!(
        serde_json::to_string(&TenantRole::Viewer).unwrap(),
        "\"viewer\""
    );
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
