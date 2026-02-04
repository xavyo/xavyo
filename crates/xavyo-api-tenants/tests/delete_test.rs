//! Integration tests for tenant soft delete handlers.
//!
//! F-DELETE: Tests for tenant soft delete functionality.

use chrono::Utc;
use uuid::Uuid;
use xavyo_api_tenants::models::{
    DeleteTenantRequest, DeleteTenantResponse, DeletedTenantInfo, DeletedTenantListResponse,
    RestoreTenantResponse,
};

/// Test that the `DeleteTenantRequest` validation rejects empty reason.
#[test]
fn test_delete_request_validation_empty_reason() {
    let request = DeleteTenantRequest {
        reason: String::new(),
        immediate: false,
    };
    assert_eq!(
        request.validate(),
        Some("Deletion reason is required".to_string())
    );
}

/// Test that the `DeleteTenantRequest` validation rejects whitespace reason.
#[test]
fn test_delete_request_validation_whitespace_reason() {
    let request = DeleteTenantRequest {
        reason: "   ".to_string(),
        immediate: false,
    };
    assert_eq!(
        request.validate(),
        Some("Deletion reason is required".to_string())
    );
}

/// Test that the `DeleteTenantRequest` validation rejects too long reason.
#[test]
fn test_delete_request_validation_too_long() {
    let request = DeleteTenantRequest {
        reason: "x".repeat(1001),
        immediate: false,
    };
    assert_eq!(
        request.validate(),
        Some("Deletion reason must be at most 1000 characters".to_string())
    );
}

/// Test that the `DeleteTenantRequest` validation accepts valid request.
#[test]
fn test_delete_request_validation_valid() {
    let request = DeleteTenantRequest {
        reason: "Customer requested account closure".to_string(),
        immediate: false,
    };
    assert_eq!(request.validate(), None);
}

/// Test that the `DeleteTenantRequest` validation accepts max length reason.
#[test]
fn test_delete_request_validation_max_length() {
    let request = DeleteTenantRequest {
        reason: "x".repeat(1000),
        immediate: false,
    };
    assert_eq!(request.validate(), None);
}

/// Test that the `DeleteTenantRequest` default is correct.
#[test]
fn test_delete_request_default() {
    let request = DeleteTenantRequest::default();
    assert!(request.reason.is_empty());
    assert!(!request.immediate);
}

/// Test response serialization for `DeleteTenantResponse`.
#[test]
fn test_delete_response_serialization() {
    let now = Utc::now();
    let response = DeleteTenantResponse {
        tenant_id: Uuid::new_v4(),
        deleted_at: now,
        scheduled_purge_at: now + chrono::Duration::days(30),
        reason: "Test deletion".to_string(),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("tenant_id"));
    assert!(json.contains("deleted_at"));
    assert!(json.contains("scheduled_purge_at"));
    assert!(json.contains("Test deletion"));
}

/// Test response serialization for `RestoreTenantResponse`.
#[test]
fn test_restore_response_serialization() {
    let response = RestoreTenantResponse {
        tenant_id: Uuid::new_v4(),
        restored_at: Utc::now(),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("tenant_id"));
    assert!(json.contains("restored_at"));
}

/// Test response serialization for `DeletedTenantInfo`.
#[test]
fn test_deleted_tenant_info_serialization() {
    let now = Utc::now();
    let info = DeletedTenantInfo {
        id: Uuid::new_v4(),
        name: "Acme Corp".to_string(),
        slug: "acme-corp".to_string(),
        deleted_at: now,
        scheduled_purge_at: now + chrono::Duration::days(30),
        deletion_reason: Some("Customer requested".to_string()),
    };

    let json = serde_json::to_string(&info).unwrap();
    assert!(json.contains("Acme Corp"));
    assert!(json.contains("acme-corp"));
    assert!(json.contains("Customer requested"));
    assert!(json.contains("deleted_at"));
    assert!(json.contains("scheduled_purge_at"));
}

/// Test response serialization for `DeletedTenantInfo` without reason.
#[test]
fn test_deleted_tenant_info_serialization_no_reason() {
    let now = Utc::now();
    let info = DeletedTenantInfo {
        id: Uuid::new_v4(),
        name: "Test Corp".to_string(),
        slug: "test-corp".to_string(),
        deleted_at: now,
        scheduled_purge_at: now + chrono::Duration::days(30),
        deletion_reason: None,
    };

    let json = serde_json::to_string(&info).unwrap();
    assert!(json.contains("Test Corp"));
    assert!(json.contains("\"deletion_reason\":null"));
}

/// Test response serialization for `DeletedTenantListResponse`.
#[test]
fn test_deleted_tenant_list_response_serialization() {
    let now = Utc::now();
    let response = DeletedTenantListResponse {
        deleted_tenants: vec![
            DeletedTenantInfo {
                id: Uuid::new_v4(),
                name: "Tenant 1".to_string(),
                slug: "tenant-1".to_string(),
                deleted_at: now,
                scheduled_purge_at: now + chrono::Duration::days(30),
                deletion_reason: Some("Reason 1".to_string()),
            },
            DeletedTenantInfo {
                id: Uuid::new_v4(),
                name: "Tenant 2".to_string(),
                slug: "tenant-2".to_string(),
                deleted_at: now,
                scheduled_purge_at: now + chrono::Duration::days(30),
                deletion_reason: None,
            },
        ],
        total: 2,
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"total\":2"));
    assert!(json.contains("Tenant 1"));
    assert!(json.contains("Tenant 2"));
    assert!(json.contains("tenant-1"));
    assert!(json.contains("tenant-2"));
}

/// Test response serialization for empty `DeletedTenantListResponse`.
#[test]
fn test_deleted_tenant_list_response_empty() {
    let response = DeletedTenantListResponse {
        deleted_tenants: vec![],
        total: 0,
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"total\":0"));
    assert!(json.contains("\"deleted_tenants\":[]"));
}

/// Test response deserialization for `DeleteTenantRequest`.
#[test]
fn test_delete_request_deserialization() {
    let json = r#"{"reason":"Customer requested closure","immediate":true}"#;
    let request: DeleteTenantRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.reason, "Customer requested closure");
    assert!(request.immediate);
}

/// Test response deserialization for `DeleteTenantRequest` with defaults.
#[test]
fn test_delete_request_deserialization_defaults() {
    let json = r#"{"reason":"Customer requested closure"}"#;
    let request: DeleteTenantRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.reason, "Customer requested closure");
    assert!(!request.immediate); // Default is false
}
