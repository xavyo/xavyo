//! Integration tests for tenant suspension handlers.
//!
//! F-SUSPEND: Tests for suspend, reactivate, and status endpoints.

use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_api_tenants::models::{
    ReactivateTenantResponse, SuspendTenantRequest, SuspendTenantResponse, TenantStatusResponse,
};

/// Test that the SuspendTenantRequest validation works correctly.
#[test]
fn test_suspend_request_validation_valid() {
    let request = SuspendTenantRequest {
        reason: "Violation of terms of service".to_string(),
    };
    assert!(request.validate().is_none());
}

#[test]
fn test_suspend_request_validation_empty_reason() {
    let request = SuspendTenantRequest {
        reason: "".to_string(),
    };
    let error = request.validate();
    assert!(error.is_some());
    assert!(error.unwrap().contains("required"));
}

#[test]
fn test_suspend_request_validation_whitespace_reason() {
    let request = SuspendTenantRequest {
        reason: "   ".to_string(),
    };
    let error = request.validate();
    assert!(error.is_some());
}

#[test]
fn test_suspend_request_validation_too_long() {
    let request = SuspendTenantRequest {
        reason: "a".repeat(501),
    };
    let error = request.validate();
    assert!(error.is_some());
    assert!(error.unwrap().contains("500"));
}

#[test]
fn test_suspend_request_validation_max_length() {
    let request = SuspendTenantRequest {
        reason: "a".repeat(500),
    };
    assert!(request.validate().is_none());
}

/// Test response serialization for SuspendTenantResponse.
#[test]
fn test_suspend_response_serialization() {
    let response = SuspendTenantResponse {
        tenant_id: Uuid::new_v4(),
        suspended_at: Utc::now(),
        suspension_reason: "Test suspension".to_string(),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("tenant_id"));
    assert!(json.contains("suspended_at"));
    assert!(json.contains("suspension_reason"));
    assert!(json.contains("Test suspension"));
}

/// Test response serialization for ReactivateTenantResponse.
#[test]
fn test_reactivate_response_serialization() {
    let response = ReactivateTenantResponse {
        tenant_id: Uuid::new_v4(),
        reactivated_at: Utc::now(),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("tenant_id"));
    assert!(json.contains("reactivated_at"));
}

/// Test response serialization for TenantStatusResponse.
#[test]
fn test_status_response_serialization_active() {
    let response = TenantStatusResponse {
        id: Uuid::new_v4(),
        name: "Test Tenant".to_string(),
        slug: "test-tenant".to_string(),
        is_suspended: false,
        suspended_at: None,
        suspension_reason: None,
        is_deleted: false,
        deleted_at: None,
        deletion_reason: None,
        scheduled_purge_at: None,
        created_at: Utc::now() - Duration::days(30),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"is_suspended\":false"));
    assert!(json.contains("\"is_deleted\":false"));
    // Optional fields should be omitted when None
    assert!(!json.contains("suspended_at"));
    assert!(!json.contains("suspension_reason"));
    assert!(!json.contains("deleted_at"));
    assert!(!json.contains("deletion_reason"));
    assert!(!json.contains("scheduled_purge_at"));
}

#[test]
fn test_status_response_serialization_suspended() {
    let suspended_at = Utc::now();
    let response = TenantStatusResponse {
        id: Uuid::new_v4(),
        name: "Suspended Tenant".to_string(),
        slug: "suspended-tenant".to_string(),
        is_suspended: true,
        suspended_at: Some(suspended_at),
        suspension_reason: Some("Terms violation".to_string()),
        is_deleted: false,
        deleted_at: None,
        deletion_reason: None,
        scheduled_purge_at: None,
        created_at: Utc::now() - Duration::days(30),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"is_suspended\":true"));
    assert!(json.contains("suspended_at"));
    assert!(json.contains("Terms violation"));
    assert!(json.contains("\"is_deleted\":false"));
}

#[test]
fn test_status_response_serialization_deleted() {
    let deleted_at = Utc::now();
    let scheduled_purge_at = deleted_at + Duration::days(30);
    let response = TenantStatusResponse {
        id: Uuid::new_v4(),
        name: "Deleted Tenant".to_string(),
        slug: "deleted-tenant".to_string(),
        is_suspended: false,
        suspended_at: None,
        suspension_reason: None,
        is_deleted: true,
        deleted_at: Some(deleted_at),
        deletion_reason: Some("Customer requested".to_string()),
        scheduled_purge_at: Some(scheduled_purge_at),
        created_at: Utc::now() - Duration::days(60),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"is_deleted\":true"));
    assert!(json.contains("deleted_at"));
    assert!(json.contains("Customer requested"));
    assert!(json.contains("scheduled_purge_at"));
    assert!(json.contains("\"is_suspended\":false"));
}
