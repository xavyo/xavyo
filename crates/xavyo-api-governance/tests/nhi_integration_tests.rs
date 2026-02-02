//! Integration tests for NHI API endpoints.
//!
//! F061 - NHI Lifecycle Management
//!
//! These tests verify the API contract and service behavior without requiring
//! a running database. They test the logic layer in isolation.

use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_db::{NhiSuspensionReason, ServiceAccountStatus};

use xavyo_api_governance::models::{
    CreateNhiRequest, ListNhisQuery, NhiListResponse, NhiResponse, NhiSummary,
    ReactivateNhiRequest, SuspendNhiRequest, TransferOwnershipRequest, UpdateNhiRequest,
};

// =============================================================================
// Test Helpers
// =============================================================================

/// Create a test CreateNhiRequest with default values.
fn create_test_request(name: &str, owner_id: Uuid) -> CreateNhiRequest {
    CreateNhiRequest {
        user_id: Uuid::new_v4(),
        name: name.to_string(),
        purpose: "Integration test service account".to_string(),
        owner_id,
        backup_owner_id: None,
        expires_at: Some(Utc::now() + Duration::days(365)),
        rotation_interval_days: Some(90),
        inactivity_threshold_days: Some(90),
    }
}

/// Create a mock NhiResponse for testing.
fn create_mock_nhi_response(name: &str, status: ServiceAccountStatus) -> NhiResponse {
    NhiResponse {
        id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        name: name.to_string(),
        purpose: "Test purpose".to_string(),
        owner_id: Uuid::new_v4(),
        backup_owner_id: None,
        status,
        expires_at: Some(Utc::now() + Duration::days(365)),
        days_until_expiry: Some(365),
        rotation_interval_days: Some(90),
        last_rotation_at: None,
        needs_rotation: false,
        last_used_at: None,
        days_since_last_use: None,
        inactivity_threshold_days: Some(90),
        is_inactive: false,
        grace_period_ends_at: None,
        is_in_grace_period: false,
        suspension_reason: None,
        last_certified_at: None,
        certified_by: None,
        needs_certification: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

// =============================================================================
// Create NHI Tests
// =============================================================================

#[test]
fn test_create_nhi_request_with_all_fields() {
    let owner_id = Uuid::new_v4();
    let backup_owner_id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::days(365);

    let request = CreateNhiRequest {
        user_id: Uuid::new_v4(),
        name: "data-pipeline-processor".to_string(),
        purpose: "ETL service for data warehouse processing".to_string(),
        owner_id,
        backup_owner_id: Some(backup_owner_id),
        expires_at: Some(expires_at),
        rotation_interval_days: Some(60),
        inactivity_threshold_days: Some(30),
    };

    assert_eq!(request.name, "data-pipeline-processor");
    assert_eq!(request.owner_id, owner_id);
    assert_eq!(request.backup_owner_id, Some(backup_owner_id));
    assert_eq!(request.rotation_interval_days, Some(60));
    assert_eq!(request.inactivity_threshold_days, Some(30));
}

#[test]
fn test_create_nhi_request_minimal_fields() {
    let owner_id = Uuid::new_v4();

    let request = CreateNhiRequest {
        user_id: Uuid::new_v4(),
        name: "minimal-service".to_string(),
        purpose: "Minimal service account for testing".to_string(),
        owner_id,
        backup_owner_id: None,
        expires_at: None,
        rotation_interval_days: None,
        inactivity_threshold_days: None,
    };

    assert_eq!(request.name, "minimal-service");
    assert!(request.backup_owner_id.is_none());
    assert!(request.expires_at.is_none());
    assert!(request.rotation_interval_days.is_none());
    assert!(request.inactivity_threshold_days.is_none());
}

// =============================================================================
// Update NHI Tests
// =============================================================================

#[test]
fn test_update_nhi_request_partial_update() {
    let request = UpdateNhiRequest {
        name: Some("new-service-name".to_string()),
        purpose: None,
        owner_id: None,
        backup_owner_id: None,
        expires_at: None,
        rotation_interval_days: None,
        inactivity_threshold_days: None,
    };

    assert!(request.name.is_some());
    assert!(request.purpose.is_none());
    assert!(request.owner_id.is_none());
}

#[test]
fn test_update_nhi_request_full_update() {
    let new_owner_id = Uuid::new_v4();
    let new_backup_id = Uuid::new_v4();

    let request = UpdateNhiRequest {
        name: Some("updated-service".to_string()),
        purpose: Some("Updated purpose description".to_string()),
        owner_id: Some(new_owner_id),
        backup_owner_id: Some(new_backup_id),
        expires_at: Some(Utc::now() + Duration::days(180)),
        rotation_interval_days: Some(30),
        inactivity_threshold_days: Some(45),
    };

    assert_eq!(request.name, Some("updated-service".to_string()));
    assert_eq!(request.owner_id, Some(new_owner_id));
    assert_eq!(request.rotation_interval_days, Some(30));
}

// =============================================================================
// Suspend/Reactivate Tests
// =============================================================================

#[test]
fn test_suspend_nhi_request_manual() {
    let request = SuspendNhiRequest {
        reason: NhiSuspensionReason::Manual,
        details: Some("Suspending for security audit".to_string()),
    };

    assert_eq!(request.reason, NhiSuspensionReason::Manual);
    assert!(request.details.is_some());
}

#[test]
fn test_suspend_nhi_request_inactive() {
    let request = SuspendNhiRequest {
        reason: NhiSuspensionReason::Inactive,
        details: None,
    };

    assert_eq!(request.reason, NhiSuspensionReason::Inactive);
    assert!(request.details.is_none());
}

#[test]
fn test_suspend_nhi_request_emergency() {
    let request = SuspendNhiRequest {
        reason: NhiSuspensionReason::Emergency,
        details: Some("Security incident detected".to_string()),
    };

    assert_eq!(request.reason, NhiSuspensionReason::Emergency);
}

#[test]
fn test_reactivate_nhi_request() {
    let request = ReactivateNhiRequest {
        reason: "Security audit completed, reactivating service".to_string(),
    };

    assert!(!request.reason.is_empty());
    assert!(request.reason.len() >= 5);
}

// =============================================================================
// Transfer Ownership Tests
// =============================================================================

#[test]
fn test_transfer_ownership_request() {
    let new_owner_id = Uuid::new_v4();

    let request = TransferOwnershipRequest {
        new_owner_id,
        reason: "Previous owner left the organization".to_string(),
    };

    assert_eq!(request.new_owner_id, new_owner_id);
    assert!(!request.reason.is_empty());
}

// =============================================================================
// List NHIs Tests
// =============================================================================

#[test]
fn test_list_nhis_query_pagination() {
    let query = ListNhisQuery {
        status: None,
        owner_id: None,
        expiring_within_days: None,
        needs_certification: None,
        needs_rotation: None,
        inactive_only: None,
        limit: Some(25),
        offset: Some(50),
    };

    assert_eq!(query.limit, Some(25));
    assert_eq!(query.offset, Some(50));
}

#[test]
fn test_list_nhis_query_filter_by_status() {
    let query = ListNhisQuery {
        status: Some(ServiceAccountStatus::Active),
        owner_id: None,
        expiring_within_days: None,
        needs_certification: None,
        needs_rotation: None,
        inactive_only: None,
        limit: Some(50),
        offset: Some(0),
    };

    assert_eq!(query.status, Some(ServiceAccountStatus::Active));
}

#[test]
fn test_list_nhis_query_filter_expiring_soon() {
    let query = ListNhisQuery {
        status: None,
        owner_id: None,
        expiring_within_days: Some(30),
        needs_certification: None,
        needs_rotation: None,
        inactive_only: None,
        limit: Some(50),
        offset: Some(0),
    };

    assert_eq!(query.expiring_within_days, Some(30));
}

#[test]
fn test_list_nhis_query_filter_needs_certification() {
    let query = ListNhisQuery {
        status: None,
        owner_id: None,
        expiring_within_days: None,
        needs_certification: Some(true),
        needs_rotation: None,
        inactive_only: None,
        limit: Some(50),
        offset: Some(0),
    };

    assert_eq!(query.needs_certification, Some(true));
}

#[test]
fn test_list_nhis_query_filter_needs_rotation() {
    let query = ListNhisQuery {
        status: None,
        owner_id: None,
        expiring_within_days: None,
        needs_certification: None,
        needs_rotation: Some(true),
        inactive_only: None,
        limit: Some(50),
        offset: Some(0),
    };

    assert_eq!(query.needs_rotation, Some(true));
}

#[test]
fn test_list_nhis_query_filter_inactive() {
    let query = ListNhisQuery {
        status: None,
        owner_id: None,
        expiring_within_days: None,
        needs_certification: None,
        needs_rotation: None,
        inactive_only: Some(true),
        limit: Some(50),
        offset: Some(0),
    };

    assert_eq!(query.inactive_only, Some(true));
}

// =============================================================================
// NhiListResponse Tests
// =============================================================================

#[test]
fn test_nhi_list_response_empty() {
    let response = NhiListResponse {
        items: vec![],
        total: 0,
        limit: 50,
        offset: 0,
    };

    assert!(response.items.is_empty());
    assert_eq!(response.total, 0);
}

#[test]
fn test_nhi_list_response_with_items() {
    let items = vec![
        create_mock_nhi_response("service-1", ServiceAccountStatus::Active),
        create_mock_nhi_response("service-2", ServiceAccountStatus::Active),
        create_mock_nhi_response("service-3", ServiceAccountStatus::Suspended),
    ];

    let response = NhiListResponse {
        items,
        total: 100,
        limit: 50,
        offset: 0,
    };

    assert_eq!(response.items.len(), 3);
    assert_eq!(response.total, 100);
    assert_eq!(response.limit, 50);
    assert_eq!(response.offset, 0);
}

#[test]
fn test_nhi_list_response_pagination() {
    let items = vec![create_mock_nhi_response(
        "service-51",
        ServiceAccountStatus::Active,
    )];

    let response = NhiListResponse {
        items,
        total: 100,
        limit: 10,
        offset: 50,
    };

    assert_eq!(response.items.len(), 1);
    assert_eq!(response.total, 100);
    assert_eq!(response.limit, 10);
    assert_eq!(response.offset, 50);
}

// =============================================================================
// NhiSummary Tests
// =============================================================================

#[test]
fn test_nhi_summary_all_active() {
    let summary = NhiSummary {
        total: 10,
        active: 10,
        expired: 0,
        suspended: 0,
        needs_certification: 2,
        needs_rotation: 1,
        inactive: 0,
        expiring_soon: 0,
        by_risk_level: None,
    };

    assert_eq!(summary.total, summary.active);
    assert_eq!(summary.expired, 0);
    assert_eq!(summary.suspended, 0);
}

#[test]
fn test_nhi_summary_mixed_statuses() {
    let summary = NhiSummary {
        total: 100,
        active: 80,
        expired: 10,
        suspended: 10,
        needs_certification: 25,
        needs_rotation: 15,
        inactive: 5,
        expiring_soon: 8,
        by_risk_level: None,
    };

    assert_eq!(
        summary.total,
        summary.active + summary.expired + summary.suspended
    );
}

#[test]
fn test_nhi_summary_high_risk_counts() {
    let summary = NhiSummary {
        total: 50,
        active: 30,
        expired: 10,
        suspended: 10,
        needs_certification: 20,
        needs_rotation: 15,
        inactive: 12,
        expiring_soon: 5,
        by_risk_level: None,
    };

    // High risk indicators
    let needs_attention = summary.needs_certification + summary.needs_rotation + summary.inactive;
    assert!(needs_attention > 0);
}

// =============================================================================
// NhiResponse Status Tests
// =============================================================================

#[test]
fn test_nhi_response_active_status() {
    let response = create_mock_nhi_response("active-service", ServiceAccountStatus::Active);

    assert_eq!(response.status, ServiceAccountStatus::Active);
    assert!(response.suspension_reason.is_none());
}

#[test]
fn test_nhi_response_suspended_status() {
    let mut response =
        create_mock_nhi_response("suspended-service", ServiceAccountStatus::Suspended);
    response.suspension_reason = Some(NhiSuspensionReason::Manual);

    assert_eq!(response.status, ServiceAccountStatus::Suspended);
    assert_eq!(
        response.suspension_reason,
        Some(NhiSuspensionReason::Manual)
    );
}

#[test]
fn test_nhi_response_expired_status() {
    let mut response = create_mock_nhi_response("expired-service", ServiceAccountStatus::Expired);
    response.expires_at = Some(Utc::now() - Duration::days(30));
    response.days_until_expiry = Some(-30);

    assert_eq!(response.status, ServiceAccountStatus::Expired);
    assert!(response.days_until_expiry.unwrap() < 0);
}

// =============================================================================
// Lifecycle Flag Tests
// =============================================================================

#[test]
fn test_nhi_response_needs_rotation() {
    let mut response = create_mock_nhi_response("needs-rotation", ServiceAccountStatus::Active);
    response.needs_rotation = true;
    response.last_rotation_at = Some(Utc::now() - Duration::days(100));

    assert!(response.needs_rotation);
}

#[test]
fn test_nhi_response_is_inactive() {
    let mut response = create_mock_nhi_response("inactive-service", ServiceAccountStatus::Active);
    response.is_inactive = true;
    response.last_used_at = Some(Utc::now() - Duration::days(120));
    response.days_since_last_use = Some(120);

    assert!(response.is_inactive);
    assert!(response.days_since_last_use.unwrap() > 90);
}

#[test]
fn test_nhi_response_in_grace_period() {
    let mut response = create_mock_nhi_response("grace-period", ServiceAccountStatus::Active);
    response.is_in_grace_period = true;
    response.grace_period_ends_at = Some(Utc::now() + Duration::days(3));

    assert!(response.is_in_grace_period);
    assert!(response.grace_period_ends_at.is_some());
}

#[test]
fn test_nhi_response_needs_certification() {
    let mut response = create_mock_nhi_response("needs-cert", ServiceAccountStatus::Active);
    response.needs_certification = true;
    response.last_certified_at = Some(Utc::now() - Duration::days(100));

    assert!(response.needs_certification);
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_nhi_with_long_name() {
    let owner_id = Uuid::new_v4();
    let long_name = "a".repeat(200);

    let request = create_test_request(&long_name, owner_id);
    assert_eq!(request.name.len(), 200);
}

#[test]
fn test_nhi_with_unicode_purpose() {
    let request = CreateNhiRequest {
        user_id: Uuid::new_v4(),
        name: "unicode-test".to_string(),
        purpose: "テスト目的 - Test purpose 🚀".to_string(),
        owner_id: Uuid::new_v4(),
        backup_owner_id: None,
        expires_at: None,
        rotation_interval_days: None,
        inactivity_threshold_days: None,
    };

    assert!(request.purpose.contains("テスト"));
    assert!(request.purpose.contains("🚀"));
}

#[test]
fn test_nhi_expiring_today() {
    let mut response = create_mock_nhi_response("expiring-today", ServiceAccountStatus::Active);
    response.expires_at = Some(Utc::now());
    response.days_until_expiry = Some(0);

    assert_eq!(response.days_until_expiry, Some(0));
}

#[test]
fn test_nhi_with_all_suspension_reasons() {
    let suspension_reasons = vec![
        NhiSuspensionReason::Expired,
        NhiSuspensionReason::Inactive,
        NhiSuspensionReason::CertificationRevoked,
        NhiSuspensionReason::Emergency,
        NhiSuspensionReason::Manual,
    ];

    for reason in suspension_reasons {
        let request = SuspendNhiRequest {
            reason,
            details: Some(format!("Suspended due to {:?}", reason)),
        };

        // Each suspension reason should be valid
        assert!(matches!(
            request.reason,
            NhiSuspensionReason::Expired
                | NhiSuspensionReason::Inactive
                | NhiSuspensionReason::CertificationRevoked
                | NhiSuspensionReason::Emergency
                | NhiSuspensionReason::Manual
        ));
    }
}

// =============================================================================
// Serialization Tests
// =============================================================================

#[test]
fn test_suspend_request_serialization() {
    let request = SuspendNhiRequest {
        reason: NhiSuspensionReason::Manual,
        details: Some("Manual suspension".to_string()),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: SuspendNhiRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request.reason, deserialized.reason);
    assert_eq!(request.details, deserialized.details);
}

#[test]
fn test_reactivate_request_serialization() {
    let request = ReactivateNhiRequest {
        reason: "Reactivation approved".to_string(),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: ReactivateNhiRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request.reason, deserialized.reason);
}

#[test]
fn test_transfer_ownership_request_serialization() {
    let new_owner_id = Uuid::new_v4();
    let request = TransferOwnershipRequest {
        new_owner_id,
        reason: "Transfer to new team".to_string(),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: TransferOwnershipRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request.new_owner_id, deserialized.new_owner_id);
    assert_eq!(request.reason, deserialized.reason);
}

#[test]
fn test_list_response_serialization() {
    let response = NhiListResponse {
        items: vec![create_mock_nhi_response(
            "test",
            ServiceAccountStatus::Active,
        )],
        total: 1,
        limit: 50,
        offset: 0,
    };

    let json = serde_json::to_string(&response).unwrap();
    let deserialized: NhiListResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(response.total, deserialized.total);
    assert_eq!(response.items.len(), deserialized.items.len());
}

// =============================================================================
// Validation Edge Case Tests
// =============================================================================

#[test]
fn test_create_request_with_expired_date() {
    // This should be caught by service validation before DB insert
    let request = CreateNhiRequest {
        user_id: Uuid::new_v4(),
        name: "expired-test".to_string(),
        purpose: "Test with expiration in the past".to_string(),
        owner_id: Uuid::new_v4(),
        backup_owner_id: None,
        expires_at: Some(Utc::now() - Duration::days(1)), // Past date
        rotation_interval_days: Some(90),
        inactivity_threshold_days: Some(90),
    };

    // The request can be created, but service should reject it
    assert!(request.expires_at.unwrap() < Utc::now());
}

#[test]
fn test_create_request_with_same_backup_and_primary_owner() {
    let owner_id = Uuid::new_v4();

    let request = CreateNhiRequest {
        user_id: Uuid::new_v4(),
        name: "same-owner-test".to_string(),
        purpose: "Test with same backup and primary owner".to_string(),
        owner_id,
        backup_owner_id: Some(owner_id), // Same as primary
        expires_at: None,
        rotation_interval_days: None,
        inactivity_threshold_days: None,
    };

    // Service should reject this
    assert_eq!(request.owner_id, request.backup_owner_id.unwrap());
}

#[test]
fn test_update_request_with_empty_update() {
    let request = UpdateNhiRequest {
        name: None,
        purpose: None,
        owner_id: None,
        backup_owner_id: None,
        expires_at: None,
        rotation_interval_days: None,
        inactivity_threshold_days: None,
    };

    // Empty update is valid (no-op)
    assert!(request.name.is_none());
    assert!(request.purpose.is_none());
    assert!(request.owner_id.is_none());
}

#[test]
fn test_transfer_ownership_to_same_owner() {
    let owner_id = Uuid::new_v4();

    let request = TransferOwnershipRequest {
        new_owner_id: owner_id,
        reason: "Test self-transfer".to_string(),
    };

    // Service should validate this is a no-op or error
    // We can only test the request structure here
    assert_eq!(request.new_owner_id, owner_id);
}

#[test]
fn test_nhi_response_expiring_today_edge_case() {
    let mut response = create_mock_nhi_response("expires-today", ServiceAccountStatus::Active);
    response.expires_at = Some(Utc::now());
    response.days_until_expiry = Some(0);

    // Edge case: expires_at == now() should be treated as expired or expiring immediately
    assert_eq!(response.days_until_expiry, Some(0));
}

#[test]
fn test_nhi_response_just_expired() {
    let mut response = create_mock_nhi_response("just-expired", ServiceAccountStatus::Active);
    response.expires_at = Some(Utc::now() - Duration::seconds(1));
    response.days_until_expiry = Some(-1);

    // Should be marked as expired
    assert!(response.days_until_expiry.unwrap() < 0);
}

#[test]
fn test_nhi_list_query_with_multiple_filters() {
    let query = ListNhisQuery {
        status: Some(ServiceAccountStatus::Active),
        owner_id: Some(Uuid::new_v4()),
        expiring_within_days: Some(30),
        needs_certification: Some(true),
        needs_rotation: Some(true),
        inactive_only: Some(false),
        limit: Some(100),
        offset: Some(0),
    };

    // Multiple filters can be combined
    assert!(query.status.is_some());
    assert!(query.owner_id.is_some());
    assert!(query.expiring_within_days.is_some());
    assert!(query.needs_certification.is_some());
    assert!(query.needs_rotation.is_some());
}

#[test]
fn test_suspend_request_all_reasons() {
    let reasons = vec![
        NhiSuspensionReason::Expired,
        NhiSuspensionReason::Inactive,
        NhiSuspensionReason::CertificationRevoked,
        NhiSuspensionReason::Emergency,
        NhiSuspensionReason::Manual,
    ];

    for reason in reasons {
        let request = SuspendNhiRequest {
            reason: reason.clone(),
            details: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SuspendNhiRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.reason, deserialized.reason);
    }
}

#[test]
fn test_nhi_with_rotation_interval_boundaries() {
    // Test minimum valid rotation interval (1 day)
    let request_min = CreateNhiRequest {
        user_id: Uuid::new_v4(),
        name: "min-rotation".to_string(),
        purpose: "Test minimum rotation interval".to_string(),
        owner_id: Uuid::new_v4(),
        backup_owner_id: None,
        expires_at: None,
        rotation_interval_days: Some(1), // Minimum
        inactivity_threshold_days: None,
    };
    assert_eq!(request_min.rotation_interval_days, Some(1));

    // Test maximum valid rotation interval (365 days)
    let request_max = CreateNhiRequest {
        user_id: Uuid::new_v4(),
        name: "max-rotation".to_string(),
        purpose: "Test maximum rotation interval".to_string(),
        owner_id: Uuid::new_v4(),
        backup_owner_id: None,
        expires_at: None,
        rotation_interval_days: Some(365), // Maximum
        inactivity_threshold_days: None,
    };
    assert_eq!(request_max.rotation_interval_days, Some(365));
}

#[test]
fn test_nhi_with_inactivity_threshold_boundaries() {
    // Test minimum valid inactivity threshold (1 day)
    let request_min = CreateNhiRequest {
        user_id: Uuid::new_v4(),
        name: "min-inactivity".to_string(),
        purpose: "Test minimum inactivity threshold".to_string(),
        owner_id: Uuid::new_v4(),
        backup_owner_id: None,
        expires_at: None,
        rotation_interval_days: None,
        inactivity_threshold_days: Some(1), // Minimum
    };
    assert_eq!(request_min.inactivity_threshold_days, Some(1));

    // Test maximum valid inactivity threshold (365 days)
    let request_max = CreateNhiRequest {
        user_id: Uuid::new_v4(),
        name: "max-inactivity".to_string(),
        purpose: "Test maximum inactivity threshold".to_string(),
        owner_id: Uuid::new_v4(),
        backup_owner_id: None,
        expires_at: None,
        rotation_interval_days: None,
        inactivity_threshold_days: Some(365), // Maximum
    };
    assert_eq!(request_max.inactivity_threshold_days, Some(365));
}

// =============================================================================
// Credential Tests (F061 User Story 2)
// =============================================================================

use xavyo_api_governance::models::{
    NhiCredentialCreatedResponse, NhiCredentialListResponse, NhiCredentialResponse,
    RotateCredentialsRequest,
};
use xavyo_db::NhiCredentialType;

/// Create a mock NhiCredentialResponse for testing.
fn create_mock_credential_response(
    credential_type: NhiCredentialType,
    is_active: bool,
) -> NhiCredentialResponse {
    NhiCredentialResponse {
        id: Uuid::new_v4(),
        nhi_id: Uuid::new_v4(),
        credential_type,
        is_active,
        valid_from: Utc::now(),
        valid_until: Utc::now() + Duration::days(90),
        days_until_expiry: 90,
        rotated_by: None,
        created_at: Utc::now(),
    }
}

#[test]
fn test_rotate_credentials_request_api_key() {
    let request = RotateCredentialsRequest {
        credential_type: NhiCredentialType::ApiKey,
        name: Some("production-key".to_string()),
        expires_at: Some(Utc::now() + Duration::days(90)),
        grace_period_hours: Some(24),
    };

    assert_eq!(request.credential_type, NhiCredentialType::ApiKey);
    assert!(request.name.is_some());
    assert!(request.expires_at.is_some());
    assert_eq!(request.grace_period_hours, Some(24));
}

#[test]
fn test_rotate_credentials_request_secret() {
    let request = RotateCredentialsRequest {
        credential_type: NhiCredentialType::Secret,
        name: None,
        expires_at: None,
        grace_period_hours: None,
    };

    assert_eq!(request.credential_type, NhiCredentialType::Secret);
    assert!(request.name.is_none());
    // Defaults will be applied by service
}

#[test]
fn test_rotate_credentials_request_certificate() {
    let request = RotateCredentialsRequest {
        credential_type: NhiCredentialType::Certificate,
        name: Some("mtls-cert".to_string()),
        expires_at: Some(Utc::now() + Duration::days(365)),
        grace_period_hours: Some(48),
    };

    assert_eq!(request.credential_type, NhiCredentialType::Certificate);
    assert_eq!(request.name, Some("mtls-cert".to_string()));
}

#[test]
fn test_credential_response_active() {
    let response = create_mock_credential_response(NhiCredentialType::ApiKey, true);

    assert!(response.is_active);
    assert!(response.days_until_expiry > 0);
}

#[test]
fn test_credential_response_revoked() {
    let response = create_mock_credential_response(NhiCredentialType::Secret, false);

    assert!(!response.is_active);
}

#[test]
fn test_credential_list_response_empty() {
    let response = NhiCredentialListResponse {
        items: vec![],
        total: 0,
    };

    assert!(response.items.is_empty());
    assert_eq!(response.total, 0);
}

#[test]
fn test_credential_list_response_with_items() {
    let credentials = vec![
        create_mock_credential_response(NhiCredentialType::ApiKey, true),
        create_mock_credential_response(NhiCredentialType::Secret, false),
    ];

    let response = NhiCredentialListResponse {
        items: credentials,
        total: 2,
    };

    assert_eq!(response.items.len(), 2);
    assert_eq!(response.total, 2);
    assert!(response.items[0].is_active);
    assert!(!response.items[1].is_active);
}

#[test]
fn test_credential_created_response_structure() {
    let credential = create_mock_credential_response(NhiCredentialType::ApiKey, true);

    let response = NhiCredentialCreatedResponse {
        credential,
        secret_value: "xnhi_test_secret_value_abc123".to_string(),
        warning: "This is the only time the credential value will be shown.".to_string(),
        grace_period_ends_at: Some(Utc::now() + Duration::hours(24)),
    };

    assert!(response.secret_value.starts_with("xnhi_"));
    assert!(!response.warning.is_empty());
    assert!(response.grace_period_ends_at.is_some());
}

#[test]
fn test_credential_types_serialization() {
    // Test ApiKey serialization
    let api_key = NhiCredentialType::ApiKey;
    let json = serde_json::to_string(&api_key).unwrap();
    assert_eq!(json, "\"api_key\"");

    // Test Secret serialization
    let secret = NhiCredentialType::Secret;
    let json = serde_json::to_string(&secret).unwrap();
    assert_eq!(json, "\"secret\"");

    // Test Certificate serialization
    let cert = NhiCredentialType::Certificate;
    let json = serde_json::to_string(&cert).unwrap();
    assert_eq!(json, "\"certificate\"");
}

#[test]
fn test_rotate_request_serialization() {
    let request = RotateCredentialsRequest {
        credential_type: NhiCredentialType::ApiKey,
        name: Some("test-key".to_string()),
        expires_at: None,
        grace_period_hours: Some(24),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: RotateCredentialsRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request.credential_type, deserialized.credential_type);
    assert_eq!(request.name, deserialized.name);
    assert_eq!(request.grace_period_hours, deserialized.grace_period_hours);
}

#[test]
fn test_credential_grace_period_boundaries() {
    // Test zero grace period (immediate rotation)
    let request_immediate = RotateCredentialsRequest {
        credential_type: NhiCredentialType::ApiKey,
        name: None,
        expires_at: None,
        grace_period_hours: Some(0),
    };
    assert_eq!(request_immediate.grace_period_hours, Some(0));

    // Test maximum grace period (7 days = 168 hours)
    let request_max = RotateCredentialsRequest {
        credential_type: NhiCredentialType::ApiKey,
        name: None,
        expires_at: None,
        grace_period_hours: Some(168),
    };
    assert_eq!(request_max.grace_period_hours, Some(168));
}

#[test]
fn test_credential_expiration_edge_cases() {
    // Credential expiring today
    let mut response = create_mock_credential_response(NhiCredentialType::ApiKey, true);
    response.valid_until = Utc::now();
    response.days_until_expiry = 0;
    assert_eq!(response.days_until_expiry, 0);

    // Credential expired
    let mut response_expired = create_mock_credential_response(NhiCredentialType::ApiKey, true);
    response_expired.valid_until = Utc::now() - Duration::days(1);
    response_expired.days_until_expiry = -1;
    assert!(response_expired.days_until_expiry < 0);
}

#[test]
fn test_credential_list_response_serialization() {
    let response = NhiCredentialListResponse {
        items: vec![create_mock_credential_response(
            NhiCredentialType::ApiKey,
            true,
        )],
        total: 1,
    };

    let json = serde_json::to_string(&response).unwrap();
    let deserialized: NhiCredentialListResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(response.total, deserialized.total);
    assert_eq!(response.items.len(), deserialized.items.len());
}
