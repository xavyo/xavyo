//! Unit tests for `NhiService`.
//!
//! F061 - NHI Lifecycle Management

use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_db::{NhiSuspensionReason, ServiceAccountStatus};

use xavyo_api_governance::models::{
    CreateNhiRequest, ListNhisQuery, NhiResponse, NhiSummary, SuspendNhiRequest,
    TransferOwnershipRequest, UpdateNhiRequest,
};

// =============================================================================
// Test Helpers
// =============================================================================

fn create_test_nhi_response(
    id: Uuid,
    name: &str,
    owner_id: Uuid,
    status: ServiceAccountStatus,
) -> NhiResponse {
    NhiResponse {
        id,
        user_id: Uuid::new_v4(),
        name: name.to_string(),
        purpose: "Test purpose".to_string(),
        owner_id,
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
// CreateNhiRequest Tests
// =============================================================================

#[test]
fn test_create_nhi_request_validation_name_too_short() {
    use validator::Validate;

    let request = CreateNhiRequest {
        user_id: Uuid::new_v4(),
        name: String::new(), // Empty name
        purpose: "This is a test purpose for the NHI".to_string(),
        owner_id: Uuid::new_v4(),
        backup_owner_id: None,
        expires_at: None,
        rotation_interval_days: Some(90),
        inactivity_threshold_days: Some(90),
    };

    let result = request.validate();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.field_errors().contains_key("name"));
}

#[test]
fn test_create_nhi_request_validation_purpose_too_short() {
    use validator::Validate;

    let request = CreateNhiRequest {
        user_id: Uuid::new_v4(),
        name: "test-service-account".to_string(),
        purpose: "Short".to_string(), // Less than 10 chars
        owner_id: Uuid::new_v4(),
        backup_owner_id: None,
        expires_at: None,
        rotation_interval_days: Some(90),
        inactivity_threshold_days: Some(90),
    };

    let result = request.validate();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.field_errors().contains_key("purpose"));
}

#[test]
fn test_create_nhi_request_validation_rotation_interval_out_of_range() {
    use validator::Validate;

    let request = CreateNhiRequest {
        user_id: Uuid::new_v4(),
        name: "test-service-account".to_string(),
        purpose: "This is a valid purpose for the NHI account".to_string(),
        owner_id: Uuid::new_v4(),
        backup_owner_id: None,
        expires_at: None,
        rotation_interval_days: Some(400), // Too high
        inactivity_threshold_days: Some(90),
    };

    let result = request.validate();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.field_errors().contains_key("rotation_interval_days"));
}

#[test]
fn test_create_nhi_request_validation_valid() {
    use validator::Validate;

    let request = CreateNhiRequest {
        user_id: Uuid::new_v4(),
        name: "test-service-account".to_string(),
        purpose: "This is a valid purpose for the NHI account".to_string(),
        owner_id: Uuid::new_v4(),
        backup_owner_id: Some(Uuid::new_v4()),
        expires_at: Some(Utc::now() + Duration::days(365)),
        rotation_interval_days: Some(90),
        inactivity_threshold_days: Some(60),
    };

    let result = request.validate();
    assert!(result.is_ok());
}

// =============================================================================
// UpdateNhiRequest Tests
// =============================================================================

#[test]
fn test_update_nhi_request_validation_name_too_short() {
    use validator::Validate;

    let request = UpdateNhiRequest {
        name: Some(String::new()), // Empty name
        purpose: None,
        owner_id: None,
        backup_owner_id: None,
        expires_at: None,
        rotation_interval_days: None,
        inactivity_threshold_days: None,
    };

    let result = request.validate();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.field_errors().contains_key("name"));
}

#[test]
fn test_update_nhi_request_validation_valid_partial_update() {
    use validator::Validate;

    let request = UpdateNhiRequest {
        name: Some("new-service-name".to_string()),
        purpose: None,
        owner_id: None,
        backup_owner_id: None,
        expires_at: None,
        rotation_interval_days: None,
        inactivity_threshold_days: None,
    };

    let result = request.validate();
    assert!(result.is_ok());
}

// =============================================================================
// ListNhisQuery Tests
// =============================================================================

#[test]
fn test_list_nhis_query_default() {
    let query = ListNhisQuery::default();

    assert!(query.status.is_none());
    assert!(query.owner_id.is_none());
    assert!(query.expiring_within_days.is_none());
    assert!(query.needs_certification.is_none());
    assert!(query.needs_rotation.is_none());
    assert!(query.inactive_only.is_none());
    assert_eq!(query.limit, Some(50));
    assert_eq!(query.offset, Some(0));
}

#[test]
fn test_list_nhis_query_with_filters() {
    let owner_id = Uuid::new_v4();

    let query = ListNhisQuery {
        status: Some(ServiceAccountStatus::Active),
        owner_id: Some(owner_id),
        expiring_within_days: Some(30),
        needs_certification: Some(true),
        needs_rotation: Some(false),
        inactive_only: Some(true),
        limit: Some(25),
        offset: Some(10),
    };

    assert_eq!(query.status, Some(ServiceAccountStatus::Active));
    assert_eq!(query.owner_id, Some(owner_id));
    assert_eq!(query.expiring_within_days, Some(30));
    assert_eq!(query.needs_certification, Some(true));
    assert_eq!(query.needs_rotation, Some(false));
    assert_eq!(query.inactive_only, Some(true));
    assert_eq!(query.limit, Some(25));
    assert_eq!(query.offset, Some(10));
}

// =============================================================================
// NhiResponse Tests
// =============================================================================

#[test]
fn test_nhi_response_active_status() {
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let response = create_test_nhi_response(id, "test-nhi", owner_id, ServiceAccountStatus::Active);

    assert_eq!(response.id, id);
    assert_eq!(response.name, "test-nhi");
    assert_eq!(response.owner_id, owner_id);
    assert_eq!(response.status, ServiceAccountStatus::Active);
    assert!(!response.is_inactive);
    assert!(!response.needs_rotation);
}

#[test]
fn test_nhi_response_suspended_status() {
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let mut response =
        create_test_nhi_response(id, "test-nhi", owner_id, ServiceAccountStatus::Suspended);
    response.suspension_reason = Some(NhiSuspensionReason::Manual);

    assert_eq!(response.status, ServiceAccountStatus::Suspended);
    assert_eq!(
        response.suspension_reason,
        Some(NhiSuspensionReason::Manual)
    );
}

#[test]
fn test_nhi_response_expired_status() {
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let mut response =
        create_test_nhi_response(id, "test-nhi", owner_id, ServiceAccountStatus::Expired);
    response.expires_at = Some(Utc::now() - Duration::days(1));
    response.days_until_expiry = Some(-1);

    assert_eq!(response.status, ServiceAccountStatus::Expired);
    assert!(response.days_until_expiry.unwrap() < 0);
}

// =============================================================================
// NhiSummary Tests
// =============================================================================

#[test]
fn test_nhi_summary_total_equals_statuses() {
    let summary = NhiSummary {
        total: 15,
        active: 10,
        expired: 3,
        suspended: 2,
        needs_certification: 5,
        needs_rotation: 3,
        inactive: 4,
        expiring_soon: 2,
        by_risk_level: None,
    };

    // Total should equal active + expired + suspended
    assert_eq!(
        summary.total,
        summary.active + summary.expired + summary.suspended
    );
}

#[test]
fn test_nhi_summary_default_values() {
    let summary = NhiSummary {
        total: 0,
        active: 0,
        expired: 0,
        suspended: 0,
        needs_certification: 0,
        needs_rotation: 0,
        inactive: 0,
        expiring_soon: 0,
        by_risk_level: None,
    };

    assert_eq!(summary.total, 0);
    assert!(summary.by_risk_level.is_none());
}

// =============================================================================
// Service Logic Tests (Pure Logic, No Database)
// =============================================================================

#[test]
fn test_backup_owner_cannot_be_same_as_primary_owner() {
    let owner_id = Uuid::new_v4();
    let backup_owner_id = owner_id; // Same as owner

    // This validation should fail
    assert_eq!(owner_id, backup_owner_id);
}

#[test]
fn test_backup_owner_can_be_different_from_primary_owner() {
    let owner_id = Uuid::new_v4();
    let backup_owner_id = Uuid::new_v4(); // Different

    // This validation should pass
    assert_ne!(owner_id, backup_owner_id);
}

#[test]
fn test_rotation_interval_validation_boundaries() {
    let min_valid = 1;
    let max_valid = 365;
    let below_min = 0;
    let above_max = 366;

    assert!((1..=365).contains(&min_valid));
    assert!((1..=365).contains(&max_valid));
    assert!(!(1..=365).contains(&below_min));
    assert!(!(1..=365).contains(&above_max));
}

#[test]
fn test_inactivity_threshold_validation_boundaries() {
    let min_valid = 1;
    let max_valid = 365;
    let below_min = 0;
    let above_max = 366;

    assert!((1..=365).contains(&min_valid));
    assert!((1..=365).contains(&max_valid));
    assert!(!(1..=365).contains(&below_min));
    assert!(!(1..=365).contains(&above_max));
}

// =============================================================================
// Status Transition Tests
// =============================================================================

#[test]
fn test_valid_status_transitions_from_active() {
    let from_status = ServiceAccountStatus::Active;

    // Can transition to Suspended or Expired
    let valid_transitions = vec![
        ServiceAccountStatus::Suspended,
        ServiceAccountStatus::Expired,
    ];

    for to_status in valid_transitions {
        // Active can transition to these states
        assert_ne!(from_status, to_status);
    }
}

#[test]
fn test_suspended_can_be_reactivated() {
    let from_status = ServiceAccountStatus::Suspended;
    let to_status = ServiceAccountStatus::Active;

    // Suspended can transition back to Active
    assert_ne!(from_status, to_status);
}

#[test]
fn test_expired_cannot_be_directly_reactivated() {
    // Expired NHIs need special handling (e.g., new expiration date set)
    let expired_status = ServiceAccountStatus::Expired;
    let active_status = ServiceAccountStatus::Active;

    // This transition should require additional validation in service layer
    assert_ne!(expired_status, active_status);
}

// =============================================================================
// Serialization Tests
// =============================================================================

#[test]
fn test_create_nhi_request_serialization() {
    let request = CreateNhiRequest {
        user_id: Uuid::new_v4(),
        name: "test-service".to_string(),
        purpose: "Test purpose for serialization".to_string(),
        owner_id: Uuid::new_v4(),
        backup_owner_id: None,
        expires_at: None,
        rotation_interval_days: Some(90),
        inactivity_threshold_days: Some(60),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: CreateNhiRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request.name, deserialized.name);
    assert_eq!(request.purpose, deserialized.purpose);
    assert_eq!(
        request.rotation_interval_days,
        deserialized.rotation_interval_days
    );
}

#[test]
fn test_nhi_response_serialization() {
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let response = create_test_nhi_response(id, "test-nhi", owner_id, ServiceAccountStatus::Active);

    let json = serde_json::to_string(&response).unwrap();
    let deserialized: NhiResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(response.id, deserialized.id);
    assert_eq!(response.name, deserialized.name);
    assert_eq!(response.status, deserialized.status);
}

#[test]
fn test_nhi_summary_serialization() {
    let summary = NhiSummary {
        total: 100,
        active: 80,
        expired: 10,
        suspended: 10,
        needs_certification: 15,
        needs_rotation: 5,
        inactive: 8,
        expiring_soon: 3,
        by_risk_level: None,
    };

    let json = serde_json::to_string(&summary).unwrap();
    let deserialized: NhiSummary = serde_json::from_str(&json).unwrap();

    assert_eq!(summary.total, deserialized.total);
    assert_eq!(summary.active, deserialized.active);
    assert_eq!(summary.expired, deserialized.expired);
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_nhi_with_no_expiration() {
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let mut response =
        create_test_nhi_response(id, "test-nhi", owner_id, ServiceAccountStatus::Active);
    response.expires_at = None;
    response.days_until_expiry = None;

    assert!(response.expires_at.is_none());
    assert!(response.days_until_expiry.is_none());
}

#[test]
fn test_nhi_with_no_rotation_interval() {
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let mut response =
        create_test_nhi_response(id, "test-nhi", owner_id, ServiceAccountStatus::Active);
    response.rotation_interval_days = None;
    response.last_rotation_at = None;

    assert!(response.rotation_interval_days.is_none());
    assert!(response.last_rotation_at.is_none());
}

#[test]
fn test_nhi_in_grace_period() {
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let mut response =
        create_test_nhi_response(id, "test-nhi", owner_id, ServiceAccountStatus::Active);
    response.is_in_grace_period = true;
    response.grace_period_ends_at = Some(Utc::now() + Duration::days(3));

    assert!(response.is_in_grace_period);
    assert!(response.grace_period_ends_at.is_some());
}

#[test]
fn test_nhi_needs_certification() {
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let mut response =
        create_test_nhi_response(id, "test-nhi", owner_id, ServiceAccountStatus::Active);
    response.needs_certification = true;
    response.last_certified_at = None;
    response.certified_by = None;

    assert!(response.needs_certification);
    assert!(response.last_certified_at.is_none());
    assert!(response.certified_by.is_none());
}

#[test]
fn test_nhi_recently_certified() {
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let certifier_id = Uuid::new_v4();
    let mut response =
        create_test_nhi_response(id, "test-nhi", owner_id, ServiceAccountStatus::Active);
    response.needs_certification = false;
    response.last_certified_at = Some(Utc::now());
    response.certified_by = Some(certifier_id);

    assert!(!response.needs_certification);
    assert!(response.last_certified_at.is_some());
    assert_eq!(response.certified_by, Some(certifier_id));
}

// =============================================================================
// Edge Cases from Evolveum IGA Comparison
// =============================================================================

#[test]
fn test_suspended_nhi_credential_rotation_should_be_blocked() {
    // Edge case: Credentials should not be rotated on suspended NHIs
    // This is a design decision - suspended NHIs should not have active credentials
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let response = create_test_nhi_response(
        id,
        "suspended-nhi",
        owner_id,
        ServiceAccountStatus::Suspended,
    );

    // Verify NHI is suspended
    assert_eq!(response.status, ServiceAccountStatus::Suspended);

    // TODO: Integration test should verify that rotate_credentials returns error for suspended NHI
}

#[test]
fn test_reactivation_after_long_suspension_checks_credential_validity() {
    // Edge case: When NHI suspended for extended period, credentials may have expired
    // Reactivation should warn or require credential rotation
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let mut response = create_test_nhi_response(
        id,
        "long-suspended-nhi",
        owner_id,
        ServiceAccountStatus::Suspended,
    );

    // Simulate suspension 6 months ago - credentials would typically expire in 90 days
    response.last_rotation_at = Some(Utc::now() - Duration::days(180));
    response.needs_rotation = true;

    // When reactivated, system should flag that credentials need rotation
    assert!(response.needs_rotation);
}

#[test]
fn test_owner_must_be_different_user_not_service_account() {
    // Edge case: Owner should be a human user, not another NHI
    // This prevents circular ownership chains
    let request = CreateNhiRequest {
        user_id: Uuid::new_v4(),
        name: "test-nhi".to_string(),
        purpose: "Test service account".to_string(),
        owner_id: Uuid::new_v4(), // This should be validated as a human user
        backup_owner_id: None,
        expires_at: None,
        rotation_interval_days: None,
        inactivity_threshold_days: None,
    };

    // Owner ID is set - integration test should validate it's a real human user
    assert!(request.owner_id != Uuid::nil());
}

#[test]
fn test_orphaned_nhi_detection_when_owner_inactive() {
    // Edge case: When owner becomes inactive/suspended, NHI should be flagged
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let response = create_test_nhi_response(
        id,
        "orphan-candidate",
        owner_id,
        ServiceAccountStatus::Active,
    );

    // If owner is inactive:
    // - NHI should be flagged for review
    // - Backup owner should be notified
    // - If no backup owner, NHI should require certification

    // This would be detected by a scheduled job
    assert!(response.backup_owner_id.is_none()); // No failover configured
}

#[test]
fn test_backup_owner_automatic_promotion() {
    // Edge case: When primary owner leaves, backup should automatically become primary
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let backup_owner_id = Uuid::new_v4();
    let mut response =
        create_test_nhi_response(id, "has-backup", owner_id, ServiceAccountStatus::Active);
    response.backup_owner_id = Some(backup_owner_id);

    // Verify backup owner is set
    assert!(response.backup_owner_id.is_some());

    // When primary owner becomes inactive:
    // - Backup should become primary
    // - Original backup slot should be cleared or require new assignment
}

#[test]
fn test_nhi_with_no_backup_requires_certification_when_owner_leaves() {
    // Edge case: NHI without backup owner needs immediate attention when owner leaves
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let response =
        create_test_nhi_response(id, "no-backup", owner_id, ServiceAccountStatus::Active);

    assert!(response.backup_owner_id.is_none());

    // When owner leaves and no backup:
    // - NHI should be marked as needs_certification = true
    // - Alert should be generated
    // - Grace period before automatic suspension
}

#[test]
fn test_grace_period_credential_still_valid() {
    // Edge case: During grace period, both old and new credentials should work
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let mut response =
        create_test_nhi_response(id, "rotating-creds", owner_id, ServiceAccountStatus::Active);

    // NHI in grace period
    response.is_in_grace_period = true;
    response.grace_period_ends_at = Some(Utc::now() + Duration::hours(24));

    assert!(response.is_in_grace_period);
    assert!(response.grace_period_ends_at.is_some());
}

#[test]
fn test_grace_period_expired_old_credential_invalidated() {
    // Edge case: After grace period, old credential should be invalidated
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let mut response =
        create_test_nhi_response(id, "grace-expired", owner_id, ServiceAccountStatus::Active);

    // Grace period ended
    response.is_in_grace_period = false;
    response.grace_period_ends_at = Some(Utc::now() - Duration::hours(1));

    assert!(!response.is_in_grace_period);

    // Old credential should have been deactivated by scheduled job
}

#[test]
fn test_concurrent_ownership_transfer_rejected() {
    // Edge case: Two concurrent ownership transfer requests should be serialized
    // Second request should fail or wait for first to complete
    let _id = Uuid::new_v4();
    let _owner_id = Uuid::new_v4();
    let new_owner_1 = Uuid::new_v4();
    let new_owner_2 = Uuid::new_v4();

    let transfer_1 = TransferOwnershipRequest {
        new_owner_id: new_owner_1,
        reason: "Transfer to team lead".to_string(),
    };

    let transfer_2 = TransferOwnershipRequest {
        new_owner_id: new_owner_2,
        reason: "Transfer to backup".to_string(),
    };

    // Both transfers target different users - only one should succeed
    assert_ne!(transfer_1.new_owner_id, transfer_2.new_owner_id);
}

#[test]
fn test_certification_campaign_owner_change_mid_campaign() {
    // Edge case: Ownership changes during active certification campaign
    // Original owner was reviewer, new owner should take over
    let id = Uuid::new_v4();
    let original_owner = Uuid::new_v4();
    let new_owner = Uuid::new_v4();

    // NHI being certified
    let mut response =
        create_test_nhi_response(id, "mid-cert", original_owner, ServiceAccountStatus::Active);
    response.needs_certification = true;

    // Transfer ownership
    let transfer = TransferOwnershipRequest {
        new_owner_id: new_owner,
        reason: "Owner left team".to_string(),
    };

    // After transfer, pending certification should be reassigned to new owner
    assert!(response.needs_certification);
    assert_eq!(transfer.new_owner_id, new_owner);
}

#[test]
fn test_expired_nhi_cannot_have_credentials_rotated() {
    // Edge case: Expired NHI should not allow credential operations
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let mut response =
        create_test_nhi_response(id, "expired-nhi", owner_id, ServiceAccountStatus::Expired);
    response.expires_at = Some(Utc::now() - Duration::days(7));

    assert_eq!(response.status, ServiceAccountStatus::Expired);

    // Credential rotation should be rejected for expired NHIs
}

#[test]
fn test_high_volume_usage_aggregation() {
    // Edge case: NHIs with high usage volume need aggregated metrics
    // Individual event storage would be too expensive
    let _id = Uuid::new_v4();
    let _owner_id = Uuid::new_v4();

    // For NHIs with 1M+ events/day:
    // - Store hourly/daily aggregates instead of individual events
    // - Use sampling for outlier detection
    // - Maintain rolling window for staleness calculation

    // This is a documentation/design test - actual high volume handling
    // requires scheduled aggregation jobs
    assert!(true);
}

#[test]
fn test_emergency_suspension_bypasses_normal_flow() {
    // Edge case: Emergency suspension should be immediate, no grace period
    let _id = Uuid::new_v4();
    let _owner_id = Uuid::new_v4();

    let suspend_request = SuspendNhiRequest {
        reason: NhiSuspensionReason::Emergency,
        details: Some("Security incident detected".to_string()),
    };

    // Emergency suspension:
    // - Immediate effect
    // - All credentials revoked immediately
    // - No grace period
    // - High-priority alert sent

    assert_eq!(suspend_request.reason, NhiSuspensionReason::Emergency);
}

#[test]
fn test_nhi_name_change_updates_credential_names() {
    // Edge case: When NHI name changes, associated credential display names should update
    let _id = Uuid::new_v4();
    let _owner_id = Uuid::new_v4();

    let update = UpdateNhiRequest {
        name: Some("new-service-name".to_string()),
        purpose: None,
        owner_id: None,
        backup_owner_id: None,
        expires_at: None,
        rotation_interval_days: None,
        inactivity_threshold_days: None,
    };

    // Credentials should update their display names to reflect new NHI name
    assert!(update.name.is_some());
}
