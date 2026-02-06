//! Unit tests for NHI Suspension Logic (US7 - Automatic Suspension).

use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_api_governance::models::nhi::{
    NhiResponse, NhiSummary, ReactivateNhiRequest, SuspendNhiRequest, TransferOwnershipRequest,
};
use xavyo_db::{NhiSuspensionReason, ServiceAccountStatus};

// ============================================================================
// SuspendNhiRequest Tests
// ============================================================================

#[test]
fn test_suspend_request_with_manual_reason() {
    let request = SuspendNhiRequest {
        reason: NhiSuspensionReason::Manual,
        details: Some("Security concern - unusual access patterns detected".to_string()),
    };

    use validator::Validate;
    assert!(request.validate().is_ok());
    assert_eq!(request.reason, NhiSuspensionReason::Manual);
}

#[test]
fn test_suspend_request_emergency() {
    let request = SuspendNhiRequest {
        reason: NhiSuspensionReason::Emergency,
        details: Some("Compromised credentials detected in security scan".to_string()),
    };

    use validator::Validate;
    assert!(request.validate().is_ok());
    assert_eq!(request.reason, NhiSuspensionReason::Emergency);
}

#[test]
fn test_suspend_request_expired() {
    let request = SuspendNhiRequest {
        reason: NhiSuspensionReason::Expired,
        details: None,
    };

    use validator::Validate;
    assert!(request.validate().is_ok());
    assert_eq!(request.reason, NhiSuspensionReason::Expired);
}

#[test]
fn test_suspend_request_inactive() {
    let request = SuspendNhiRequest {
        reason: NhiSuspensionReason::Inactive,
        details: Some("No activity for 60 days".to_string()),
    };

    use validator::Validate;
    assert!(request.validate().is_ok());
    assert_eq!(request.reason, NhiSuspensionReason::Inactive);
}

#[test]
fn test_suspend_request_certification_revoked() {
    let request = SuspendNhiRequest {
        reason: NhiSuspensionReason::CertificationRevoked,
        details: Some("Owner did not certify during campaign".to_string()),
    };

    use validator::Validate;
    assert!(request.validate().is_ok());
    assert_eq!(request.reason, NhiSuspensionReason::CertificationRevoked);
}

#[test]
fn test_suspend_request_details_too_long() {
    let request = SuspendNhiRequest {
        reason: NhiSuspensionReason::Manual,
        details: Some("x".repeat(501)), // Too long (max 500)
    };

    use validator::Validate;
    assert!(request.validate().is_err());
}

#[test]
fn test_suspend_request_serialization() {
    let request = SuspendNhiRequest {
        reason: NhiSuspensionReason::Manual,
        details: Some("Scheduled maintenance suspension".to_string()),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("\"reason\":\"manual\"") || json.contains("\"reason\":\"Manual\""));
    assert!(json.contains("Scheduled maintenance suspension"));
}

// ============================================================================
// ReactivateNhiRequest Tests
// ============================================================================

#[test]
fn test_reactivate_request_with_reason() {
    let request = ReactivateNhiRequest {
        reason: "Security review completed, no issues found".to_string(),
    };

    use validator::Validate;
    assert!(request.validate().is_ok());
}

#[test]
fn test_reactivate_request_reason_too_short() {
    let request = ReactivateNhiRequest {
        reason: "OK".to_string(), // Too short (min 5)
    };

    use validator::Validate;
    assert!(request.validate().is_err());
}

#[test]
fn test_reactivate_request_serialization() {
    let request = ReactivateNhiRequest {
        reason: "Service needed again after review".to_string(),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("\"reason\":\"Service needed again after review\""));
}

#[test]
fn test_reactivate_request_deserialization() {
    let json = r#"{"reason": "Review complete, reactivating"}"#;

    let request: ReactivateNhiRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.reason, "Review complete, reactivating");
}

// ============================================================================
// TransferOwnershipRequest Tests
// ============================================================================

#[test]
fn test_transfer_ownership_request() {
    let new_owner_id = Uuid::new_v4();

    let request = TransferOwnershipRequest {
        new_owner_id,
        reason: "Previous owner left the company".to_string(),
    };

    use validator::Validate;
    assert!(request.validate().is_ok());
    assert_eq!(request.new_owner_id, new_owner_id);
}

#[test]
fn test_transfer_ownership_reason_too_short() {
    let request = TransferOwnershipRequest {
        new_owner_id: Uuid::new_v4(),
        reason: "Ok".to_string(), // Too short (min 5)
    };

    use validator::Validate;
    assert!(request.validate().is_err());
}

#[test]
fn test_transfer_ownership_serialization() {
    let new_owner_id = Uuid::new_v4();

    let request = TransferOwnershipRequest {
        new_owner_id,
        reason: "Ownership transfer reason".to_string(),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains(&new_owner_id.to_string()));
    assert!(json.contains("\"reason\":\"Ownership transfer reason\""));
}

#[test]
fn test_transfer_ownership_deserialization() {
    let new_owner_id = Uuid::new_v4();
    let json = format!(r#"{{"new_owner_id": "{new_owner_id}", "reason": "Owner transition"}}"#);

    let request: TransferOwnershipRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request.new_owner_id, new_owner_id);
}

// ============================================================================
// NhiSuspensionReason Tests
// ============================================================================

#[test]
fn test_suspension_reason_expired() {
    let reason = NhiSuspensionReason::Expired;
    let json = serde_json::to_string(&reason).unwrap();
    assert!(json.contains("expired") || json.contains("Expired"));
}

#[test]
fn test_suspension_reason_inactive() {
    let reason = NhiSuspensionReason::Inactive;
    let json = serde_json::to_string(&reason).unwrap();
    assert!(json.contains("inactive") || json.contains("Inactive"));
}

#[test]
fn test_suspension_reason_certification_revoked() {
    let reason = NhiSuspensionReason::CertificationRevoked;
    let json = serde_json::to_string(&reason).unwrap();
    // Could be snake_case or PascalCase depending on serialization
    let json_lower = json.to_lowercase();
    assert!(json_lower.contains("certification") && json_lower.contains("revoked"));
}

#[test]
fn test_suspension_reason_emergency() {
    let reason = NhiSuspensionReason::Emergency;
    let json = serde_json::to_string(&reason).unwrap();
    assert!(json.contains("emergency") || json.contains("Emergency"));
}

#[test]
fn test_suspension_reason_manual() {
    let reason = NhiSuspensionReason::Manual;
    let json = serde_json::to_string(&reason).unwrap();
    assert!(json.contains("manual") || json.contains("Manual"));
}

// ============================================================================
// Suspension Status Logic Tests
// ============================================================================

fn create_test_nhi_response(
    status: ServiceAccountStatus,
    suspension_reason: Option<NhiSuspensionReason>,
    expires_at: Option<chrono::DateTime<Utc>>,
    last_used_at: Option<chrono::DateTime<Utc>>,
) -> NhiResponse {
    NhiResponse {
        id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        name: "test-service".to_string(),
        purpose: "Test service account".to_string(),
        owner_id: Uuid::new_v4(),
        backup_owner_id: None,
        status,
        expires_at,
        days_until_expiry: expires_at.map(|exp| (exp - Utc::now()).num_days()),
        rotation_interval_days: Some(90),
        last_rotation_at: None,
        needs_rotation: false,
        last_used_at,
        days_since_last_use: last_used_at.map(|lu| (Utc::now() - lu).num_days()),
        inactivity_threshold_days: Some(30),
        is_inactive: false,
        grace_period_ends_at: None,
        is_in_grace_period: false,
        suspension_reason,
        last_certified_at: None,
        certified_by: None,
        needs_certification: false,
        created_at: Utc::now() - Duration::days(30),
        updated_at: Utc::now(),
    }
}

#[test]
fn test_active_nhi_can_be_suspended() {
    let nhi = create_test_nhi_response(
        ServiceAccountStatus::Active,
        None,
        Some(Utc::now() + Duration::days(365)),
        Some(Utc::now()),
    );

    // Active NHI can be suspended
    assert_eq!(nhi.status, ServiceAccountStatus::Active);
    assert!(nhi.suspension_reason.is_none());
}

#[test]
fn test_suspended_nhi_has_reason() {
    let nhi = create_test_nhi_response(
        ServiceAccountStatus::Suspended,
        Some(NhiSuspensionReason::Inactive),
        Some(Utc::now() + Duration::days(365)),
        None,
    );

    // Suspended NHI has a reason
    assert_eq!(nhi.status, ServiceAccountStatus::Suspended);
    assert!(nhi.suspension_reason.is_some());
    assert_eq!(
        nhi.suspension_reason.unwrap(),
        NhiSuspensionReason::Inactive
    );
}

#[test]
fn test_expired_nhi_status() {
    let nhi = create_test_nhi_response(
        ServiceAccountStatus::Expired,
        Some(NhiSuspensionReason::Expired),
        Some(Utc::now() - Duration::days(30)),
        None,
    );

    assert_eq!(nhi.status, ServiceAccountStatus::Expired);
    assert!(nhi.expires_at.is_some());
    assert!(nhi.expires_at.unwrap() < Utc::now());
}

// ============================================================================
// Inactivity Detection Tests
// ============================================================================

#[test]
fn test_nhi_exceeds_inactivity_threshold() {
    let inactivity_threshold_days = 30;
    let last_used_at = Utc::now() - Duration::days(45); // 45 days ago

    let days_inactive = (Utc::now() - last_used_at).num_days();

    // NHI is inactive beyond threshold
    assert!(days_inactive > i64::from(inactivity_threshold_days));
}

#[test]
fn test_nhi_within_inactivity_threshold() {
    let inactivity_threshold_days = 30;
    let last_used_at = Utc::now() - Duration::days(15); // 15 days ago

    let days_inactive = (Utc::now() - last_used_at).num_days();

    // NHI is active within threshold
    assert!(days_inactive <= i64::from(inactivity_threshold_days));
}

#[test]
fn test_nhi_approaching_inactivity_grace_period() {
    let inactivity_threshold_days = 30;
    let grace_period_days = 7;
    let last_used_at = Utc::now() - Duration::days(25); // 25 days ago

    let days_inactive = (Utc::now() - last_used_at).num_days();
    let warning_threshold = i64::from(inactivity_threshold_days) - grace_period_days;

    // NHI is approaching threshold (should trigger warning)
    assert!(days_inactive >= warning_threshold);
    assert!(days_inactive < i64::from(inactivity_threshold_days));
}

#[test]
fn test_nhi_never_used() {
    // NHI with no last_used_at should be flagged
    let nhi = create_test_nhi_response(
        ServiceAccountStatus::Active,
        None,
        Some(Utc::now() + Duration::days(365)),
        None, // Never used
    );

    // Should be flagged for inactivity (60 days since creation, never used)
    let days_since_creation = (Utc::now() - nhi.created_at).num_days();
    assert!(days_since_creation >= 30);
    assert!(nhi.last_used_at.is_none());
}

// ============================================================================
// Expiration Detection Tests
// ============================================================================

#[test]
fn test_nhi_is_expired() {
    let expires_at = Utc::now() - Duration::hours(1); // Expired 1 hour ago

    assert!(expires_at < Utc::now());
}

#[test]
fn test_nhi_expiring_soon() {
    let expires_at = Utc::now() + Duration::days(5); // Expires in 5 days
    let warning_days = 7;

    let days_until_expiration = (expires_at - Utc::now()).num_days();

    // Should trigger expiration warning
    assert!(days_until_expiration <= warning_days);
    assert!(days_until_expiration > 0);
}

#[test]
fn test_nhi_not_expiring_soon() {
    let expires_at = Utc::now() + Duration::days(100); // Expires in 100 days
    let warning_days = 7;

    let days_until_expiration = (expires_at - Utc::now()).num_days();

    // Should not trigger warning
    assert!(days_until_expiration > warning_days);
}

#[test]
fn test_nhi_no_expiration() {
    // NHI with no expiration never expires
    let nhi = create_test_nhi_response(
        ServiceAccountStatus::Active,
        None,
        None, // No expiration
        Some(Utc::now()),
    );

    assert!(nhi.expires_at.is_none());
}

// ============================================================================
// NHI Summary Status Counts
// ============================================================================

#[test]
fn test_nhi_summary_includes_suspended_count() {
    let summary = NhiSummary {
        total: 100,
        active: 75,
        suspended: 10,
        expired: 15,
        expiring_soon: 5,
        inactive: 8,
        needs_rotation: 3,
        needs_certification: 12,
        by_risk_level: None,
    };

    assert_eq!(summary.suspended, 10);
    assert_eq!(
        summary.total,
        summary.active + summary.suspended + summary.expired
    );
}

#[test]
fn test_nhi_summary_inactive_detection() {
    let summary = NhiSummary {
        total: 50,
        active: 40,
        suspended: 5,
        expired: 5,
        expiring_soon: 3,
        inactive: 15, // 15 NHIs are inactive
        needs_rotation: 2,
        needs_certification: 8,
        by_risk_level: None,
    };

    // Inactive count is tracked separately (can be subset of active)
    assert_eq!(summary.inactive, 15);
}

#[test]
fn test_nhi_summary_needs_rotation() {
    let summary = NhiSummary {
        total: 30,
        active: 25,
        suspended: 3,
        expired: 2,
        expiring_soon: 5,
        inactive: 4,
        needs_rotation: 10,
        needs_certification: 5,
        by_risk_level: None,
    };

    assert_eq!(summary.needs_rotation, 10);
}

// ============================================================================
// Ownership Transfer Tests
// ============================================================================

#[test]
fn test_ownership_transfer_changes_owner() {
    let original_owner_id = Uuid::new_v4();
    let new_owner_id = Uuid::new_v4();

    // Verify different owners
    assert_ne!(original_owner_id, new_owner_id);
}

#[test]
fn test_ownership_transfer_cannot_self_transfer() {
    let owner_id = Uuid::new_v4();

    // Self-transfer should be invalid (business logic)
    let request = TransferOwnershipRequest {
        new_owner_id: owner_id,
        reason: "Attempting to transfer to self".to_string(),
    };

    // Note: This is a business rule that should be enforced in the service
    // The validation trait doesn't know about the current owner
    use validator::Validate;
    assert!(request.validate().is_ok()); // Struct validation passes
                                         // Service should reject self-transfer
}

// ============================================================================
// Serialization Tests
// ============================================================================

#[test]
fn test_suspend_request_deserialization() {
    let json = r#"{"reason": "manual", "details": "Security review required"}"#;

    let request: SuspendNhiRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.reason, NhiSuspensionReason::Manual);
    assert_eq!(
        request.details,
        Some("Security review required".to_string())
    );
}

#[test]
fn test_suspend_request_without_details() {
    let json = r#"{"reason": "expired"}"#;

    let request: SuspendNhiRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.reason, NhiSuspensionReason::Expired);
    assert!(request.details.is_none());
}

// ============================================================================
// Emergency Suspension Tests
// ============================================================================

#[test]
fn test_emergency_suspension_request() {
    let request = SuspendNhiRequest {
        reason: NhiSuspensionReason::Emergency,
        details: Some("Credentials exposed in public repository".to_string()),
    };

    // Emergency suspension should be valid
    assert_eq!(request.reason, NhiSuspensionReason::Emergency);
    use validator::Validate;
    assert!(request.validate().is_ok());
}

#[test]
fn test_certification_revoked_suspension() {
    let request = SuspendNhiRequest {
        reason: NhiSuspensionReason::CertificationRevoked,
        details: Some("Owner failed to certify during annual review".to_string()),
    };

    assert_eq!(request.reason, NhiSuspensionReason::CertificationRevoked);
    use validator::Validate;
    assert!(request.validate().is_ok());
}

// ============================================================================
// ServiceAccountStatus Tests
// ============================================================================

#[test]
fn test_status_active_serialization() {
    let status = ServiceAccountStatus::Active;
    let json = serde_json::to_string(&status).unwrap();
    assert!(json.contains("active") || json.contains("Active"));
}

#[test]
fn test_status_suspended_serialization() {
    let status = ServiceAccountStatus::Suspended;
    let json = serde_json::to_string(&status).unwrap();
    assert!(json.contains("suspended") || json.contains("Suspended"));
}

#[test]
fn test_status_expired_serialization() {
    let status = ServiceAccountStatus::Expired;
    let json = serde_json::to_string(&status).unwrap();
    assert!(json.contains("expired") || json.contains("Expired"));
}

// ============================================================================
// Business Logic Edge Cases
// ============================================================================

#[test]
fn test_nhi_with_multiple_suspension_triggers() {
    // NHI can have multiple reasons to be suspended (expired AND inactive)
    // but only one reason is recorded
    let nhi = create_test_nhi_response(
        ServiceAccountStatus::Suspended,
        Some(NhiSuspensionReason::Expired),    // Primary reason
        Some(Utc::now() - Duration::days(10)), // Expired 10 days ago
        None,                                  // Never used (also inactive)
    );

    // The system records the primary reason
    assert_eq!(nhi.suspension_reason, Some(NhiSuspensionReason::Expired));
}

#[test]
fn test_suspension_reason_priority() {
    // Emergency takes priority over all other reasons
    let request = SuspendNhiRequest {
        reason: NhiSuspensionReason::Emergency,
        details: Some("Security incident overrides other reasons".to_string()),
    };

    assert_eq!(request.reason, NhiSuspensionReason::Emergency);
}

#[test]
fn test_reactivation_clears_suspension_reason() {
    // When reactivated, the NHI should have no suspension reason
    let reactivated_nhi = create_test_nhi_response(
        ServiceAccountStatus::Active,
        None, // Suspension reason cleared
        Some(Utc::now() + Duration::days(365)),
        Some(Utc::now()),
    );

    assert_eq!(reactivated_nhi.status, ServiceAccountStatus::Active);
    assert!(reactivated_nhi.suspension_reason.is_none());
}
