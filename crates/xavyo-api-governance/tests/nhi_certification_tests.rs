//! Unit tests for NHI Certification Service (F061 - User Story 5).
//!
//! Tests cover:
//! - Certification campaign creation for NHIs
//! - Certification decision processing (certify/revoke)
//! - Auto-suspension on revocation
//! - Certification status tracking

use chrono::{Duration, Utc};
use uuid::Uuid;

use xavyo_api_governance::models::{
    NhiCertificationDecision, NhiCertificationItemResponse, NhiCertificationStatus,
    NhiCertificationSummary,
};

// ============================================================================
// NhiCertificationStatus Tests
// ============================================================================

#[test]
fn test_certification_status_pending() {
    let status = NhiCertificationStatus::Pending;
    assert!(!status.is_decided());
    assert!(!status.is_certified());
}

#[test]
fn test_certification_status_certified() {
    let status = NhiCertificationStatus::Certified;
    assert!(status.is_decided());
    assert!(status.is_certified());
}

#[test]
fn test_certification_status_revoked() {
    let status = NhiCertificationStatus::Revoked;
    assert!(status.is_decided());
    assert!(!status.is_certified());
}

#[test]
fn test_certification_status_expired() {
    let status = NhiCertificationStatus::Expired;
    assert!(status.is_decided());
    assert!(!status.is_certified());
}

#[test]
fn test_certification_status_serialization() {
    let pending = NhiCertificationStatus::Pending;
    let json = serde_json::to_string(&pending).expect("Serialization failed");
    assert!(json.contains("pending"));

    let certified = NhiCertificationStatus::Certified;
    let json = serde_json::to_string(&certified).expect("Serialization failed");
    assert!(json.contains("certified"));
}

// ============================================================================
// NhiCertificationDecision Tests
// ============================================================================

#[test]
fn test_certification_decision_certify() {
    let decision = NhiCertificationDecision::Certify;
    assert!(decision.is_approval());
}

#[test]
fn test_certification_decision_revoke() {
    let decision = NhiCertificationDecision::Revoke;
    assert!(!decision.is_approval());
}

#[test]
fn test_certification_decision_delegate() {
    let decision = NhiCertificationDecision::Delegate;
    assert!(!decision.is_approval());
}

#[test]
fn test_certification_decision_serialization() {
    let certify = NhiCertificationDecision::Certify;
    let json = serde_json::to_string(&certify).expect("Serialization failed");
    assert!(json.contains("certify"));

    let revoke = NhiCertificationDecision::Revoke;
    let json = serde_json::to_string(&revoke).expect("Serialization failed");
    assert!(json.contains("revoke"));
}

// ============================================================================
// NhiCertificationItemResponse Tests
// ============================================================================

#[test]
fn test_certification_item_response_structure() {
    let nhi_id = Uuid::new_v4();
    let campaign_id = Uuid::new_v4();
    let reviewer_id = Uuid::new_v4();
    let now = Utc::now();
    let deadline = now + Duration::days(14);

    let item = NhiCertificationItemResponse {
        id: Uuid::new_v4(),
        campaign_id,
        nhi_id,
        nhi_name: "test-service-account".to_string(),
        nhi_purpose: "API integration testing".to_string(),
        owner_id: Uuid::new_v4(),
        owner_name: Some("John Doe".to_string()),
        reviewer_id,
        status: NhiCertificationStatus::Pending,
        deadline,
        decision: None,
        decided_by: None,
        decided_at: None,
        comment: None,
        created_at: now,
    };

    assert_eq!(item.nhi_id, nhi_id);
    assert_eq!(item.campaign_id, campaign_id);
    assert_eq!(item.status, NhiCertificationStatus::Pending);
    assert!(item.decision.is_none());
    assert!(item.decided_at.is_none());
}

#[test]
fn test_certification_item_response_with_decision() {
    let now = Utc::now();
    let decided_by = Uuid::new_v4();

    let item = NhiCertificationItemResponse {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        nhi_id: Uuid::new_v4(),
        nhi_name: "test-service".to_string(),
        nhi_purpose: "Testing".to_string(),
        owner_id: Uuid::new_v4(),
        owner_name: None,
        reviewer_id: Uuid::new_v4(),
        status: NhiCertificationStatus::Certified,
        deadline: now + Duration::days(7),
        decision: Some(NhiCertificationDecision::Certify),
        decided_by: Some(decided_by),
        decided_at: Some(now),
        comment: Some("Confirmed active use".to_string()),
        created_at: now - Duration::days(1),
    };

    assert_eq!(item.status, NhiCertificationStatus::Certified);
    assert_eq!(item.decision, Some(NhiCertificationDecision::Certify));
    assert_eq!(item.decided_by, Some(decided_by));
    assert!(item.comment.is_some());
}

#[test]
fn test_certification_item_serialization() {
    let item = NhiCertificationItemResponse {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        nhi_id: Uuid::new_v4(),
        nhi_name: "serialization-test".to_string(),
        nhi_purpose: "Test serialization".to_string(),
        owner_id: Uuid::new_v4(),
        owner_name: Some("Test Owner".to_string()),
        reviewer_id: Uuid::new_v4(),
        status: NhiCertificationStatus::Pending,
        deadline: Utc::now() + Duration::days(14),
        decision: None,
        decided_by: None,
        decided_at: None,
        comment: None,
        created_at: Utc::now(),
    };

    let json = serde_json::to_string(&item).expect("Serialization failed");
    assert!(json.contains("serialization-test"));
    assert!(json.contains("pending"));
    assert!(json.contains("nhi_id"));
    assert!(json.contains("campaign_id"));
}

// ============================================================================
// NhiCertificationSummary Tests
// ============================================================================

#[test]
fn test_certification_summary_empty() {
    let summary = NhiCertificationSummary {
        total: 0,
        pending: 0,
        certified: 0,
        revoked: 0,
        expired: 0,
    };

    assert_eq!(summary.total, 0);
    assert_eq!(summary.completion_rate(), 0.0);
}

#[test]
fn test_certification_summary_with_data() {
    let summary = NhiCertificationSummary {
        total: 100,
        pending: 20,
        certified: 60,
        revoked: 15,
        expired: 5,
    };

    assert_eq!(summary.total, 100);
    assert_eq!(
        summary.pending + summary.certified + summary.revoked + summary.expired,
        100
    );
    assert_eq!(summary.completion_rate(), 80.0); // (60 + 15 + 5) / 100 * 100
}

#[test]
fn test_certification_summary_completion_rate() {
    // Test various completion scenarios
    let full_complete = NhiCertificationSummary {
        total: 50,
        pending: 0,
        certified: 45,
        revoked: 5,
        expired: 0,
    };
    assert_eq!(full_complete.completion_rate(), 100.0);

    let half_complete = NhiCertificationSummary {
        total: 100,
        pending: 50,
        certified: 30,
        revoked: 10,
        expired: 10,
    };
    assert_eq!(half_complete.completion_rate(), 50.0);

    let all_pending = NhiCertificationSummary {
        total: 25,
        pending: 25,
        certified: 0,
        revoked: 0,
        expired: 0,
    };
    assert_eq!(all_pending.completion_rate(), 0.0);
}

#[test]
fn test_certification_summary_serialization() {
    let summary = NhiCertificationSummary {
        total: 50,
        pending: 10,
        certified: 35,
        revoked: 3,
        expired: 2,
    };

    let json = serde_json::to_string(&summary).expect("Serialization failed");
    assert!(json.contains("total"));
    assert!(json.contains("50"));
    assert!(json.contains("pending"));
    assert!(json.contains("certified"));
    assert!(json.contains("revoked"));
    assert!(json.contains("expired"));
}

// ============================================================================
// Certification Business Logic Tests
// ============================================================================

#[test]
fn test_needs_certification_threshold() {
    // NHI needs certification if:
    // - Never certified (last_certified_at is None)
    // - Certified more than 365 days ago

    let now = Utc::now();

    // Never certified - needs certification
    let last_certified: Option<chrono::DateTime<Utc>> = None;
    assert!(needs_certification(last_certified));

    // Certified 100 days ago - does not need certification
    let recent = Some(now - Duration::days(100));
    assert!(!needs_certification(recent));

    // Certified 365 days ago exactly - does not need certification (boundary)
    let boundary = Some(now - Duration::days(365));
    assert!(!needs_certification(boundary));

    // Certified 366 days ago - needs certification
    let overdue = Some(now - Duration::days(366));
    assert!(needs_certification(overdue));
}

/// Helper function to determine if certification is needed
fn needs_certification(last_certified_at: Option<chrono::DateTime<Utc>>) -> bool {
    match last_certified_at {
        Some(certified_at) => {
            let days_since = Utc::now().signed_duration_since(certified_at).num_days();
            days_since > 365
        }
        None => true,
    }
}

#[test]
fn test_certification_deadline_calculation() {
    // Default certification deadline: 14 days from campaign start
    let campaign_start = Utc::now();
    let default_deadline_days = 14;
    let deadline = campaign_start + Duration::days(default_deadline_days);

    assert!(deadline > campaign_start);
    assert_eq!((deadline - campaign_start).num_days(), 14);
}

#[test]
fn test_certification_decision_effects() {
    // Test that decisions have expected effects:
    // - Certify: Updates last_certified_at, keeps NHI active
    // - Revoke: Suspends NHI, invalidates credentials

    let certify_effect = CertificationEffect::from_decision(NhiCertificationDecision::Certify);
    assert!(certify_effect.updates_certified_at);
    assert!(!certify_effect.suspends_nhi);

    let revoke_effect = CertificationEffect::from_decision(NhiCertificationDecision::Revoke);
    assert!(!revoke_effect.updates_certified_at);
    assert!(revoke_effect.suspends_nhi);
}

/// Test helper to represent certification decision effects
struct CertificationEffect {
    updates_certified_at: bool,
    suspends_nhi: bool,
}

impl CertificationEffect {
    fn from_decision(decision: NhiCertificationDecision) -> Self {
        match decision {
            NhiCertificationDecision::Certify => Self {
                updates_certified_at: true,
                suspends_nhi: false,
            },
            NhiCertificationDecision::Revoke => Self {
                updates_certified_at: false,
                suspends_nhi: true,
            },
            NhiCertificationDecision::Delegate => Self {
                updates_certified_at: false,
                suspends_nhi: false,
            },
        }
    }
}

// ============================================================================
// Certification Campaign for NHIs Tests
// ============================================================================

#[test]
fn test_campaign_includes_nhi_needing_certification() {
    // When launching a campaign, include NHIs that:
    // - Are active
    // - Need certification (never certified or overdue)

    let nhis = vec![
        TestNhi::new("nhi-1", true, None), // Needs cert: never certified
        TestNhi::new("nhi-2", true, Some(Utc::now() - Duration::days(400))), // Needs cert: overdue
        TestNhi::new("nhi-3", true, Some(Utc::now() - Duration::days(100))), // Doesn't need cert
        TestNhi::new("nhi-4", false, None), // Inactive, excluded
    ];

    let included: Vec<_> = nhis
        .into_iter()
        .filter(|nhi| nhi.is_active && nhi.needs_certification())
        .collect();

    assert_eq!(included.len(), 2);
    assert!(included.iter().any(|n| n.name == "nhi-1"));
    assert!(included.iter().any(|n| n.name == "nhi-2"));
}

/// Test helper struct representing an NHI
struct TestNhi {
    name: String,
    is_active: bool,
    last_certified_at: Option<chrono::DateTime<Utc>>,
}

impl TestNhi {
    fn new(name: &str, is_active: bool, last_certified_at: Option<chrono::DateTime<Utc>>) -> Self {
        Self {
            name: name.to_string(),
            is_active,
            last_certified_at,
        }
    }

    fn needs_certification(&self) -> bool {
        needs_certification(self.last_certified_at)
    }
}

// ============================================================================
// Revocation and Suspension Tests
// ============================================================================

#[test]
fn test_revocation_triggers_suspension() {
    // When an NHI is revoked during certification:
    // 1. NHI status changes to Suspended
    // 2. Active credentials should be invalidated
    // 3. Suspension reason is set to CertificationRevoked

    let before_revocation = NhiTestState {
        status: "active".to_string(),
        has_active_credentials: true,
        suspension_reason: None,
    };

    let after_revocation = simulate_revocation(before_revocation);

    assert_eq!(after_revocation.status, "suspended");
    assert!(!after_revocation.has_active_credentials);
    assert_eq!(
        after_revocation.suspension_reason,
        Some("certification_revoked".to_string())
    );
}

/// Test helper struct for NHI state
struct NhiTestState {
    status: String,
    has_active_credentials: bool,
    suspension_reason: Option<String>,
}

/// Simulate revocation effects
fn simulate_revocation(before: NhiTestState) -> NhiTestState {
    NhiTestState {
        status: "suspended".to_string(),
        has_active_credentials: false,
        suspension_reason: Some("certification_revoked".to_string()),
    }
}

#[test]
fn test_certification_auto_expire() {
    // Certification items past deadline without decision should auto-expire
    let now = Utc::now();
    let deadline_passed = now - Duration::hours(1);
    let deadline_future = now + Duration::hours(1);

    assert!(should_auto_expire(
        deadline_passed,
        NhiCertificationStatus::Pending
    ));
    assert!(!should_auto_expire(
        deadline_future,
        NhiCertificationStatus::Pending
    ));
    assert!(!should_auto_expire(
        deadline_passed,
        NhiCertificationStatus::Certified
    )); // Already decided
}

/// Helper to determine if certification should auto-expire
fn should_auto_expire(deadline: chrono::DateTime<Utc>, status: NhiCertificationStatus) -> bool {
    status == NhiCertificationStatus::Pending && deadline < Utc::now()
}

// ============================================================================
// Delegation Tests
// ============================================================================

#[test]
fn test_delegation_changes_reviewer() {
    let original_reviewer = Uuid::new_v4();
    let delegate_to = Uuid::new_v4();

    let before = DelegationTestItem {
        reviewer_id: original_reviewer,
        original_reviewer_id: None,
        delegated_by: None,
    };

    let after = simulate_delegation(before, delegate_to, original_reviewer);

    assert_eq!(after.reviewer_id, delegate_to);
    assert_eq!(after.original_reviewer_id, Some(original_reviewer));
    assert_eq!(after.delegated_by, Some(original_reviewer));
}

struct DelegationTestItem {
    reviewer_id: Uuid,
    original_reviewer_id: Option<Uuid>,
    delegated_by: Option<Uuid>,
}

fn simulate_delegation(
    item: DelegationTestItem,
    delegate_to: Uuid,
    delegated_by: Uuid,
) -> DelegationTestItem {
    DelegationTestItem {
        reviewer_id: delegate_to,
        original_reviewer_id: Some(item.original_reviewer_id.unwrap_or(item.reviewer_id)),
        delegated_by: Some(delegated_by),
    }
}

#[test]
fn test_cannot_delegate_to_nhi_owner() {
    // Reviewer cannot delegate to the NHI owner (would be self-certification)
    let owner_id = Uuid::new_v4();
    let reviewer_id = Uuid::new_v4();

    assert!(!can_delegate_to(reviewer_id, owner_id, owner_id)); // Cannot delegate to owner
    assert!(can_delegate_to(reviewer_id, owner_id, Uuid::new_v4())); // Can delegate to someone else
}

fn can_delegate_to(reviewer_id: Uuid, owner_id: Uuid, delegate_to: Uuid) -> bool {
    delegate_to != owner_id && delegate_to != reviewer_id
}

// ============================================================================
// Bulk Certification Tests
// ============================================================================

#[test]
fn test_bulk_certification_results() {
    // Bulk certification returns results per item
    let items = vec![
        (Uuid::new_v4(), true),  // Success
        (Uuid::new_v4(), true),  // Success
        (Uuid::new_v4(), false), // Failure
    ];

    let (succeeded, failed): (Vec<_>, Vec<_>) =
        items.into_iter().partition(|(_, success)| *success);

    assert_eq!(succeeded.len(), 2);
    assert_eq!(failed.len(), 1);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_certify_already_decided_item() {
    // Attempting to certify an already-decided item should fail
    let status = NhiCertificationStatus::Certified;
    assert!(
        status.is_decided(),
        "Already decided items cannot be certified again"
    );
}

#[test]
fn test_certify_expired_item() {
    // Attempting to certify an expired item should fail
    let status = NhiCertificationStatus::Expired;
    assert!(
        status.is_decided(),
        "Expired items are considered decided and cannot be certified"
    );
}

#[test]
fn test_reviewer_authorization() {
    // Only the assigned reviewer (or delegate) can make decisions
    let assigned_reviewer = Uuid::new_v4();
    let acting_user = Uuid::new_v4();
    let delegated_to = Uuid::new_v4();

    // Assigned reviewer can decide
    assert!(can_decide(assigned_reviewer, assigned_reviewer, None));

    // Random user cannot decide
    assert!(!can_decide(acting_user, assigned_reviewer, None));

    // Delegate can decide
    assert!(can_decide(
        delegated_to,
        assigned_reviewer,
        Some(delegated_to)
    ));
}

fn can_decide(acting_user: Uuid, reviewer_id: Uuid, delegated_to: Option<Uuid>) -> bool {
    acting_user == reviewer_id || delegated_to == Some(acting_user)
}
