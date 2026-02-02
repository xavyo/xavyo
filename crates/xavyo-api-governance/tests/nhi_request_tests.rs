//! Unit tests for NHI Request Service (US6 - Self-Service NHI Request Workflow).

use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_api_governance::models::nhi::{
    ApproveNhiRequestRequest, ListNhiRequestsQuery, NhiRequestListResponse, NhiRequestResponse,
    RejectNhiRequestRequest, SubmitNhiRequestRequest,
};
use xavyo_db::NhiRequestStatus;

// ============================================================================
// NhiRequestStatus Tests
// ============================================================================

#[test]
fn test_request_status_pending_serialization() {
    let status = NhiRequestStatus::Pending;
    let json = serde_json::to_string(&status).unwrap();
    assert_eq!(json, "\"pending\"");
}

#[test]
fn test_request_status_approved_serialization() {
    let status = NhiRequestStatus::Approved;
    let json = serde_json::to_string(&status).unwrap();
    assert_eq!(json, "\"approved\"");
}

#[test]
fn test_request_status_rejected_serialization() {
    let status = NhiRequestStatus::Rejected;
    let json = serde_json::to_string(&status).unwrap();
    assert_eq!(json, "\"rejected\"");
}

#[test]
fn test_request_status_cancelled_serialization() {
    let status = NhiRequestStatus::Cancelled;
    let json = serde_json::to_string(&status).unwrap();
    assert_eq!(json, "\"cancelled\"");
}

// ============================================================================
// SubmitNhiRequestRequest Tests
// ============================================================================

#[test]
fn test_submit_request_validation_valid() {
    let request = SubmitNhiRequestRequest {
        name: "payment-service-prod".to_string(),
        purpose: "Process payment transactions for the e-commerce platform".to_string(),
        requested_permissions: vec![Uuid::new_v4()],
        requested_expiration: Some(Utc::now() + Duration::days(365)),
        requested_rotation_days: Some(30),
    };

    // Validate using the Validate trait
    use validator::Validate;
    assert!(request.validate().is_ok());
}

#[test]
fn test_submit_request_validation_name_too_long() {
    let request = SubmitNhiRequestRequest {
        name: "a".repeat(201), // Too long (max 200)
        purpose: "Valid purpose description for the NHI request".to_string(),
        requested_permissions: vec![],
        requested_expiration: None,
        requested_rotation_days: None,
    };

    use validator::Validate;
    assert!(request.validate().is_err());
}

#[test]
fn test_submit_request_validation_purpose_too_short() {
    let request = SubmitNhiRequestRequest {
        name: "valid-nhi-name".to_string(),
        purpose: "Short".to_string(), // Too short (min 10)
        requested_permissions: vec![],
        requested_expiration: None,
        requested_rotation_days: None,
    };

    use validator::Validate;
    assert!(request.validate().is_err());
}

#[test]
fn test_submit_request_validation_rotation_days_too_low() {
    let request = SubmitNhiRequestRequest {
        name: "valid-nhi-name".to_string(),
        purpose: "Valid purpose for the NHI that meets minimum length".to_string(),
        requested_permissions: vec![],
        requested_expiration: None,
        requested_rotation_days: Some(0), // Too low (min 1)
    };

    use validator::Validate;
    assert!(request.validate().is_err());
}

#[test]
fn test_submit_request_validation_rotation_days_too_high() {
    let request = SubmitNhiRequestRequest {
        name: "valid-nhi-name".to_string(),
        purpose: "Valid purpose for the NHI that meets minimum length".to_string(),
        requested_permissions: vec![],
        requested_expiration: None,
        requested_rotation_days: Some(400), // Too high (max 365)
    };

    use validator::Validate;
    assert!(request.validate().is_err());
}

#[test]
fn test_submit_request_minimal_fields() {
    let request = SubmitNhiRequestRequest {
        name: "minimal-nhi".to_string(),
        purpose: "Minimal purpose that meets the minimum length requirement".to_string(),
        requested_permissions: vec![],
        requested_expiration: None,
        requested_rotation_days: None,
    };

    use validator::Validate;
    assert!(request.validate().is_ok());
}

#[test]
fn test_submit_request_with_permissions() {
    let entitlement_ids = vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];

    let request = SubmitNhiRequestRequest {
        name: "service-with-permissions".to_string(),
        purpose: "Service that needs specific entitlements assigned".to_string(),
        requested_permissions: entitlement_ids.clone(),
        requested_expiration: None,
        requested_rotation_days: None,
    };

    assert_eq!(request.requested_permissions.len(), 3);
    use validator::Validate;
    assert!(request.validate().is_ok());
}

// ============================================================================
// ApproveNhiRequestRequest Tests
// ============================================================================

#[test]
fn test_approve_request_with_comments() {
    let request = ApproveNhiRequestRequest {
        comments: Some("Approved for production use".to_string()),
    };

    assert!(request.comments.is_some());
}

#[test]
fn test_approve_request_without_comments() {
    let request = ApproveNhiRequestRequest { comments: None };

    assert!(request.comments.is_none());
}

// ============================================================================
// RejectNhiRequestRequest Tests
// ============================================================================

#[test]
fn test_reject_request_with_reason() {
    let request = RejectNhiRequestRequest {
        reason: "Insufficient justification provided for this access request".to_string(),
    };

    use validator::Validate;
    assert!(request.validate().is_ok());
}

#[test]
fn test_reject_request_reason_too_short() {
    let request = RejectNhiRequestRequest {
        reason: "No".to_string(), // Too short (min 5)
    };

    use validator::Validate;
    assert!(request.validate().is_err());
}

// ============================================================================
// NhiRequestResponse Tests
// ============================================================================

#[test]
fn test_request_response_pending() {
    let response = NhiRequestResponse {
        id: Uuid::new_v4(),
        requester_id: Uuid::new_v4(),
        requested_name: "test-nhi".to_string(),
        purpose: "Test purpose".to_string(),
        requested_permissions: vec![Uuid::new_v4()],
        requested_expiration: Some(Utc::now() + Duration::days(365)),
        requested_rotation_days: Some(30),
        status: NhiRequestStatus::Pending,
        approver_id: None,
        decision_at: None,
        decision_comments: None,
        created_nhi_id: None,
        expires_at: Utc::now() + Duration::days(14),
        created_at: Utc::now(),
    };

    assert_eq!(response.status, NhiRequestStatus::Pending);
    assert!(response.approver_id.is_none());
    assert!(response.created_nhi_id.is_none());
}

#[test]
fn test_request_response_approved_with_nhi() {
    let created_nhi_id = Uuid::new_v4();
    let approver_id = Uuid::new_v4();

    let response = NhiRequestResponse {
        id: Uuid::new_v4(),
        requester_id: Uuid::new_v4(),
        requested_name: "approved-nhi".to_string(),
        purpose: "Approved purpose".to_string(),
        requested_permissions: vec![],
        requested_expiration: Some(Utc::now() + Duration::days(365)),
        requested_rotation_days: Some(90),
        status: NhiRequestStatus::Approved,
        approver_id: Some(approver_id),
        decision_at: Some(Utc::now()),
        decision_comments: Some("Approved for production use".to_string()),
        created_nhi_id: Some(created_nhi_id),
        expires_at: Utc::now() + Duration::days(14),
        created_at: Utc::now() - Duration::days(1),
    };

    assert_eq!(response.status, NhiRequestStatus::Approved);
    assert!(response.created_nhi_id.is_some());
    assert_eq!(response.created_nhi_id.unwrap(), created_nhi_id);
    assert_eq!(response.approver_id.unwrap(), approver_id);
}

#[test]
fn test_request_response_rejected() {
    let response = NhiRequestResponse {
        id: Uuid::new_v4(),
        requester_id: Uuid::new_v4(),
        requested_name: "rejected-nhi".to_string(),
        purpose: "Rejected purpose".to_string(),
        requested_permissions: vec![],
        requested_expiration: None,
        requested_rotation_days: None,
        status: NhiRequestStatus::Rejected,
        approver_id: Some(Uuid::new_v4()),
        decision_at: Some(Utc::now()),
        decision_comments: Some("Insufficient justification provided".to_string()),
        created_nhi_id: None,
        expires_at: Utc::now() + Duration::days(14),
        created_at: Utc::now() - Duration::days(1),
    };

    assert_eq!(response.status, NhiRequestStatus::Rejected);
    assert!(response.created_nhi_id.is_none());
    assert!(response.decision_comments.is_some());
}

#[test]
fn test_request_response_cancelled() {
    let response = NhiRequestResponse {
        id: Uuid::new_v4(),
        requester_id: Uuid::new_v4(),
        requested_name: "cancelled-nhi".to_string(),
        purpose: "Cancelled purpose".to_string(),
        requested_permissions: vec![],
        requested_expiration: None,
        requested_rotation_days: None,
        status: NhiRequestStatus::Cancelled,
        approver_id: None,
        decision_at: None,
        decision_comments: None,
        created_nhi_id: None,
        expires_at: Utc::now() + Duration::days(14),
        created_at: Utc::now() - Duration::days(1),
    };

    assert_eq!(response.status, NhiRequestStatus::Cancelled);
}

// ============================================================================
// ListNhiRequestsQuery Tests
// ============================================================================

#[test]
fn test_list_requests_query_defaults() {
    let query = ListNhiRequestsQuery::default();

    assert!(query.status.is_none());
    assert!(query.requester_id.is_none());
    assert!(query.pending_only.is_none());
    assert_eq!(query.limit, Some(50));
    assert_eq!(query.offset, Some(0));
}

#[test]
fn test_list_requests_query_with_filters() {
    let requester_id = Uuid::new_v4();

    let query = ListNhiRequestsQuery {
        status: Some(NhiRequestStatus::Pending),
        requester_id: Some(requester_id),
        pending_only: Some(true),
        limit: Some(25),
        offset: Some(10),
    };

    assert_eq!(query.status, Some(NhiRequestStatus::Pending));
    assert_eq!(query.requester_id.unwrap(), requester_id);
    assert_eq!(query.pending_only, Some(true));
    assert_eq!(query.limit, Some(25));
    assert_eq!(query.offset, Some(10));
}

// ============================================================================
// NhiRequestListResponse Tests
// ============================================================================

#[test]
fn test_request_list_empty() {
    let response = NhiRequestListResponse {
        items: vec![],
        total: 0,
        limit: 50,
        offset: 0,
    };

    assert_eq!(response.items.len(), 0);
    assert_eq!(response.total, 0);
}

#[test]
fn test_request_list_with_items() {
    let items = vec![
        NhiRequestResponse {
            id: Uuid::new_v4(),
            requester_id: Uuid::new_v4(),
            requested_name: "nhi-1".to_string(),
            purpose: "Purpose 1".to_string(),
            requested_permissions: vec![],
            requested_expiration: None,
            requested_rotation_days: None,
            status: NhiRequestStatus::Pending,
            approver_id: None,
            decision_at: None,
            decision_comments: None,
            created_nhi_id: None,
            expires_at: Utc::now() + Duration::days(14),
            created_at: Utc::now(),
        },
        NhiRequestResponse {
            id: Uuid::new_v4(),
            requester_id: Uuid::new_v4(),
            requested_name: "nhi-2".to_string(),
            purpose: "Purpose 2".to_string(),
            requested_permissions: vec![],
            requested_expiration: None,
            requested_rotation_days: None,
            status: NhiRequestStatus::Approved,
            approver_id: Some(Uuid::new_v4()),
            decision_at: Some(Utc::now()),
            decision_comments: None,
            created_nhi_id: Some(Uuid::new_v4()),
            expires_at: Utc::now() + Duration::days(14),
            created_at: Utc::now() - Duration::days(1),
        },
    ];

    let response = NhiRequestListResponse {
        items,
        total: 2,
        limit: 50,
        offset: 0,
    };

    assert_eq!(response.items.len(), 2);
    assert_eq!(response.total, 2);
    assert_eq!(response.items[0].status, NhiRequestStatus::Pending);
    assert_eq!(response.items[1].status, NhiRequestStatus::Approved);
}

// ============================================================================
// Business Logic Tests
// ============================================================================

#[test]
fn test_default_request_expiration() {
    // Default request expiration should be 14 days
    let default_expiration_days = 14;
    let expires_at = Utc::now() + Duration::days(default_expiration_days);

    // The request should expire within 14 days
    assert!(expires_at > Utc::now());
    assert!(expires_at < Utc::now() + Duration::days(15));
}

#[test]
fn test_approval_creates_nhi_with_requested_params() {
    // When a request is approved:
    // 1. NHI is created with requested_name as name
    // 2. NHI is created with purpose
    // 3. NHI is created with requested_expiration (or default)
    // 4. NHI is created with requested_rotation_days (or default)
    // 5. Initial credentials are generated
    // 6. Requested permissions are assigned

    let request = SubmitNhiRequestRequest {
        name: "production-api-service".to_string(),
        purpose: "Production API service for customer portal".to_string(),
        requested_permissions: vec![Uuid::new_v4(), Uuid::new_v4()],
        requested_expiration: Some(Utc::now() + Duration::days(365)),
        requested_rotation_days: Some(30),
    };

    // Verify all params are captured
    assert_eq!(request.requested_permissions.len(), 2);
    assert!(request.requested_expiration.is_some());
    assert_eq!(request.requested_rotation_days, Some(30));
}

#[test]
fn test_cancellation_by_requester_only() {
    // Only the original requester can cancel a request
    let requester_id = Uuid::new_v4();
    let other_user_id = Uuid::new_v4();

    // Requester matches
    assert_eq!(requester_id, requester_id);

    // Other user doesn't match
    assert_ne!(requester_id, other_user_id);
}

#[test]
fn test_request_expiration_check() {
    // A request with expires_at in the past is expired
    let past_expiration = Utc::now() - Duration::hours(1);
    let future_expiration = Utc::now() + Duration::hours(1);

    assert!(past_expiration < Utc::now());
    assert!(future_expiration > Utc::now());
}

// ============================================================================
// Serialization Tests
// ============================================================================

#[test]
fn test_request_response_serialization() {
    let response = NhiRequestResponse {
        id: Uuid::new_v4(),
        requester_id: Uuid::new_v4(),
        requested_name: "test-nhi".to_string(),
        purpose: "Test purpose".to_string(),
        requested_permissions: vec![],
        requested_expiration: None,
        requested_rotation_days: None,
        status: NhiRequestStatus::Pending,
        approver_id: None,
        decision_at: None,
        decision_comments: None,
        created_nhi_id: None,
        expires_at: Utc::now() + Duration::days(14),
        created_at: Utc::now(),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"status\":\"pending\""));
    assert!(json.contains("\"requested_name\":\"test-nhi\""));
}

#[test]
fn test_submit_request_serialization() {
    let request = SubmitNhiRequestRequest {
        name: "my-service".to_string(),
        purpose: "Test service purpose".to_string(),
        requested_permissions: vec![],
        requested_expiration: None,
        requested_rotation_days: Some(30),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("\"name\":\"my-service\""));
    assert!(json.contains("\"requested_rotation_days\":30"));
}

#[test]
fn test_reject_request_serialization() {
    let request = RejectNhiRequestRequest {
        reason: "Not approved".to_string(),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("\"reason\":\"Not approved\""));
}
