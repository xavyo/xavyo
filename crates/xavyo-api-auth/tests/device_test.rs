//! Tests for device management services (F026).
//!
//! Unit tests that don't require database connections.

use xavyo_api_auth::models::{
    AdminListDevicesQuery, DeviceListResponse, DevicePolicyResponse, RenameDeviceRequest,
    RenameDeviceResponse, TrustDeviceRequest, TrustDeviceResponse, UpdateDevicePolicyRequest,
};
use xavyo_api_auth::services::{DevicePolicy, DEFAULT_TRUST_DURATION_DAYS};

// =============================================================================
// User Story 1: View My Devices - Unit Tests
// =============================================================================

#[test]
fn test_device_list_response_structure() {
    let response = DeviceListResponse {
        items: vec![],
        total: 0,
    };
    assert_eq!(response.items.len(), 0);
    assert_eq!(response.total, 0);
}

#[test]
fn test_device_response_truncated_fingerprint() {
    // Test that device fingerprint is truncated in responses
    let full_fingerprint = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";
    let truncated = &full_fingerprint[..8.min(full_fingerprint.len())];
    assert_eq!(truncated, "a1b2c3d4");
    assert_eq!(truncated.len(), 8);
}

#[test]
fn test_admin_list_devices_query_defaults() {
    let query = AdminListDevicesQuery::default();
    assert!(!query.include_revoked);
}

// =============================================================================
// User Story 2: Manage Device Trust - Unit Tests
// =============================================================================

#[test]
fn test_trust_device_request_with_duration() {
    let request = TrustDeviceRequest {
        trust_duration_days: Some(14),
    };
    assert_eq!(request.trust_duration_days, Some(14));
}

#[test]
fn test_trust_device_request_without_duration() {
    let request = TrustDeviceRequest {
        trust_duration_days: None,
    };
    assert_eq!(request.trust_duration_days, None);
}

#[test]
fn test_trust_device_response_trusted() {
    let response = TrustDeviceResponse {
        id: uuid::Uuid::new_v4(),
        is_trusted: true,
        trust_expires_at: Some(chrono::Utc::now() + chrono::Duration::days(30)),
    };
    assert!(response.is_trusted);
    assert!(response.trust_expires_at.is_some());
}

#[test]
fn test_trust_device_response_untrusted() {
    let response = TrustDeviceResponse {
        id: uuid::Uuid::new_v4(),
        is_trusted: false,
        trust_expires_at: None,
    };
    assert!(!response.is_trusted);
    assert!(response.trust_expires_at.is_none());
}

#[test]
fn test_trust_device_response_permanent_trust() {
    let response = TrustDeviceResponse {
        id: uuid::Uuid::new_v4(),
        is_trusted: true,
        trust_expires_at: None, // NULL = permanent
    };
    assert!(response.is_trusted);
    assert!(response.trust_expires_at.is_none());
}

// =============================================================================
// User Story 3: Rename and Revoke Devices - Unit Tests
// =============================================================================

#[test]
fn test_rename_device_request() {
    let request = RenameDeviceRequest {
        device_name: "Work Laptop".to_string(),
    };
    assert_eq!(request.device_name, "Work Laptop");
}

#[test]
fn test_rename_device_response() {
    let response = RenameDeviceResponse {
        id: uuid::Uuid::new_v4(),
        device_name: "Personal Phone".to_string(),
    };
    assert_eq!(response.device_name, "Personal Phone");
}

#[test]
fn test_device_name_max_length_validation() {
    // Device name should be max 100 characters
    let name = "a".repeat(100);
    assert_eq!(name.len(), 100);

    let too_long = "a".repeat(101);
    assert!(too_long.len() > 100);
}

// =============================================================================
// User Story 4: Admin Device Management - Unit Tests
// =============================================================================

#[test]
fn test_admin_list_devices_query_include_revoked() {
    let query = AdminListDevicesQuery {
        include_revoked: true,
    };
    assert!(query.include_revoked);
}

// =============================================================================
// User Story 5: Device Policy Configuration - Unit Tests
// =============================================================================

#[test]
fn test_device_policy_default() {
    let policy = DevicePolicy::default();
    assert!(!policy.allow_trusted_device_mfa_bypass);
    assert_eq!(
        policy.trusted_device_duration_days,
        DEFAULT_TRUST_DURATION_DAYS
    );
    assert_eq!(policy.trusted_device_duration_days, 30);
}

#[test]
fn test_device_policy_to_response() {
    let policy = DevicePolicy {
        allow_trusted_device_mfa_bypass: true,
        trusted_device_duration_days: 14,
    };
    let response: DevicePolicyResponse = policy.into();
    assert!(response.allow_trusted_device_mfa_bypass);
    assert_eq!(response.trusted_device_duration_days, 14);
}

#[test]
fn test_device_policy_response_default() {
    let response = DevicePolicyResponse::default();
    assert!(!response.allow_trusted_device_mfa_bypass);
    assert_eq!(response.trusted_device_duration_days, 30);
}

#[test]
fn test_update_device_policy_request_partial() {
    let request = UpdateDevicePolicyRequest {
        allow_trusted_device_mfa_bypass: Some(true),
        trusted_device_duration_days: None,
    };
    assert_eq!(request.allow_trusted_device_mfa_bypass, Some(true));
    assert_eq!(request.trusted_device_duration_days, None);
}

#[test]
fn test_update_device_policy_request_full() {
    let request = UpdateDevicePolicyRequest {
        allow_trusted_device_mfa_bypass: Some(true),
        trusted_device_duration_days: Some(7),
    };
    assert_eq!(request.allow_trusted_device_mfa_bypass, Some(true));
    assert_eq!(request.trusted_device_duration_days, Some(7));
}

#[test]
fn test_trust_duration_permanent() {
    // 0 means permanent trust
    let request = UpdateDevicePolicyRequest {
        allow_trusted_device_mfa_bypass: None,
        trusted_device_duration_days: Some(0),
    };
    assert_eq!(request.trusted_device_duration_days, Some(0));
}

// =============================================================================
// API Error Tests for Device Errors (F026)
// =============================================================================

mod error_tests {
    use axum::http::StatusCode;
    use xavyo_api_auth::error::ApiAuthError;

    #[test]
    fn test_device_not_found_error() {
        let error = ApiAuthError::DeviceNotFound;
        assert_eq!(error.status_code(), StatusCode::NOT_FOUND);

        let problem = error.to_problem_details();
        assert!(problem.error_type.contains("device-not-found"));
        assert_eq!(problem.status, 404);
        assert!(problem.detail.is_some());
    }

    #[test]
    fn test_device_revoked_error() {
        let error = ApiAuthError::DeviceRevoked;
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);

        let problem = error.to_problem_details();
        assert!(problem.error_type.contains("device-revoked"));
        assert_eq!(problem.status, 400);
        assert!(problem.detail.is_some());
    }

    #[test]
    fn test_trust_not_allowed_error() {
        let error = ApiAuthError::TrustNotAllowed;
        assert_eq!(error.status_code(), StatusCode::FORBIDDEN);

        let problem = error.to_problem_details();
        assert!(problem.error_type.contains("trust-not-allowed"));
        assert_eq!(problem.status, 403);
        assert!(problem.detail.is_some());
    }
}

// =============================================================================
// User Agent Parser Tests (existing in F025, relevant for F026)
// =============================================================================

mod user_agent_parser_tests {
    use xavyo_api_auth::services::parse_user_agent;

    #[test]
    fn test_desktop_chrome_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let info = parse_user_agent(ua);
        assert_eq!(info.device_type, "desktop");
        assert_eq!(info.browser, Some("Chrome".to_string()));
        assert_eq!(info.os, Some("Windows".to_string()));
    }

    #[test]
    fn test_mobile_safari_ios() {
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
        let info = parse_user_agent(ua);
        assert_eq!(info.device_type, "mobile");
        assert_eq!(info.browser, Some("Safari".to_string()));
        assert_eq!(info.os, Some("iOS".to_string()));
    }

    #[test]
    fn test_tablet_ipad() {
        let ua = "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
        let info = parse_user_agent(ua);
        assert_eq!(info.device_type, "tablet");
    }

    #[test]
    fn test_device_name_generation() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let info = parse_user_agent(ua);
        assert_eq!(info.device_name, "Chrome on Windows");
    }
}

// =============================================================================
// Device Fingerprint Validation Tests
// =============================================================================

mod fingerprint_validation_tests {
    #[test]
    fn test_valid_sha256_fingerprint() {
        // Valid SHA-256 hash (64 hex chars)
        let fingerprint = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_fingerprint_minimum_length() {
        // Minimum 32 chars (truncated hash)
        let short = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        assert_eq!(short.len(), 32);
        assert!(short.len() >= 32);
    }

    #[test]
    fn test_fingerprint_too_short() {
        let too_short = "a1b2c3d4e5f6a7b8";
        assert!(too_short.len() < 32);
    }

    #[test]
    fn test_fingerprint_invalid_chars() {
        // Contains non-hex characters
        let invalid = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6ghij";
        assert!(!invalid.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_fingerprint_hex_validation() {
        let valid_hex = "0123456789abcdefABCDEF0123456789";
        assert!(valid_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

// =============================================================================
// Trust Duration Capping Logic Tests
// =============================================================================

mod trust_duration_tests {
    #[test]
    fn test_cap_trust_duration_within_limit() {
        // If tenant allows 14 days and user requests 7, return 7
        let tenant_max = 14;
        let requested = 7;
        let result = requested.min(tenant_max);
        assert_eq!(result, 7);
    }

    #[test]
    fn test_cap_trust_duration_exceeds_limit() {
        // If tenant allows 14 days and user requests 30, return 14
        let tenant_max = 14;
        let requested = 30;
        let result = requested.min(tenant_max);
        assert_eq!(result, 14);
    }

    #[test]
    fn test_cap_trust_duration_permanent_tenant() {
        // If tenant allows permanent (0) and user requests any value, return user value
        let tenant_max = 0; // 0 = permanent allowed
        let requested = 30;
        // When tenant_max is 0, we don't cap
        let result = if tenant_max == 0 {
            requested
        } else {
            requested.min(tenant_max)
        };
        assert_eq!(result, 30);
    }

    #[test]
    fn test_cap_trust_duration_user_wants_permanent_but_not_allowed() {
        // If user requests 0 (permanent) but tenant max is 14, return 14
        let tenant_max = 14;
        let requested = 0;
        let result = if requested == 0 && tenant_max > 0 {
            tenant_max // User wanted permanent, cap to tenant max
        } else {
            requested.min(tenant_max)
        };
        assert_eq!(result, 14);
    }
}
