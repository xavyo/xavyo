//! Tests for audit and alert services (F025).
//!
//! Unit tests that don't require database connections.

use xavyo_api_auth::services::{
    FailureReasonCount, HourlyCount, LoginAttemptStats, RecordLoginAttemptInput,
};
use xavyo_db::{AlertType, AuthMethod, Severity};

#[test]
fn test_auth_method_display() {
    assert_eq!(AuthMethod::Password.to_string(), "password");
    assert_eq!(AuthMethod::Social.to_string(), "social");
    assert_eq!(AuthMethod::Sso.to_string(), "sso");
    assert_eq!(AuthMethod::Mfa.to_string(), "mfa");
    assert_eq!(AuthMethod::Refresh.to_string(), "refresh");
}

#[test]
fn test_record_login_attempt_input_creation() {
    let input = RecordLoginAttemptInput {
        user_id: Some(uuid::Uuid::new_v4()),
        email: "user@example.com".to_string(),
        success: true,
        failure_reason: None,
        auth_method: AuthMethod::Password,
        ip_address: Some("192.168.1.1".to_string()),
        user_agent: Some("Mozilla/5.0".to_string()),
        device_fingerprint: Some("abc123hash".to_string()),
        geo_country: Some("US".to_string()),
        geo_city: Some("New York".to_string()),
    };

    assert!(input.success);
    assert!(input.failure_reason.is_none());
    assert_eq!(input.auth_method, AuthMethod::Password);
}

#[test]
fn test_record_login_attempt_input_failed() {
    let input = RecordLoginAttemptInput {
        user_id: Some(uuid::Uuid::new_v4()),
        email: "user@example.com".to_string(),
        success: false,
        failure_reason: Some("invalid_password".to_string()),
        auth_method: AuthMethod::Password,
        ip_address: Some("192.168.1.1".to_string()),
        user_agent: None,
        device_fingerprint: None,
        geo_country: None,
        geo_city: None,
    };

    assert!(!input.success);
    assert_eq!(input.failure_reason, Some("invalid_password".to_string()));
}

#[test]
fn test_login_attempt_stats_success_rate_calculation() {
    // Test 80% success rate
    let total = 100i64;
    let successful = 80i64;
    let success_rate = if total > 0 {
        (successful as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    assert!((success_rate - 80.0).abs() < f64::EPSILON);

    // Test 0% with zero total
    let total = 0i64;
    let successful = 0i64;
    let success_rate = if total > 0 {
        (successful as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    assert!((success_rate - 0.0).abs() < f64::EPSILON);
}

#[test]
fn test_login_attempt_stats_structure() {
    let stats = LoginAttemptStats {
        total_attempts: 150,
        successful_attempts: 120,
        failed_attempts: 30,
        success_rate: 80.0,
        failure_reasons: vec![
            FailureReasonCount {
                reason: "invalid_password".to_string(),
                count: 20,
            },
            FailureReasonCount {
                reason: "account_locked".to_string(),
                count: 10,
            },
        ],
        hourly_distribution: vec![
            HourlyCount { hour: 9, count: 50 },
            HourlyCount {
                hour: 14,
                count: 30,
            },
        ],
        unique_users: 45,
        new_device_logins: 5,
        new_location_logins: 3,
    };

    assert_eq!(stats.total_attempts, 150);
    assert_eq!(stats.successful_attempts, 120);
    assert_eq!(stats.failed_attempts, 30);
    assert!((stats.success_rate - 80.0).abs() < f64::EPSILON);
    assert_eq!(stats.failure_reasons.len(), 2);
    assert_eq!(stats.hourly_distribution.len(), 2);
    assert_eq!(stats.unique_users, 45);
    assert_eq!(stats.new_device_logins, 5);
    assert_eq!(stats.new_location_logins, 3);
}

#[test]
fn test_failure_reason_count() {
    let reason = FailureReasonCount {
        reason: "invalid_password".to_string(),
        count: 42,
    };

    assert_eq!(reason.reason, "invalid_password");
    assert_eq!(reason.count, 42);
}

#[test]
fn test_hourly_count() {
    let hourly = HourlyCount {
        hour: 14,
        count: 100,
    };

    assert_eq!(hourly.hour, 14);
    assert_eq!(hourly.count, 100);
}

// Tests for AlertType and Severity from xavyo_db
mod alert_type_tests {
    use super::*;

    #[test]
    fn test_alert_type_display() {
        assert_eq!(AlertType::NewDevice.to_string(), "new_device");
        assert_eq!(AlertType::NewLocation.to_string(), "new_location");
        assert_eq!(AlertType::FailedAttempts.to_string(), "failed_attempts");
        assert_eq!(AlertType::PasswordChange.to_string(), "password_change");
        assert_eq!(AlertType::MfaDisabled.to_string(), "mfa_disabled");
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Info.to_string(), "info");
        assert_eq!(Severity::Warning.to_string(), "warning");
        assert_eq!(Severity::Critical.to_string(), "critical");
    }

    #[test]
    fn test_alert_type_severity_mapping() {
        // Test expected severity for each alert type per spec
        let mappings = [
            (AlertType::NewDevice, Severity::Warning),
            (AlertType::NewLocation, Severity::Info),
            (AlertType::FailedAttempts, Severity::Warning),
            (AlertType::PasswordChange, Severity::Info),
            (AlertType::MfaDisabled, Severity::Critical),
        ];

        for (alert_type, expected_severity) in mappings {
            let severity = match alert_type {
                AlertType::NewDevice => Severity::Warning,
                AlertType::NewLocation => Severity::Info,
                AlertType::FailedAttempts => Severity::Warning,
                AlertType::PasswordChange => Severity::Info,
                AlertType::MfaDisabled => Severity::Critical,
            };
            assert_eq!(
                severity, expected_severity,
                "Alert type {:?} should have severity {:?}",
                alert_type, expected_severity
            );
        }
    }

    #[test]
    fn test_alert_types_complete() {
        // Verify we have all expected alert types
        let alert_types = [
            AlertType::NewDevice,
            AlertType::NewLocation,
            AlertType::FailedAttempts,
            AlertType::PasswordChange,
            AlertType::MfaDisabled,
        ];
        assert_eq!(alert_types.len(), 5);
    }

    #[test]
    fn test_severity_levels_complete() {
        // Verify we have all expected severity levels
        let severities = [Severity::Info, Severity::Warning, Severity::Critical];
        assert_eq!(severities.len(), 3);
    }
}

// API error tests for new variants
mod error_tests {
    use axum::http::StatusCode;
    use xavyo_api_auth::error::ApiAuthError;

    #[test]
    fn test_alert_not_found_error() {
        let error = ApiAuthError::AlertNotFound;
        assert_eq!(error.status_code(), StatusCode::NOT_FOUND);

        let problem = error.to_problem_details();
        assert!(problem.error_type.contains("alert-not-found"));
        assert_eq!(problem.status, 404);
    }

    #[test]
    fn test_alert_already_acknowledged_error() {
        let error = ApiAuthError::AlertAlreadyAcknowledged;
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);

        let problem = error.to_problem_details();
        assert!(problem.error_type.contains("alert-already-acknowledged"));
        assert_eq!(problem.status, 400);
    }
}
