//! Tests for the lockout service.
//!
//! These are unit tests for lockout policy logic.
//! Integration tests require database setup.

use xavyo_db::{TenantLockoutPolicy, UpsertLockoutPolicy};

/// Test default lockout policy values.
#[test]
fn test_default_lockout_policy() {
    let policy = TenantLockoutPolicy::default();
    assert_eq!(policy.max_failed_attempts, 5);
    assert_eq!(policy.lockout_duration_minutes, 30);
    assert!(!policy.notify_on_lockout);
}

/// Test lockout policy is_enabled check.
#[test]
fn test_lockout_policy_is_enabled() {
    let mut policy = TenantLockoutPolicy::default();
    assert!(policy.is_enabled());

    policy.max_failed_attempts = 0;
    assert!(!policy.is_enabled());
}

/// Test lockout policy is_permanent_lockout check.
#[test]
fn test_lockout_policy_is_permanent() {
    let mut policy = TenantLockoutPolicy::default();
    assert!(!policy.is_permanent_lockout());

    policy.lockout_duration_minutes = 0;
    assert!(policy.is_permanent_lockout());
}

/// Test lockout duration calculation.
#[test]
fn test_lockout_duration() {
    let mut policy = TenantLockoutPolicy::default();
    assert_eq!(policy.lockout_duration().num_minutes(), 30);

    policy.lockout_duration_minutes = 60;
    assert_eq!(policy.lockout_duration().num_minutes(), 60);
}

/// Test upsert lockout policy conversion.
#[test]
fn test_upsert_lockout_policy() {
    let upsert = UpsertLockoutPolicy {
        max_failed_attempts: Some(3),
        lockout_duration_minutes: Some(60),
        notify_on_lockout: Some(true),
    };

    assert_eq!(upsert.max_failed_attempts, Some(3));
    assert_eq!(upsert.lockout_duration_minutes, Some(60));
    assert_eq!(upsert.notify_on_lockout, Some(true));
}

/// Test partial upsert with None values.
#[test]
fn test_partial_upsert_lockout_policy() {
    let upsert = UpsertLockoutPolicy {
        max_failed_attempts: Some(10),
        lockout_duration_minutes: None,
        notify_on_lockout: None,
    };

    assert_eq!(upsert.max_failed_attempts, Some(10));
    assert!(upsert.lockout_duration_minutes.is_none());
    assert!(upsert.notify_on_lockout.is_none());
}

// LockoutStatus tests
mod lockout_status_tests {
    use chrono::{Duration, Utc};
    use xavyo_api_auth::services::LockoutStatus;

    #[test]
    fn test_lockout_status_locked() {
        let status = LockoutStatus {
            is_locked: true,
            locked_until: Some(Utc::now() + Duration::minutes(30)),
            failed_attempts: 5,
            max_attempts: 5,
            lockout_reason: Some("max_attempts".to_string()),
        };

        assert!(status.is_locked);
        assert!(status.locked_until.is_some());
        assert_eq!(status.failed_attempts, 5);
        assert_eq!(status.lockout_reason, Some("max_attempts".to_string()));
    }

    #[test]
    fn test_lockout_status_not_locked() {
        let status = LockoutStatus {
            is_locked: false,
            locked_until: None,
            failed_attempts: 2,
            max_attempts: 5,
            lockout_reason: None,
        };

        assert!(!status.is_locked);
        assert!(status.locked_until.is_none());
        assert_eq!(status.failed_attempts, 2);
    }

    #[test]
    fn test_permanent_lockout() {
        let status = LockoutStatus {
            is_locked: true,
            locked_until: None, // Permanent - no expiration
            failed_attempts: 5,
            max_attempts: 5,
            lockout_reason: Some("max_attempts".to_string()),
        };

        assert!(status.is_locked);
        assert!(status.locked_until.is_none());
    }
}

// FailureReason tests
mod failure_reason_tests {
    use xavyo_db::FailureReason;

    #[test]
    fn test_failure_reason_roundtrip() {
        let reasons = [
            FailureReason::InvalidPassword,
            FailureReason::AccountLocked,
            FailureReason::AccountInactive,
            FailureReason::UnknownEmail,
            FailureReason::PasswordExpired,
            FailureReason::MfaFailed,
            FailureReason::Other,
        ];

        for reason in reasons {
            let s = reason.as_str();
            let parsed = FailureReason::parse(s);
            assert_eq!(reason, parsed);
        }
    }

    #[test]
    fn test_failure_reason_display() {
        assert_eq!(
            FailureReason::InvalidPassword.to_string(),
            "invalid_password"
        );
        assert_eq!(FailureReason::AccountLocked.to_string(), "account_locked");
        assert_eq!(FailureReason::UnknownEmail.to_string(), "unknown_email");
    }

    #[test]
    fn test_unknown_reason_parses_as_other() {
        let parsed = FailureReason::parse("unknown_reason");
        assert_eq!(parsed, FailureReason::Other);
    }
}
