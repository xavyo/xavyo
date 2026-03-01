//! Tests for the password policy service.
//!
//! These are unit tests for password policy logic.
//! Integration tests require database setup.

use xavyo_db::{TenantPasswordPolicy, UpsertPasswordPolicy};

/// Test default password policy values (NIST 800-63B compliant).
#[test]
fn test_default_password_policy() {
    let policy = TenantPasswordPolicy::default();
    // NIST 800-63B recommends minimum 8 characters
    assert_eq!(policy.min_length, 8);
    // Allow long passwords
    assert_eq!(policy.max_length, 128);
    // NIST 800-63B does not recommend character class requirements
    assert!(!policy.require_uppercase);
    assert!(!policy.require_lowercase);
    assert!(!policy.require_digit);
    assert!(!policy.require_special);
    // No forced expiration by default (NIST recommends against it)
    assert_eq!(policy.expiration_days, 0);
    // No password history by default
    assert_eq!(policy.history_count, 0);
    // No minimum age by default
    assert_eq!(policy.min_age_hours, 0);
}

/// Test upsert password policy conversion.
#[test]
fn test_upsert_password_policy() {
    let upsert = UpsertPasswordPolicy {
        min_length: Some(12),
        max_length: Some(64),
        require_uppercase: Some(true),
        require_lowercase: Some(true),
        require_digit: Some(true),
        require_special: Some(true),
        expiration_days: Some(90),
        history_count: Some(5),
        min_age_hours: Some(24),
        check_breached_passwords: Some(true),
    };

    assert_eq!(upsert.min_length, Some(12));
    assert_eq!(upsert.max_length, Some(64));
    assert_eq!(upsert.require_uppercase, Some(true));
    assert_eq!(upsert.require_lowercase, Some(true));
    assert_eq!(upsert.require_digit, Some(true));
    assert_eq!(upsert.require_special, Some(true));
    assert_eq!(upsert.expiration_days, Some(90));
    assert_eq!(upsert.history_count, Some(5));
    assert_eq!(upsert.min_age_hours, Some(24));
    assert_eq!(upsert.check_breached_passwords, Some(true));
}

/// Test partial upsert with None values.
#[test]
fn test_partial_upsert_password_policy() {
    let upsert = UpsertPasswordPolicy {
        min_length: Some(10),
        max_length: None,
        require_uppercase: None,
        require_lowercase: None,
        require_digit: None,
        require_special: None,
        expiration_days: None,
        history_count: None,
        min_age_hours: None,
        check_breached_passwords: None,
    };

    assert_eq!(upsert.min_length, Some(10));
    assert!(upsert.max_length.is_none());
    assert!(upsert.require_uppercase.is_none());
}

// PasswordPolicyService validation tests
mod password_validation_tests {
    use xavyo_api_auth::services::{PasswordPolicyError, PasswordPolicyService};
    use xavyo_db::TenantPasswordPolicy;

    fn default_policy() -> TenantPasswordPolicy {
        TenantPasswordPolicy::default()
    }

    fn strict_policy() -> TenantPasswordPolicy {
        TenantPasswordPolicy {
            min_length: 12,
            max_length: 64,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            expiration_days: 90,
            history_count: 5,
            min_age_hours: 24,
            ..default_policy()
        }
    }

    #[test]
    fn test_validate_password_default_policy_valid() {
        let policy = default_policy();
        let result = PasswordPolicyService::validate_password("password", &policy);
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validate_password_too_short() {
        let policy = default_policy();
        let result = PasswordPolicyService::validate_password("short", &policy);
        assert!(!result.is_valid);
        assert!(matches!(
            result.errors.first(),
            Some(PasswordPolicyError::TooShort { min: 8, .. })
        ));
    }

    #[test]
    fn test_validate_password_too_long() {
        let policy = strict_policy();
        let long_pass = "A".repeat(100) + "a1!";
        let result = PasswordPolicyService::validate_password(&long_pass, &policy);
        assert!(!result.is_valid);
        assert!(matches!(
            result.errors.first(),
            Some(PasswordPolicyError::TooLong { max: 64, .. })
        ));
    }

    #[test]
    fn test_validate_password_strict_valid() {
        let policy = strict_policy();
        let result = PasswordPolicyService::validate_password("SecureP@ss123!", &policy);
        assert!(result.is_valid);
    }

    #[test]
    fn test_validate_password_missing_uppercase() {
        let policy = strict_policy();
        let result = PasswordPolicyService::validate_password("securep@ss123!", &policy);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .contains(&PasswordPolicyError::MissingUppercase));
    }

    #[test]
    fn test_validate_password_missing_lowercase() {
        let policy = strict_policy();
        let result = PasswordPolicyService::validate_password("SECUREP@SS123!", &policy);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .contains(&PasswordPolicyError::MissingLowercase));
    }

    #[test]
    fn test_validate_password_missing_digit() {
        let policy = strict_policy();
        let result = PasswordPolicyService::validate_password("SecureP@ssword!", &policy);
        assert!(!result.is_valid);
        assert!(result.errors.contains(&PasswordPolicyError::MissingDigit));
    }

    #[test]
    fn test_validate_password_missing_special() {
        let policy = strict_policy();
        let result = PasswordPolicyService::validate_password("SecurePassword123", &policy);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .contains(&PasswordPolicyError::MissingSpecialChar));
    }

    #[test]
    fn test_validate_password_multiple_errors() {
        let policy = strict_policy();
        let result = PasswordPolicyService::validate_password("weak", &policy);
        assert!(!result.is_valid);
        // Should have multiple errors: too short, missing uppercase, digit, special
        assert!(result.errors.len() >= 2);
    }

    #[test]
    fn test_error_message() {
        let policy = strict_policy();
        let result = PasswordPolicyService::validate_password("weak", &policy);
        let msg = result.error_message();
        assert!(msg.contains("at least 12 characters"));
        assert!(msg.contains("uppercase"));
    }
}

// Password expiration tests
mod expiration_tests {
    use chrono::{Duration, Utc};
    use xavyo_api_auth::services::PasswordPolicyService;

    #[test]
    fn test_check_password_expired_disabled() {
        // expiration_days = 0 means disabled
        assert!(!PasswordPolicyService::check_password_expired(
            Some(Utc::now()),
            0
        ));
    }

    #[test]
    fn test_check_password_expired_not_expired() {
        let recent = Utc::now() - Duration::days(30);
        assert!(!PasswordPolicyService::check_password_expired(
            Some(recent),
            90
        ));
    }

    #[test]
    fn test_check_password_expired_expired() {
        let old_date = Utc::now() - Duration::days(100);
        assert!(PasswordPolicyService::check_password_expired(
            Some(old_date),
            90
        ));
    }

    #[test]
    fn test_check_password_expired_no_change_recorded() {
        // No password change recorded - consider expired
        assert!(PasswordPolicyService::check_password_expired(None, 90));
    }

    #[test]
    fn test_calculate_password_expiration_disabled() {
        assert!(PasswordPolicyService::calculate_password_expiration(0).is_none());
    }

    #[test]
    fn test_calculate_password_expiration_enabled() {
        let expires = PasswordPolicyService::calculate_password_expiration(90);
        assert!(expires.is_some());
        let diff = expires.unwrap() - Utc::now();
        assert!(diff.num_days() >= 89 && diff.num_days() <= 90);
    }
}

// Minimum password age tests
mod min_age_tests {
    use chrono::{Duration, Utc};
    use xavyo_api_auth::services::{PasswordPolicyError, PasswordPolicyService};

    #[test]
    fn test_check_min_password_age_disabled() {
        // min_age_hours = 0 means disabled
        assert!(PasswordPolicyService::check_min_password_age(Some(Utc::now()), 0).is_ok());
    }

    #[test]
    fn test_check_min_password_age_met() {
        let old_date = Utc::now() - Duration::hours(48);
        assert!(PasswordPolicyService::check_min_password_age(Some(old_date), 24).is_ok());
    }

    #[test]
    fn test_check_min_password_age_not_met() {
        let recent_date = Utc::now() - Duration::hours(12);
        let result = PasswordPolicyService::check_min_password_age(Some(recent_date), 24);
        assert!(matches!(
            result,
            Err(PasswordPolicyError::TooSoonToChange { min_hours: 24 })
        ));
    }

    #[test]
    fn test_check_min_password_age_no_previous_password() {
        // No previous password - allow change
        assert!(PasswordPolicyService::check_min_password_age(None, 24).is_ok());
    }
}
