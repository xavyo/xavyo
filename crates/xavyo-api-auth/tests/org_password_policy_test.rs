//! Integration tests for organization-level password policy enforcement (F-066).
//!
//! Tests that org-level password policies are properly resolved and enforced
//! through the PasswordPolicyService.

use xavyo_api_auth::models::{MfaPolicyConfig, PasswordPolicyConfig, SessionPolicyConfig};
use xavyo_api_auth::services::{PasswordPolicyError, PasswordPolicyService};
use xavyo_db::TenantPasswordPolicy;

/// Helper to create a TenantPasswordPolicy from a PasswordPolicyConfig.
fn config_to_tenant_policy(config: &PasswordPolicyConfig) -> TenantPasswordPolicy {
    TenantPasswordPolicy {
        tenant_id: uuid::Uuid::nil(),
        min_length: config.min_length,
        max_length: config.max_length,
        require_uppercase: config.require_uppercase,
        require_lowercase: config.require_lowercase,
        require_digit: config.require_digit,
        require_special: config.require_special,
        expiration_days: config.expiration_days,
        history_count: config.history_count,
        min_age_hours: config.min_age_hours,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[test]
fn test_org_password_config_to_tenant_policy_conversion() {
    let config = PasswordPolicyConfig {
        min_length: 12,
        max_length: 64,
        require_uppercase: true,
        require_lowercase: true,
        require_digit: true,
        require_special: true,
        expiration_days: 90,
        history_count: 5,
        min_age_hours: 24,
    };

    let policy = config_to_tenant_policy(&config);

    assert_eq!(policy.min_length, 12);
    assert_eq!(policy.max_length, 64);
    assert!(policy.require_uppercase);
    assert!(policy.require_lowercase);
    assert!(policy.require_digit);
    assert!(policy.require_special);
    assert_eq!(policy.expiration_days, 90);
    assert_eq!(policy.history_count, 5);
    assert_eq!(policy.min_age_hours, 24);
}

#[test]
fn test_org_password_policy_validates_against_converted_policy() {
    let config = PasswordPolicyConfig {
        min_length: 12,
        max_length: 64,
        require_uppercase: true,
        require_lowercase: true,
        require_digit: true,
        require_special: true,
        ..Default::default()
    };

    let policy = config_to_tenant_policy(&config);

    // Valid password
    let result = PasswordPolicyService::validate_password("SecureP@ss123!", &policy);
    assert!(result.is_valid);

    // Too short (org requires 12)
    let result = PasswordPolicyService::validate_password("Short1!", &policy);
    assert!(!result.is_valid);
    assert!(result
        .errors
        .iter()
        .any(|e| matches!(e, PasswordPolicyError::TooShort { min: 12, .. })));

    // Missing uppercase
    let result = PasswordPolicyService::validate_password("securep@ss123!", &policy);
    assert!(!result.is_valid);
    assert!(result
        .errors
        .contains(&PasswordPolicyError::MissingUppercase));

    // Missing special
    let result = PasswordPolicyService::validate_password("SecurePassword123", &policy);
    assert!(!result.is_valid);
    assert!(result
        .errors
        .contains(&PasswordPolicyError::MissingSpecialChar));
}

#[test]
fn test_org_password_policy_most_restrictive_combination() {
    let tenant_config = PasswordPolicyConfig {
        min_length: 8,
        max_length: 128,
        require_uppercase: false,
        require_lowercase: false,
        require_digit: false,
        require_special: false,
        expiration_days: 0,
        history_count: 0,
        min_age_hours: 0,
    };

    let org_config = PasswordPolicyConfig {
        min_length: 12,
        max_length: 64,
        require_uppercase: true,
        require_digit: true,
        expiration_days: 90,
        history_count: 5,
        ..Default::default()
    };

    let combined = tenant_config.most_restrictive(&org_config);

    // Most restrictive: higher min_length
    assert_eq!(combined.min_length, 12);
    // Most restrictive: lower max_length
    assert_eq!(combined.max_length, 64);
    // Most restrictive: require if either requires
    assert!(combined.require_uppercase);
    assert!(combined.require_digit);
    // Not required by either
    assert!(!combined.require_special);
    // Most restrictive: shorter expiration
    assert_eq!(combined.expiration_days, 90);
    // Most restrictive: higher history count
    assert_eq!(combined.history_count, 5);
}

#[test]
fn test_org_password_policy_expiration_enforcement() {
    // Org policy with 90-day expiration
    let config = PasswordPolicyConfig {
        expiration_days: 90,
        ..Default::default()
    };

    let policy = config_to_tenant_policy(&config);

    // Not expired (changed recently)
    assert!(!PasswordPolicyService::check_password_expired(
        Some(chrono::Utc::now()),
        policy.expiration_days
    ));

    // Expired (changed 100 days ago)
    let old_date = chrono::Utc::now() - chrono::Duration::days(100);
    assert!(PasswordPolicyService::check_password_expired(
        Some(old_date),
        policy.expiration_days
    ));
}

#[test]
fn test_org_password_min_age_enforcement() {
    // Org policy with 24-hour minimum age
    let config = PasswordPolicyConfig {
        min_age_hours: 24,
        ..Default::default()
    };

    // Password changed 12 hours ago - should be rejected
    let recent_date = chrono::Utc::now() - chrono::Duration::hours(12);
    let result =
        PasswordPolicyService::check_min_password_age(Some(recent_date), config.min_age_hours);
    assert!(matches!(
        result,
        Err(PasswordPolicyError::TooSoonToChange { min_hours: 24 })
    ));

    // Password changed 48 hours ago - should be allowed
    let old_date = chrono::Utc::now() - chrono::Duration::hours(48);
    let result =
        PasswordPolicyService::check_min_password_age(Some(old_date), config.min_age_hours);
    assert!(result.is_ok());
}

#[test]
fn test_org_password_policy_default_matches_tenant_default() {
    let default_config = PasswordPolicyConfig::default();
    let default_tenant = TenantPasswordPolicy::default();

    assert_eq!(default_config.min_length, default_tenant.min_length);
    assert_eq!(default_config.max_length, default_tenant.max_length);
    assert_eq!(
        default_config.require_uppercase,
        default_tenant.require_uppercase
    );
    assert_eq!(
        default_config.require_lowercase,
        default_tenant.require_lowercase
    );
    assert_eq!(default_config.require_digit, default_tenant.require_digit);
    assert_eq!(
        default_config.require_special,
        default_tenant.require_special
    );
    assert_eq!(
        default_config.expiration_days,
        default_tenant.expiration_days
    );
    assert_eq!(default_config.history_count, default_tenant.history_count);
    assert_eq!(default_config.min_age_hours, default_tenant.min_age_hours);
}

#[test]
fn test_org_password_policy_serialization_roundtrip() {
    let config = PasswordPolicyConfig {
        min_length: 14,
        max_length: 72,
        require_uppercase: true,
        require_lowercase: true,
        require_digit: true,
        require_special: false,
        expiration_days: 60,
        history_count: 10,
        min_age_hours: 12,
    };

    let json = serde_json::to_value(&config).unwrap();
    let roundtrip: PasswordPolicyConfig = serde_json::from_value(json).unwrap();

    assert_eq!(roundtrip.min_length, config.min_length);
    assert_eq!(roundtrip.max_length, config.max_length);
    assert_eq!(roundtrip.require_uppercase, config.require_uppercase);
    assert_eq!(roundtrip.require_lowercase, config.require_lowercase);
    assert_eq!(roundtrip.require_digit, config.require_digit);
    assert_eq!(roundtrip.require_special, config.require_special);
    assert_eq!(roundtrip.expiration_days, config.expiration_days);
    assert_eq!(roundtrip.history_count, config.history_count);
    assert_eq!(roundtrip.min_age_hours, config.min_age_hours);
}

#[test]
fn test_org_password_policy_stricter_than_tenant() {
    let tenant = PasswordPolicyConfig {
        min_length: 8,
        require_uppercase: false,
        ..Default::default()
    };

    let org = PasswordPolicyConfig {
        min_length: 16,
        require_uppercase: true,
        require_special: true,
        ..Default::default()
    };

    assert!(org.is_more_restrictive_than(&tenant));
    assert!(!tenant.is_more_restrictive_than(&org));
}

#[test]
fn test_multiple_org_policies_most_restrictive() {
    // Finance org: long passwords, no special chars
    let finance = PasswordPolicyConfig {
        min_length: 16,
        max_length: 128,
        require_uppercase: true,
        require_digit: true,
        ..Default::default()
    };

    // Security org: special chars required, shorter min
    let security = PasswordPolicyConfig {
        min_length: 12,
        max_length: 64,
        require_special: true,
        expiration_days: 30,
        history_count: 12,
        ..Default::default()
    };

    let combined = finance.most_restrictive(&security);

    // Takes the stricter value from each
    assert_eq!(combined.min_length, 16); // max of 16 and 12
    assert_eq!(combined.max_length, 64); // min of 128 and 64
    assert!(combined.require_uppercase); // from finance
    assert!(combined.require_digit); // from finance
    assert!(combined.require_special); // from security
    assert_eq!(combined.expiration_days, 30); // non-zero from security
    assert_eq!(combined.history_count, 12); // max of 0 and 12
}
