//! Integration tests for organization-level MFA policy enforcement (F-066).
//!
//! Tests that org-level MFA policies are properly resolved and the
//! requirement/configuration is correctly computed.

use xavyo_api_auth::models::{
    IpRestrictionPolicyConfig, MfaPolicyConfig, PasswordPolicyConfig, SessionPolicyConfig,
};

// ---------------------------------------------------------------------------
// MFA Policy Tests
// ---------------------------------------------------------------------------

#[test]
fn test_mfa_policy_required_defaults_to_false() {
    let config = MfaPolicyConfig::default();
    assert!(!config.required);
    assert!(config.allowed_methods.contains(&"totp".to_string()));
    assert!(config.allowed_methods.contains(&"webauthn".to_string()));
    assert_eq!(config.grace_period_hours, 0);
    assert_eq!(config.remember_device_days, 0);
}

#[test]
fn test_mfa_policy_required_org_override() {
    let config = MfaPolicyConfig {
        required: true,
        allowed_methods: vec!["totp".to_string()],
        grace_period_hours: 72,
        remember_device_days: 30,
    };

    assert!(config.required);
    assert_eq!(config.allowed_methods.len(), 1);
    assert_eq!(config.grace_period_hours, 72);
    assert_eq!(config.remember_device_days, 30);
}

#[test]
fn test_mfa_policy_most_restrictive_requires_mfa() {
    let org1 = MfaPolicyConfig {
        required: false,
        ..Default::default()
    };

    let org2 = MfaPolicyConfig {
        required: true,
        ..Default::default()
    };

    let combined = org1.most_restrictive(&org2);

    // If either requires MFA, combined should require it
    assert!(combined.required);
}

#[test]
fn test_mfa_policy_most_restrictive_methods_intersection() {
    let org1 = MfaPolicyConfig {
        allowed_methods: vec!["totp".to_string(), "webauthn".to_string()],
        ..Default::default()
    };

    let org2 = MfaPolicyConfig {
        allowed_methods: vec!["totp".to_string()],
        ..Default::default()
    };

    let combined = org1.most_restrictive(&org2);

    // Intersection: only "totp" is in both
    assert_eq!(combined.allowed_methods, vec!["totp".to_string()]);
}

#[test]
fn test_mfa_policy_most_restrictive_grace_period() {
    let org1 = MfaPolicyConfig {
        grace_period_hours: 72,
        ..Default::default()
    };

    let org2 = MfaPolicyConfig {
        grace_period_hours: 24,
        ..Default::default()
    };

    let combined = org1.most_restrictive(&org2);

    // Shorter grace period is more restrictive
    assert_eq!(combined.grace_period_hours, 24);
}

#[test]
fn test_mfa_policy_most_restrictive_remember_device() {
    let org1 = MfaPolicyConfig {
        remember_device_days: 30,
        ..Default::default()
    };

    let org2 = MfaPolicyConfig {
        remember_device_days: 7,
        ..Default::default()
    };

    let combined = org1.most_restrictive(&org2);

    // Fewer days is more restrictive
    assert_eq!(combined.remember_device_days, 7);
}

#[test]
fn test_mfa_policy_serialization_roundtrip() {
    let config = MfaPolicyConfig {
        required: true,
        allowed_methods: vec!["totp".to_string(), "webauthn".to_string()],
        grace_period_hours: 48,
        remember_device_days: 14,
    };

    let json = serde_json::to_value(&config).unwrap();
    let roundtrip: MfaPolicyConfig = serde_json::from_value(json).unwrap();

    assert_eq!(roundtrip.required, config.required);
    assert_eq!(roundtrip.allowed_methods, config.allowed_methods);
    assert_eq!(roundtrip.grace_period_hours, config.grace_period_hours);
    assert_eq!(roundtrip.remember_device_days, config.remember_device_days);
}

#[test]
fn test_mfa_policy_validation_valid() {
    let config = MfaPolicyConfig {
        required: true,
        allowed_methods: vec!["totp".to_string()],
        grace_period_hours: 24,
        remember_device_days: 7,
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_mfa_policy_validation_invalid_method() {
    let config = MfaPolicyConfig {
        allowed_methods: vec!["invalid_method".to_string()],
        ..Default::default()
    };

    let result = config.validate();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors
        .iter()
        .any(|e| e.contains("Invalid MFA method: invalid_method")));
}

#[test]
fn test_mfa_policy_is_more_restrictive() {
    let strict = MfaPolicyConfig {
        required: true,
        allowed_methods: vec!["totp".to_string()],
        grace_period_hours: 0,
        remember_device_days: 0,
    };

    let lenient = MfaPolicyConfig {
        required: false,
        allowed_methods: vec!["totp".to_string(), "webauthn".to_string()],
        grace_period_hours: 72,
        remember_device_days: 30,
    };

    assert!(strict.is_more_restrictive_than(&lenient));
    assert!(!lenient.is_more_restrictive_than(&strict));
}

// ---------------------------------------------------------------------------
// Session Policy Tests
// ---------------------------------------------------------------------------

#[test]
fn test_session_policy_most_restrictive() {
    let tenant = SessionPolicyConfig {
        max_duration_hours: 24,
        idle_timeout_minutes: 30,
        concurrent_session_limit: 0, // unlimited
        require_reauth_sensitive: false,
    };

    let org = SessionPolicyConfig {
        max_duration_hours: 8,
        idle_timeout_minutes: 15,
        concurrent_session_limit: 3,
        require_reauth_sensitive: true,
    };

    let combined = tenant.most_restrictive(&org);

    assert_eq!(combined.max_duration_hours, 8); // shorter
    assert_eq!(combined.idle_timeout_minutes, 15); // shorter
    assert_eq!(combined.concurrent_session_limit, 3); // non-zero wins
    assert!(combined.require_reauth_sensitive); // true wins
}

#[test]
fn test_session_policy_zero_means_unlimited() {
    let p1 = SessionPolicyConfig {
        idle_timeout_minutes: 0,     // disabled
        concurrent_session_limit: 0, // unlimited
        ..Default::default()
    };

    let p2 = SessionPolicyConfig {
        idle_timeout_minutes: 15,
        concurrent_session_limit: 5,
        ..Default::default()
    };

    let combined = p1.most_restrictive(&p2);

    // Non-zero wins over zero (which means disabled/unlimited)
    assert_eq!(combined.idle_timeout_minutes, 15);
    assert_eq!(combined.concurrent_session_limit, 5);
}

// ---------------------------------------------------------------------------
// IP Restriction Policy Tests
// ---------------------------------------------------------------------------

#[test]
fn test_ip_restriction_allows_when_no_restrictions() {
    let config = IpRestrictionPolicyConfig::default();
    assert!(!config.has_restrictions());
    assert!(config.is_ip_allowed("192.168.1.1".parse().unwrap()));
}

#[test]
fn test_ip_restriction_allowed_cidr_enforcement() {
    let config = IpRestrictionPolicyConfig {
        allowed_cidrs: vec!["10.0.0.0/8".to_string()],
        denied_cidrs: vec![],
        action_on_violation: "deny".to_string(),
    };

    assert!(config.is_ip_allowed("10.0.0.1".parse().unwrap()));
    assert!(config.is_ip_allowed("10.255.255.255".parse().unwrap()));
    assert!(!config.is_ip_allowed("192.168.1.1".parse().unwrap()));
}

#[test]
fn test_ip_restriction_denied_takes_precedence() {
    let config = IpRestrictionPolicyConfig {
        allowed_cidrs: vec!["10.0.0.0/8".to_string()],
        denied_cidrs: vec!["10.1.0.0/16".to_string()],
        action_on_violation: "deny".to_string(),
    };

    assert!(config.is_ip_allowed("10.0.0.1".parse().unwrap()));
    assert!(!config.is_ip_allowed("10.1.0.1".parse().unwrap())); // denied
    assert!(!config.is_ip_allowed("192.168.1.1".parse().unwrap())); // not allowed
}

#[test]
fn test_ip_restriction_most_restrictive_union_denied() {
    let p1 = IpRestrictionPolicyConfig {
        allowed_cidrs: vec!["10.0.0.0/8".to_string()],
        denied_cidrs: vec!["10.1.0.0/16".to_string()],
        action_on_violation: "warn".to_string(),
    };

    let p2 = IpRestrictionPolicyConfig {
        allowed_cidrs: vec!["10.0.0.0/8".to_string()],
        denied_cidrs: vec!["10.2.0.0/16".to_string()],
        action_on_violation: "deny".to_string(),
    };

    let combined = p1.most_restrictive(&p2);

    // Denied CIDRs: union of both
    assert_eq!(combined.denied_cidrs.len(), 2);
    assert!(combined.denied_cidrs.contains(&"10.1.0.0/16".to_string()));
    assert!(combined.denied_cidrs.contains(&"10.2.0.0/16".to_string()));

    // Allowed CIDRs: intersection (same in both)
    assert_eq!(combined.allowed_cidrs, vec!["10.0.0.0/8".to_string()]);

    // Action: "deny" is most restrictive
    assert_eq!(combined.action_on_violation, "deny");
}

#[test]
fn test_ip_restriction_ipv6_support() {
    let config = IpRestrictionPolicyConfig {
        allowed_cidrs: vec!["2001:db8::/32".to_string()],
        denied_cidrs: vec![],
        action_on_violation: "deny".to_string(),
    };

    assert!(config.is_ip_allowed("2001:db8::1".parse().unwrap()));
    assert!(!config.is_ip_allowed("2001:db9::1".parse().unwrap()));
}

#[test]
fn test_ip_restriction_validation() {
    let valid = IpRestrictionPolicyConfig {
        allowed_cidrs: vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()],
        denied_cidrs: vec!["10.1.0.0/16".to_string()],
        action_on_violation: "deny".to_string(),
    };
    assert!(valid.validate().is_ok());

    let invalid_cidr = IpRestrictionPolicyConfig {
        allowed_cidrs: vec!["not-a-cidr".to_string()],
        ..Default::default()
    };
    assert!(invalid_cidr.validate().is_err());

    let invalid_action = IpRestrictionPolicyConfig {
        action_on_violation: "block".to_string(), // not valid
        ..Default::default()
    };
    assert!(invalid_action.validate().is_err());
}

// ---------------------------------------------------------------------------
// Cross-Policy Most Restrictive Tests
// ---------------------------------------------------------------------------

#[test]
fn test_user_in_multiple_orgs_gets_strictest_password_policy() {
    // Simulate a user in Finance and Security orgs
    let finance = PasswordPolicyConfig {
        min_length: 12,
        require_uppercase: true,
        require_digit: true,
        expiration_days: 90,
        ..Default::default()
    };

    let security = PasswordPolicyConfig {
        min_length: 16,
        require_special: true,
        expiration_days: 30,
        history_count: 12,
        ..Default::default()
    };

    // Simulate what OrgPolicyService.combine_policies_most_restrictive does
    let combined = finance.most_restrictive(&security);

    assert_eq!(combined.min_length, 16); // highest min
    assert!(combined.require_uppercase); // from finance
    assert!(combined.require_digit); // from finance
    assert!(combined.require_special); // from security
    assert_eq!(combined.expiration_days, 30); // shortest
    assert_eq!(combined.history_count, 12); // highest
}

#[test]
fn test_user_in_multiple_orgs_gets_strictest_session_policy() {
    let engineering = SessionPolicyConfig {
        max_duration_hours: 12,
        idle_timeout_minutes: 30,
        concurrent_session_limit: 5,
        require_reauth_sensitive: false,
    };

    let compliance = SessionPolicyConfig {
        max_duration_hours: 8,
        idle_timeout_minutes: 15,
        concurrent_session_limit: 3,
        require_reauth_sensitive: true,
    };

    let combined = engineering.most_restrictive(&compliance);

    assert_eq!(combined.max_duration_hours, 8);
    assert_eq!(combined.idle_timeout_minutes, 15);
    assert_eq!(combined.concurrent_session_limit, 3);
    assert!(combined.require_reauth_sensitive);
}
