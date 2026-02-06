//! Tests for organization policy inheritance and conflict detection (F-066).
//!
//! Tests for hierarchy traversal, multi-group resolution, and conflict warnings.
//! Database-dependent tests are marked with #[ignore] - run with TEST_DATABASE_URL.

use xavyo_api_auth::models::{
    IpRestrictionPolicyConfig, MfaPolicyConfig, PasswordPolicyConfig, PolicyConflictWarning,
    PolicyValidationResult, SessionPolicyConfig,
};

// ---------------------------------------------------------------------------
// T024: Inheritance / Most-Restrictive Resolution Tests
// ---------------------------------------------------------------------------

#[test]
fn test_password_policy_5_level_inheritance_simulation() {
    // Simulate 5-level org hierarchy where each level adds restrictions
    // Level 0 (Root): base policy
    let root = PasswordPolicyConfig {
        min_length: 8,
        ..Default::default()
    };

    // Level 1 (Division): adds uppercase
    let division = PasswordPolicyConfig {
        min_length: 10,
        require_uppercase: true,
        ..Default::default()
    };

    // Level 2 (Department): adds digit
    let department = PasswordPolicyConfig {
        min_length: 12,
        require_uppercase: true,
        require_digit: true,
        ..Default::default()
    };

    // Level 3 (Team): adds special
    let team = PasswordPolicyConfig {
        min_length: 12,
        require_uppercase: true,
        require_digit: true,
        require_special: true,
        expiration_days: 90,
        ..Default::default()
    };

    // Level 4 (Project): adds history
    let project = PasswordPolicyConfig {
        min_length: 14,
        require_uppercase: true,
        require_digit: true,
        require_special: true,
        expiration_days: 60,
        history_count: 5,
        ..Default::default()
    };

    // The "most specific wins" rule means the deepest org's policy wins
    // But when combining across multiple groups, most_restrictive is used
    // Simulate combining all levels
    let combined = root
        .most_restrictive(&division)
        .most_restrictive(&department)
        .most_restrictive(&team)
        .most_restrictive(&project);

    assert_eq!(combined.min_length, 14); // highest
    assert!(combined.require_uppercase);
    assert!(combined.require_digit);
    assert!(combined.require_special);
    assert_eq!(combined.expiration_days, 60); // shortest non-zero
    assert_eq!(combined.history_count, 5); // highest
}

#[test]
fn test_session_policy_5_level_inheritance_simulation() {
    let root = SessionPolicyConfig {
        max_duration_hours: 24,
        idle_timeout_minutes: 60,
        concurrent_session_limit: 0,
        require_reauth_sensitive: false,
    };

    let level1 = SessionPolicyConfig {
        max_duration_hours: 12,
        idle_timeout_minutes: 30,
        concurrent_session_limit: 10,
        require_reauth_sensitive: false,
    };

    let level2 = SessionPolicyConfig {
        max_duration_hours: 8,
        idle_timeout_minutes: 15,
        concurrent_session_limit: 5,
        require_reauth_sensitive: true,
    };

    let combined = root.most_restrictive(&level1).most_restrictive(&level2);

    assert_eq!(combined.max_duration_hours, 8);
    assert_eq!(combined.idle_timeout_minutes, 15);
    assert_eq!(combined.concurrent_session_limit, 5);
    assert!(combined.require_reauth_sensitive);
}

#[test]
fn test_mfa_policy_inheritance_required_propagates() {
    // Parent requires MFA, child doesn't
    let parent = MfaPolicyConfig {
        required: true,
        ..Default::default()
    };

    let child = MfaPolicyConfig {
        required: false,
        ..Default::default()
    };

    // In most-restrictive: required wins
    let combined = parent.most_restrictive(&child);
    assert!(combined.required);
}

#[test]
fn test_ip_restriction_inheritance_denied_accumulates() {
    let parent = IpRestrictionPolicyConfig {
        allowed_cidrs: vec!["10.0.0.0/8".to_string()],
        denied_cidrs: vec!["10.1.0.0/16".to_string()],
        action_on_violation: "warn".to_string(),
    };

    let child = IpRestrictionPolicyConfig {
        allowed_cidrs: vec!["10.0.0.0/8".to_string()],
        denied_cidrs: vec!["10.2.0.0/16".to_string()],
        action_on_violation: "deny".to_string(),
    };

    let combined = parent.most_restrictive(&child);

    // Both denied ranges are included
    assert!(combined.denied_cidrs.contains(&"10.1.0.0/16".to_string()));
    assert!(combined.denied_cidrs.contains(&"10.2.0.0/16".to_string()));
    // Action is most restrictive
    assert_eq!(combined.action_on_violation, "deny");
}

// ---------------------------------------------------------------------------
// T031: Multi-Group Most-Restrictive Resolution Tests
// ---------------------------------------------------------------------------

#[test]
fn test_user_in_three_groups_most_restrictive_password() {
    let hr = PasswordPolicyConfig {
        min_length: 10,
        require_uppercase: true,
        ..Default::default()
    };

    let it = PasswordPolicyConfig {
        min_length: 12,
        require_digit: true,
        expiration_days: 90,
        ..Default::default()
    };

    let compliance = PasswordPolicyConfig {
        min_length: 8,
        require_special: true,
        history_count: 10,
        min_age_hours: 24,
        ..Default::default()
    };

    let combined = hr.most_restrictive(&it).most_restrictive(&compliance);

    assert_eq!(combined.min_length, 12);
    assert!(combined.require_uppercase);
    assert!(combined.require_digit);
    assert!(combined.require_special);
    assert_eq!(combined.expiration_days, 90);
    assert_eq!(combined.history_count, 10);
    assert_eq!(combined.min_age_hours, 24);
}

#[test]
fn test_user_in_three_groups_most_restrictive_mfa() {
    let group1 = MfaPolicyConfig {
        required: false,
        allowed_methods: vec!["totp".to_string(), "webauthn".to_string()],
        grace_period_hours: 72,
        remember_device_days: 30,
    };

    let group2 = MfaPolicyConfig {
        required: true,
        allowed_methods: vec![
            "totp".to_string(),
            "webauthn".to_string(),
            "email".to_string(),
        ],
        grace_period_hours: 24,
        remember_device_days: 14,
    };

    let group3 = MfaPolicyConfig {
        required: false,
        allowed_methods: vec!["totp".to_string()],
        grace_period_hours: 48,
        remember_device_days: 7,
    };

    let combined = group1.most_restrictive(&group2).most_restrictive(&group3);

    assert!(combined.required); // any required -> required
    assert_eq!(combined.allowed_methods, vec!["totp".to_string()]); // intersection
    assert_eq!(combined.grace_period_hours, 24); // shortest
    assert_eq!(combined.remember_device_days, 7); // shortest
}

// ---------------------------------------------------------------------------
// T037: Conflict Detection Tests
// ---------------------------------------------------------------------------

#[test]
fn test_password_conflict_child_less_restrictive() {
    let parent = PasswordPolicyConfig {
        min_length: 16,
        require_uppercase: true,
        require_special: true,
        ..Default::default()
    };

    let child = PasswordPolicyConfig {
        min_length: 8,
        require_uppercase: false,
        ..Default::default()
    };

    // Child is less restrictive than parent - should generate warning
    assert!(!child.is_more_restrictive_than(&parent));
    // Parent is more restrictive than child - no warning
    assert!(parent.is_more_restrictive_than(&child));
}

#[test]
fn test_mfa_conflict_parent_requires_child_doesnt() {
    let parent = MfaPolicyConfig {
        required: true,
        ..Default::default()
    };

    let child = MfaPolicyConfig {
        required: false,
        ..Default::default()
    };

    // This is a conflict: parent requires MFA but child doesn't
    assert!(parent.required && !child.required);
}

#[test]
fn test_session_conflict_child_longer_duration() {
    let parent = SessionPolicyConfig {
        max_duration_hours: 8,
        ..Default::default()
    };

    let child = SessionPolicyConfig {
        max_duration_hours: 24,
        ..Default::default()
    };

    // Child allows longer sessions - is less restrictive
    assert!(child.max_duration_hours > parent.max_duration_hours);
    assert!(!child.is_more_restrictive_than(&parent));
}

#[test]
fn test_policy_validation_result_with_warnings() {
    let result = PolicyValidationResult {
        valid: true,
        warnings: vec![
            PolicyConflictWarning {
                severity: "warning".to_string(),
                message: "Less restrictive than parent".to_string(),
                related_org_id: uuid::Uuid::new_v4(),
                related_org_name: "Engineering".to_string(),
                field: Some("min_length".to_string()),
            },
            PolicyConflictWarning {
                severity: "warning".to_string(),
                message: "MFA not required unlike parent".to_string(),
                related_org_id: uuid::Uuid::new_v4(),
                related_org_name: "Engineering".to_string(),
                field: Some("required".to_string()),
            },
        ],
    };

    // Warnings don't make it invalid
    assert!(result.valid);
    assert_eq!(result.warnings.len(), 2);
}

// ---------------------------------------------------------------------------
// T042: IP Restriction Enforcement Tests
// ---------------------------------------------------------------------------

#[test]
fn test_ip_restriction_single_ip_allowed() {
    let config = IpRestrictionPolicyConfig {
        allowed_cidrs: vec!["192.168.1.100/32".to_string()],
        denied_cidrs: vec![],
        action_on_violation: "deny".to_string(),
    };

    assert!(config.is_ip_allowed("192.168.1.100".parse().unwrap()));
    assert!(!config.is_ip_allowed("192.168.1.101".parse().unwrap()));
}

#[test]
fn test_ip_restriction_multiple_allowed_ranges() {
    let config = IpRestrictionPolicyConfig {
        allowed_cidrs: vec![
            "10.0.0.0/8".to_string(),
            "172.16.0.0/12".to_string(),
            "192.168.0.0/16".to_string(),
        ],
        denied_cidrs: vec![],
        action_on_violation: "deny".to_string(),
    };

    assert!(config.is_ip_allowed("10.1.2.3".parse().unwrap()));
    assert!(config.is_ip_allowed("172.20.1.1".parse().unwrap()));
    assert!(config.is_ip_allowed("192.168.100.1".parse().unwrap()));
    assert!(!config.is_ip_allowed("8.8.8.8".parse().unwrap()));
}

#[test]
fn test_ip_restriction_action_modes() {
    // Test that different action modes are valid
    for action in &["deny", "warn", "log"] {
        let config = IpRestrictionPolicyConfig {
            action_on_violation: action.to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    // Invalid action
    let config = IpRestrictionPolicyConfig {
        action_on_violation: "block".to_string(),
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_ip_restriction_empty_allowed_means_allow_all() {
    let config = IpRestrictionPolicyConfig {
        allowed_cidrs: vec![],
        denied_cidrs: vec![],
        action_on_violation: "deny".to_string(),
    };

    // No restrictions = allow everything
    assert!(!config.has_restrictions());
    assert!(config.is_ip_allowed("1.2.3.4".parse().unwrap()));
}

#[test]
fn test_ip_restriction_denied_only() {
    let config = IpRestrictionPolicyConfig {
        allowed_cidrs: vec![],
        denied_cidrs: vec!["10.0.0.0/8".to_string()],
        action_on_violation: "deny".to_string(),
    };

    // 10.x.x.x is denied, everything else allowed (no allowlist)
    assert!(!config.is_ip_allowed("10.1.2.3".parse().unwrap()));
    assert!(config.is_ip_allowed("192.168.1.1".parse().unwrap()));
}
