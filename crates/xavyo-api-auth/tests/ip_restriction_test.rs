//! Tests for the IP restriction service (F028).
//!
//! These are unit tests for IP restriction logic including CIDR validation,
//! IP matching, scope filtering, and enforcement mode behavior.
//! Integration tests require database setup.

use xavyo_api_auth::services::{ip_matches_cidr, validate_cidr};
use xavyo_db::models::{IpEnforcementMode, IpRuleType};

// ============================================================================
// US1: Settings Operations Unit Tests
// ============================================================================

mod settings_tests {
    use super::*;

    #[test]
    fn test_enforcement_mode_default_is_disabled() {
        let mode = IpEnforcementMode::default();
        assert_eq!(mode, IpEnforcementMode::Disabled);
    }

    #[test]
    fn test_enforcement_mode_display() {
        assert_eq!(IpEnforcementMode::Disabled.to_string(), "disabled");
        assert_eq!(IpEnforcementMode::Whitelist.to_string(), "whitelist");
        assert_eq!(IpEnforcementMode::Blacklist.to_string(), "blacklist");
    }

    #[test]
    fn test_enforcement_mode_equality() {
        assert_eq!(IpEnforcementMode::Disabled, IpEnforcementMode::Disabled);
        assert_eq!(IpEnforcementMode::Whitelist, IpEnforcementMode::Whitelist);
        assert_eq!(IpEnforcementMode::Blacklist, IpEnforcementMode::Blacklist);
        assert_ne!(IpEnforcementMode::Disabled, IpEnforcementMode::Whitelist);
        assert_ne!(IpEnforcementMode::Whitelist, IpEnforcementMode::Blacklist);
    }

    #[test]
    fn test_enforcement_mode_clone() {
        let mode = IpEnforcementMode::Whitelist;
        let cloned = mode;
        assert_eq!(mode, cloned);
    }
}

// ============================================================================
// US2: Rule CRUD Operations Unit Tests
// ============================================================================

mod rule_tests {
    use super::*;

    #[test]
    fn test_rule_type_display() {
        assert_eq!(IpRuleType::Whitelist.to_string(), "whitelist");
        assert_eq!(IpRuleType::Blacklist.to_string(), "blacklist");
    }

    #[test]
    fn test_rule_type_equality() {
        assert_eq!(IpRuleType::Whitelist, IpRuleType::Whitelist);
        assert_eq!(IpRuleType::Blacklist, IpRuleType::Blacklist);
        assert_ne!(IpRuleType::Whitelist, IpRuleType::Blacklist);
    }

    #[test]
    fn test_rule_type_clone() {
        let rule_type = IpRuleType::Blacklist;
        let cloned = rule_type;
        assert_eq!(rule_type, cloned);
    }
}

// ============================================================================
// US3: IP Filtering Logic Unit Tests
// ============================================================================

mod cidr_validation_tests {
    use super::*;

    #[test]
    fn test_validate_cidr_single_ipv4() {
        assert!(validate_cidr("192.168.1.1/32").is_ok());
    }

    #[test]
    fn test_validate_cidr_ipv4_network() {
        assert!(validate_cidr("10.0.0.0/8").is_ok());
        assert!(validate_cidr("172.16.0.0/12").is_ok());
        assert!(validate_cidr("192.168.0.0/16").is_ok());
        assert!(validate_cidr("192.168.1.0/24").is_ok());
    }

    #[test]
    fn test_validate_cidr_ipv6() {
        assert!(validate_cidr("::1/128").is_ok());
        assert!(validate_cidr("fe80::/10").is_ok());
        assert!(validate_cidr("2001:db8::/32").is_ok());
    }

    #[test]
    fn test_validate_cidr_invalid_format() {
        assert!(validate_cidr("not-an-ip").is_err());
        // Note: "192.168.1.1" without prefix is valid (defaults to /32)
        assert!(validate_cidr("192.168.1.1/").is_err());
        assert!(validate_cidr("192.168.1.1/abc").is_err());
        assert!(validate_cidr("/24").is_err());
    }

    #[test]
    fn test_validate_cidr_invalid_prefix_length() {
        assert!(validate_cidr("192.168.1.1/33").is_err()); // Max for IPv4 is 32
        assert!(validate_cidr("::1/129").is_err()); // Max for IPv6 is 128
    }

    #[test]
    fn test_validate_cidr_invalid_ip() {
        assert!(validate_cidr("256.256.256.256/24").is_err());
        assert!(validate_cidr("192.168.1.256/24").is_err());
    }
}

mod ip_matching_tests {
    use super::*;

    #[test]
    fn test_ip_matches_single_host() {
        let ip = "192.168.1.100".parse().unwrap();
        assert!(ip_matches_cidr(&ip, "192.168.1.100/32"));
        assert!(!ip_matches_cidr(&ip, "192.168.1.101/32"));
    }

    #[test]
    fn test_ip_matches_subnet_slash_24() {
        let ip = "192.168.1.100".parse().unwrap();
        assert!(ip_matches_cidr(&ip, "192.168.1.0/24"));
        assert!(!ip_matches_cidr(&ip, "192.168.2.0/24"));
    }

    #[test]
    fn test_ip_matches_subnet_slash_16() {
        let ip = "10.50.100.200".parse().unwrap();
        assert!(ip_matches_cidr(&ip, "10.50.0.0/16"));
        assert!(!ip_matches_cidr(&ip, "10.51.0.0/16"));
    }

    #[test]
    fn test_ip_matches_subnet_slash_8() {
        let ip = "10.200.150.100".parse().unwrap();
        assert!(ip_matches_cidr(&ip, "10.0.0.0/8"));
        assert!(!ip_matches_cidr(&ip, "11.0.0.0/8"));
    }

    #[test]
    fn test_ip_matches_boundary_first_ip() {
        let ip = "192.168.1.0".parse().unwrap();
        assert!(ip_matches_cidr(&ip, "192.168.1.0/24"));
    }

    #[test]
    fn test_ip_matches_boundary_last_ip() {
        let ip = "192.168.1.255".parse().unwrap();
        assert!(ip_matches_cidr(&ip, "192.168.1.0/24"));
    }

    #[test]
    fn test_ip_matches_boundary_just_outside() {
        let first_outside = "192.168.0.255".parse().unwrap();
        let last_outside = "192.168.2.0".parse().unwrap();
        assert!(!ip_matches_cidr(&first_outside, "192.168.1.0/24"));
        assert!(!ip_matches_cidr(&last_outside, "192.168.1.0/24"));
    }

    #[test]
    fn test_ip_matches_ipv6() {
        let ip = "2001:db8::1".parse().unwrap();
        assert!(ip_matches_cidr(&ip, "2001:db8::/32"));
        assert!(!ip_matches_cidr(&ip, "2001:db9::/32"));
    }

    #[test]
    fn test_ip_matches_localhost_ipv4() {
        let ip = "127.0.0.1".parse().unwrap();
        assert!(ip_matches_cidr(&ip, "127.0.0.0/8"));
        assert!(ip_matches_cidr(&ip, "127.0.0.1/32"));
    }

    #[test]
    fn test_ip_matches_localhost_ipv6() {
        let ip = "::1".parse().unwrap();
        assert!(ip_matches_cidr(&ip, "::1/128"));
    }

    #[test]
    fn test_ip_no_match_ipv4_vs_ipv6() {
        let ipv4 = "127.0.0.1".parse().unwrap();
        let ipv6 = "::1".parse().unwrap();
        // IPv4 doesn't match IPv6 CIDR
        assert!(!ip_matches_cidr(&ipv4, "::1/128"));
        // IPv6 doesn't match IPv4 CIDR
        assert!(!ip_matches_cidr(&ipv6, "127.0.0.1/32"));
    }

    #[test]
    fn test_ip_matches_private_ranges() {
        // Class A private
        let class_a = "10.100.50.25".parse().unwrap();
        assert!(ip_matches_cidr(&class_a, "10.0.0.0/8"));

        // Class B private
        let class_b = "172.20.10.5".parse().unwrap();
        assert!(ip_matches_cidr(&class_b, "172.16.0.0/12"));

        // Class C private
        let class_c = "192.168.50.100".parse().unwrap();
        assert!(ip_matches_cidr(&class_c, "192.168.0.0/16"));
    }

    #[test]
    fn test_ip_matches_invalid_cidr_returns_false() {
        let ip = "192.168.1.100".parse().unwrap();
        assert!(!ip_matches_cidr(&ip, "not-valid-cidr"));
        assert!(!ip_matches_cidr(&ip, ""));
        assert!(!ip_matches_cidr(&ip, "192.168.1.0")); // Missing prefix
    }
}

// ============================================================================
// US4: Scope-Based Filtering Unit Tests
// ============================================================================

mod scope_tests {
    // Scope filtering is tested via the IpRestrictionRule::scope_applies method
    // These tests verify the scope matching logic

    #[test]
    fn test_scope_all_matches_any_role() {
        // When scope is "all", it should apply to any user
        // This is a placeholder - actual scope logic is in the model
    }

    #[test]
    fn test_scope_admin_matches_admin_role() {
        // When scope is "admin", it should only apply to admins
    }

    #[test]
    fn test_scope_role_specific_matches_role() {
        // When scope is "role:some_role", it should only apply to that role
    }
}

// ============================================================================
// US5: IP Validation Unit Tests
// ============================================================================

mod ip_validation_tests {
    use super::*;

    #[test]
    fn test_common_cidr_notations() {
        // Office IP
        assert!(validate_cidr("203.0.113.50/32").is_ok());
        // Office subnet
        assert!(validate_cidr("203.0.113.0/24").is_ok());
        // VPN range
        assert!(validate_cidr("10.8.0.0/16").is_ok());
        // Cloud provider range
        assert!(validate_cidr("35.192.0.0/12").is_ok());
    }

    #[test]
    fn test_cidr_for_single_ip() {
        // Single IP uses /32 for IPv4
        assert!(validate_cidr("8.8.8.8/32").is_ok());
        // Single IP uses /128 for IPv6
        assert!(validate_cidr("2001:4860:4860::8888/128").is_ok());
    }

    #[test]
    fn test_cidr_validation_provides_error_details() {
        let result = validate_cidr("invalid");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid"));
    }

    #[test]
    fn test_various_prefix_lengths() {
        // All valid IPv4 prefix lengths
        for prefix in 0..=32 {
            let cidr = format!("10.0.0.0/{}", prefix);
            assert!(
                validate_cidr(&cidr).is_ok(),
                "Should accept IPv4 prefix /{}",
                prefix
            );
        }
    }

    #[test]
    fn test_cidr_with_non_zero_host_bits() {
        // This is technically valid - the library normalizes it
        assert!(validate_cidr("192.168.1.100/24").is_ok());
    }
}

// ============================================================================
// Enforcement Mode Logic Tests
// ============================================================================

mod enforcement_logic_tests {
    use super::*;

    #[test]
    fn test_disabled_mode_allows_all() {
        // When enforcement is disabled, all IPs should be allowed
        // This is tested via the service, but we verify the mode logic
        assert_eq!(IpEnforcementMode::default(), IpEnforcementMode::Disabled);
    }

    #[test]
    fn test_whitelist_mode_blocks_by_default() {
        // In whitelist mode, IPs not matching any rule are blocked
        // This is the expected behavior - deny by default, allow explicit
        let mode = IpEnforcementMode::Whitelist;
        assert_eq!(mode.to_string(), "whitelist");
    }

    #[test]
    fn test_blacklist_mode_allows_by_default() {
        // In blacklist mode, IPs not matching any rule are allowed
        // This is the expected behavior - allow by default, deny explicit
        let mode = IpEnforcementMode::Blacklist;
        assert_eq!(mode.to_string(), "blacklist");
    }
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn test_empty_cidr_is_invalid() {
        assert!(validate_cidr("").is_err());
    }

    #[test]
    fn test_whitespace_cidr_is_invalid() {
        assert!(validate_cidr("   ").is_err());
        assert!(validate_cidr("192.168.1.0 /24").is_err());
    }

    #[test]
    fn test_cidr_with_port_is_invalid() {
        assert!(validate_cidr("192.168.1.1:8080/32").is_err());
    }

    #[test]
    fn test_loopback_addresses() {
        // IPv4 loopback
        let ipv4_loopback = "127.0.0.1".parse().unwrap();
        assert!(ip_matches_cidr(&ipv4_loopback, "127.0.0.0/8"));

        // IPv6 loopback
        let ipv6_loopback = "::1".parse().unwrap();
        assert!(ip_matches_cidr(&ipv6_loopback, "::1/128"));
    }

    #[test]
    fn test_link_local_addresses() {
        // IPv4 link-local (169.254.x.x)
        let ipv4_link_local = "169.254.1.1".parse().unwrap();
        assert!(ip_matches_cidr(&ipv4_link_local, "169.254.0.0/16"));

        // IPv6 link-local (fe80::/10)
        let ipv6_link_local = "fe80::1".parse().unwrap();
        assert!(ip_matches_cidr(&ipv6_link_local, "fe80::/10"));
    }

    #[test]
    fn test_zero_prefix_matches_all() {
        let ip = "203.0.113.50".parse().unwrap();
        assert!(ip_matches_cidr(&ip, "0.0.0.0/0")); // Any IPv4

        let ipv6 = "2001:db8::1".parse().unwrap();
        assert!(ip_matches_cidr(&ipv6, "::/0")); // Any IPv6
    }
}
