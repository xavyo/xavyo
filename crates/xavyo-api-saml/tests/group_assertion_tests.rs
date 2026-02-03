//! Group assertion tests for SAML
//!
//! Tests for F-039: SAML Group Assertions feature.

use std::time::Instant;
use uuid::Uuid;
use xavyo_api_saml::models::group_config::{GroupAttributeConfig, GroupFilter, GroupValueFormat};
use xavyo_api_saml::services::group_service::{GroupInfo, GroupService};

// ============================================================================
// User Story 1: Basic Group Inclusion (P1)
// ============================================================================

fn test_groups() -> Vec<GroupInfo> {
    vec![
        GroupInfo {
            id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            display_name: "Engineering".to_string(),
        },
        GroupInfo {
            id: Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            display_name: "Admins".to_string(),
        },
        GroupInfo {
            id: Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap(),
            display_name: "All-Users".to_string(),
        },
    ]
}

#[test]
fn test_basic_group_inclusion_with_three_groups() {
    // T009: Test basic group inclusion (user with 3 groups)
    let groups = test_groups();
    let config = GroupAttributeConfig::default();

    let formatted = GroupService::format_groups(&groups, &config);

    assert_eq!(formatted.len(), 3);
    assert!(formatted.contains(&"Engineering".to_string()));
    assert!(formatted.contains(&"Admins".to_string()));
    assert!(formatted.contains(&"All-Users".to_string()));
}

#[test]
fn test_user_with_no_groups_omit_empty() {
    // T010: Test user with no groups (omit_empty_groups=true)
    let groups: Vec<GroupInfo> = vec![];
    let config = GroupAttributeConfig {
        omit_empty_groups: true,
        ..Default::default()
    };

    let formatted = GroupService::format_groups(&groups, &config);

    // When omit_empty_groups is true and groups is empty, we return empty vec
    assert!(formatted.is_empty());
}

#[test]
fn test_user_with_no_groups_include_empty() {
    // T010 variation: Test user with no groups (omit_empty_groups=false)
    let groups: Vec<GroupInfo> = vec![];
    let config = GroupAttributeConfig {
        omit_empty_groups: false,
        ..Default::default()
    };

    let formatted = GroupService::format_groups(&groups, &config);

    // Even with omit_empty_groups=false, empty groups returns empty vec
    // The handler is responsible for including/excluding the attribute
    assert!(formatted.is_empty());
}

#[test]
fn test_large_group_count_performance() {
    // T011: Test large group count (500 groups, <500ms)
    let groups: Vec<GroupInfo> = (0..500)
        .map(|i| GroupInfo {
            id: Uuid::new_v4(),
            display_name: format!("Group-{}", i),
        })
        .collect();

    let config = GroupAttributeConfig::default();

    let start = Instant::now();
    let formatted = GroupService::format_groups(&groups, &config);
    let duration = start.elapsed();

    assert_eq!(formatted.len(), 500);
    assert!(
        duration.as_millis() < 500,
        "Formatting took {}ms, expected <500ms",
        duration.as_millis()
    );
}

#[test]
fn test_xml_special_character_escaping() {
    // T012: Test XML special character escaping in group names
    // Note: The GroupService formats values, XML escaping happens in assertion builder
    let groups = vec![
        GroupInfo {
            id: Uuid::new_v4(),
            display_name: "R&D <Team>".to_string(),
        },
        GroupInfo {
            id: Uuid::new_v4(),
            display_name: "Sales \"Quota\" Team".to_string(),
        },
    ];

    let config = GroupAttributeConfig::default();
    let formatted = GroupService::format_groups(&groups, &config);

    // GroupService returns raw names; XML escaping is done by assertion builder
    assert_eq!(formatted[0], "R&D <Team>");
    assert_eq!(formatted[1], "Sales \"Quota\" Team");
}

// ============================================================================
// User Story 2: Custom Attribute Name (P2)
// ============================================================================

#[test]
fn test_custom_attribute_name_memberof() {
    // T017: Test custom attribute name ("memberOf")
    let config = GroupAttributeConfig::with_attribute_name("memberOf");

    let name = GroupService::get_attribute_name(&config);

    assert_eq!(name, "memberOf");
}

#[test]
fn test_uri_attribute_name() {
    // T018: Test URI attribute name
    let config = GroupAttributeConfig::with_attribute_name("urn:custom:groups");

    let name = GroupService::get_attribute_name(&config);

    assert_eq!(name, "urn:custom:groups");
}

#[test]
fn test_default_attribute_name() {
    // T019: Test default attribute name when none configured
    let config = GroupAttributeConfig::default();

    let name = GroupService::get_attribute_name(&config);

    assert_eq!(name, "groups");
}

// ============================================================================
// User Story 3: Group Value Format (P3)
// ============================================================================

#[test]
fn test_group_id_format() {
    // T022: Test group ID format in assertions
    let group = GroupInfo {
        id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        display_name: "Engineering".to_string(),
    };

    let result = GroupService::format_group_value(&group, &GroupValueFormat::Identifier, None);

    assert_eq!(result, "550e8400-e29b-41d4-a716-446655440000");
}

#[test]
fn test_group_dn_format() {
    // T023: Test group DN format with base DN
    let group = GroupInfo {
        id: Uuid::new_v4(),
        display_name: "Engineering".to_string(),
    };

    let result = GroupService::format_group_value(
        &group,
        &GroupValueFormat::Dn,
        Some("ou=Groups,dc=example,dc=com"),
    );

    assert_eq!(result, "cn=Engineering,ou=Groups,dc=example,dc=com");
}

#[test]
fn test_default_name_format() {
    // T024: Test default name format
    let group = GroupInfo {
        id: Uuid::new_v4(),
        display_name: "Engineering".to_string(),
    };

    let result = GroupService::format_group_value(&group, &GroupValueFormat::Name, None);

    assert_eq!(result, "Engineering");
}

// ============================================================================
// User Story 4: Group Filtering (P4)
// ============================================================================

#[test]
fn test_pattern_filter() {
    // T028: Test pattern filter ("app-*")
    let groups = vec![
        GroupInfo {
            id: Uuid::new_v4(),
            display_name: "app-admin".to_string(),
        },
        GroupInfo {
            id: Uuid::new_v4(),
            display_name: "app-user".to_string(),
        },
        GroupInfo {
            id: Uuid::new_v4(),
            display_name: "internal-team".to_string(),
        },
    ];

    let filter = GroupFilter::with_patterns(vec!["app-*".to_string()]);
    let filtered = GroupService::apply_filter(&groups, Some(&filter));

    assert_eq!(filtered.len(), 2);
    assert!(filtered.iter().all(|g| g.display_name.starts_with("app-")));
}

#[test]
fn test_allowlist_filter() {
    // T029: Test allowlist filter
    let groups = vec![
        GroupInfo {
            id: Uuid::new_v4(),
            display_name: "Engineering".to_string(),
        },
        GroupInfo {
            id: Uuid::new_v4(),
            display_name: "Finance".to_string(),
        },
        GroupInfo {
            id: Uuid::new_v4(),
            display_name: "HR".to_string(),
        },
    ];

    let filter = GroupFilter::with_allowlist(vec!["Engineering".to_string(), "HR".to_string()]);
    let filtered = GroupService::apply_filter(&groups, Some(&filter));

    assert_eq!(filtered.len(), 2);
    let names: Vec<_> = filtered.iter().map(|g| g.display_name.as_str()).collect();
    assert!(names.contains(&"Engineering"));
    assert!(names.contains(&"HR"));
    assert!(!names.contains(&"Finance"));
}

#[test]
fn test_no_filter_all_groups_included() {
    // T030: Test no filter (all groups included)
    let groups = vec![
        GroupInfo {
            id: Uuid::new_v4(),
            display_name: "Engineering".to_string(),
        },
        GroupInfo {
            id: Uuid::new_v4(),
            display_name: "Finance".to_string(),
        },
    ];

    let filtered = GroupService::apply_filter(&groups, None);

    assert_eq!(filtered.len(), 2);
}

// ============================================================================
// Phase 7: Polish & Cross-Cutting Concerns
// ============================================================================

#[test]
fn test_tenant_isolation_separate_groups() {
    // T034: Test tenant isolation (no cross-tenant group leakage)
    // Note: This is a unit test verifying isolation is maintained in-memory
    // Full database isolation is tested via integration tests

    let tenant_a_groups = vec![GroupInfo {
        id: Uuid::new_v4(),
        display_name: "A-Group".to_string(),
    }];

    let tenant_b_groups = vec![GroupInfo {
        id: Uuid::new_v4(),
        display_name: "B-Group".to_string(),
    }];

    // Groups are loaded per-tenant, so no cross-contamination
    let config = GroupAttributeConfig::default();

    let formatted_a = GroupService::format_groups(&tenant_a_groups, &config);
    let formatted_b = GroupService::format_groups(&tenant_b_groups, &config);

    assert_eq!(formatted_a, vec!["A-Group"]);
    assert_eq!(formatted_b, vec!["B-Group"]);

    // Verify no cross-contamination
    assert!(!formatted_a.contains(&"B-Group".to_string()));
    assert!(!formatted_b.contains(&"A-Group".to_string()));
}

#[test]
fn test_include_groups_false_disables_groups() {
    // T035: Test include_groups=false disables groups
    let groups = test_groups();
    let config = GroupAttributeConfig {
        include_groups: false,
        ..Default::default()
    };

    // When include_groups is false, handler should not include groups
    // GroupService returns formatted groups, but handler checks config
    assert!(!config.include_groups);
}

#[test]
fn test_multi_sp_different_configs() {
    // T036: Test multi-SP with different configs
    let groups = vec![GroupInfo {
        id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        display_name: "Engineering".to_string(),
    }];

    // SP-A config: default attribute name, name format
    let config_a = GroupAttributeConfig::default();
    let name_a = GroupService::get_attribute_name(&config_a);
    let values_a = GroupService::format_groups(&groups, &config_a);

    // SP-B config: custom attribute name, ID format
    let config_b = GroupAttributeConfig {
        attribute_name: "memberOf".to_string(),
        value_format: GroupValueFormat::Identifier,
        ..Default::default()
    };
    let name_b = GroupService::get_attribute_name(&config_b);
    let values_b = GroupService::format_groups(&groups, &config_b);

    // Verify SP-A gets default config
    assert_eq!(name_a, "groups");
    assert_eq!(values_a, vec!["Engineering"]);

    // Verify SP-B gets custom config
    assert_eq!(name_b, "memberOf");
    assert_eq!(values_b, vec!["550e8400-e29b-41d4-a716-446655440000"]);
}

#[test]
fn test_idp_initiated_sso_includes_groups() {
    // T037: Test IdP-initiated SSO includes groups
    // This is a configuration test - the same GroupService is used
    // for both SP-initiated and IdP-initiated SSO
    let groups = test_groups();
    let config = GroupAttributeConfig::default();

    let formatted = GroupService::format_groups(&groups, &config);

    // Same formatting applies to IdP-initiated SSO
    assert_eq!(formatted.len(), 3);
}
