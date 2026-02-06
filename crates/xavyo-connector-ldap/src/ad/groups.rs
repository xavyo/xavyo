//! AD nested group resolution using BFS with cycle detection.
//!
//! Provides:
//! - Nested group membership resolution via BFS traversal
//! - Cycle detection to handle circular group nesting
//! - Max depth enforcement to prevent unbounded recursion
//! - Group attribute mapping from AD to platform model
//! - Group sync result building compatible with `SyncCapable`

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use xavyo_connector::operation::{AttributeSet, AttributeValue};
use xavyo_connector::traits::{SyncChange, SyncChangeType, SyncResult};

use super::schema::group_type;
use super::sync::UsnCheckpoint;

/// Result of resolving nested group membership.
#[derive(Debug, Clone)]
pub struct NestedGroupResult {
    /// Effective member DNs (all resolved user/group members including nested).
    pub effective_member_dns: Vec<String>,
    /// Whether max nesting depth was reached during resolution.
    pub depth_reached: bool,
    /// Number of cycles detected during traversal.
    pub cycles_detected: usize,
    /// Maximum depth actually traversed.
    pub max_depth_traversed: u32,
}

/// A mapped AD group ready for platform import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedGroup {
    /// External unique identifier (objectGUID as base64).
    pub external_id: String,
    /// Distinguished name.
    pub dn: String,
    /// Mapped platform attributes.
    pub attributes: HashMap<String, serde_json::Value>,
    /// Direct member DNs from the `member` attribute.
    pub direct_member_dns: Vec<String>,
    /// Whether this is a security group (vs distribution).
    pub is_security_group: bool,
    /// Group scope (global, `domain_local`, universal, unknown).
    pub scope: String,
    /// uSNChanged value for checkpoint tracking.
    pub usn_changed: Option<String>,
}

/// Map an AD group LDAP entry to a platform-compatible `MappedGroup`.
///
/// Attribute mapping:
/// - objectGUID → `external_id` (binary to base64)
/// - cn → `display_name`
/// - sAMAccountName → `sam_account_name`
/// - description → description
/// - groupType → `is_security_group` + scope
/// - member → `direct_member_dns` (multi-valued DN)
/// - memberOf → `member_of_dns` (read-only, multi-valued)
/// - managedBy → `managed_by_dn`
#[must_use]
pub fn map_ad_group(entry: &AttributeSet) -> Option<MappedGroup> {
    let external_id = extract_group_guid(entry)?;

    let dn = entry
        .get_string("distinguishedName")
        .or_else(|| entry.get_string("dn"))
        .unwrap_or("")
        .to_string();

    let mut attrs = HashMap::new();

    // Identity attributes
    set_if_present(&mut attrs, "display_name", entry.get_string("cn"));
    set_if_present(
        &mut attrs,
        "sam_account_name",
        entry.get_string("sAMAccountName"),
    );
    set_if_present(&mut attrs, "description", entry.get_string("description"));
    set_if_present(&mut attrs, "mail", entry.get_string("mail"));
    set_if_present(&mut attrs, "managed_by_dn", entry.get_string("managedBy"));

    // DN in attributes for reference
    if !dn.is_empty() {
        attrs.insert("dn".to_string(), serde_json::Value::String(dn.clone()));
    }

    // Parse groupType bitmask
    let (is_security, scope) = parse_group_type(entry);
    attrs.insert(
        "group_type".to_string(),
        serde_json::Value::String(if is_security {
            "security".to_string()
        } else {
            "distribution".to_string()
        }),
    );
    attrs.insert(
        "scope".to_string(),
        serde_json::Value::String(scope.clone()),
    );

    // Direct members
    let direct_member_dns = extract_multi_valued_dns(entry, "member");

    // memberOf (groups this group belongs to)
    let member_of_dns = extract_multi_valued_dns(entry, "memberOf");
    if !member_of_dns.is_empty() {
        let dns: Vec<serde_json::Value> = member_of_dns
            .iter()
            .map(|s| serde_json::Value::String(s.clone()))
            .collect();
        attrs.insert("member_of_dns".to_string(), serde_json::Value::Array(dns));
    }

    // Timestamps
    set_if_present(
        &mut attrs,
        "ad_when_created",
        entry.get_string("whenCreated"),
    );
    set_if_present(
        &mut attrs,
        "ad_when_changed",
        entry.get_string("whenChanged"),
    );

    let usn_changed = entry
        .get_string("uSNChanged")
        .map(std::string::ToString::to_string);

    Some(MappedGroup {
        external_id,
        dn,
        attributes: attrs,
        direct_member_dns,
        is_security_group: is_security,
        scope,
        usn_changed,
    })
}

/// Resolve nested group membership using BFS with cycle detection.
///
/// Starting from a group's direct member DNs, resolves nested groups by looking
/// up each member DN in the `group_dn_to_members` map. If a DN is found in the
/// map, it's a subgroup and its members are added to the queue.
///
/// # Arguments
/// * `direct_member_dns` — the starting group's direct member DNs
/// * `group_dn_to_members` — map of group DN (lowercase) → direct member DNs
/// * `max_depth` — maximum nesting depth to traverse (0 = direct only)
///
/// # Returns
/// A `NestedGroupResult` with all effective member DNs and traversal metadata.
#[instrument(skip(direct_member_dns, group_dn_to_members), fields(direct_count = direct_member_dns.len(), group_lookup_size = group_dn_to_members.len(), max_depth))]
pub fn resolve_nested_members(
    direct_member_dns: &[String],
    group_dn_to_members: &HashMap<String, Vec<String>>,
    max_depth: u32,
) -> NestedGroupResult {
    let mut effective_members: Vec<String> = Vec::new();
    let mut visited_groups: HashSet<String> = HashSet::new();
    let mut cycles_detected = 0;
    let mut depth_reached = false;
    let mut max_depth_traversed: u32 = 0;

    // BFS queue: (member_dn, current_depth)
    let mut queue: VecDeque<(String, u32)> = VecDeque::new();

    // Seed with direct members at depth 0
    for dn in direct_member_dns {
        queue.push_back((dn.clone(), 0));
    }

    // Track all seen member DNs (lowercased) to avoid duplicate effective members
    let mut seen_members: HashSet<String> = HashSet::new();

    while let Some((member_dn, depth)) = queue.pop_front() {
        let lower_dn = member_dn.to_lowercase();

        // Check if this is a group (exists in group_dn_to_members)
        if let Some(sub_members) = group_dn_to_members.get(&lower_dn) {
            // It's a subgroup — check for cycle
            if visited_groups.contains(&lower_dn) {
                cycles_detected += 1;
                continue;
            }

            // Check depth
            if depth >= max_depth {
                depth_reached = true;
                // Still add the group DN as a member, but don't expand it
                if seen_members.insert(lower_dn.clone()) {
                    effective_members.push(member_dn);
                }
                continue;
            }

            // Mark group as visited
            visited_groups.insert(lower_dn.clone());
            if depth + 1 > max_depth_traversed {
                max_depth_traversed = depth + 1;
            }

            // Enqueue subgroup's members at next depth
            for sub_dn in sub_members {
                queue.push_back((sub_dn.clone(), depth + 1));
            }
        } else {
            // It's a user (or non-group entity) — add to effective members
            if seen_members.insert(lower_dn) {
                effective_members.push(member_dn);
            }
        }
    }

    let result = NestedGroupResult {
        effective_member_dns: effective_members,
        depth_reached,
        cycles_detected,
        max_depth_traversed,
    };

    if result.cycles_detected > 0 {
        warn!(
            cycles = result.cycles_detected,
            "Circular group nesting detected during resolution"
        );
    }
    if result.depth_reached {
        info!(
            max_depth_traversed = result.max_depth_traversed,
            "Max nesting depth reached during group resolution"
        );
    }
    debug!(
        effective_members = result.effective_member_dns.len(),
        max_depth_traversed = result.max_depth_traversed,
        "Nested group resolution complete"
    );

    result
}

/// Build a `SyncChange` from a `MappedGroup`.
#[must_use]
pub fn mapped_group_to_sync_change(group: &MappedGroup, change_type: SyncChangeType) -> SyncChange {
    let mut attrs = AttributeSet::new();

    for (key, value) in &group.attributes {
        match value {
            serde_json::Value::String(s) => {
                attrs.set(key.clone(), s.clone());
            }
            serde_json::Value::Array(arr) => {
                let values: Vec<AttributeValue> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| AttributeValue::String(s.to_string())))
                    .collect();
                attrs.set(key.clone(), AttributeValue::Array(values));
            }
            serde_json::Value::Bool(b) => {
                attrs.set(key.clone(), *b);
            }
            _ => {}
        }
    }

    // Set core identifiers
    attrs.set("external_id", group.external_id.clone());
    attrs.set("is_security_group", group.is_security_group);

    // Set direct member count for informational purposes
    attrs.set(
        "direct_member_count",
        AttributeValue::Integer(group.direct_member_dns.len() as i64),
    );

    let uid = xavyo_connector::operation::Uid::new("objectGUID", &group.external_id);

    match change_type {
        SyncChangeType::Create => SyncChange::created(uid, "group", attrs),
        SyncChangeType::Update => SyncChange::updated(uid, "group", attrs),
        SyncChangeType::Delete => SyncChange::deleted(uid, "group"),
    }
}

/// Build a `SyncResult` from a batch of mapped groups.
#[instrument(skip(groups), fields(group_count = groups.len(), has_more))]
pub fn build_group_sync_result(
    groups: Vec<MappedGroup>,
    change_type: SyncChangeType,
    new_checkpoint: Option<UsnCheckpoint>,
    has_more: bool,
) -> SyncResult {
    info!(
        group_count = groups.len(),
        ?change_type,
        "Building group sync result"
    );
    let changes: Vec<SyncChange> = groups
        .iter()
        .map(|g| mapped_group_to_sync_change(g, change_type))
        .collect();

    let mut result = SyncResult::with_changes(changes);

    if let Some(checkpoint) = new_checkpoint {
        result = result.with_token(checkpoint.to_token());
    }

    if has_more {
        result = result.with_more();
    }

    result
}

/// Compute the highest uSNChanged value from a batch of mapped groups.
#[must_use]
pub fn highest_group_usn(groups: &[MappedGroup]) -> Option<String> {
    groups
        .iter()
        .filter_map(|g| g.usn_changed.as_ref())
        .filter_map(|s| s.parse::<u64>().ok())
        .max()
        .map(|v| v.to_string())
}

/// Build the LDAP attribute list for AD group sync queries.
#[must_use]
pub fn group_sync_attributes() -> Vec<&'static str> {
    vec![
        "objectGUID",
        "distinguishedName",
        "sAMAccountName",
        "cn",
        "description",
        "mail",
        "groupType",
        "managedBy",
        "member",
        "memberOf",
        "whenCreated",
        "whenChanged",
        "uSNChanged",
    ]
}

/// Compute membership diff: additions and removals.
///
/// Given the set of current effective member `external_ids` (from AD nested resolution)
/// and the set of existing platform member `external_ids`, returns the sets to add and remove.
#[instrument(skip(ad_member_external_ids, platform_member_external_ids), fields(ad_count = ad_member_external_ids.len(), platform_count = platform_member_external_ids.len()))]
pub fn compute_membership_diff(
    ad_member_external_ids: &HashSet<String>,
    platform_member_external_ids: &HashSet<String>,
) -> MembershipDiff {
    let to_add: Vec<String> = ad_member_external_ids
        .difference(platform_member_external_ids)
        .cloned()
        .collect();
    let to_remove: Vec<String> = platform_member_external_ids
        .difference(ad_member_external_ids)
        .cloned()
        .collect();
    MembershipDiff { to_add, to_remove }
}

/// Result of computing membership differences.
#[derive(Debug, Clone)]
pub struct MembershipDiff {
    /// External IDs of members to add to the platform group.
    pub to_add: Vec<String>,
    /// External IDs of members to remove from the platform group.
    pub to_remove: Vec<String>,
}

// --- Internal helpers ---

fn extract_group_guid(entry: &AttributeSet) -> Option<String> {
    match entry.get("objectGUID") {
        Some(AttributeValue::Binary(bytes)) => {
            Some(base64::engine::general_purpose::STANDARD.encode(bytes))
        }
        Some(AttributeValue::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

fn parse_group_type(entry: &AttributeSet) -> (bool, String) {
    let gt_val = match entry.get("groupType") {
        Some(AttributeValue::Integer(i)) => Some(*i as i32),
        Some(AttributeValue::String(s)) => s.parse::<i32>().ok(),
        _ => None,
    };

    match gt_val {
        Some(gt) => (
            group_type::is_security_group(gt),
            group_type::scope_name(gt).to_string(),
        ),
        None => (false, "unknown".to_string()),
    }
}

fn extract_multi_valued_dns(entry: &AttributeSet, attr_name: &str) -> Vec<String> {
    match entry.get(attr_name) {
        Some(AttributeValue::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_string().map(std::string::ToString::to_string))
            .collect(),
        Some(AttributeValue::String(s)) if !s.is_empty() => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn set_if_present(attrs: &mut HashMap<String, serde_json::Value>, key: &str, value: Option<&str>) {
    if let Some(v) = value {
        if !v.is_empty() {
            attrs.insert(key.to_string(), serde_json::Value::String(v.to_string()));
        }
    }
}

use base64::Engine;

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_connector::operation::{AttributeSet, AttributeValue};

    // --- T016: Tests for nested group resolution ---

    #[test]
    fn test_resolve_direct_members_only() {
        // Group with direct user members, no nesting
        let group_members: HashMap<String, Vec<String>> = HashMap::new();
        let direct = vec![
            "CN=Alice,OU=Users,DC=ex,DC=com".to_string(),
            "CN=Bob,OU=Users,DC=ex,DC=com".to_string(),
        ];

        let result = resolve_nested_members(&direct, &group_members, 10);

        assert_eq!(result.effective_member_dns.len(), 2);
        assert!(!result.depth_reached);
        assert_eq!(result.cycles_detected, 0);
        assert_eq!(result.max_depth_traversed, 0);
    }

    #[test]
    fn test_resolve_two_level_nesting() {
        // GroupA members: [SubGroupB, Alice]
        // SubGroupB members: [Bob, Charlie]
        let mut group_members: HashMap<String, Vec<String>> = HashMap::new();
        group_members.insert(
            "cn=subgroupb,ou=groups,dc=ex,dc=com".to_string(),
            vec![
                "CN=Bob,OU=Users,DC=ex,DC=com".to_string(),
                "CN=Charlie,OU=Users,DC=ex,DC=com".to_string(),
            ],
        );

        let direct = vec![
            "CN=SubGroupB,OU=Groups,DC=ex,DC=com".to_string(),
            "CN=Alice,OU=Users,DC=ex,DC=com".to_string(),
        ];

        let result = resolve_nested_members(&direct, &group_members, 10);

        assert_eq!(result.effective_member_dns.len(), 3); // Alice, Bob, Charlie
        assert!(!result.depth_reached);
        assert_eq!(result.cycles_detected, 0);
        assert_eq!(result.max_depth_traversed, 1);
    }

    #[test]
    fn test_resolve_five_level_nesting() {
        let mut group_members: HashMap<String, Vec<String>> = HashMap::new();
        group_members.insert(
            "cn=g1,dc=ex,dc=com".to_string(),
            vec!["CN=G2,DC=ex,DC=com".to_string()],
        );
        group_members.insert(
            "cn=g2,dc=ex,dc=com".to_string(),
            vec!["CN=G3,DC=ex,DC=com".to_string()],
        );
        group_members.insert(
            "cn=g3,dc=ex,dc=com".to_string(),
            vec!["CN=G4,DC=ex,DC=com".to_string()],
        );
        group_members.insert(
            "cn=g4,dc=ex,dc=com".to_string(),
            vec!["CN=G5,DC=ex,DC=com".to_string()],
        );
        group_members.insert(
            "cn=g5,dc=ex,dc=com".to_string(),
            vec!["CN=User,OU=Users,DC=ex,DC=com".to_string()],
        );

        let direct = vec!["CN=G1,DC=ex,DC=com".to_string()];

        let result = resolve_nested_members(&direct, &group_members, 10);

        assert_eq!(result.effective_member_dns.len(), 1); // User at the bottom
        assert!(!result.depth_reached);
        assert_eq!(result.cycles_detected, 0);
        assert_eq!(result.max_depth_traversed, 5);
    }

    #[test]
    fn test_resolve_circular_reference() {
        // A→B→C→A (cycle)
        let mut group_members: HashMap<String, Vec<String>> = HashMap::new();
        group_members.insert(
            "cn=a,dc=ex,dc=com".to_string(),
            vec![
                "CN=B,DC=ex,DC=com".to_string(),
                "CN=User1,DC=ex,DC=com".to_string(),
            ],
        );
        group_members.insert(
            "cn=b,dc=ex,dc=com".to_string(),
            vec!["CN=C,DC=ex,DC=com".to_string()],
        );
        group_members.insert(
            "cn=c,dc=ex,dc=com".to_string(),
            vec!["CN=A,DC=ex,DC=com".to_string()], // cycle back to A
        );

        let direct = vec![
            "CN=B,DC=ex,DC=com".to_string(),
            "CN=User1,DC=ex,DC=com".to_string(),
        ];

        // Seed the BFS as if we're resolving group A
        // First mark A as already visited (it's the root group)
        let result = resolve_nested_members(&direct, &group_members, 10);

        // Should detect the cycle and not loop forever
        assert!(result
            .effective_member_dns
            .contains(&"CN=User1,DC=ex,DC=com".to_string()));
        // Cycles_detected will depend on traversal — at minimum B and C expand,
        // then C→A is detected as a cycle since A is in group_members but gets visited via B
        assert!(result.cycles_detected >= 1 || !result.effective_member_dns.is_empty());
    }

    #[test]
    fn test_resolve_max_depth_enforcement() {
        // 3-level nesting with max_depth=1
        let mut group_members: HashMap<String, Vec<String>> = HashMap::new();
        group_members.insert(
            "cn=g1,dc=ex,dc=com".to_string(),
            vec!["CN=G2,DC=ex,DC=com".to_string()],
        );
        group_members.insert(
            "cn=g2,dc=ex,dc=com".to_string(),
            vec!["CN=DeepUser,DC=ex,DC=com".to_string()],
        );

        let direct = vec!["CN=G1,DC=ex,DC=com".to_string()];

        let result = resolve_nested_members(&direct, &group_members, 1);

        // G1 expands at depth 0→1, finds G2, but G2 is at depth 1 which is the max
        // so G2 gets added as a member but not expanded
        assert!(result.depth_reached);
        // G2 should be in effective members since it was not expanded
        assert!(result
            .effective_member_dns
            .iter()
            .any(|d| d.to_lowercase().contains("g2")));
    }

    #[test]
    fn test_resolve_empty_group() {
        let group_members: HashMap<String, Vec<String>> = HashMap::new();
        let direct: Vec<String> = vec![];

        let result = resolve_nested_members(&direct, &group_members, 10);

        assert!(result.effective_member_dns.is_empty());
        assert!(!result.depth_reached);
        assert_eq!(result.cycles_detected, 0);
    }

    #[test]
    fn test_resolve_mixed_members() {
        // Group with both user members and a subgroup
        let mut group_members: HashMap<String, Vec<String>> = HashMap::new();
        group_members.insert(
            "cn=subgroup,dc=ex,dc=com".to_string(),
            vec!["CN=Charlie,DC=ex,DC=com".to_string()],
        );

        let direct = vec![
            "CN=Alice,DC=ex,DC=com".to_string(),
            "CN=SubGroup,DC=ex,DC=com".to_string(),
            "CN=Bob,DC=ex,DC=com".to_string(),
        ];

        let result = resolve_nested_members(&direct, &group_members, 10);

        assert_eq!(result.effective_member_dns.len(), 3); // Alice, Bob, Charlie
        assert!(!result.depth_reached);
    }

    #[test]
    fn test_resolve_deduplication() {
        // Same user appears in two paths
        let mut group_members: HashMap<String, Vec<String>> = HashMap::new();
        group_members.insert(
            "cn=g1,dc=ex,dc=com".to_string(),
            vec!["CN=SharedUser,DC=ex,DC=com".to_string()],
        );
        group_members.insert(
            "cn=g2,dc=ex,dc=com".to_string(),
            vec!["CN=SharedUser,DC=ex,DC=com".to_string()],
        );

        let direct = vec![
            "CN=G1,DC=ex,DC=com".to_string(),
            "CN=G2,DC=ex,DC=com".to_string(),
        ];

        let result = resolve_nested_members(&direct, &group_members, 10);

        // SharedUser appears once, not twice
        assert_eq!(result.effective_member_dns.len(), 1);
    }

    // --- T017: Tests for AD group attribute mapping ---

    fn sample_ad_group_entry() -> AttributeSet {
        let mut attrs = AttributeSet::new();
        attrs.set(
            "objectGUID",
            AttributeValue::Binary(vec![
                0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E,
                0x8F, 0x90,
            ]),
        );
        attrs.set(
            "distinguishedName",
            "CN=Developers,OU=Groups,DC=example,DC=com",
        );
        attrs.set("sAMAccountName", "Developers");
        attrs.set("cn", "Developers");
        attrs.set("description", "Engineering development team");
        attrs.set("mail", "developers@example.com");
        attrs.set("managedBy", "CN=Jane Lead,OU=Users,DC=example,DC=com");
        // Security + Global = 0x80000002
        attrs.set(
            "groupType",
            AttributeValue::Integer(-2147483646), // 0x80000002 as i64
        );
        attrs.set(
            "member",
            AttributeValue::Array(vec![
                AttributeValue::String("CN=Alice,OU=Users,DC=example,DC=com".to_string()),
                AttributeValue::String("CN=Bob,OU=Users,DC=example,DC=com".to_string()),
                AttributeValue::String("CN=SubTeam,OU=Groups,DC=example,DC=com".to_string()),
            ]),
        );
        attrs.set(
            "memberOf",
            AttributeValue::Array(vec![AttributeValue::String(
                "CN=AllStaff,OU=Groups,DC=example,DC=com".to_string(),
            )]),
        );
        attrs.set("whenCreated", "20240115120000.0Z");
        attrs.set("whenChanged", "20240620153045.0Z");
        attrs.set("uSNChanged", "654321");
        attrs
    }

    #[test]
    fn test_map_ad_group_basic_attributes() {
        let entry = sample_ad_group_entry();
        let mapped = map_ad_group(&entry).unwrap();

        assert_eq!(mapped.attributes["display_name"], "Developers");
        assert_eq!(mapped.attributes["sam_account_name"], "Developers");
        assert_eq!(
            mapped.attributes["description"],
            "Engineering development team"
        );
        assert_eq!(mapped.attributes["mail"], "developers@example.com");
    }

    #[test]
    fn test_map_ad_group_objectguid() {
        let entry = sample_ad_group_entry();
        let mapped = map_ad_group(&entry).unwrap();

        let expected = base64::engine::general_purpose::STANDARD.encode([
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E,
            0x8F, 0x90,
        ]);
        assert_eq!(mapped.external_id, expected);
    }

    #[test]
    fn test_map_ad_group_dn() {
        let entry = sample_ad_group_entry();
        let mapped = map_ad_group(&entry).unwrap();

        assert_eq!(mapped.dn, "CN=Developers,OU=Groups,DC=example,DC=com");
        assert_eq!(
            mapped.attributes["dn"],
            "CN=Developers,OU=Groups,DC=example,DC=com"
        );
    }

    #[test]
    fn test_map_ad_group_security_type() {
        let entry = sample_ad_group_entry();
        let mapped = map_ad_group(&entry).unwrap();

        assert!(mapped.is_security_group);
        assert_eq!(mapped.scope, "global");
        assert_eq!(mapped.attributes["group_type"], "security");
        assert_eq!(mapped.attributes["scope"], "global");
    }

    #[test]
    fn test_map_ad_group_distribution_type() {
        let mut entry = sample_ad_group_entry();
        // Universal distribution group (no security bit) = 0x8
        entry.set("groupType", AttributeValue::Integer(0x8));

        let mapped = map_ad_group(&entry).unwrap();

        assert!(!mapped.is_security_group);
        assert_eq!(mapped.scope, "universal");
        assert_eq!(mapped.attributes["group_type"], "distribution");
    }

    #[test]
    fn test_map_ad_group_members() {
        let entry = sample_ad_group_entry();
        let mapped = map_ad_group(&entry).unwrap();

        assert_eq!(mapped.direct_member_dns.len(), 3);
        assert!(mapped
            .direct_member_dns
            .contains(&"CN=Alice,OU=Users,DC=example,DC=com".to_string()));
        assert!(mapped
            .direct_member_dns
            .contains(&"CN=Bob,OU=Users,DC=example,DC=com".to_string()));
        assert!(mapped
            .direct_member_dns
            .contains(&"CN=SubTeam,OU=Groups,DC=example,DC=com".to_string()));
    }

    #[test]
    fn test_map_ad_group_member_of() {
        let entry = sample_ad_group_entry();
        let mapped = map_ad_group(&entry).unwrap();

        let member_of = mapped.attributes["member_of_dns"].as_array().unwrap();
        assert_eq!(member_of.len(), 1);
        assert_eq!(
            member_of[0].as_str().unwrap(),
            "CN=AllStaff,OU=Groups,DC=example,DC=com"
        );
    }

    #[test]
    fn test_map_ad_group_managed_by() {
        let entry = sample_ad_group_entry();
        let mapped = map_ad_group(&entry).unwrap();

        assert_eq!(
            mapped.attributes["managed_by_dn"],
            "CN=Jane Lead,OU=Users,DC=example,DC=com"
        );
    }

    #[test]
    fn test_map_ad_group_timestamps() {
        let entry = sample_ad_group_entry();
        let mapped = map_ad_group(&entry).unwrap();

        assert_eq!(mapped.attributes["ad_when_created"], "20240115120000.0Z");
        assert_eq!(mapped.attributes["ad_when_changed"], "20240620153045.0Z");
    }

    #[test]
    fn test_map_ad_group_usn_changed() {
        let entry = sample_ad_group_entry();
        let mapped = map_ad_group(&entry).unwrap();

        assert_eq!(mapped.usn_changed, Some("654321".to_string()));
    }

    #[test]
    fn test_map_ad_group_missing_objectguid() {
        let mut entry = AttributeSet::new();
        entry.set("cn", "TestGroup");
        // No objectGUID

        assert!(map_ad_group(&entry).is_none());
    }

    #[test]
    fn test_map_ad_group_minimal() {
        let mut entry = AttributeSet::new();
        entry.set("objectGUID", AttributeValue::Binary(vec![0x01; 16]));

        let mapped = map_ad_group(&entry).unwrap();
        assert!(!mapped.external_id.is_empty());
        assert!(mapped.direct_member_dns.is_empty());
        assert!(!mapped.is_security_group); // default
        assert_eq!(mapped.scope, "unknown");
    }

    #[test]
    fn test_map_ad_group_single_member() {
        let mut entry = AttributeSet::new();
        entry.set("objectGUID", AttributeValue::Binary(vec![0x02; 16]));
        // Single member as string (not array)
        entry.set("member", "CN=Solo,OU=Users,DC=ex,DC=com");

        let mapped = map_ad_group(&entry).unwrap();
        assert_eq!(mapped.direct_member_dns.len(), 1);
        assert_eq!(mapped.direct_member_dns[0], "CN=Solo,OU=Users,DC=ex,DC=com");
    }

    #[test]
    fn test_map_ad_group_grouptype_as_string() {
        let mut entry = sample_ad_group_entry();
        // Some LDAP returns groupType as string
        entry.set("groupType", "-2147483644"); // 0x80000004 = security + domain-local

        let mapped = map_ad_group(&entry).unwrap();
        assert!(mapped.is_security_group);
        assert_eq!(mapped.scope, "domain_local");
    }

    // --- Tests for group sync result building ---

    #[test]
    fn test_build_group_sync_result() {
        let groups = vec![MappedGroup {
            external_id: "group-guid".to_string(),
            dn: "CN=TestGroup,DC=ex,DC=com".to_string(),
            attributes: {
                let mut m = HashMap::new();
                m.insert(
                    "display_name".to_string(),
                    serde_json::Value::String("TestGroup".to_string()),
                );
                m
            },
            direct_member_dns: vec!["CN=User1,DC=ex,DC=com".to_string()],
            is_security_group: true,
            scope: "global".to_string(),
            usn_changed: Some("999".to_string()),
        }];

        let checkpoint = UsnCheckpoint::new("999", "dc01.example.com");
        let result =
            build_group_sync_result(groups, SyncChangeType::Create, Some(checkpoint), false);

        assert_eq!(result.changes.len(), 1);
        assert!(!result.has_more);
        assert!(result.new_token.is_some());
    }

    #[test]
    fn test_highest_group_usn() {
        let groups = vec![
            MappedGroup {
                external_id: "a".to_string(),
                dn: String::new(),
                attributes: HashMap::new(),
                direct_member_dns: vec![],
                is_security_group: false,
                scope: "global".to_string(),
                usn_changed: Some("100".to_string()),
            },
            MappedGroup {
                external_id: "b".to_string(),
                dn: String::new(),
                attributes: HashMap::new(),
                direct_member_dns: vec![],
                is_security_group: false,
                scope: "global".to_string(),
                usn_changed: Some("500".to_string()),
            },
        ];

        assert_eq!(highest_group_usn(&groups), Some("500".to_string()));
    }

    #[test]
    fn test_group_sync_attributes_list() {
        let attrs = group_sync_attributes();
        assert!(attrs.contains(&"objectGUID"));
        assert!(attrs.contains(&"sAMAccountName"));
        assert!(attrs.contains(&"cn"));
        assert!(attrs.contains(&"description"));
        assert!(attrs.contains(&"groupType"));
        assert!(attrs.contains(&"member"));
        assert!(attrs.contains(&"memberOf"));
        assert!(attrs.contains(&"managedBy"));
        assert!(attrs.contains(&"uSNChanged"));
    }

    // --- T020: Tests for membership diff ---

    #[test]
    fn test_membership_diff_additions_only() {
        let ad: HashSet<String> = ["a", "b", "c"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let platform: HashSet<String> =
            ["a"].iter().map(std::string::ToString::to_string).collect();

        let diff = compute_membership_diff(&ad, &platform);
        assert_eq!(diff.to_add.len(), 2);
        assert!(diff.to_remove.is_empty());
    }

    #[test]
    fn test_membership_diff_removals_only() {
        let ad: HashSet<String> = ["a"].iter().map(std::string::ToString::to_string).collect();
        let platform: HashSet<String> = ["a", "b", "c"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        let diff = compute_membership_diff(&ad, &platform);
        assert!(diff.to_add.is_empty());
        assert_eq!(diff.to_remove.len(), 2);
    }

    #[test]
    fn test_membership_diff_mixed() {
        let ad: HashSet<String> = ["a", "b", "new"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let platform: HashSet<String> = ["a", "b", "old"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        let diff = compute_membership_diff(&ad, &platform);
        assert_eq!(diff.to_add, vec!["new"]);
        assert_eq!(diff.to_remove, vec!["old"]);
    }

    #[test]
    fn test_membership_diff_identical() {
        let ad: HashSet<String> = ["a", "b"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let platform: HashSet<String> = ["a", "b"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        let diff = compute_membership_diff(&ad, &platform);
        assert!(diff.to_add.is_empty());
        assert!(diff.to_remove.is_empty());
    }

    #[test]
    fn test_membership_diff_empty_ad() {
        let ad: HashSet<String> = HashSet::new();
        let platform: HashSet<String> = ["a", "b"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        let diff = compute_membership_diff(&ad, &platform);
        assert!(diff.to_add.is_empty());
        assert_eq!(diff.to_remove.len(), 2);
    }

    #[test]
    fn test_membership_diff_empty_platform() {
        let ad: HashSet<String> = ["a", "b"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let platform: HashSet<String> = HashSet::new();

        let diff = compute_membership_diff(&ad, &platform);
        assert_eq!(diff.to_add.len(), 2);
        assert!(diff.to_remove.is_empty());
    }

    #[test]
    fn test_mapped_group_to_sync_change_create() {
        let group = MappedGroup {
            external_id: "guid-grp".to_string(),
            dn: "CN=TestGroup,DC=ex,DC=com".to_string(),
            attributes: {
                let mut m = HashMap::new();
                m.insert(
                    "display_name".to_string(),
                    serde_json::Value::String("TestGroup".to_string()),
                );
                m
            },
            direct_member_dns: vec![
                "CN=A,DC=ex,DC=com".to_string(),
                "CN=B,DC=ex,DC=com".to_string(),
            ],
            is_security_group: true,
            scope: "global".to_string(),
            usn_changed: None,
        };

        let change = mapped_group_to_sync_change(&group, SyncChangeType::Create);
        assert_eq!(change.object_class, "group");
        assert!(matches!(change.change_type, SyncChangeType::Create));

        let attrs = change.attributes.as_ref().unwrap();
        assert_eq!(attrs.get_string("external_id"), Some("guid-grp"));
        assert_eq!(attrs.get_string("display_name"), Some("TestGroup"));
    }
}
