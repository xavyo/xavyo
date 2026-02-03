//! Group service for loading and formatting user groups in SAML assertions
//!
//! Provides group loading, filtering, and value formatting for SAML assertions.

use crate::models::group_config::{GroupAttributeConfig, GroupFilter, GroupValueFormat};
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::models::group_membership::UserGroupInfo;

/// Group information with full details for SAML assertion generation
#[derive(Debug, Clone)]
pub struct GroupInfo {
    /// Group UUID
    pub id: Uuid,
    /// Group display name
    pub display_name: String,
}

impl From<UserGroupInfo> for GroupInfo {
    fn from(info: UserGroupInfo) -> Self {
        Self {
            id: info.group_id,
            display_name: info.display_name,
        }
    }
}

/// Service for loading and processing user groups for SAML assertions
pub struct GroupService;

impl GroupService {
    /// Load user groups from database
    pub async fn load_user_groups(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<GroupInfo>, sqlx::Error> {
        let groups = xavyo_db::models::group_membership::GroupMembership::get_user_groups(
            pool, tenant_id, user_id,
        )
        .await?;

        Ok(groups.into_iter().map(GroupInfo::from).collect())
    }

    /// Load and process user groups according to SP configuration
    pub async fn load_groups_for_assertion(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        config: &GroupAttributeConfig,
    ) -> Result<Vec<String>, sqlx::Error> {
        // If groups are disabled, return empty
        if !config.include_groups {
            return Ok(vec![]);
        }

        // Load groups from database
        let groups = Self::load_user_groups(pool, tenant_id, user_id).await?;

        // Apply filter if configured
        let filtered = Self::apply_filter(&groups, config.filter.as_ref());

        // Format group values
        let formatted = Self::format_groups(&filtered, config);

        Ok(formatted)
    }

    /// Apply group filter to list of groups
    pub fn apply_filter(groups: &[GroupInfo], filter: Option<&GroupFilter>) -> Vec<GroupInfo> {
        match filter {
            Some(f) => groups
                .iter()
                .filter(|g| f.matches(&g.display_name))
                .cloned()
                .collect(),
            None => groups.to_vec(),
        }
    }

    /// Format groups according to configuration
    pub fn format_groups(groups: &[GroupInfo], config: &GroupAttributeConfig) -> Vec<String> {
        groups
            .iter()
            .map(|g| Self::format_group_value(g, &config.value_format, config.dn_base.as_deref()))
            .collect()
    }

    /// Format a single group value according to format specification
    pub fn format_group_value(
        group: &GroupInfo,
        format: &GroupValueFormat,
        dn_base: Option<&str>,
    ) -> String {
        match format {
            GroupValueFormat::Name => group.display_name.clone(),
            GroupValueFormat::Identifier => group.id.to_string(),
            GroupValueFormat::Dn => {
                let base = dn_base.unwrap_or("ou=Groups,dc=example,dc=com");
                // Escape special DN characters in group name
                let escaped_name = Self::escape_dn_value(&group.display_name);
                format!("cn={},{}", escaped_name, base)
            }
        }
    }

    /// Escape special characters in DN values per RFC 4514
    fn escape_dn_value(value: &str) -> String {
        let mut result = String::with_capacity(value.len() * 2);
        for c in value.chars() {
            match c {
                '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                    result.push('\\');
                    result.push(c);
                }
                '#' if result.is_empty() => {
                    result.push('\\');
                    result.push(c);
                }
                ' ' if result.is_empty() => {
                    result.push('\\');
                    result.push(c);
                }
                _ => result.push(c),
            }
        }
        // Escape trailing space
        if result.ends_with(' ') {
            result.pop();
            result.push_str("\\ ");
        }
        result
    }

    /// Get the attribute name to use for groups
    pub fn get_attribute_name(config: &GroupAttributeConfig) -> &str {
        &config.attribute_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_group(id: &str, name: &str) -> GroupInfo {
        GroupInfo {
            id: Uuid::parse_str(id).unwrap_or_else(|_| Uuid::new_v4()),
            display_name: name.to_string(),
        }
    }

    #[test]
    fn test_format_group_value_name() {
        let group = test_group("550e8400-e29b-41d4-a716-446655440000", "Engineering");
        let result = GroupService::format_group_value(&group, &GroupValueFormat::Name, None);
        assert_eq!(result, "Engineering");
    }

    #[test]
    fn test_format_group_value_id() {
        let group = test_group("550e8400-e29b-41d4-a716-446655440000", "Engineering");
        let result = GroupService::format_group_value(&group, &GroupValueFormat::Identifier, None);
        assert_eq!(result, "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_format_group_value_dn() {
        let group = test_group("550e8400-e29b-41d4-a716-446655440000", "Engineering");
        let result = GroupService::format_group_value(
            &group,
            &GroupValueFormat::Dn,
            Some("ou=Groups,dc=example,dc=com"),
        );
        assert_eq!(result, "cn=Engineering,ou=Groups,dc=example,dc=com");
    }

    #[test]
    fn test_format_group_value_dn_default_base() {
        let group = test_group("550e8400-e29b-41d4-a716-446655440000", "Admins");
        let result = GroupService::format_group_value(&group, &GroupValueFormat::Dn, None);
        assert_eq!(result, "cn=Admins,ou=Groups,dc=example,dc=com");
    }

    #[test]
    fn test_escape_dn_value() {
        assert_eq!(GroupService::escape_dn_value("Simple"), "Simple");
        assert_eq!(GroupService::escape_dn_value("R&D"), "R&D");
        assert_eq!(
            GroupService::escape_dn_value("Group, Inc."),
            "Group\\, Inc."
        );
        assert_eq!(GroupService::escape_dn_value("A+B"), "A\\+B");
        assert_eq!(GroupService::escape_dn_value(" Leading"), "\\ Leading");
        assert_eq!(GroupService::escape_dn_value("#Hash"), "\\#Hash");
    }

    #[test]
    fn test_apply_filter_none() {
        let groups = vec![
            test_group("00000000-0000-0000-0000-000000000001", "Engineering"),
            test_group("00000000-0000-0000-0000-000000000002", "Finance"),
        ];
        let result = GroupService::apply_filter(&groups, None);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_apply_filter_pattern() {
        let groups = vec![
            test_group("00000000-0000-0000-0000-000000000001", "app-admin"),
            test_group("00000000-0000-0000-0000-000000000002", "app-user"),
            test_group("00000000-0000-0000-0000-000000000003", "internal-team"),
        ];
        let filter = GroupFilter::with_patterns(vec!["app-*".to_string()]);
        let result = GroupService::apply_filter(&groups, Some(&filter));
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|g| g.display_name.starts_with("app-")));
    }

    #[test]
    fn test_apply_filter_allowlist() {
        let groups = vec![
            test_group("00000000-0000-0000-0000-000000000001", "Engineering"),
            test_group("00000000-0000-0000-0000-000000000002", "Finance"),
            test_group("00000000-0000-0000-0000-000000000003", "HR"),
        ];
        let filter = GroupFilter::with_allowlist(vec!["Engineering".to_string(), "HR".to_string()]);
        let result = GroupService::apply_filter(&groups, Some(&filter));
        assert_eq!(result.len(), 2);
        let names: Vec<_> = result.iter().map(|g| g.display_name.as_str()).collect();
        assert!(names.contains(&"Engineering"));
        assert!(names.contains(&"HR"));
        assert!(!names.contains(&"Finance"));
    }

    #[test]
    fn test_format_groups() {
        let groups = vec![
            test_group("00000000-0000-0000-0000-000000000001", "Engineering"),
            test_group("00000000-0000-0000-0000-000000000002", "Admins"),
        ];
        let config = GroupAttributeConfig::default();
        let result = GroupService::format_groups(&groups, &config);
        assert_eq!(result, vec!["Engineering", "Admins"]);
    }
}
