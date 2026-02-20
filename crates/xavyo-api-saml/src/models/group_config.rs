//! Group attribute configuration types for SAML assertions
//!
//! Defines how groups are included in SAML assertions per Service Provider.

use serde::{Deserialize, Serialize};

/// Format for group values in SAML assertions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum GroupValueFormat {
    /// Use group `display_name` (default)
    #[default]
    Name,
    /// Use group UUID
    #[serde(rename = "id")]
    Identifier,
    /// Use Distinguished Name format (e.g., cn=GroupName,ou=Groups,dc=example,dc=com)
    Dn,
}

impl GroupValueFormat {
    /// Parse from string representation
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "id" | "identifier" => Self::Identifier,
            "dn" => Self::Dn,
            _ => Self::Name,
        }
    }

    /// Convert to string representation
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Identifier => "id",
            Self::Dn => "dn",
        }
    }
}

/// Type of group filter
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum GroupFilterType {
    /// Include all groups (no filtering)
    #[default]
    None,
    /// Filter by glob patterns (e.g., "app-*", "*-admin")
    Pattern,
    /// Filter by explicit allowlist of group names
    Allowlist,
}

/// Group filter configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GroupFilter {
    /// Type of filter to apply
    #[serde(default)]
    pub filter_type: GroupFilterType,
    /// Patterns for pattern-based filtering (glob syntax)
    #[serde(default)]
    pub patterns: Vec<String>,
    /// Explicit list of allowed group names
    #[serde(default)]
    pub allowlist: Vec<String>,
}

impl GroupFilter {
    /// Create a filter that includes all groups
    #[must_use]
    pub fn none() -> Self {
        Self {
            filter_type: GroupFilterType::None,
            patterns: vec![],
            allowlist: vec![],
        }
    }

    /// Create a pattern-based filter
    #[must_use]
    pub fn with_patterns(patterns: Vec<String>) -> Self {
        Self {
            filter_type: GroupFilterType::Pattern,
            patterns,
            allowlist: vec![],
        }
    }

    /// Create an allowlist filter
    #[must_use]
    pub fn with_allowlist(allowlist: Vec<String>) -> Self {
        Self {
            filter_type: GroupFilterType::Allowlist,
            patterns: vec![],
            allowlist,
        }
    }

    /// Check if a group name matches the filter
    #[must_use]
    pub fn matches(&self, group_name: &str) -> bool {
        match self.filter_type {
            GroupFilterType::None => true,
            GroupFilterType::Pattern => self.matches_pattern(group_name),
            GroupFilterType::Allowlist => self.allowlist.contains(&group_name.to_string()),
        }
    }

    /// Check if group name matches any pattern
    fn matches_pattern(&self, group_name: &str) -> bool {
        for pattern in &self.patterns {
            if Self::glob_match(pattern, group_name) {
                return true;
            }
        }
        false
    }

    /// Simple glob matching (supports * wildcard)
    fn glob_match(pattern: &str, text: &str) -> bool {
        // Handle simple glob patterns with * wildcard
        if pattern == "*" {
            return true;
        }

        if !pattern.contains('*') {
            return pattern == text;
        }

        let parts: Vec<&str> = pattern.split('*').collect();

        if parts.len() == 2 {
            // Single wildcard: prefix*, *suffix, or *middle*
            let prefix = parts[0];
            let suffix = parts[1];

            if prefix.is_empty() && suffix.is_empty() {
                // Just "*" - matches everything
                return true;
            } else if prefix.is_empty() {
                // *suffix - ends with
                return text.ends_with(suffix);
            } else if suffix.is_empty() {
                // prefix* - starts with
                return text.starts_with(prefix);
            }
            // prefix*suffix - starts with prefix and ends with suffix
            return text.starts_with(prefix) && text.ends_with(suffix);
        }

        // Multi-segment wildcard: verify all parts appear in order within the text.
        // For pattern "a*b*c", parts = ["a", "b", "c"] — each must appear
        // sequentially in the text.
        let mut remaining = text;
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }
            if i == 0 {
                // First segment must be a prefix
                if !remaining.starts_with(*part) {
                    return false;
                }
                remaining = &remaining[part.len()..];
            } else if i == parts.len() - 1 {
                // Last segment must be a suffix of the remaining text
                if !remaining.ends_with(*part) {
                    return false;
                }
            } else {
                // Middle segments must appear somewhere in the remaining text
                match remaining.find(*part) {
                    Some(pos) => {
                        remaining = &remaining[pos + part.len()..];
                    }
                    None => return false,
                }
            }
        }

        true
    }
}

/// Complete group attribute configuration for an SP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupAttributeConfig {
    /// SAML attribute name for groups (default: "groups")
    #[serde(default = "default_attribute_name")]
    pub attribute_name: String,

    /// How to format group values
    #[serde(default)]
    pub value_format: GroupValueFormat,

    /// Optional filter for which groups to include
    #[serde(default)]
    pub filter: Option<GroupFilter>,

    /// Whether to include groups in assertions at all
    #[serde(default = "default_true")]
    pub include_groups: bool,

    /// Whether to omit the groups attribute when user has no groups
    #[serde(default = "default_true")]
    pub omit_empty_groups: bool,

    /// Base DN for DN format (e.g., "ou=Groups,dc=example,dc=com")
    #[serde(default)]
    pub dn_base: Option<String>,
}

fn default_attribute_name() -> String {
    "groups".to_string()
}

fn default_true() -> bool {
    true
}

impl Default for GroupAttributeConfig {
    fn default() -> Self {
        Self {
            attribute_name: default_attribute_name(),
            value_format: GroupValueFormat::default(),
            filter: None,
            include_groups: true,
            omit_empty_groups: true,
            dn_base: None,
        }
    }
}

impl GroupAttributeConfig {
    /// Create a minimal config with custom attribute name
    pub fn with_attribute_name(name: impl Into<String>) -> Self {
        Self {
            attribute_name: name.into(),
            ..Default::default()
        }
    }

    /// Create a config with ID format
    #[must_use]
    pub fn with_id_format() -> Self {
        Self {
            value_format: GroupValueFormat::Identifier,
            ..Default::default()
        }
    }

    /// Create a config with DN format
    pub fn with_dn_format(dn_base: impl Into<String>) -> Self {
        Self {
            value_format: GroupValueFormat::Dn,
            dn_base: Some(dn_base.into()),
            ..Default::default()
        }
    }

    /// Create a config that disables groups
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            include_groups: false,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_value_format_default() {
        let format = GroupValueFormat::default();
        assert_eq!(format, GroupValueFormat::Name);
    }

    #[test]
    fn test_group_value_format_from_str() {
        assert_eq!(GroupValueFormat::parse("name"), GroupValueFormat::Name);
        assert_eq!(GroupValueFormat::parse("id"), GroupValueFormat::Identifier);
        assert_eq!(
            GroupValueFormat::parse("identifier"),
            GroupValueFormat::Identifier
        );
        assert_eq!(GroupValueFormat::parse("dn"), GroupValueFormat::Dn);
        assert_eq!(GroupValueFormat::parse("unknown"), GroupValueFormat::Name);
    }

    #[test]
    fn test_group_filter_none() {
        let filter = GroupFilter::none();
        assert!(filter.matches("any-group"));
        assert!(filter.matches("another-group"));
    }

    #[test]
    fn test_group_filter_pattern_prefix() {
        let filter = GroupFilter::with_patterns(vec!["app-*".to_string()]);
        assert!(filter.matches("app-admin"));
        assert!(filter.matches("app-user"));
        assert!(!filter.matches("internal-team"));
    }

    #[test]
    fn test_group_filter_pattern_suffix() {
        let filter = GroupFilter::with_patterns(vec!["*-admin".to_string()]);
        assert!(filter.matches("app-admin"));
        assert!(filter.matches("super-admin"));
        assert!(!filter.matches("admin-user"));
    }

    #[test]
    fn test_group_filter_allowlist() {
        let filter =
            GroupFilter::with_allowlist(vec!["Engineering".to_string(), "Admins".to_string()]);
        assert!(filter.matches("Engineering"));
        assert!(filter.matches("Admins"));
        assert!(!filter.matches("Finance"));
    }

    #[test]
    fn test_group_attribute_config_default() {
        let config = GroupAttributeConfig::default();
        assert_eq!(config.attribute_name, "groups");
        assert_eq!(config.value_format, GroupValueFormat::Name);
        assert!(config.include_groups);
        assert!(config.omit_empty_groups);
        assert!(config.filter.is_none());
    }

    #[test]
    fn test_group_attribute_config_serialization() {
        let config = GroupAttributeConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: GroupAttributeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.attribute_name, config.attribute_name);
    }
}
