//! Filter parsing and matching for batch delete operations
//!
//! Supports glob patterns for matching resources by field values.

use crate::error::{CliError, CliResult};

/// Filter for selecting resources to delete
#[derive(Debug, Clone)]
pub struct Filter {
    /// Field to match (name, type, status, risk_level)
    pub field: String,
    /// Pattern to match (supports glob: *, ?)
    pub pattern: String,
}

impl Filter {
    /// Parse a filter from "field=pattern" syntax
    pub fn parse(filter_str: &str) -> CliResult<Self> {
        let parts: Vec<&str> = filter_str.splitn(2, '=').collect();

        if parts.len() != 2 {
            return Err(CliError::Validation(format!(
                "Invalid filter format '{}'. Use 'field=pattern' syntax (e.g., 'name=test-*')",
                filter_str
            )));
        }

        let field = parts[0].trim().to_lowercase();
        let pattern = parts[1].trim().to_string();

        // Validate field name
        match field.as_str() {
            "name" | "type" | "status" | "risk_level" => {}
            _ => {
                return Err(CliError::Validation(format!(
                    "Unknown filter field '{}'. Valid fields: name, type, status, risk_level",
                    field
                )));
            }
        }

        // Validate pattern is not empty
        if pattern.is_empty() {
            return Err(CliError::Validation(
                "Filter pattern cannot be empty".to_string(),
            ));
        }

        Ok(Self { field, pattern })
    }

    /// Check if a value matches this filter
    pub fn matches(&self, value: &str) -> bool {
        glob_match(&self.pattern, value)
    }

    /// Check if an agent matches this filter
    pub fn matches_agent(
        &self,
        name: &str,
        agent_type: &str,
        status: &str,
        risk_level: &str,
    ) -> bool {
        let value = match self.field.as_str() {
            "name" => name,
            "type" => agent_type,
            "status" => status,
            "risk_level" => risk_level,
            _ => return false,
        };
        self.matches(value)
    }

    /// Check if a tool matches this filter
    pub fn matches_tool(&self, name: &str, status: &str, risk_level: &str) -> bool {
        let value = match self.field.as_str() {
            "name" => name,
            "status" => status,
            "risk_level" => risk_level,
            "type" => return false, // Tools don't have a type field
            _ => return false,
        };
        self.matches(value)
    }
}

/// Simple glob pattern matching
///
/// Supports:
/// - `*` matches any sequence of characters
/// - `?` matches any single character
/// - Exact match otherwise
fn glob_match(pattern: &str, value: &str) -> bool {
    // Quick exact match check
    if !pattern.contains('*') && !pattern.contains('?') {
        return pattern == value;
    }

    // Convert glob to regex-like matching
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let value_chars: Vec<char> = value.chars().collect();

    glob_match_recursive(&pattern_chars, &value_chars, 0, 0)
}

/// Recursive glob matching helper
fn glob_match_recursive(pattern: &[char], value: &[char], mut pi: usize, mut vi: usize) -> bool {
    // Track backtrack points for * matching
    let mut star_idx: Option<usize> = None;
    let mut match_idx: usize = 0;

    while vi < value.len() {
        if pi < pattern.len() && (pattern[pi] == '?' || pattern[pi] == value[vi]) {
            // Character match or single wildcard
            pi += 1;
            vi += 1;
        } else if pi < pattern.len() && pattern[pi] == '*' {
            // Star wildcard - save backtrack point
            star_idx = Some(pi);
            match_idx = vi;
            pi += 1;
        } else if let Some(star) = star_idx {
            // Backtrack to last star
            pi = star + 1;
            match_idx += 1;
            vi = match_idx;
        } else {
            return false;
        }
    }

    // Check remaining pattern (must all be *)
    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }

    pi == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_parse_valid() {
        let filter = Filter::parse("name=test-*").unwrap();
        assert_eq!(filter.field, "name");
        assert_eq!(filter.pattern, "test-*");

        let filter2 = Filter::parse("type=copilot").unwrap();
        assert_eq!(filter2.field, "type");
        assert_eq!(filter2.pattern, "copilot");

        let filter3 = Filter::parse("risk_level=high").unwrap();
        assert_eq!(filter3.field, "risk_level");
        assert_eq!(filter3.pattern, "high");

        let filter4 = Filter::parse("status=active").unwrap();
        assert_eq!(filter4.field, "status");
        assert_eq!(filter4.pattern, "active");
    }

    #[test]
    fn test_filter_parse_case_insensitive_field() {
        let filter = Filter::parse("NAME=test").unwrap();
        assert_eq!(filter.field, "name");

        let filter2 = Filter::parse("Risk_Level=high").unwrap();
        assert_eq!(filter2.field, "risk_level");
    }

    #[test]
    fn test_filter_parse_invalid_format() {
        assert!(Filter::parse("name").is_err());
        assert!(Filter::parse("no-equals-sign").is_err());
        assert!(Filter::parse("").is_err());
    }

    #[test]
    fn test_filter_parse_unknown_field() {
        assert!(Filter::parse("unknown=value").is_err());
        assert!(Filter::parse("foo=bar").is_err());
    }

    #[test]
    fn test_filter_parse_empty_pattern() {
        assert!(Filter::parse("name=").is_err());
    }

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("test", "test"));
        assert!(!glob_match("test", "testing"));
        assert!(!glob_match("testing", "test"));
    }

    #[test]
    fn test_glob_match_prefix() {
        assert!(glob_match("test-*", "test-agent"));
        assert!(glob_match("test-*", "test-"));
        assert!(glob_match("test-*", "test-agent-1"));
        assert!(!glob_match("test-*", "my-test-agent"));
        assert!(!glob_match("test-*", "test"));
    }

    #[test]
    fn test_glob_match_suffix() {
        assert!(glob_match("*-prod", "agent-prod"));
        assert!(glob_match("*-prod", "my-agent-prod"));
        assert!(!glob_match("*-prod", "prod"));
        assert!(!glob_match("*-prod", "prod-agent"));
    }

    #[test]
    fn test_glob_match_contains() {
        assert!(glob_match("*test*", "test"));
        assert!(glob_match("*test*", "my-test-agent"));
        assert!(glob_match("*test*", "testing"));
        assert!(glob_match("*test*", "attest"));
        assert!(!glob_match("*test*", "no-match"));
    }

    #[test]
    fn test_glob_match_single_char() {
        assert!(glob_match("test-?", "test-1"));
        assert!(glob_match("test-?", "test-a"));
        assert!(!glob_match("test-?", "test-12"));
        assert!(!glob_match("test-?", "test-"));
    }

    #[test]
    fn test_glob_match_complex() {
        assert!(glob_match("*-agent-*", "my-agent-prod"));
        assert!(glob_match("test-*-agent", "test-1-agent"));
        assert!(glob_match("test-*-agent", "test-foo-bar-agent"));
        assert!(!glob_match("test-*-agent", "test-agent"));
    }

    #[test]
    fn test_glob_match_star_only() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("**", "anything"));
    }

    #[test]
    fn test_filter_matches_agent() {
        let filter = Filter::parse("name=test-*").unwrap();
        assert!(filter.matches_agent("test-agent", "copilot", "active", "low"));
        assert!(!filter.matches_agent("prod-agent", "copilot", "active", "low"));

        let type_filter = Filter::parse("type=copilot").unwrap();
        assert!(type_filter.matches_agent("any", "copilot", "active", "low"));
        assert!(!type_filter.matches_agent("any", "autonomous", "active", "low"));

        let risk_filter = Filter::parse("risk_level=high").unwrap();
        assert!(risk_filter.matches_agent("any", "any", "active", "high"));
        assert!(!risk_filter.matches_agent("any", "any", "active", "low"));
    }

    #[test]
    fn test_filter_matches_tool() {
        let filter = Filter::parse("name=send-*").unwrap();
        assert!(filter.matches_tool("send-email", "active", "low"));
        assert!(!filter.matches_tool("receive-data", "active", "low"));

        let status_filter = Filter::parse("status=active").unwrap();
        assert!(status_filter.matches_tool("any", "active", "low"));
        assert!(!status_filter.matches_tool("any", "inactive", "low"));

        // Type filter should not match tools
        let type_filter = Filter::parse("type=copilot").unwrap();
        assert!(!type_filter.matches_tool("any", "active", "low"));
    }
}
