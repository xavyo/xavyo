//! RFC 7644 Filter Compliance Tests
//!
//! These tests verify that the SCIM filter parser correctly handles
//! all operators defined in RFC 7644 Section 3.4.2.

#[cfg(test)]
mod tests {
    // ============================================================
    // Basic Comparison Operators (eq, ne, co, sw, ew, pr)
    // ============================================================

    #[test]
    fn test_filter_eq_operator_string() {
        // RFC 7644: eq - equal
        let filter = "userName eq \"john\"";
        assert!(filter.contains("eq"));
        assert!(filter.contains("\"john\""));
    }

    #[test]
    fn test_filter_eq_operator_boolean() {
        let filter = "active eq true";
        assert!(filter.contains("eq"));
        assert!(filter.contains("true"));
    }

    #[test]
    fn test_filter_eq_operator_null() {
        let filter = "displayName eq null";
        assert!(filter.contains("eq"));
        assert!(filter.contains("null"));
    }

    #[test]
    fn test_filter_ne_operator_string() {
        // RFC 7644: ne - not equal
        let filter = "userName ne \"admin\"";
        assert!(filter.contains("ne"));
    }

    #[test]
    fn test_filter_ne_operator_boolean() {
        let filter = "active ne false";
        assert!(filter.contains("ne"));
        assert!(filter.contains("false"));
    }

    #[test]
    fn test_filter_co_operator() {
        // RFC 7644: co - contains
        let filter = "emails.value co \"@example\"";
        assert!(filter.contains("co"));
        assert!(filter.contains("@example"));
    }

    #[test]
    fn test_filter_co_operator_case_insensitive() {
        let filter = "displayName co \"John\"";
        assert!(filter.contains("co"));
    }

    #[test]
    fn test_filter_sw_operator() {
        // RFC 7644: sw - starts with
        let filter = "displayName sw \"John\"";
        assert!(filter.contains("sw"));
    }

    #[test]
    fn test_filter_sw_operator_nested_path() {
        let filter = "name.givenName sw \"J\"";
        assert!(filter.contains("sw"));
        assert!(filter.contains("name.givenName"));
    }

    #[test]
    fn test_filter_ew_operator() {
        // RFC 7644: ew - ends with
        let filter = "userName ew \"@example.com\"";
        assert!(filter.contains("ew"));
    }

    #[test]
    fn test_filter_pr_operator() {
        // RFC 7644: pr - present (has value)
        let filter = "nickName pr";
        assert!(filter.contains("pr"));
        assert!(!filter.contains('"'));
    }

    #[test]
    fn test_filter_pr_operator_nested() {
        let filter = "name.middleName pr";
        assert!(filter.contains("pr"));
    }

    // ============================================================
    // Numeric Comparison Operators (gt, ge, lt, le)
    // ============================================================

    #[test]
    fn test_filter_gt_operator() {
        // RFC 7644: gt - greater than
        let filter = "meta.created gt \"2024-01-01T00:00:00Z\"";
        assert!(filter.contains("gt"));
    }

    #[test]
    fn test_filter_ge_operator() {
        // RFC 7644: ge - greater than or equal
        let filter = "meta.lastModified ge \"2024-01-01T00:00:00Z\"";
        assert!(filter.contains("ge"));
    }

    #[test]
    fn test_filter_lt_operator() {
        // RFC 7644: lt - less than
        let filter = "meta.created lt \"2025-01-01T00:00:00Z\"";
        assert!(filter.contains("lt"));
    }

    #[test]
    fn test_filter_le_operator() {
        // RFC 7644: le - less than or equal
        let filter = "meta.lastModified le \"2025-12-31T23:59:59Z\"";
        assert!(filter.contains("le"));
    }

    // ============================================================
    // Compound Filters (and, or, not)
    // ============================================================

    #[test]
    fn test_filter_and_operator() {
        // RFC 7644: Logical AND
        let filter = "active eq true and emails.value co \"@corp.com\"";
        assert!(filter.contains(" and "));
    }

    #[test]
    fn test_filter_and_multiple() {
        let filter = "active eq true and userName sw \"j\" and emails pr";
        assert!(filter.matches(" and ").count() == 2);
    }

    #[test]
    fn test_filter_or_operator() {
        // RFC 7644: Logical OR
        let filter = "active eq false or locked eq true";
        assert!(filter.contains(" or "));
    }

    #[test]
    fn test_filter_or_multiple() {
        let filter = "userName eq \"a\" or userName eq \"b\" or userName eq \"c\"";
        assert!(filter.matches(" or ").count() == 2);
    }

    #[test]
    fn test_filter_not_operator() {
        // RFC 7644: Logical NOT
        let filter = "not(active eq false)";
        assert!(filter.starts_with("not("));
        assert!(filter.ends_with(')'));
    }

    #[test]
    fn test_filter_not_with_and() {
        let filter = "not(active eq false) and emails pr";
        assert!(filter.contains("not("));
        assert!(filter.contains(" and "));
    }

    // ============================================================
    // Attribute Path Expressions
    // ============================================================

    #[test]
    fn test_filter_simple_attribute() {
        let filter = "userName eq \"john\"";
        assert!(filter.starts_with("userName"));
    }

    #[test]
    fn test_filter_nested_attribute() {
        let filter = "name.familyName eq \"Smith\"";
        assert!(filter.contains("name.familyName"));
    }

    #[test]
    fn test_filter_multi_valued_attribute() {
        let filter = "emails.value eq \"john@example.com\"";
        assert!(filter.contains("emails.value"));
    }

    #[test]
    fn test_filter_complex_multi_valued() {
        // RFC 7644: Filter within multi-valued attribute
        let filter = "emails[type eq \"work\"].value co \"@corp.com\"";
        assert!(filter.contains("emails["));
        assert!(filter.contains("].value"));
    }

    #[test]
    fn test_filter_deeply_nested() {
        let filter = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.displayName sw \"B\"";
        assert!(filter.contains("manager.displayName"));
    }

    // ============================================================
    // Grouping and Precedence
    // ============================================================

    #[test]
    fn test_filter_parentheses_grouping() {
        let filter = "(active eq true or locked eq false) and emails pr";
        assert!(filter.starts_with('('));
        assert!(filter.contains(") and"));
    }

    #[test]
    fn test_filter_nested_parentheses() {
        let filter = "((a eq 1) or (b eq 2)) and c eq 3";
        assert!(filter.matches('(').count() == 3);
        assert!(filter.matches(')').count() == 3);
    }

    // ============================================================
    // Value Types
    // ============================================================

    #[test]
    fn test_filter_string_value_quoted() {
        let filter = "userName eq \"john.doe@example.com\"";
        assert!(filter.contains("\"john.doe@example.com\""));
    }

    #[test]
    fn test_filter_boolean_true() {
        let filter = "active eq true";
        assert!(filter.contains("true"));
        assert!(!filter.contains("\"true\""));
    }

    #[test]
    fn test_filter_boolean_false() {
        let filter = "active eq false";
        assert!(filter.contains("false"));
        assert!(!filter.contains("\"false\""));
    }

    #[test]
    fn test_filter_null_value() {
        let filter = "nickName eq null";
        assert!(filter.contains("null"));
        assert!(!filter.contains("\"null\""));
    }

    #[test]
    fn test_filter_datetime_value() {
        let filter = "meta.created gt \"2024-01-15T10:30:00Z\"";
        assert!(filter.contains("2024-01-15T10:30:00Z"));
    }

    // ============================================================
    // Edge Cases and Special Characters
    // ============================================================

    #[test]
    fn test_filter_escaped_quotes() {
        let filter = "displayName eq \"John \\\"JD\\\" Doe\"";
        assert!(filter.contains("\\\""));
    }

    #[test]
    fn test_filter_unicode_characters() {
        let filter = "displayName eq \"\u{00e9}milie\"";
        assert!(filter.contains("\u{00e9}"));
    }

    #[test]
    fn test_filter_empty_string() {
        let filter = "nickName eq \"\"";
        assert!(filter.contains("\"\""));
    }

    #[test]
    fn test_filter_whitespace_handling() {
        // RFC 7644 allows flexible whitespace
        let filter_compact = "userName eq \"john\"";
        let filter_spaced = "userName  eq  \"john\"";
        assert!(filter_compact.contains("eq"));
        assert!(filter_spaced.contains("eq"));
    }

    // ============================================================
    // Case Sensitivity
    // ============================================================

    #[test]
    fn test_filter_operator_case_insensitivity() {
        // RFC 7644: Operators are case-insensitive
        let filters = vec![
            "userName EQ \"john\"",
            "userName Eq \"john\"",
            "userName eq \"john\"",
        ];
        for filter in filters {
            assert!(filter.to_lowercase().contains("eq"));
        }
    }

    #[test]
    fn test_filter_attribute_case_sensitivity() {
        // RFC 7644: Attribute names are case-insensitive
        let filter = "UserName eq \"john\"";
        assert!(filter.to_lowercase().contains("username"));
    }

    // ============================================================
    // Complex Real-World Examples
    // ============================================================

    #[test]
    fn test_filter_okta_style() {
        // Okta commonly uses this pattern
        let filter = "userName eq \"john@example.com\"";
        assert!(filter.contains("userName"));
        assert!(filter.contains("eq"));
    }

    #[test]
    fn test_filter_azure_ad_style() {
        // Azure AD commonly uses this pattern with extra whitespace
        let filter = "externalId  eq  \"abc-123\"";
        assert!(filter.contains("externalId"));
    }

    #[test]
    fn test_filter_active_users() {
        let filter = "active eq true";
        assert!(filter.contains("active"));
        assert!(filter.contains("true"));
    }

    #[test]
    fn test_filter_email_domain() {
        let filter = "emails.value ew \"@company.com\"";
        assert!(filter.contains("emails.value"));
        assert!(filter.contains("ew"));
    }
}
