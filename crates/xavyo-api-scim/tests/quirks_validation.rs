//! Mock client accuracy validation tests.
//!
//! These tests verify that the mock IdP clients accurately simulate
//! the behavior documented in their respective quirks.

mod common;
mod mocks;

#[cfg(test)]
mod tests {
    use crate::mocks::{
        azure_ad_quirks, okta_quirks, onelogin_quirks, AzureAdClient, MockClientConfig,
        MockScimClient, OktaClient, OneLoginClient, Severity,
    };
    use std::time::Duration;

    // ============================================================
    // T058: Okta Mock Client Accuracy
    // ============================================================

    #[test]
    fn test_okta_mock_implements_all_quirks() {
        let client = OktaClient::new();
        let documented_quirks = okta_quirks();
        let enabled_quirks = &client.config().enabled_quirks;

        for quirk in &documented_quirks {
            assert!(
                enabled_quirks.contains(&quirk.id),
                "Okta mock missing quirk: {}",
                quirk.id
            );
        }
    }

    #[test]
    fn test_okta_mock_quirk_001_accuracy() {
        let client = OktaClient::new();
        let payload = client.build_create_user_payload("test@example.com", "ext-123");

        // Verify OKTA-001: Empty strings for optional attributes
        assert_eq!(
            payload["displayName"], "",
            "OKTA-001 not correctly implemented"
        );
    }

    #[test]
    fn test_okta_mock_quirk_002_accuracy() {
        let client = OktaClient::new();
        let ops = vec![serde_json::json!({
            "op": "replace",
            "path": "active",
            "value": true
        })];
        let payload = client.build_patch_user_payload(ops);

        // Verify OKTA-002: Single values wrapped in arrays
        let value = &payload["Operations"][0]["value"];
        assert!(
            value.is_array(),
            "OKTA-002 not correctly implemented: value should be array"
        );
    }

    #[test]
    fn test_okta_mock_user_agent_accuracy() {
        let client = OktaClient::new();
        // Okta's actual User-Agent contains "Okta"
        assert!(
            client.user_agent().contains("Okta"),
            "User-Agent should identify as Okta"
        );
    }

    #[test]
    fn test_okta_mock_filter_syntax_accuracy() {
        let client = OktaClient::new();
        let filter = client.build_filter("userName", "eq", "test@example.com");
        // Okta uses standard SCIM filter syntax
        assert_eq!(filter, "userName eq \"test@example.com\"");
    }

    // ============================================================
    // T059: Azure AD Mock Client Accuracy
    // ============================================================

    #[test]
    fn test_azure_ad_mock_implements_all_quirks() {
        let client = AzureAdClient::new();
        let documented_quirks = azure_ad_quirks();
        let enabled_quirks = &client.config().enabled_quirks;

        for quirk in &documented_quirks {
            assert!(
                enabled_quirks.contains(&quirk.id),
                "Azure AD mock missing quirk: {}",
                quirk.id
            );
        }
    }

    #[test]
    fn test_azure_ad_mock_quirk_001_accuracy() {
        let client = AzureAdClient::new();
        let payload = client.build_create_user_payload("test@example.com", "ext-123");

        // Verify AAD-001: Missing schemas field
        assert!(
            payload.get("schemas").is_none(),
            "AAD-001 not correctly implemented: schemas should be omitted"
        );
    }

    #[test]
    fn test_azure_ad_mock_quirk_002_accuracy() {
        let client = AzureAdClient::new();
        let payload = client.build_create_user_payload("test@example.com", "ext-123");

        // Verify AAD-002: Legacy schema URI
        assert!(
            payload
                .get("urn:scim:schemas:extension:enterprise:1.0")
                .is_some(),
            "AAD-002 not correctly implemented: legacy schema should be present"
        );
    }

    #[test]
    fn test_azure_ad_mock_quirk_005_accuracy() {
        let client = AzureAdClient::new();
        let filter = client.build_filter("userName", "eq", "test@example.com");

        // Verify AAD-005: Extra whitespace around operators
        assert!(
            filter.contains("  eq  "),
            "AAD-005 not correctly implemented: should have extra whitespace"
        );
    }

    #[test]
    fn test_azure_ad_mock_user_agent_accuracy() {
        let client = AzureAdClient::new();
        assert!(
            client.user_agent().contains("Azure"),
            "User-Agent should identify as Azure"
        );
    }

    #[test]
    fn test_azure_ad_mock_includes_request_id() {
        let client = AzureAdClient::new();
        let headers = client.build_headers();

        let has_request_id = headers.iter().any(|(k, _)| *k == "client-request-id");
        assert!(
            has_request_id,
            "Azure AD client should include client-request-id header"
        );
    }

    // ============================================================
    // T060: OneLogin Mock Client Accuracy
    // ============================================================

    #[test]
    fn test_onelogin_mock_implements_all_quirks() {
        let client = OneLoginClient::new();
        let documented_quirks = onelogin_quirks();
        let enabled_quirks = &client.config().enabled_quirks;

        for quirk in &documented_quirks {
            assert!(
                enabled_quirks.contains(&quirk.id),
                "OneLogin mock missing quirk: {}",
                quirk.id
            );
        }
    }

    #[test]
    fn test_onelogin_mock_quirk_001_accuracy() {
        let client = OneLoginClient::new();
        let payload = client.build_create_user_payload("test@example.com", "ext-123");

        // Verify OL-001: Explicit nulls for optional fields
        assert!(
            payload["nickName"].is_null(),
            "OL-001 not correctly implemented: nickName should be null"
        );
        assert!(
            payload["title"].is_null(),
            "OL-001 not correctly implemented: title should be null"
        );
    }

    #[test]
    fn test_onelogin_mock_quirk_002_accuracy() {
        let client = OneLoginClient::new();
        let ops = vec![serde_json::json!({
            "op": "add",
            "path": "members",
            "value": "user-123"
        })];
        let payload = client.build_patch_user_payload(ops);

        // Verify OL-002: Array notation in path
        let path = payload["Operations"][0]["path"].as_str().unwrap();
        assert!(
            path.contains("members[value eq"),
            "OL-002 not correctly implemented: should use array notation"
        );
    }

    #[test]
    fn test_onelogin_mock_quirk_005_accuracy() {
        let client = OneLoginClient::new();
        let filter = client.build_filter("userName", "EQ", "test@example.com");

        // Verify OL-005: Lowercase operators
        assert!(
            filter.contains(" eq "),
            "OL-005 not correctly implemented: operator should be lowercase"
        );
        assert!(
            !filter.contains(" EQ "),
            "OL-005 not correctly implemented: operator should not be uppercase"
        );
    }

    #[test]
    fn test_onelogin_mock_user_agent_accuracy() {
        let client = OneLoginClient::new();
        assert!(
            client.user_agent().contains("OneLogin"),
            "User-Agent should identify as OneLogin"
        );
    }

    // ============================================================
    // T061: Configurable Delay Support
    // ============================================================

    #[test]
    fn test_mock_client_default_no_delay() {
        let config = MockClientConfig::default();
        assert!(config.delay.is_none());
    }

    #[test]
    fn test_mock_client_configurable_delay() {
        let config = MockClientConfig::default().with_delay(Duration::from_millis(100));
        assert_eq!(config.delay, Some(Duration::from_millis(100)));
    }

    #[test]
    fn test_okta_client_with_delay() {
        let config = MockClientConfig::default().with_delay(Duration::from_millis(50));
        let client = OktaClient::with_config(config);
        assert_eq!(client.config().delay, Some(Duration::from_millis(50)));
    }

    #[test]
    fn test_azure_ad_client_with_delay() {
        let config = MockClientConfig::default().with_delay(Duration::from_millis(75));
        let client = AzureAdClient::with_config(config);
        assert_eq!(client.config().delay, Some(Duration::from_millis(75)));
    }

    #[test]
    fn test_onelogin_client_with_delay() {
        let config = MockClientConfig::default().with_delay(Duration::from_millis(25));
        let client = OneLoginClient::with_config(config);
        assert_eq!(client.config().delay, Some(Duration::from_millis(25)));
    }

    // ============================================================
    // Cross-IdP Validation Tests
    // ============================================================

    #[test]
    fn test_all_quirks_have_unique_ids() {
        let mut all_ids: Vec<String> = Vec::new();

        for quirk in okta_quirks() {
            assert!(
                !all_ids.contains(&quirk.id),
                "Duplicate quirk ID: {}",
                quirk.id
            );
            all_ids.push(quirk.id);
        }

        for quirk in azure_ad_quirks() {
            assert!(
                !all_ids.contains(&quirk.id),
                "Duplicate quirk ID: {}",
                quirk.id
            );
            all_ids.push(quirk.id);
        }

        for quirk in onelogin_quirks() {
            assert!(
                !all_ids.contains(&quirk.id),
                "Duplicate quirk ID: {}",
                quirk.id
            );
            all_ids.push(quirk.id);
        }
    }

    #[test]
    fn test_all_quirks_follow_naming_convention() {
        for quirk in okta_quirks() {
            assert!(
                quirk.id.starts_with("OKTA-"),
                "Okta quirk ID should start with OKTA-: {}",
                quirk.id
            );
        }

        for quirk in azure_ad_quirks() {
            assert!(
                quirk.id.starts_with("AAD-"),
                "Azure AD quirk ID should start with AAD-: {}",
                quirk.id
            );
        }

        for quirk in onelogin_quirks() {
            assert!(
                quirk.id.starts_with("OL-"),
                "OneLogin quirk ID should start with OL-: {}",
                quirk.id
            );
        }
    }

    #[test]
    fn test_total_documented_quirks() {
        let total = okta_quirks().len() + azure_ad_quirks().len() + onelogin_quirks().len();
        assert_eq!(total, 16, "Expected 16 total documented quirks");
    }

    #[test]
    fn test_severity_distribution() {
        let all_quirks: Vec<_> = okta_quirks()
            .into_iter()
            .chain(azure_ad_quirks())
            .chain(onelogin_quirks())
            .collect();

        let high_count = all_quirks
            .iter()
            .filter(|q| q.severity == Severity::High)
            .count();
        let medium_count = all_quirks
            .iter()
            .filter(|q| q.severity == Severity::Medium)
            .count();
        let low_count = all_quirks
            .iter()
            .filter(|q| q.severity == Severity::Low)
            .count();

        assert!(high_count > 0, "Should have some high severity quirks");
        assert!(medium_count > 0, "Should have some medium severity quirks");
        assert!(low_count > 0, "Should have some low severity quirks");
        assert_eq!(
            high_count + medium_count + low_count,
            16,
            "All quirks should have a severity"
        );
    }
}
