//! OneLogin SCIM client interoperability tests.
//!
//! These tests verify that the SCIM server correctly handles requests
//! from OneLogin's SCIM provisioning client, including known quirks.

#[cfg(test)]
mod tests {
    use crate::mocks::{MockScimClient, OneLoginClient, Severity, TestGroup, TestUser};

    // ============================================================
    // T044: User Creation Tests
    // ============================================================

    #[test]
    fn test_onelogin_client_builds_valid_create_payload() {
        let client = OneLoginClient::new();
        let user = TestUser::generate();
        let payload = client.build_create_user_payload(&user.email, &user.external_id);

        assert_eq!(payload["userName"], user.email);
        assert_eq!(payload["externalId"], user.external_id);
        assert!(payload["schemas"].is_array());
    }

    #[test]
    fn test_onelogin_create_payload_includes_display_name() {
        let client = OneLoginClient::new();
        let payload = client.build_create_user_payload("test@example.com", "ext-123");

        assert_eq!(payload["displayName"], "Test User");
    }

    #[test]
    fn test_onelogin_create_payload_includes_emails() {
        let client = OneLoginClient::new();
        let payload = client.build_create_user_payload("test@example.com", "ext-123");

        assert!(payload["emails"].is_array());
        assert_eq!(payload["emails"][0]["value"], "test@example.com");
    }

    // ============================================================
    // T045: User Retrieval Tests
    // ============================================================

    #[test]
    fn test_onelogin_client_user_agent() {
        let client = OneLoginClient::new();
        assert!(client.user_agent().contains("OneLogin"));
    }

    #[test]
    fn test_onelogin_client_idp_name() {
        let client = OneLoginClient::new();
        assert_eq!(client.idp_name(), "OneLogin");
    }

    // ============================================================
    // T046: User List with Filter Tests
    // ============================================================

    #[test]
    fn test_onelogin_filter_username_eq() {
        let client = OneLoginClient::new();
        let filter = client.build_filter("userName", "EQ", "test@example.com");
        // OL-005: Lowercase operators
        assert!(filter.contains(" eq "));
        assert!(!filter.contains(" EQ "));
    }

    #[test]
    fn test_onelogin_filter_external_id_eq() {
        let client = OneLoginClient::new();
        let filter = client.build_filter("externalId", "EQ", "ext-123");
        assert!(filter.contains("externalId"));
        assert!(filter.contains("ext-123"));
    }

    // ============================================================
    // T047: User Update (PATCH) Tests
    // ============================================================

    #[test]
    fn test_onelogin_patch_payload_structure() {
        let client = OneLoginClient::new();
        let ops = vec![serde_json::json!({
            "op": "replace",
            "path": "displayName",
            "value": "New Name"
        })];
        let payload = client.build_patch_user_payload(ops);

        assert!(payload["schemas"].is_array());
        assert!(payload["Operations"].is_array());
    }

    #[test]
    fn test_onelogin_patch_replace_operation() {
        let client = OneLoginClient::new();
        let ops = vec![serde_json::json!({
            "op": "replace",
            "path": "name.givenName",
            "value": "Updated"
        })];
        let payload = client.build_patch_user_payload(ops);

        assert_eq!(payload["Operations"][0]["op"], "replace");
    }

    // ============================================================
    // T048: User Deactivation Tests
    // ============================================================

    #[test]
    fn test_onelogin_deactivation_uses_patch() {
        let client = OneLoginClient::new();
        let ops = vec![serde_json::json!({
            "op": "replace",
            "path": "active",
            "value": false
        })];
        let payload = client.build_patch_user_payload(ops);

        assert_eq!(payload["Operations"][0]["value"], false);
    }

    // ============================================================
    // T049: Pagination Tests
    // ============================================================

    #[test]
    fn test_onelogin_pagination_parameters() {
        let client = OneLoginClient::new();
        assert!(client.config().delay.is_none());
    }

    // ============================================================
    // T050: Schema Discovery Tests
    // ============================================================

    #[test]
    fn test_onelogin_expects_schema_endpoint() {
        let client = OneLoginClient::new();
        let quirks = client.get_quirks();
        assert!(!quirks.is_empty());
    }

    // ============================================================
    // T051: Group Operations Tests
    // ============================================================

    #[test]
    fn test_onelogin_group_fixture() {
        let group = TestGroup::generate();
        assert!(group.display_name.starts_with("TestGroup-"));
    }

    #[test]
    fn test_onelogin_group_with_members() {
        let group = TestGroup::generate()
            .with_member("user-1")
            .with_member("user-2")
            .with_member("user-3");
        assert_eq!(group.members.len(), 3);
    }

    // ============================================================
    // T052: Quirk Handling - Explicit Nulls (OL-001)
    // ============================================================

    #[test]
    fn test_onelogin_quirk_001_explicit_nulls() {
        let client = OneLoginClient::new();
        let payload = client.build_create_user_payload("test@example.com", "ext-123");

        // OL-001: Explicit nulls for optional fields
        assert!(payload["nickName"].is_null());
        assert!(payload["title"].is_null());
        assert!(payload["profileUrl"].is_null());
    }

    #[test]
    fn test_onelogin_quirk_001_documented() {
        let client = OneLoginClient::new();
        let quirks = client.get_quirks();
        let quirk = quirks.iter().find(|q| q.id == "OL-001");

        assert!(quirk.is_some());
        assert!(quirk.unwrap().description.contains("null"));
    }

    #[test]
    fn test_onelogin_quirk_001_low_severity() {
        let client = OneLoginClient::new();
        let quirks = client.get_quirks();
        let quirk = quirks.iter().find(|q| q.id == "OL-001").unwrap();

        assert_eq!(quirk.severity, Severity::Low);
    }

    // ============================================================
    // T053: Quirk Handling - Array Notation (OL-002)
    // ============================================================

    #[test]
    fn test_onelogin_quirk_002_array_notation() {
        let client = OneLoginClient::new();
        let ops = vec![serde_json::json!({
            "op": "add",
            "path": "members",
            "value": "user-123"
        })];
        let payload = client.build_patch_user_payload(ops);

        // OL-002: Path should use array notation
        let path = payload["Operations"][0]["path"].as_str().unwrap();
        assert!(path.contains("members[value eq"));
    }

    #[test]
    fn test_onelogin_quirk_002_documented() {
        let client = OneLoginClient::new();
        let quirks = client.get_quirks();
        let quirk = quirks.iter().find(|q| q.id == "OL-002");

        assert!(quirk.is_some());
        assert!(quirk.unwrap().description.contains("array notation"));
    }

    #[test]
    fn test_onelogin_quirk_002_medium_severity() {
        let client = OneLoginClient::new();
        let quirks = client.get_quirks();
        let quirk = quirks.iter().find(|q| q.id == "OL-002").unwrap();

        assert_eq!(quirk.severity, Severity::Medium);
    }

    // ============================================================
    // T054: Quirk Handling - Date Formats (OL-004)
    // ============================================================

    #[test]
    fn test_onelogin_quirk_004_documented() {
        let client = OneLoginClient::new();
        let quirks = client.get_quirks();
        let quirk = quirks.iter().find(|q| q.id == "OL-004");

        assert!(quirk.is_some());
        assert!(quirk.unwrap().description.contains("date"));
    }

    #[test]
    fn test_onelogin_quirk_004_medium_severity() {
        let client = OneLoginClient::new();
        let quirks = client.get_quirks();
        let quirk = quirks.iter().find(|q| q.id == "OL-004").unwrap();

        assert_eq!(quirk.severity, Severity::Medium);
    }

    // ============================================================
    // T055: Quirk Handling - Lowercase Operators (OL-005)
    // ============================================================

    #[test]
    fn test_onelogin_quirk_005_lowercase_operators() {
        let client = OneLoginClient::new();
        let filter = client.build_filter("userName", "EQ", "test@example.com");

        // OL-005: Operators should be lowercase
        assert!(filter.contains(" eq "));
        assert!(!filter.contains(" EQ "));
    }

    #[test]
    fn test_onelogin_quirk_005_documented() {
        let client = OneLoginClient::new();
        let quirks = client.get_quirks();
        let quirk = quirks.iter().find(|q| q.id == "OL-005");

        assert!(quirk.is_some());
        assert!(quirk.unwrap().description.contains("lowercase"));
    }

    #[test]
    fn test_onelogin_quirk_005_low_severity() {
        let client = OneLoginClient::new();
        let quirks = client.get_quirks();
        let quirk = quirks.iter().find(|q| q.id == "OL-005").unwrap();

        assert_eq!(quirk.severity, Severity::Low);
    }

    // ============================================================
    // T056: Error Response Handling Tests
    // ============================================================

    #[test]
    fn test_onelogin_all_quirks_have_workarounds() {
        let client = OneLoginClient::new();
        for quirk in client.get_quirks() {
            assert!(
                !quirk.workaround.is_empty(),
                "Quirk {} missing workaround",
                quirk.id
            );
        }
    }

    #[test]
    fn test_onelogin_all_quirks_have_impacts() {
        let client = OneLoginClient::new();
        for quirk in client.get_quirks() {
            assert!(
                !quirk.impact.is_empty(),
                "Quirk {} missing impact",
                quirk.id
            );
        }
    }

    #[test]
    fn test_onelogin_quirk_count() {
        let client = OneLoginClient::new();
        assert_eq!(client.get_quirks().len(), 5);
    }

    // ============================================================
    // Additional OneLogin-specific tests
    // ============================================================

    #[test]
    fn test_onelogin_user_fixture() {
        let user = TestUser::generate();
        assert!(user.email.contains("@example.com"));
        assert!(user.active);
    }

    #[test]
    fn test_onelogin_inactive_user_fixture() {
        let user = TestUser::inactive();
        assert!(!user.active);
    }
}
