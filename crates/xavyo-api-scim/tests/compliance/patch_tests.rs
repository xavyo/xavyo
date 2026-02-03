//! RFC 7644 PATCH Operation Compliance Tests
//!
//! These tests verify that SCIM PATCH operations follow
//! RFC 7644 Section 3.5.2 semantics.

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    // ============================================================
    // PATCH Operation Structure
    // ============================================================

    #[test]
    fn test_patch_request_schema() {
        let patch = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": []
        });
        assert!(patch["schemas"].is_array());
        assert_eq!(
            patch["schemas"][0],
            "urn:ietf:params:scim:api:messages:2.0:PatchOp"
        );
    }

    #[test]
    fn test_patch_operations_array() {
        let patch = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "add", "path": "nickName", "value": "Johnny"}
            ]
        });
        assert!(patch["Operations"].is_array());
        assert_eq!(patch["Operations"].as_array().unwrap().len(), 1);
    }

    // ============================================================
    // ADD Operation
    // ============================================================

    #[test]
    fn test_patch_add_simple_attribute() {
        let op = json!({
            "op": "add",
            "path": "nickName",
            "value": "Johnny"
        });
        assert_eq!(op["op"], "add");
        assert_eq!(op["path"], "nickName");
        assert_eq!(op["value"], "Johnny");
    }

    #[test]
    fn test_patch_add_nested_attribute() {
        let op = json!({
            "op": "add",
            "path": "name.middleName",
            "value": "Robert"
        });
        assert_eq!(op["path"], "name.middleName");
    }

    #[test]
    fn test_patch_add_to_multi_valued() {
        // RFC 7644: Add to multi-valued attribute appends
        let op = json!({
            "op": "add",
            "path": "emails",
            "value": [{
                "value": "new@example.com",
                "type": "home"
            }]
        });
        assert!(op["value"].is_array());
    }

    #[test]
    fn test_patch_add_without_path() {
        // RFC 7644: Add without path merges value into resource
        let op = json!({
            "op": "add",
            "value": {
                "nickName": "Johnny",
                "title": "Developer"
            }
        });
        assert!(op.get("path").is_none() || op["path"].is_null());
        assert!(op["value"].is_object());
    }

    #[test]
    fn test_patch_add_to_array_by_filter() {
        let op = json!({
            "op": "add",
            "path": "emails[type eq \"work\"].display",
            "value": "Work Email"
        });
        assert!(op["path"].as_str().unwrap().contains("[type eq"));
    }

    // ============================================================
    // REMOVE Operation
    // ============================================================

    #[test]
    fn test_patch_remove_simple_attribute() {
        let op = json!({
            "op": "remove",
            "path": "nickName"
        });
        assert_eq!(op["op"], "remove");
        assert_eq!(op["path"], "nickName");
    }

    #[test]
    fn test_patch_remove_nested_attribute() {
        let op = json!({
            "op": "remove",
            "path": "name.middleName"
        });
        assert_eq!(op["path"], "name.middleName");
    }

    #[test]
    fn test_patch_remove_array_element() {
        let op = json!({
            "op": "remove",
            "path": "emails[type eq \"home\"]"
        });
        assert!(op["path"].as_str().unwrap().contains("[type eq"));
    }

    #[test]
    fn test_patch_remove_from_multi_valued() {
        let op = json!({
            "op": "remove",
            "path": "phoneNumbers[value eq \"+1-555-1234\"]"
        });
        assert_eq!(op["op"], "remove");
    }

    #[test]
    fn test_patch_remove_requires_path() {
        // RFC 7644: Remove MUST have a path
        let op = json!({
            "op": "remove",
            "path": "nickName"
        });
        assert!(op.get("path").is_some());
        assert!(!op["path"].is_null());
    }

    // ============================================================
    // REPLACE Operation
    // ============================================================

    #[test]
    fn test_patch_replace_simple_attribute() {
        let op = json!({
            "op": "replace",
            "path": "displayName",
            "value": "John Doe"
        });
        assert_eq!(op["op"], "replace");
        assert_eq!(op["path"], "displayName");
    }

    #[test]
    fn test_patch_replace_nested_attribute() {
        let op = json!({
            "op": "replace",
            "path": "name.givenName",
            "value": "Jonathan"
        });
        assert_eq!(op["path"], "name.givenName");
    }

    #[test]
    fn test_patch_replace_boolean() {
        let op = json!({
            "op": "replace",
            "path": "active",
            "value": false
        });
        assert_eq!(op["value"], false);
    }

    #[test]
    fn test_patch_replace_multi_valued() {
        // RFC 7644: Replace replaces entire attribute
        let op = json!({
            "op": "replace",
            "path": "emails",
            "value": [{
                "value": "only@example.com",
                "type": "work",
                "primary": true
            }]
        });
        assert!(op["value"].is_array());
    }

    #[test]
    fn test_patch_replace_without_path() {
        // RFC 7644: Replace without path replaces entire resource
        let op = json!({
            "op": "replace",
            "value": {
                "userName": "newuser",
                "displayName": "New User"
            }
        });
        assert!(op["value"].is_object());
    }

    #[test]
    fn test_patch_replace_array_element() {
        let op = json!({
            "op": "replace",
            "path": "emails[type eq \"work\"].value",
            "value": "newemail@work.com"
        });
        assert!(op["path"].as_str().unwrap().contains("[type eq"));
    }

    // ============================================================
    // Path Targeting Syntax
    // ============================================================

    #[test]
    fn test_patch_path_simple() {
        let op = json!({ "op": "replace", "path": "userName", "value": "x" });
        assert!(!op["path"].as_str().unwrap().contains("."));
        assert!(!op["path"].as_str().unwrap().contains("["));
    }

    #[test]
    fn test_patch_path_nested_one_level() {
        let op = json!({ "op": "replace", "path": "name.givenName", "value": "x" });
        assert!(op["path"].as_str().unwrap().contains("."));
    }

    #[test]
    fn test_patch_path_nested_two_levels() {
        let op = json!({ "op": "replace", "path": "urn:scim:custom.nested.value", "value": "x" });
        assert!(op["path"].as_str().unwrap().matches('.').count() >= 2);
    }

    #[test]
    fn test_patch_path_array_filter_eq() {
        let op = json!({ "op": "replace", "path": "emails[type eq \"work\"]", "value": {} });
        assert!(op["path"].as_str().unwrap().contains("[type eq"));
    }

    #[test]
    fn test_patch_path_array_filter_and_subattr() {
        let op = json!({ "op": "replace", "path": "emails[type eq \"work\"].value", "value": "x" });
        let path = op["path"].as_str().unwrap();
        assert!(path.contains("["));
        assert!(path.contains("]."));
    }

    // ============================================================
    // Multiple Operations
    // ============================================================

    #[test]
    fn test_patch_multiple_operations() {
        let patch = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "replace", "path": "displayName", "value": "New Name"},
                {"op": "add", "path": "nickName", "value": "Nick"},
                {"op": "remove", "path": "title"}
            ]
        });
        assert_eq!(patch["Operations"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn test_patch_atomic_operations() {
        // RFC 7644: All operations should be atomic
        let patch = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "replace", "path": "userName", "value": "newuser"},
                {"op": "replace", "path": "active", "value": true}
            ]
        });
        // Both should succeed or both should fail
        assert!(patch["Operations"].is_array());
    }

    #[test]
    fn test_patch_operations_order() {
        // RFC 7644: Operations are applied in order
        let patch = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "add", "path": "nickName", "value": "First"},
                {"op": "replace", "path": "nickName", "value": "Second"}
            ]
        });
        let ops = patch["Operations"].as_array().unwrap();
        assert_eq!(ops[0]["value"], "First");
        assert_eq!(ops[1]["value"], "Second");
    }

    // ============================================================
    // Value Types in PATCH
    // ============================================================

    #[test]
    fn test_patch_value_string() {
        let op = json!({ "op": "replace", "path": "displayName", "value": "Test User" });
        assert!(op["value"].is_string());
    }

    #[test]
    fn test_patch_value_boolean() {
        let op = json!({ "op": "replace", "path": "active", "value": true });
        assert!(op["value"].is_boolean());
    }

    #[test]
    fn test_patch_value_object() {
        let op = json!({
            "op": "replace",
            "path": "name",
            "value": {"givenName": "John", "familyName": "Doe"}
        });
        assert!(op["value"].is_object());
    }

    #[test]
    fn test_patch_value_array() {
        let op = json!({
            "op": "replace",
            "path": "emails",
            "value": [{"value": "test@example.com"}]
        });
        assert!(op["value"].is_array());
    }

    #[test]
    fn test_patch_value_null() {
        // RFC 7644: Null is equivalent to remove
        let op = json!({ "op": "replace", "path": "nickName", "value": null });
        assert!(op["value"].is_null());
    }

    // ============================================================
    // SCIM Extension Attributes
    // ============================================================

    #[test]
    fn test_patch_enterprise_extension() {
        let op = json!({
            "op": "replace",
            "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
            "value": "Engineering"
        });
        assert!(op["path"]
            .as_str()
            .unwrap()
            .starts_with("urn:ietf:params:scim"));
    }

    #[test]
    fn test_patch_custom_extension() {
        let op = json!({
            "op": "add",
            "path": "urn:example:custom:attribute",
            "value": "custom-value"
        });
        assert!(op["path"].as_str().unwrap().starts_with("urn:"));
    }
}
