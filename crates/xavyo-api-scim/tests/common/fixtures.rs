//! Test fixtures for SCIM user and group payloads.

use serde_json::{json, Value};
use uuid::Uuid;

/// Generate a unique test email.
pub fn unique_email() -> String {
    format!("test-{}@example.com", Uuid::new_v4())
}

/// Generate a unique external ID.
pub fn unique_external_id() -> String {
    Uuid::new_v4().to_string()
}

/// Generate a unique group name.
pub fn unique_group_name() -> String {
    format!("TestGroup-{}", &Uuid::new_v4().to_string()[..8])
}

/// Create a standard SCIM user creation payload.
pub fn scim_user_payload(email: &str, external_id: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": email,
        "externalId": external_id,
        "name": {
            "givenName": "Test",
            "familyName": "User",
            "formatted": "Test User"
        },
        "emails": [
            {
                "value": email,
                "type": "work",
                "primary": true
            }
        ],
        "active": true
    })
}

/// Create a SCIM user with enterprise extension.
pub fn scim_user_with_enterprise(
    email: &str,
    external_id: &str,
    manager_id: Option<&str>,
) -> Value {
    let mut payload = scim_user_payload(email, external_id);
    if let Some(manager) = manager_id {
        payload["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"] = json!({
            "manager": {
                "value": manager
            }
        });
        payload["schemas"].as_array_mut().unwrap().push(json!(
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        ));
    }
    payload
}

/// Create a SCIM group creation payload.
pub fn scim_group_payload(display_name: &str, external_id: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": display_name,
        "externalId": external_id,
        "members": []
    })
}

/// Create a SCIM PATCH operation payload.
pub fn scim_patch_payload(operations: Vec<Value>) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": operations
    })
}

/// Create a single PATCH operation.
pub fn patch_op(op: &str, path: Option<&str>, value: Value) -> Value {
    let mut operation = json!({
        "op": op,
        "value": value
    });
    if let Some(p) = path {
        operation["path"] = json!(p);
    }
    operation
}

/// Create a SCIM list response wrapper.
pub fn scim_list_response(resources: Vec<Value>, total: i64, start_index: i64) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "itemsPerPage": resources.len(),
        "startIndex": start_index,
        "Resources": resources
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unique_email_is_unique() {
        let email1 = unique_email();
        let email2 = unique_email();
        assert_ne!(email1, email2);
        assert!(email1.contains("@example.com"));
    }

    #[test]
    fn test_scim_user_payload_has_required_fields() {
        let email = "test@example.com";
        let external_id = "ext-123";
        let payload = scim_user_payload(email, external_id);

        assert!(payload["schemas"].is_array());
        assert_eq!(payload["userName"], email);
        assert_eq!(payload["externalId"], external_id);
        assert!(payload["active"].as_bool().unwrap());
    }

    #[test]
    fn test_scim_patch_payload_structure() {
        let ops = vec![patch_op("replace", Some("active"), json!(false))];
        let payload = scim_patch_payload(ops);

        assert!(payload["schemas"].is_array());
        assert!(payload["Operations"].is_array());
        assert_eq!(payload["Operations"][0]["op"], "replace");
    }
}
