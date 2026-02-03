//! Test data generators for SCIM client integration tests.
//!
//! Provides builders and generators for creating realistic test data
//! including SCIM users, groups, and tenant configurations.

#![allow(dead_code)]

use serde_json::{json, Value};
use uuid::Uuid;
use xavyo_api_scim::models::{ScimEmail, ScimGroup, ScimName, ScimUser};

/// A test tenant with associated IDs for multi-tenant testing.
#[derive(Clone, Debug)]
pub struct TestTenant {
    pub tenant_id: Uuid,
    pub target_id: Uuid,
    pub name: String,
}

impl TestTenant {
    /// Create a new test tenant with random IDs.
    pub fn new(name: &str) -> Self {
        Self {
            tenant_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            name: name.to_string(),
        }
    }

    /// Create tenant A for multi-tenant isolation tests.
    pub fn tenant_a() -> Self {
        Self::new("Tenant A")
    }

    /// Create tenant B for multi-tenant isolation tests.
    pub fn tenant_b() -> Self {
        Self::new("Tenant B")
    }
}

/// Generate a SCIM user with the given email and tenant ID.
pub fn generate_scim_user(email: &str, _tenant_id: Uuid) -> ScimUser {
    let user_id = Uuid::new_v4();
    let parts: Vec<&str> = email.split('@').collect();
    let username = parts.first().unwrap_or(&"user");

    ScimUser {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".to_string()],
        id: None,
        external_id: Some(user_id.to_string()),
        user_name: email.to_string(),
        name: Some(ScimName {
            formatted: Some(format!("{} User", username)),
            family_name: Some("User".to_string()),
            given_name: Some(username.to_string()),
            middle_name: None,
            honorific_prefix: None,
            honorific_suffix: None,
        }),
        display_name: Some(format!("{} User", username)),
        nick_name: None,
        profile_url: None,
        title: None,
        user_type: None,
        preferred_language: None,
        locale: None,
        timezone: None,
        active: true,
        emails: vec![ScimEmail {
            value: email.to_string(),
            email_type: Some("work".to_string()),
            primary: true,
        }],
        groups: vec![],
        meta: None,
        extensions: serde_json::Map::new(),
    }
}

/// Generate a SCIM user with full details.
pub fn generate_scim_user_full(
    email: &str,
    first_name: &str,
    last_name: &str,
    active: bool,
    external_id: Option<&str>,
) -> ScimUser {
    ScimUser {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".to_string()],
        id: None,
        external_id: external_id.map(|s| s.to_string()),
        user_name: email.to_string(),
        name: Some(ScimName {
            formatted: Some(format!("{} {}", first_name, last_name)),
            family_name: Some(last_name.to_string()),
            given_name: Some(first_name.to_string()),
            middle_name: None,
            honorific_prefix: None,
            honorific_suffix: None,
        }),
        display_name: Some(format!("{} {}", first_name, last_name)),
        nick_name: None,
        profile_url: None,
        title: None,
        user_type: None,
        preferred_language: None,
        locale: None,
        timezone: None,
        active,
        emails: vec![ScimEmail {
            value: email.to_string(),
            email_type: Some("work".to_string()),
            primary: true,
        }],
        groups: vec![],
        meta: None,
        extensions: serde_json::Map::new(),
    }
}

/// Generate a batch of SCIM users.
pub fn generate_user_batch(count: usize, tenant_id: Uuid) -> Vec<ScimUser> {
    (0..count)
        .map(|i| generate_scim_user(&format!("user{}@example.com", i), tenant_id))
        .collect()
}

/// Generate a SCIM group with the given name and tenant ID.
pub fn generate_scim_group(display_name: &str, _tenant_id: Uuid) -> ScimGroup {
    let group_id = Uuid::new_v4();

    ScimGroup {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:Group".to_string()],
        id: None,
        external_id: Some(group_id.to_string()),
        display_name: display_name.to_string(),
        members: vec![],
        meta: None,
        xavyo_extension: None,
    }
}

/// Generate a SCIM group with members.
pub fn generate_scim_group_with_members(
    display_name: &str,
    member_external_ids: &[String],
) -> ScimGroup {
    let group_id = Uuid::new_v4();

    let members = member_external_ids
        .iter()
        .filter_map(|id| {
            // Try to parse as UUID, skip if invalid
            Uuid::parse_str(id)
                .ok()
                .map(|uuid| xavyo_api_scim::models::ScimGroupMember {
                    value: uuid,
                    display: None,
                    member_type: Some("User".to_string()),
                    ref_uri: Some(format!("/Users/{}", id)),
                })
        })
        .collect();

    ScimGroup {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:Group".to_string()],
        id: None,
        external_id: Some(group_id.to_string()),
        display_name: display_name.to_string(),
        members,
        meta: None,
        xavyo_extension: None,
    }
}

/// Generate a SCIM user JSON response (as returned by a SCIM server).
pub fn generate_user_response(
    id: &str,
    email: &str,
    external_id: Option<&str>,
    active: bool,
) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": id,
        "externalId": external_id,
        "userName": email,
        "displayName": email.split('@').next().unwrap_or("user"),
        "active": active,
        "emails": [{
            "value": email,
            "type": "work",
            "primary": true
        }],
        "groups": [],
        "meta": {
            "resourceType": "User",
            "created": chrono::Utc::now().to_rfc3339(),
            "lastModified": chrono::Utc::now().to_rfc3339(),
            "location": format!("/Users/{}", id)
        }
    })
}

/// Generate a SCIM group JSON response (as returned by a SCIM server).
pub fn generate_group_response(
    id: &str,
    display_name: &str,
    external_id: Option<&str>,
    member_ids: &[&str],
) -> Value {
    let members: Vec<Value> = member_ids
        .iter()
        .map(|mid| {
            json!({
                "value": mid,
                "$ref": format!("/Users/{}", mid)
            })
        })
        .collect();

    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": id,
        "externalId": external_id,
        "displayName": display_name,
        "members": members,
        "meta": {
            "resourceType": "Group",
            "created": chrono::Utc::now().to_rfc3339(),
            "lastModified": chrono::Utc::now().to_rfc3339(),
            "location": format!("/Groups/{}", id)
        }
    })
}

/// Generate a list response with users.
pub fn generate_user_list_response(users: Vec<Value>) -> Value {
    let total = users.len();
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "startIndex": 1,
        "itemsPerPage": total,
        "Resources": users
    })
}

/// Generate a list response with groups.
pub fn generate_group_list_response(groups: Vec<Value>) -> Value {
    let total = groups.len();
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "startIndex": 1,
        "itemsPerPage": total,
        "Resources": groups
    })
}

/// Generate an empty list response.
pub fn generate_empty_list_response() -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 0,
        "startIndex": 1,
        "itemsPerPage": 0,
        "Resources": []
    })
}

/// Generate a SCIM error response.
pub fn generate_error_response(status: u16, detail: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "detail": detail,
        "status": status.to_string()
    })
}

/// Generate changed fields for user update testing.
pub fn generate_user_changes() -> Vec<(String, Option<String>)> {
    vec![
        (
            "email".to_string(),
            Some("newemail@example.com".to_string()),
        ),
        (
            "display_name".to_string(),
            Some("New Display Name".to_string()),
        ),
        ("first_name".to_string(), Some("NewFirst".to_string())),
        ("last_name".to_string(), Some("NewLast".to_string())),
    ]
}

/// Generate a large dataset of users for performance testing.
pub fn generate_large_user_dataset(count: usize) -> Vec<Value> {
    (0..count)
        .map(|i| {
            let id = Uuid::new_v4().to_string();
            let ext_id = Uuid::new_v4().to_string();
            generate_user_response(&id, &format!("user{}@example.com", i), Some(&ext_id), true)
        })
        .collect()
}

/// Generate a large dataset of groups for performance testing.
pub fn generate_large_group_dataset(count: usize) -> Vec<Value> {
    (0..count)
        .map(|i| {
            let id = Uuid::new_v4().to_string();
            let ext_id = Uuid::new_v4().to_string();
            generate_group_response(&id, &format!("Group {}", i), Some(&ext_id), &[])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_scim_user() {
        let tenant_id = Uuid::new_v4();
        let user = generate_scim_user("test@example.com", tenant_id);

        assert_eq!(user.user_name, "test@example.com");
        assert!(user.active);
        assert!(user.external_id.is_some());
        assert_eq!(user.emails.len(), 1);
        assert_eq!(user.emails[0].value, "test@example.com");
    }

    #[test]
    fn test_generate_user_batch() {
        let tenant_id = Uuid::new_v4();
        let users = generate_user_batch(10, tenant_id);

        assert_eq!(users.len(), 10);
        for (i, user) in users.iter().enumerate() {
            assert_eq!(user.user_name, format!("user{}@example.com", i));
        }
    }

    #[test]
    fn test_generate_scim_group() {
        let tenant_id = Uuid::new_v4();
        let group = generate_scim_group("Engineering", tenant_id);

        assert_eq!(group.display_name, "Engineering");
        assert!(group.external_id.is_some());
        assert!(group.members.is_empty());
    }

    #[test]
    fn test_test_tenant() {
        let tenant_a = TestTenant::tenant_a();
        let tenant_b = TestTenant::tenant_b();

        assert_ne!(tenant_a.tenant_id, tenant_b.tenant_id);
        assert_ne!(tenant_a.target_id, tenant_b.target_id);
    }
}
