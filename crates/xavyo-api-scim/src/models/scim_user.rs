//! SCIM User resource schema (RFC 7643).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// SCIM User name component.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    /// Formatted full name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,

    /// Family name (last name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,

    /// Given name (first name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,

    /// Middle name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,

    /// Honorific prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honorific_prefix: Option<String>,

    /// Honorific suffix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honorific_suffix: Option<String>,
}

/// SCIM Email value.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimEmail {
    /// Email address.
    pub value: String,

    /// Email type (e.g., "work", "home").
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub email_type: Option<String>,

    /// Whether this is the primary email.
    #[serde(default)]
    pub primary: bool,
}

/// SCIM Group reference for user.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimUserGroup {
    /// Group ID.
    pub value: Uuid,

    /// Group display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,

    /// Reference URI.
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_uri: Option<String>,
}

/// SCIM Resource metadata.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimMeta {
    /// Resource type (User or Group).
    pub resource_type: String,

    /// When the resource was created.
    pub created: DateTime<Utc>,

    /// When the resource was last modified.
    pub last_modified: DateTime<Utc>,

    /// Resource location URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,

    /// Resource version (`ETag`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// SCIM User resource (RFC 7643 Section 4.1).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    /// SCIM schemas.
    pub schemas: Vec<String>,

    /// Unique resource ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,

    /// External identifier from `IdP`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Unique username (typically email).
    pub user_name: String,

    /// User's name components.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,

    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Nick name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nick_name: Option<String>,

    /// Profile URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_url: Option<String>,

    /// Title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// User type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_type: Option<String>,

    /// Preferred language.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_language: Option<String>,

    /// Locale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Timezone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,

    /// Whether the user is active.
    #[serde(default = "default_active")]
    pub active: bool,

    /// User's email addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<ScimEmail>,

    /// User's group memberships (read-only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<ScimUserGroup>,

    /// Resource metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,

    /// Extension schema data (e.g., enterprise user attributes, custom attributes).
    /// Serialized as flattened top-level keys in the SCIM JSON response.
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    #[schema(value_type = Object)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

fn default_active() -> bool {
    true
}

impl ScimUser {
    /// SCIM Core User schema URI.
    pub const SCHEMA: &'static str = "urn:ietf:params:scim:schemas:core:2.0:User";

    /// Create a new SCIM User with required fields.
    pub fn new(user_name: impl Into<String>) -> Self {
        Self {
            schemas: vec![Self::SCHEMA.to_string()],
            id: None,
            external_id: None,
            user_name: user_name.into(),
            name: None,
            display_name: None,
            nick_name: None,
            profile_url: None,
            title: None,
            user_type: None,
            preferred_language: None,
            locale: None,
            timezone: None,
            active: true,
            emails: vec![],
            groups: vec![],
            meta: None,
            extensions: serde_json::Map::new(),
        }
    }

    /// Get the primary email address.
    #[must_use]
    pub fn primary_email(&self) -> Option<&str> {
        self.emails
            .iter()
            .find(|e| e.primary)
            .or(self.emails.first())
            .map(|e| e.value.as_str())
    }

    /// Set the resource ID and generate metadata.
    #[must_use]
    pub fn with_meta(
        mut self,
        id: Uuid,
        base_url: &str,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        self.id = Some(id);
        self.meta = Some(ScimMeta {
            resource_type: "User".to_string(),
            created: created_at,
            last_modified: updated_at,
            location: Some(format!("{base_url}/scim/v2/Users/{id}")),
            version: None,
        });
        self
    }
}

/// Request to create a SCIM user.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateScimUserRequest {
    pub schemas: Vec<String>,
    pub user_name: String,
    #[serde(default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub name: Option<ScimName>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default = "default_active")]
    pub active: bool,
    #[serde(default)]
    pub emails: Vec<ScimEmail>,
    /// Extension schema data (e.g., enterprise user attributes).
    /// Captures any additional JSON fields not matched by the above,
    /// including `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`.
    #[serde(flatten)]
    #[schema(value_type = Object)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

/// Request to replace a SCIM user (PUT).
pub type ReplaceScimUserRequest = CreateScimUserRequest;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scim_user_new() {
        let user = ScimUser::new("john@example.com");

        assert_eq!(user.schemas.len(), 1);
        assert_eq!(user.schemas[0], ScimUser::SCHEMA);
        assert_eq!(user.user_name, "john@example.com");
        assert!(user.active);
    }

    #[test]
    fn test_primary_email() {
        let mut user = ScimUser::new("john@example.com");
        user.emails = vec![
            ScimEmail {
                value: "john@personal.com".to_string(),
                email_type: Some("home".to_string()),
                primary: false,
            },
            ScimEmail {
                value: "john@work.com".to_string(),
                email_type: Some("work".to_string()),
                primary: true,
            },
        ];

        assert_eq!(user.primary_email(), Some("john@work.com"));
    }

    #[test]
    fn test_deserialize_scim_user() {
        let json = r#"{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "john@example.com",
            "name": {
                "givenName": "John",
                "familyName": "Doe"
            },
            "displayName": "John Doe",
            "active": true,
            "emails": [
                {
                    "value": "john@example.com",
                    "type": "work",
                    "primary": true
                }
            ]
        }"#;

        let user: CreateScimUserRequest = serde_json::from_str(json).unwrap();
        assert_eq!(user.user_name, "john@example.com");
        assert!(user.name.is_some());
        assert_eq!(user.emails.len(), 1);
    }
}
