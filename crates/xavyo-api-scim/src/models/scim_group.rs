//! SCIM Group resource schema (RFC 7643).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::scim_user::ScimMeta;

/// SCIM Group member reference.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroupMember {
    /// Member ID (user or nested group).
    pub value: Uuid,

    /// Member display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,

    /// Member type (typically "User").
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub member_type: Option<String>,

    /// Reference URI.
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_uri: Option<String>,
}

/// Xavyo SCIM extension for group hierarchy attributes.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct XavyoGroupExtension {
    /// Group type classification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_type: Option<String>,

    /// External ID of the parent group (for SCIM provisioning).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_external_id: Option<String>,
}

/// SCIM Group resource (RFC 7643 Section 4.2).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroup {
    /// SCIM schemas.
    pub schemas: Vec<String>,

    /// Unique resource ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,

    /// External identifier from IdP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Group display name.
    pub display_name: String,

    /// Group members.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<ScimGroupMember>,

    /// Resource metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,

    /// Xavyo hierarchy extension attributes.
    #[serde(
        rename = "urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group",
        skip_serializing_if = "Option::is_none"
    )]
    pub xavyo_extension: Option<XavyoGroupExtension>,
}

impl ScimGroup {
    /// SCIM Core Group schema URI.
    pub const SCHEMA: &'static str = "urn:ietf:params:scim:schemas:core:2.0:Group";

    /// Xavyo SCIM extension schema URI for group hierarchy.
    pub const XAVYO_EXTENSION_SCHEMA: &'static str =
        "urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group";

    /// Create a new SCIM Group with required fields.
    pub fn new(display_name: impl Into<String>) -> Self {
        Self {
            schemas: vec![Self::SCHEMA.to_string()],
            id: None,
            external_id: None,
            display_name: display_name.into(),
            members: vec![],
            meta: None,
            xavyo_extension: None,
        }
    }

    /// Set the resource ID and generate metadata.
    pub fn with_meta(
        mut self,
        id: Uuid,
        base_url: &str,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        self.id = Some(id);
        self.meta = Some(ScimMeta {
            resource_type: "Group".to_string(),
            created: created_at,
            last_modified: updated_at,
            location: Some(format!("{}/scim/v2/Groups/{}", base_url, id)),
            version: None,
        });
        self
    }

    /// Get member IDs.
    pub fn member_ids(&self) -> Vec<Uuid> {
        self.members.iter().map(|m| m.value).collect()
    }
}

/// Request to create a SCIM group.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateScimGroupRequest {
    pub schemas: Vec<String>,
    pub display_name: String,
    #[serde(default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub members: Vec<ScimGroupMember>,
    /// Xavyo hierarchy extension attributes (F071).
    #[serde(
        rename = "urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group",
        default
    )]
    pub xavyo_extension: Option<XavyoGroupExtension>,
}

/// Request to replace a SCIM group (PUT).
pub type ReplaceScimGroupRequest = CreateScimGroupRequest;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scim_group_new() {
        let group = ScimGroup::new("Engineering");

        assert_eq!(group.schemas.len(), 1);
        assert_eq!(group.schemas[0], ScimGroup::SCHEMA);
        assert_eq!(group.display_name, "Engineering");
        assert!(group.members.is_empty());
    }

    #[test]
    fn test_member_ids() {
        let mut group = ScimGroup::new("Engineering");
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();

        group.members = vec![
            ScimGroupMember {
                value: user1,
                display: Some("John Doe".to_string()),
                member_type: Some("User".to_string()),
                ref_uri: None,
            },
            ScimGroupMember {
                value: user2,
                display: Some("Jane Doe".to_string()),
                member_type: Some("User".to_string()),
                ref_uri: None,
            },
        ];

        let ids = group.member_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&user1));
        assert!(ids.contains(&user2));
    }

    #[test]
    fn test_deserialize_scim_group() {
        let json = r#"{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Engineering",
            "members": [
                {
                    "value": "550e8400-e29b-41d4-a716-446655440000",
                    "display": "John Doe"
                }
            ]
        }"#;

        let group: CreateScimGroupRequest = serde_json::from_str(json).unwrap();
        assert_eq!(group.display_name, "Engineering");
        assert_eq!(group.members.len(), 1);
    }
}
