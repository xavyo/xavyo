//! Attribute mapper: maps internal identity fields to SCIM resource representations.
//!
//! Translates internal user/group attributes into SCIM 2.0 resource payloads
//! using per-target attribute mapping configurations.

use uuid::Uuid;
use xavyo_api_scim::models::{
    ScimEmail, ScimGroup, ScimGroupMember, ScimName, ScimPatchOp, ScimPatchRequest, ScimUser,
};
use xavyo_db::models::ScimTargetAttributeMapping;

/// Handles mapping between internal identity attributes and SCIM representations.
pub struct AttributeMapper;

/// Default source-field-to-SCIM-path mapping for user resources.
/// Used when no custom mappings are configured.
const DEFAULT_USER_FIELD_MAP: &[(&str, &str)] = &[
    ("email", "userName"),
    ("email", "emails[0].value"),
    ("first_name", "name.givenName"),
    ("last_name", "name.familyName"),
    ("display_name", "displayName"),
    ("is_active", "active"),
];

impl AttributeMapper {
    /// Map internal user attributes to a SCIM User resource using the configured mappings.
    ///
    /// The `user_id` is set as the `externalId` on the SCIM resource so the target
    /// system can correlate the resource back to the IDP.
    ///
    /// When `mappings` is non-empty, the mapper uses those entries to decide
    /// which SCIM paths to populate and how.  When `mappings` is empty, the
    /// built-in default mapping (equivalent to the default DB rows) is used.
    pub fn map_user_to_scim(
        user_id: Uuid,
        email: Option<&str>,
        display_name: Option<&str>,
        first_name: Option<&str>,
        last_name: Option<&str>,
        active: bool,
        mappings: &[ScimTargetAttributeMapping],
    ) -> ScimUser {
        // Collect source field values into a lookup table.
        let source_values: Vec<(&str, Option<String>)> = vec![
            ("email", email.map(|s| s.to_string())),
            ("display_name", display_name.map(|s| s.to_string())),
            ("first_name", first_name.map(|s| s.to_string())),
            ("last_name", last_name.map(|s| s.to_string())),
            ("is_active", Some(active.to_string())),
        ];

        // Determine the effective mapping entries.
        #[allow(clippy::type_complexity)]
        let user_mappings: Vec<(&str, &str, &str, Option<&str>, Option<&str>)> =
            if mappings.is_empty() {
                // Use defaults.
                DEFAULT_USER_FIELD_MAP
                    .iter()
                    .map(|(src, tgt)| (*src, *tgt, "direct", None, None))
                    .collect()
            } else {
                // Filter to user-type mappings.
                mappings
                    .iter()
                    .filter(|m| m.resource_type == "user")
                    .map(|m| {
                        (
                            m.source_field.as_str(),
                            m.target_scim_path.as_str(),
                            m.mapping_type.as_str(),
                            m.constant_value.as_deref(),
                            m.transform.as_deref(),
                        )
                    })
                    .collect()
            };

        // Start with a base user.
        let user_name = email.unwrap_or("unknown").to_string();
        let mut user = ScimUser::new(&user_name);
        user.external_id = Some(user_id.to_string());
        // Defaults that may be overridden by mappings.
        user.active = active;

        // Apply each mapping entry.
        for (source_field, scim_path, mapping_type, constant_value, transform) in &user_mappings {
            let raw_value = match *mapping_type {
                "constant" => constant_value.map(|v| v.to_string()),
                _ => {
                    // "direct" or "expression" — look up source field value.
                    source_values
                        .iter()
                        .find(|(k, _)| k == source_field)
                        .and_then(|(_, v)| v.clone())
                }
            };

            // Apply optional transform.
            let value = match (raw_value, transform) {
                (Some(v), Some("lowercase")) => Some(v.to_lowercase()),
                (Some(v), Some("uppercase")) => Some(v.to_uppercase()),
                (v, _) => v,
            };

            if let Some(val) = value {
                Self::apply_scim_path(&mut user, scim_path, &val);
            }
        }

        // Build formatted name if name components are set.
        if let Some(ref mut name) = user.name {
            let formatted = match (&name.given_name, &name.family_name) {
                (Some(f), Some(l)) => Some(format!("{f} {l}")),
                (Some(f), None) => Some(f.clone()),
                (None, Some(l)) => Some(l.clone()),
                (None, None) => None,
            };
            name.formatted = formatted;
        }

        user
    }

    /// Apply a value to a specific SCIM path on a ScimUser.
    fn apply_scim_path(user: &mut ScimUser, scim_path: &str, value: &str) {
        match scim_path {
            "userName" => user.user_name = value.to_string(),
            "displayName" => user.display_name = Some(value.to_string()),
            "active" => {
                user.active = matches!(value, "true" | "1");
            }
            "name.givenName" => {
                let name = user.name.get_or_insert_with(ScimName::default);
                name.given_name = Some(value.to_string());
            }
            "name.familyName" => {
                let name = user.name.get_or_insert_with(ScimName::default);
                name.family_name = Some(value.to_string());
            }
            "name.formatted" => {
                let name = user.name.get_or_insert_with(ScimName::default);
                name.formatted = Some(value.to_string());
            }
            path if path.starts_with("emails") => {
                // Handle emails[0].value or similar.
                if user.emails.is_empty() {
                    user.emails.push(ScimEmail {
                        value: value.to_string(),
                        email_type: Some("work".to_string()),
                        primary: true,
                    });
                } else {
                    user.emails[0].value = value.to_string();
                }
            }
            _ => {
                // Unknown SCIM path — skip silently.
            }
        }
    }

    /// Map internal group attributes to a SCIM Group resource.
    ///
    /// The `group_id` is set as the `externalId`. Member external IDs are the
    /// SCIM-side resource IDs of members that have already been provisioned.
    /// These are string identifiers returned by the target system and may or
    /// may not be valid UUIDs depending on the target.
    pub fn map_group_to_scim(
        group_id: Uuid,
        display_name: &str,
        member_external_ids: &[String],
    ) -> ScimGroup {
        let mut group = ScimGroup::new(display_name);
        group.external_id = Some(group_id.to_string());

        group.members = member_external_ids
            .iter()
            .filter_map(|ext_id| {
                // SCIM member references require a UUID `value` field.
                // External resource IDs from SCIM targets are typically UUIDs.
                Uuid::parse_str(ext_id).ok().map(|id| ScimGroupMember {
                    value: id,
                    display: None,
                    member_type: Some("User".to_string()),
                    ref_uri: None,
                })
            })
            .collect();

        group
    }

    /// Build a SCIM PATCH request from a set of changed fields.
    ///
    /// Each entry in `changed_fields` is a tuple of `(field_name, new_value)`.
    /// If `new_value` is `None`, the attribute is removed; otherwise it is replaced.
    ///
    /// When `mappings` is non-empty, the mapper resolves SCIM paths from the
    /// configured mapping entries.  When empty, built-in defaults are used.
    ///
    /// Returns `None` if no patch operations would be generated (e.g. no fields
    /// map to any SCIM path).
    pub fn build_user_patch(
        changed_fields: &[(String, Option<String>)],
        mappings: &[ScimTargetAttributeMapping],
    ) -> Option<ScimPatchRequest> {
        if changed_fields.is_empty() {
            return None;
        }

        let mut operations = Vec::new();

        for (field, value) in changed_fields {
            // Resolve the SCIM paths for this source field.
            let scim_paths: Vec<&str> = if mappings.is_empty() {
                // Use built-in default mapping.
                match field.as_str() {
                    "email" => vec!["userName", "emails[type eq \"work\"].value"],
                    "display_name" => vec!["displayName"],
                    "first_name" => vec!["name.givenName"],
                    "last_name" => vec!["name.familyName"],
                    "is_active" | "active" => vec!["active"],
                    _ => vec![],
                }
            } else {
                // Look up from configured mappings.
                mappings
                    .iter()
                    .filter(|m| m.resource_type == "user" && m.source_field == *field)
                    .map(|m| m.target_scim_path.as_str())
                    .collect()
            };

            for path in scim_paths {
                match value {
                    Some(val) => {
                        // For active, convert to boolean.
                        let json_value = if path == "active" {
                            match val.as_str() {
                                "true" | "1" => serde_json::Value::Bool(true),
                                "false" | "0" => serde_json::Value::Bool(false),
                                _ => serde_json::Value::String(val.clone()),
                            }
                        } else {
                            serde_json::Value::String(val.clone())
                        };

                        operations.push(ScimPatchOp {
                            op: "replace".to_string(),
                            path: Some(path.to_string()),
                            value: Some(json_value),
                        });
                    }
                    None => {
                        operations.push(ScimPatchOp {
                            op: "remove".to_string(),
                            path: Some(path.to_string()),
                            value: None,
                        });
                    }
                }
            }
        }

        if operations.is_empty() {
            return None;
        }

        Some(ScimPatchRequest {
            schemas: vec![ScimPatchRequest::SCHEMA.to_string()],
            operations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_user_to_scim_full() {
        let user_id = Uuid::new_v4();
        let user = AttributeMapper::map_user_to_scim(
            user_id,
            Some("john@example.com"),
            Some("John Doe"),
            Some("John"),
            Some("Doe"),
            true,
            &[],
        );

        assert_eq!(user.external_id, Some(user_id.to_string()));
        assert_eq!(user.user_name, "john@example.com");
        assert_eq!(user.display_name, Some("John Doe".to_string()));
        assert!(user.active);
        assert_eq!(user.emails.len(), 1);
        assert_eq!(user.emails[0].value, "john@example.com");
        let name = user.name.as_ref().unwrap();
        assert_eq!(name.given_name, Some("John".to_string()));
        assert_eq!(name.family_name, Some("Doe".to_string()));
    }

    #[test]
    fn test_map_user_to_scim_minimal() {
        let user_id = Uuid::new_v4();
        let user = AttributeMapper::map_user_to_scim(user_id, None, None, None, None, false, &[]);

        assert_eq!(user.user_name, "unknown");
        assert!(!user.active);
        assert!(user.name.is_none());
        assert!(user.emails.is_empty());
    }

    #[test]
    fn test_map_group_to_scim() {
        let group_id = Uuid::new_v4();
        let member1 = Uuid::new_v4().to_string();
        let member2 = Uuid::new_v4().to_string();
        let group =
            AttributeMapper::map_group_to_scim(group_id, "Engineering", &[member1, member2]);

        assert_eq!(group.display_name, "Engineering");
        assert_eq!(group.external_id, Some(group_id.to_string()));
        assert_eq!(group.members.len(), 2);
    }

    #[test]
    fn test_map_group_to_scim_non_uuid_members_filtered() {
        let group_id = Uuid::new_v4();
        let valid = Uuid::new_v4().to_string();
        let invalid = "not-a-uuid".to_string();
        let group = AttributeMapper::map_group_to_scim(group_id, "Engineering", &[valid, invalid]);

        // Non-UUID member IDs are filtered out.
        assert_eq!(group.members.len(), 1);
    }

    #[test]
    fn test_build_user_patch_replace() {
        let fields = vec![
            ("display_name".to_string(), Some("New Name".to_string())),
            ("active".to_string(), Some("false".to_string())),
        ];

        let patch = AttributeMapper::build_user_patch(&fields, &[]).unwrap();
        assert_eq!(patch.operations.len(), 2);
        assert_eq!(patch.operations[0].op, "replace");
        assert_eq!(patch.operations[0].path, Some("displayName".to_string()));
    }

    #[test]
    fn test_build_user_patch_empty() {
        let result = AttributeMapper::build_user_patch(&[], &[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_build_user_patch_unknown_field() {
        let fields = vec![("unknown_field".to_string(), Some("value".to_string()))];
        let result = AttributeMapper::build_user_patch(&fields, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_build_user_patch_remove() {
        let fields = vec![("display_name".to_string(), None)];
        let patch = AttributeMapper::build_user_patch(&fields, &[]).unwrap();
        assert_eq!(patch.operations.len(), 1);
        assert_eq!(patch.operations[0].op, "remove");
        assert_eq!(patch.operations[0].path, Some("displayName".to_string()));
        assert!(patch.operations[0].value.is_none());
    }

    #[test]
    fn test_build_user_patch_email_also_updates_emails() {
        let fields = vec![("email".to_string(), Some("new@example.com".to_string()))];
        let patch = AttributeMapper::build_user_patch(&fields, &[]).unwrap();
        // Should produce two operations: replace userName + replace emails[...].value
        assert_eq!(patch.operations.len(), 2);
        assert_eq!(patch.operations[0].path, Some("userName".to_string()));
        assert!(patch.operations[1]
            .path
            .as_ref()
            .unwrap()
            .contains("emails"));
    }
}
