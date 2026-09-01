//! SAML attribute mapping utilities

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use xavyo_db::models::{AttributeMap, AttributeMapping, User};

fn nonempty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Display name from profile fields: stored display name, else given+family.
pub(crate) fn profile_display_name(
    display_name: Option<&str>,
    first_name: Option<&str>,
    last_name: Option<&str>,
) -> Option<String> {
    nonempty(display_name).or_else(|| {
        let joined = [nonempty(first_name), nonempty(last_name)]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        if joined.is_empty() {
            None
        } else {
            Some(joined)
        }
    })
}

fn email_username(email: &str) -> Option<String> {
    let local = email.split('@').next().unwrap_or(email).trim();
    if local.is_empty() {
        None
    } else {
        Some(local.to_string())
    }
}

/// User attributes available for SAML assertion mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAttributes {
    pub user_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub groups: Vec<String>,
    pub tenant_id: String,
}

impl UserAttributes {
    /// Fill advertised profile fields from the users table.
    #[must_use]
    pub fn from_db_user(user: &User, groups: Vec<String>, tenant_id: Uuid) -> Self {
        let first_name = nonempty(user.first_name.as_deref());
        let last_name = nonempty(user.last_name.as_deref());
        Self {
            user_id: user.id.to_string(),
            email: user.email.clone(),
            display_name: profile_display_name(
                user.display_name.as_deref(),
                first_name.as_deref(),
                last_name.as_deref(),
            ),
            first_name,
            last_name,
            groups,
            tenant_id: tenant_id.to_string(),
        }
    }
}

/// A resolved SAML attribute ready for assertion
#[derive(Debug, Clone)]
pub struct ResolvedAttribute {
    pub name: String,
    pub friendly_name: Option<String>,
    pub format: Option<String>,
    pub values: Vec<String>,
}

/// Resolve user attributes based on SP's attribute mapping configuration
#[must_use]
pub fn resolve_attributes(
    user: &UserAttributes,
    mapping: &AttributeMapping,
) -> Vec<ResolvedAttribute> {
    let user_fields = build_user_field_map(user);

    mapping
        .attributes
        .iter()
        .filter_map(|attr_map| resolve_single_attribute(&user_fields, attr_map, user))
        .collect()
}

/// Build a map of user field names to values
fn build_user_field_map(user: &UserAttributes) -> HashMap<&str, Option<String>> {
    let mut map = HashMap::new();
    map.insert("email", Some(user.email.clone()));
    map.insert("user_id", Some(user.user_id.clone()));
    map.insert("display_name", user.display_name.clone());
    map.insert("first_name", user.first_name.clone());
    map.insert("given_name", user.first_name.clone());
    map.insert("last_name", user.last_name.clone());
    map.insert("family_name", user.last_name.clone());
    map.insert("username", email_username(&user.email));
    map.insert("tenant_id", Some(user.tenant_id.clone()));
    // Groups handled separately as multi-value
    map
}

/// Resolve a single attribute mapping
fn resolve_single_attribute(
    user_fields: &HashMap<&str, Option<String>>,
    attr_map: &AttributeMap,
    user: &UserAttributes,
) -> Option<ResolvedAttribute> {
    let values = if let Some(ref static_val) = attr_map.static_value {
        vec![static_val.clone()]
    } else if attr_map.source == "groups" {
        // Handle groups as multi-value attribute
        if user.groups.is_empty() {
            return None;
        }
        user.groups.clone()
    } else {
        // Single value attribute
        let value = user_fields.get(attr_map.source.as_str())?.clone()?;
        vec![value]
    };

    Some(ResolvedAttribute {
        name: attr_map.target_name.clone(),
        friendly_name: attr_map.target_friendly_name.clone(),
        format: attr_map.format.clone(),
        values,
    })
}

/// Get the `NameID` value based on configuration.
///
/// Unknown sources must not silently become email — that would issue the
/// wrong subject in a SAML assertion.
#[must_use]
pub fn get_name_id_value(user: &UserAttributes, name_id_source: &str) -> Option<String> {
    match name_id_source {
        "email" => Some(user.email.clone()),
        "user_id" => Some(user.user_id.clone()),
        "display_name" => user.display_name.clone(),
        _ => None,
    }
}

/// Get default attribute mapping when none is configured
#[must_use]
pub fn default_attributes(user: &UserAttributes) -> Vec<ResolvedAttribute> {
    let mut attrs = vec![ResolvedAttribute {
        name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".to_string(),
        friendly_name: Some("email".to_string()),
        format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
        values: vec![user.email.clone()],
    }];

    if let Some(ref name) = user.display_name {
        attrs.push(ResolvedAttribute {
            name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name".to_string(),
            friendly_name: Some("name".to_string()),
            format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
            values: vec![name.clone()],
        });
    }

    if let Some(ref given) = user.first_name {
        attrs.push(ResolvedAttribute {
            name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname".to_string(),
            friendly_name: Some("givenname".to_string()),
            format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
            values: vec![given.clone()],
        });
    }

    if let Some(ref family) = user.last_name {
        attrs.push(ResolvedAttribute {
            name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname".to_string(),
            friendly_name: Some("surname".to_string()),
            format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
            values: vec![family.clone()],
        });
    }

    if !user.groups.is_empty() {
        attrs.push(ResolvedAttribute {
            name: "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups".to_string(),
            friendly_name: Some("groups".to_string()),
            format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
            values: user.groups.clone(),
        });
    }

    attrs
}

/// Supported `NameID` formats
pub const NAMEID_FORMAT_EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
pub const NAMEID_FORMAT_PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
pub const NAMEID_FORMAT_TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

/// Check if a `NameID` format is supported
#[must_use]
pub fn is_supported_nameid_format(format: &str) -> bool {
    matches!(
        format,
        NAMEID_FORMAT_EMAIL | NAMEID_FORMAT_PERSISTENT | NAMEID_FORMAT_TRANSIENT
    )
}

/// Get `NameID` value for the specified format.
///
/// Unsupported formats must not silently become email. Pair with
/// [`is_supported_nameid_format`].
pub fn get_nameid_for_format(
    user: &UserAttributes,
    format: &str,
    session_id: Option<&str>,
) -> Option<String> {
    match format {
        NAMEID_FORMAT_EMAIL => Some(user.email.clone()),
        NAMEID_FORMAT_PERSISTENT => Some(user.user_id.clone()),
        NAMEID_FORMAT_TRANSIENT => Some(
            session_id
                .map(String::from)
                .unwrap_or_else(|| format!("_transient_{}", uuid::Uuid::new_v4())),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user() -> UserAttributes {
        UserAttributes {
            user_id: "user-123".to_string(),
            email: "test@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            first_name: Some("Test".to_string()),
            last_name: Some("User".to_string()),
            groups: vec!["admin".to_string(), "users".to_string()],
            tenant_id: "tenant-456".to_string(),
        }
    }

    #[test]
    fn profile_display_name_prefers_stored_then_joins_given_family() {
        assert_eq!(
            profile_display_name(Some("Ada Lovelace"), Some("Ada"), Some("Lovelace")).as_deref(),
            Some("Ada Lovelace")
        );
        assert_eq!(
            profile_display_name(None, Some("Ada"), Some("Lovelace")).as_deref(),
            Some("Ada Lovelace")
        );
        assert_eq!(
            profile_display_name(Some("  "), Some("Ada"), None).as_deref(),
            Some("Ada")
        );
        assert!(profile_display_name(None, None, None).is_none());
    }

    #[test]
    fn advertised_profile_sources_are_mapped() {
        let user = test_user();
        let mapping = AttributeMapping {
            name_id_source: "email".to_string(),
            attributes: vec![
                AttributeMap {
                    source: "first_name".to_string(),
                    target_name: "user_first_name".to_string(),
                    target_friendly_name: None,
                    format: None,
                    multi_value: false,
                    static_value: None,
                },
                AttributeMap {
                    source: "last_name".to_string(),
                    target_name: "user_last_name".to_string(),
                    target_friendly_name: None,
                    format: None,
                    multi_value: false,
                    static_value: None,
                },
                AttributeMap {
                    source: "username".to_string(),
                    target_name: "user_name".to_string(),
                    target_friendly_name: None,
                    format: None,
                    multi_value: false,
                    static_value: None,
                },
            ],
        };
        let attrs = resolve_attributes(&user, &mapping);
        assert!(attrs
            .iter()
            .any(|a| a.name == "user_first_name" && a.values == ["Test"]));
        assert!(attrs
            .iter()
            .any(|a| a.name == "user_last_name" && a.values == ["User"]));
        assert!(attrs
            .iter()
            .any(|a| a.name == "user_name" && a.values == ["test"]));
        let src = include_str!("attributes.rs");
        let production = src.split("mod tests").next().expect("production source");
        let map_fn = production
            .split("fn build_user_field_map")
            .nth(1)
            .and_then(|s| s.split("fn resolve_single_attribute").next())
            .expect("build_user_field_map");
        assert!(
            map_fn.contains("first_name")
                && map_fn.contains("last_name")
                && map_fn.contains("username"),
            "SAML attribute mapping must expose advertised profile sources"
        );
    }

    #[test]
    fn test_get_name_id_value() {
        let user = test_user();
        assert_eq!(
            get_name_id_value(&user, "email"),
            Some("test@example.com".to_string())
        );
        assert_eq!(
            get_name_id_value(&user, "user_id"),
            Some("user-123".to_string())
        );
        assert_eq!(
            get_name_id_value(&user, "display_name"),
            Some("Test User".to_string())
        );
        assert!(
            get_name_id_value(&user, "password").is_none(),
            "unknown NameID source must not become email"
        );
        let src = include_str!("attributes.rs");
        let production = src.split("mod tests").next().expect("production source");
        let name_id = production
            .split("pub fn get_name_id_value")
            .nth(1)
            .and_then(|s| s.split("pub fn ").next())
            .expect("get_name_id_value");
        assert!(
            !name_id.contains("_ => Some(user.email.clone())"),
            "unknown NameID source must not default to email"
        );
    }

    #[test]
    fn unknown_nameid_format_is_rejected() {
        let user = test_user();
        assert_eq!(
            get_nameid_for_format(&user, NAMEID_FORMAT_EMAIL, None),
            Some("test@example.com".to_string())
        );
        assert_eq!(
            get_nameid_for_format(&user, NAMEID_FORMAT_PERSISTENT, None),
            Some("user-123".to_string())
        );
        assert!(
            get_nameid_for_format(
                &user,
                "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                None
            )
            .is_none(),
            "unsupported NameID format must not become email"
        );
        let src = include_str!("attributes.rs");
        let production = src.split("mod tests").next().expect("production source");
        let format_fn = production
            .split("pub fn get_nameid_for_format")
            .nth(1)
            .and_then(|s| s.split("pub fn ").next())
            .expect("get_nameid_for_format");
        assert!(
            !format_fn.contains("_ => Some(user.email.clone())"),
            "unsupported NameID format must not default to email"
        );
    }

    #[test]
    fn test_default_attributes() {
        let user = test_user();
        let attrs = default_attributes(&user);

        assert!(attrs
            .iter()
            .any(|a| a.values.contains(&"test@example.com".to_string())));
        assert!(attrs
            .iter()
            .any(|a| a.values.contains(&"Test User".to_string())));
        assert!(attrs
            .iter()
            .any(|a| a.values.contains(&"admin".to_string())));
    }

    #[test]
    fn test_static_value_attribute() {
        let user = test_user();
        let mapping = AttributeMapping {
            name_id_source: "email".to_string(),
            attributes: vec![AttributeMap {
                source: "unused".to_string(),
                target_name: "https://aws.amazon.com/SAML/Attributes/Role".to_string(),
                target_friendly_name: None,
                format: None,
                multi_value: false,
                static_value: Some(
                    "arn:aws:iam::123:role/R,arn:aws:iam::123:saml-provider/P".to_string(),
                ),
            }],
        };
        let attrs = resolve_attributes(&user, &mapping);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].name, "https://aws.amazon.com/SAML/Attributes/Role");
        assert_eq!(
            attrs[0].values,
            vec!["arn:aws:iam::123:role/R,arn:aws:iam::123:saml-provider/P"]
        );
    }

    #[test]
    fn test_is_supported_nameid_format() {
        assert!(is_supported_nameid_format(NAMEID_FORMAT_EMAIL));
        assert!(is_supported_nameid_format(NAMEID_FORMAT_PERSISTENT));
        assert!(is_supported_nameid_format(NAMEID_FORMAT_TRANSIENT));
        assert!(!is_supported_nameid_format("unsupported"));
    }
}
