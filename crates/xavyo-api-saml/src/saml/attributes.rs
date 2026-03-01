//! SAML attribute mapping utilities

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use xavyo_db::models::{AttributeMap, AttributeMapping};

/// User attributes available for SAML assertion mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAttributes {
    pub user_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub groups: Vec<String>,
    pub tenant_id: String,
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

/// Get the `NameID` value based on configuration
#[must_use]
pub fn get_name_id_value(user: &UserAttributes, name_id_source: &str) -> Option<String> {
    match name_id_source {
        "email" => Some(user.email.clone()),
        "user_id" => Some(user.user_id.clone()),
        "display_name" => user.display_name.clone(),
        _ => Some(user.email.clone()), // Default to email
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

/// Get `NameID` value for the specified format
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
        _ => Some(user.email.clone()), // Default to email
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
            groups: vec!["admin".to_string(), "users".to_string()],
            tenant_id: "tenant-456".to_string(),
        }
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
                static_value: Some("arn:aws:iam::123:role/R,arn:aws:iam::123:saml-provider/P".to_string()),
            }],
        };
        let attrs = resolve_attributes(&user, &mapping);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].name, "https://aws.amazon.com/SAML/Attributes/Role");
        assert_eq!(attrs[0].values, vec!["arn:aws:iam::123:role/R,arn:aws:iam::123:saml-provider/P"]);
    }

    #[test]
    fn test_is_supported_nameid_format() {
        assert!(is_supported_nameid_format(NAMEID_FORMAT_EMAIL));
        assert!(is_supported_nameid_format(NAMEID_FORMAT_PERSISTENT));
        assert!(is_supported_nameid_format(NAMEID_FORMAT_TRANSIENT));
        assert!(!is_supported_nameid_format("unsupported"));
    }
}
