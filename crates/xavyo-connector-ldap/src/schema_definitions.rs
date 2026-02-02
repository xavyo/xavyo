//! LDAP Schema Definition Constants
//!
//! Provides well-known LDAP object classes and attribute type definitions
//! for use in schema discovery fallback and attribute type resolution.
//!
//! These constants are intentionally available for fallback scenarios when
//! live LDAP schema discovery fails or is unavailable.

#![allow(dead_code)]

use std::collections::HashMap;

use xavyo_connector::schema::AttributeDataType;

/// Well-known LDAP object class definitions.
///
/// Format: (name, required_attrs, optional_attrs)
pub const COMMON_OBJECT_CLASSES: &[(&str, &[&str], &[&str])] = &[
    // Standard LDAP person classes
    (
        "inetOrgPerson",
        &["cn", "sn"],
        &[
            "givenName",
            "mail",
            "telephoneNumber",
            "uid",
            "userPassword",
            "displayName",
            "description",
            "employeeNumber",
            "employeeType",
            "departmentNumber",
            "title",
            "manager",
            "jpegPhoto",
        ],
    ),
    (
        "organizationalPerson",
        &["cn"],
        &[
            "sn",
            "title",
            "telephoneNumber",
            "facsimileTelephoneNumber",
            "street",
            "postOfficeBox",
            "postalCode",
            "postalAddress",
            "st",
            "l",
        ],
    ),
    (
        "person",
        &["cn", "sn"],
        &["userPassword", "telephoneNumber", "seeAlso", "description"],
    ),
    ("top", &["objectClass"], &[]),
    // Group classes
    (
        "groupOfNames",
        &["cn", "member"],
        &[
            "description",
            "owner",
            "seeAlso",
            "businessCategory",
            "o",
            "ou",
        ],
    ),
    (
        "groupOfUniqueNames",
        &["cn", "uniqueMember"],
        &[
            "description",
            "owner",
            "seeAlso",
            "businessCategory",
            "o",
            "ou",
        ],
    ),
    // POSIX classes
    (
        "posixAccount",
        &["cn", "uid", "uidNumber", "gidNumber", "homeDirectory"],
        &["userPassword", "loginShell", "gecos", "description"],
    ),
    (
        "posixGroup",
        &["cn", "gidNumber"],
        &["userPassword", "memberUid", "description"],
    ),
    // Active Directory specific
    (
        "user",
        &["cn"],
        &[
            "sAMAccountName",
            "userPrincipalName",
            "givenName",
            "sn",
            "displayName",
            "mail",
            "telephoneNumber",
            "department",
            "title",
            "manager",
            "memberOf",
            "userAccountControl",
            "accountExpires",
            "pwdLastSet",
            "lastLogon",
            "badPwdCount",
            "lockoutTime",
        ],
    ),
    (
        "group",
        &["cn"],
        &[
            "sAMAccountName",
            "description",
            "member",
            "managedBy",
            "groupType",
            "mail",
        ],
    ),
    // Organizational
    (
        "organizationalUnit",
        &["ou"],
        &[
            "description",
            "seeAlso",
            "searchGuide",
            "businessCategory",
            "l",
            "st",
            "postalCode",
        ],
    ),
    (
        "organization",
        &["o"],
        &[
            "description",
            "seeAlso",
            "businessCategory",
            "l",
            "st",
            "postalCode",
            "telephoneNumber",
        ],
    ),
];

/// Well-known LDAP attribute types and their data types.
///
/// Format: (name, data_type, multi_valued)
pub const ATTRIBUTE_TYPES: &[(&str, AttributeDataType, bool)] = &[
    // String attributes
    ("cn", AttributeDataType::String, false),
    ("sn", AttributeDataType::String, false),
    ("givenName", AttributeDataType::String, false),
    ("displayName", AttributeDataType::String, false),
    ("uid", AttributeDataType::String, false),
    ("mail", AttributeDataType::String, true),
    ("telephoneNumber", AttributeDataType::String, true),
    ("description", AttributeDataType::String, false),
    ("title", AttributeDataType::String, false),
    ("department", AttributeDataType::String, false),
    ("employeeNumber", AttributeDataType::String, false),
    ("employeeType", AttributeDataType::String, false),
    ("departmentNumber", AttributeDataType::String, true),
    ("manager", AttributeDataType::Dn, false),
    ("street", AttributeDataType::String, false),
    ("postalCode", AttributeDataType::String, false),
    ("postalAddress", AttributeDataType::String, false),
    ("st", AttributeDataType::String, false),
    ("l", AttributeDataType::String, false),
    ("o", AttributeDataType::String, true),
    ("ou", AttributeDataType::String, true),
    ("seeAlso", AttributeDataType::Dn, true),
    ("businessCategory", AttributeDataType::String, true),
    ("homeDirectory", AttributeDataType::String, false),
    ("loginShell", AttributeDataType::String, false),
    ("gecos", AttributeDataType::String, false),
    // AD specific strings
    ("sAMAccountName", AttributeDataType::String, false),
    ("userPrincipalName", AttributeDataType::String, false),
    // Integer attributes
    ("uidNumber", AttributeDataType::Integer, false),
    ("gidNumber", AttributeDataType::Integer, false),
    ("userAccountControl", AttributeDataType::Integer, false),
    ("groupType", AttributeDataType::Integer, false),
    ("badPwdCount", AttributeDataType::Integer, false),
    // DateTime attributes
    ("accountExpires", AttributeDataType::DateTime, false),
    ("pwdLastSet", AttributeDataType::DateTime, false),
    ("lastLogon", AttributeDataType::DateTime, false),
    ("lockoutTime", AttributeDataType::DateTime, false),
    // Binary attributes
    ("userPassword", AttributeDataType::Binary, false),
    ("jpegPhoto", AttributeDataType::Binary, false),
    // DN references (multi-valued)
    ("member", AttributeDataType::Dn, true),
    ("uniqueMember", AttributeDataType::Dn, true),
    ("memberOf", AttributeDataType::Dn, true),
    ("memberUid", AttributeDataType::String, true),
    ("owner", AttributeDataType::Dn, true),
    ("managedBy", AttributeDataType::Dn, false),
    // Object class (always multi-valued)
    ("objectClass", AttributeDataType::String, true),
];

/// Build a map of attribute names to their types for quick lookup.
pub fn build_attribute_map() -> HashMap<&'static str, (AttributeDataType, bool)> {
    ATTRIBUTE_TYPES
        .iter()
        .map(|(name, dtype, multi)| (*name, (*dtype, *multi)))
        .collect()
}

/// Get the attribute data type for a well-known attribute.
pub fn get_attribute_type(name: &str) -> Option<(AttributeDataType, bool)> {
    ATTRIBUTE_TYPES
        .iter()
        .find(|(n, _, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, dtype, multi)| (*dtype, *multi))
}

/// Convert camelCase attribute name to human-readable form.
pub fn humanize_attribute_name(name: &str) -> String {
    // Handle special cases first
    match name {
        "cn" => return "CN".to_string(),
        "sn" => return "Surname".to_string(),
        "dn" => return "DN".to_string(),
        "uid" => return "UID".to_string(),
        "sAMAccountName" => return "SAM Account Name".to_string(),
        "userPrincipalName" => return "User Principal Name".to_string(),
        _ => {}
    }

    let mut result = String::new();
    let mut prev_lower = false;

    for c in name.chars() {
        if c.is_uppercase() && prev_lower {
            result.push(' ');
        }
        if result.is_empty() {
            result.push(c.to_ascii_uppercase());
        } else {
            result.push(c);
        }
        prev_lower = c.is_lowercase();
    }

    result
}

/// Convert object class name to human-readable form.
pub fn humanize_class_name(name: &str) -> String {
    match name {
        "inetOrgPerson" => "Internet Organizational Person".to_string(),
        "organizationalPerson" => "Organizational Person".to_string(),
        "groupOfNames" => "Group of Names".to_string(),
        "groupOfUniqueNames" => "Group of Unique Names".to_string(),
        "posixAccount" => "POSIX Account".to_string(),
        "posixGroup" => "POSIX Group".to_string(),
        "organizationalUnit" => "Organizational Unit".to_string(),
        _ => humanize_attribute_name(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_attribute_map() {
        let map = build_attribute_map();
        assert!(map.contains_key("cn"));
        assert!(map.contains_key("mail"));
        assert!(map.contains_key("userAccountControl"));

        let (dtype, multi) = map.get("mail").unwrap();
        assert_eq!(*dtype, AttributeDataType::String);
        assert!(*multi); // mail is multi-valued

        let (dtype, multi) = map.get("uidNumber").unwrap();
        assert_eq!(*dtype, AttributeDataType::Integer);
        assert!(!*multi);
    }

    #[test]
    fn test_get_attribute_type() {
        let (dtype, multi) = get_attribute_type("mail").unwrap();
        assert_eq!(dtype, AttributeDataType::String);
        assert!(multi);

        let (dtype, multi) = get_attribute_type("MAIL").unwrap();
        assert_eq!(dtype, AttributeDataType::String);
        assert!(multi);

        assert!(get_attribute_type("nonexistent").is_none());
    }

    #[test]
    fn test_humanize_attribute_name() {
        assert_eq!(humanize_attribute_name("givenName"), "Given Name");
        assert_eq!(
            humanize_attribute_name("telephoneNumber"),
            "Telephone Number"
        );
        assert_eq!(humanize_attribute_name("cn"), "CN");
        assert_eq!(humanize_attribute_name("sn"), "Surname");
        assert_eq!(
            humanize_attribute_name("sAMAccountName"),
            "SAM Account Name"
        );
        assert_eq!(
            humanize_attribute_name("userPrincipalName"),
            "User Principal Name"
        );
    }

    #[test]
    fn test_humanize_class_name() {
        assert_eq!(
            humanize_class_name("inetOrgPerson"),
            "Internet Organizational Person"
        );
        assert_eq!(humanize_class_name("posixAccount"), "POSIX Account");
        assert_eq!(humanize_class_name("user"), "User");
    }

    #[test]
    fn test_common_object_classes_coverage() {
        // Verify we have the essential object classes
        let class_names: Vec<&str> = COMMON_OBJECT_CLASSES.iter().map(|(n, _, _)| *n).collect();

        assert!(class_names.contains(&"inetOrgPerson"));
        assert!(class_names.contains(&"person"));
        assert!(class_names.contains(&"groupOfNames"));
        assert!(class_names.contains(&"posixAccount"));
        assert!(class_names.contains(&"user")); // AD
        assert!(class_names.contains(&"group")); // AD
        assert!(class_names.contains(&"organizationalUnit"));
    }

    #[test]
    fn test_attribute_types_coverage() {
        let attr_names: Vec<&str> = ATTRIBUTE_TYPES.iter().map(|(n, _, _)| *n).collect();

        // Essential identity attributes
        assert!(attr_names.contains(&"cn"));
        assert!(attr_names.contains(&"sn"));
        assert!(attr_names.contains(&"givenName"));
        assert!(attr_names.contains(&"mail"));
        assert!(attr_names.contains(&"uid"));

        // Group membership
        assert!(attr_names.contains(&"member"));
        assert!(attr_names.contains(&"memberOf"));

        // AD specific
        assert!(attr_names.contains(&"sAMAccountName"));
        assert!(attr_names.contains(&"userPrincipalName"));
        assert!(attr_names.contains(&"userAccountControl"));
    }
}
