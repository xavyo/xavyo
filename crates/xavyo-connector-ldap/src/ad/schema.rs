//! AD-specific schema definitions with pre-built object classes.
//!
//! Provides default ObjectClass definitions for Active Directory user and group
//! objects, including all standard AD attributes with correct data types,
//! multi-value flags, and identifier designations.

use xavyo_connector::schema::{
    AttributeDataType, ObjectClass, ObjectClassType, Schema, SchemaAttribute, SchemaConfig,
};

/// Build the default AD user object class with standard attributes.
///
/// Includes all attributes from the AD user schema that are relevant for
/// identity provisioning: identifiers, name attributes, contact info,
/// organizational attributes, account control, and timestamps.
pub fn ad_user_object_class() -> ObjectClass {
    ObjectClass::new("user", "user")
        .with_display_name("Active Directory User")
        .with_description("AD user account (objectClass=user, objectCategory=person)")
        .with_object_class_type(ObjectClassType::Structural)
        .with_parent_classes(vec![
            "organizationalPerson".to_string(),
            "person".to_string(),
            "top".to_string(),
        ])
        // Primary identifier: objectGUID (binary, immutable)
        .with_attribute(
            SchemaAttribute::new("objectGUID", "objectGUID", AttributeDataType::Binary)
                .as_primary_identifier()
                .required()
                .read_only(),
        )
        // Secondary identifier: distinguishedName
        .with_attribute(
            SchemaAttribute::new(
                "distinguishedName",
                "distinguishedName",
                AttributeDataType::Dn,
            )
            .as_secondary_identifier()
            .read_only(),
        )
        // Account identifiers
        .with_attribute(
            SchemaAttribute::new(
                "sAMAccountName",
                "sAMAccountName",
                AttributeDataType::String,
            )
            .required()
            .case_insensitive(),
        )
        .with_attribute(
            SchemaAttribute::new(
                "userPrincipalName",
                "userPrincipalName",
                AttributeDataType::String,
            )
            .case_insensitive(),
        )
        // Name attributes
        .with_attribute(
            SchemaAttribute::new("cn", "cn", AttributeDataType::String)
                .required()
                .case_insensitive(),
        )
        .with_attribute(SchemaAttribute::new(
            "displayName",
            "displayName",
            AttributeDataType::String,
        ))
        .with_attribute(SchemaAttribute::new(
            "givenName",
            "givenName",
            AttributeDataType::String,
        ))
        .with_attribute(SchemaAttribute::new("sn", "sn", AttributeDataType::String))
        // Contact
        .with_attribute(SchemaAttribute::new(
            "mail",
            "mail",
            AttributeDataType::String,
        ))
        .with_attribute(SchemaAttribute::new(
            "telephoneNumber",
            "telephoneNumber",
            AttributeDataType::String,
        ))
        // Organizational
        .with_attribute(SchemaAttribute::new(
            "department",
            "department",
            AttributeDataType::String,
        ))
        .with_attribute(SchemaAttribute::new(
            "title",
            "title",
            AttributeDataType::String,
        ))
        .with_attribute(SchemaAttribute::new(
            "company",
            "company",
            AttributeDataType::String,
        ))
        .with_attribute(SchemaAttribute::new(
            "employeeID",
            "employeeID",
            AttributeDataType::String,
        ))
        .with_attribute(SchemaAttribute::new(
            "employeeNumber",
            "employeeNumber",
            AttributeDataType::String,
        ))
        .with_attribute(SchemaAttribute::new(
            "manager",
            "manager",
            AttributeDataType::Dn,
        ))
        // Account control
        .with_attribute(SchemaAttribute::new(
            "userAccountControl",
            "userAccountControl",
            AttributeDataType::Integer,
        ))
        .with_attribute(
            SchemaAttribute::new("accountExpires", "accountExpires", AttributeDataType::Long)
                .with_description("Windows FILETIME: 100-nanosecond intervals since 1601-01-01"),
        )
        .with_attribute(SchemaAttribute::new(
            "pwdLastSet",
            "pwdLastSet",
            AttributeDataType::Long,
        ))
        .with_attribute(
            SchemaAttribute::new("lockoutTime", "lockoutTime", AttributeDataType::Long).read_only(),
        )
        .with_attribute(
            SchemaAttribute::new("badPwdCount", "badPwdCount", AttributeDataType::Integer)
                .read_only(),
        )
        .with_attribute(
            SchemaAttribute::new("lastLogon", "lastLogon", AttributeDataType::Long).read_only(),
        )
        .with_attribute(
            SchemaAttribute::new(
                "lastLogonTimestamp",
                "lastLogonTimestamp",
                AttributeDataType::Long,
            )
            .read_only()
            .volatile(),
        )
        // Group membership (read-only, computed by AD)
        .with_attribute(
            SchemaAttribute::new("memberOf", "memberOf", AttributeDataType::Dn)
                .multi_valued()
                .read_only(),
        )
        // Password (write-only, AD uses unicodePwd)
        .with_attribute(
            SchemaAttribute::new("unicodePwd", "unicodePwd", AttributeDataType::Binary)
                .write_only(),
        )
        // Change tracking
        .with_attribute(
            SchemaAttribute::new("uSNChanged", "uSNChanged", AttributeDataType::Long)
                .read_only()
                .volatile(),
        )
        .with_attribute(
            SchemaAttribute::new("uSNCreated", "uSNCreated", AttributeDataType::Long)
                .read_only()
                .volatile(),
        )
        .with_attribute(
            SchemaAttribute::new("whenCreated", "whenCreated", AttributeDataType::DateTime)
                .read_only(),
        )
        .with_attribute(
            SchemaAttribute::new("whenChanged", "whenChanged", AttributeDataType::DateTime)
                .read_only()
                .volatile(),
        )
        // Object class info (read-only)
        .with_attribute(
            SchemaAttribute::new("objectClass", "objectClass", AttributeDataType::String)
                .multi_valued()
                .read_only(),
        )
        .with_attribute(
            SchemaAttribute::new("objectCategory", "objectCategory", AttributeDataType::Dn)
                .read_only(),
        )
}

/// Build the default AD group object class with standard attributes.
///
/// Includes attributes for group identity, membership, and type classification
/// (security vs. distribution, global vs. universal vs. domain-local).
pub fn ad_group_object_class() -> ObjectClass {
    ObjectClass::new("group", "group")
        .with_display_name("Active Directory Group")
        .with_description("AD security or distribution group (objectClass=group)")
        .with_object_class_type(ObjectClassType::Structural)
        .with_parent_classes(vec!["top".to_string()])
        // Primary identifier: objectGUID (binary, immutable)
        .with_attribute(
            SchemaAttribute::new("objectGUID", "objectGUID", AttributeDataType::Binary)
                .as_primary_identifier()
                .required()
                .read_only(),
        )
        // Secondary identifier: distinguishedName
        .with_attribute(
            SchemaAttribute::new(
                "distinguishedName",
                "distinguishedName",
                AttributeDataType::Dn,
            )
            .as_secondary_identifier()
            .read_only(),
        )
        // Group identifiers
        .with_attribute(
            SchemaAttribute::new(
                "sAMAccountName",
                "sAMAccountName",
                AttributeDataType::String,
            )
            .required()
            .case_insensitive(),
        )
        .with_attribute(
            SchemaAttribute::new("cn", "cn", AttributeDataType::String)
                .required()
                .case_insensitive(),
        )
        // Group metadata
        .with_attribute(SchemaAttribute::new(
            "description",
            "description",
            AttributeDataType::String,
        ))
        .with_attribute(SchemaAttribute::new(
            "mail",
            "mail",
            AttributeDataType::String,
        ))
        .with_attribute(SchemaAttribute::new(
            "managedBy",
            "managedBy",
            AttributeDataType::Dn,
        ))
        // Group type (bitmask: security/distribution + scope)
        .with_attribute(
            SchemaAttribute::new("groupType", "groupType", AttributeDataType::Integer)
                .with_description(
                    "Bitmask: 0x80000000=security, 0x2=global, 0x4=domain-local, 0x8=universal",
                ),
        )
        // Membership
        .with_attribute(
            SchemaAttribute::new("member", "member", AttributeDataType::Dn).multi_valued(),
        )
        .with_attribute(
            SchemaAttribute::new("memberOf", "memberOf", AttributeDataType::Dn)
                .multi_valued()
                .read_only(),
        )
        // Change tracking
        .with_attribute(
            SchemaAttribute::new("uSNChanged", "uSNChanged", AttributeDataType::Long)
                .read_only()
                .volatile(),
        )
        .with_attribute(
            SchemaAttribute::new("uSNCreated", "uSNCreated", AttributeDataType::Long)
                .read_only()
                .volatile(),
        )
        .with_attribute(
            SchemaAttribute::new("whenCreated", "whenCreated", AttributeDataType::DateTime)
                .read_only(),
        )
        .with_attribute(
            SchemaAttribute::new("whenChanged", "whenChanged", AttributeDataType::DateTime)
                .read_only()
                .volatile(),
        )
        // Object class info
        .with_attribute(
            SchemaAttribute::new("objectClass", "objectClass", AttributeDataType::String)
                .multi_valued()
                .read_only(),
        )
        .with_attribute(
            SchemaAttribute::new("objectCategory", "objectCategory", AttributeDataType::Dn)
                .read_only(),
        )
}

/// Build the complete AD schema with user and group object classes.
///
/// Returns a Schema with AD-specific configuration including
/// case-insensitive attribute matching and objectGUID as the primary identifier.
pub fn ad_default_schema() -> Schema {
    Schema::with_object_classes(vec![ad_user_object_class(), ad_group_object_class()]).with_config(
        SchemaConfig {
            case_ignore_attribute_names: true,
            preserve_native_naming: true,
            volatile_attributes: vec![
                "uSNChanged".to_string(),
                "uSNCreated".to_string(),
                "whenChanged".to_string(),
                "lastLogonTimestamp".to_string(),
            ],
            primary_identifier: Some("objectGUID".to_string()),
            secondary_identifiers: vec![
                "distinguishedName".to_string(),
                "sAMAccountName".to_string(),
            ],
        },
    )
}

/// AD group type flag constants.
///
/// The `groupType` attribute is a bitmask combining scope and type.
pub mod group_type {
    /// Global group scope.
    pub const GLOBAL: i32 = 0x0000_0002;
    /// Domain-local group scope.
    pub const DOMAIN_LOCAL: i32 = 0x0000_0004;
    /// Universal group scope.
    pub const UNIVERSAL: i32 = 0x0000_0008;
    /// Security group (vs. distribution).
    pub const SECURITY: i32 = -0x8000_0000_i32; // 0x80000000 as signed i32

    /// Check if a groupType value indicates a security group.
    pub fn is_security_group(group_type: i32) -> bool {
        group_type & SECURITY != 0
    }

    /// Get the scope name from a groupType value.
    pub fn scope_name(group_type: i32) -> &'static str {
        let scope_bits = group_type & 0x0000_000E;
        if scope_bits & GLOBAL != 0 {
            "global"
        } else if scope_bits & DOMAIN_LOCAL != 0 {
            "domain_local"
        } else if scope_bits & UNIVERSAL != 0 {
            "universal"
        } else {
            "unknown"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_connector::schema::AttributeDataType;

    #[test]
    fn test_ad_user_object_class_basic() {
        let oc = ad_user_object_class();
        assert_eq!(oc.name, "user");
        assert_eq!(oc.native_name, "user");
        assert_eq!(oc.display_name, Some("Active Directory User".to_string()));
        assert_eq!(oc.object_class_type, ObjectClassType::Structural);
        assert!(oc.supports_create);
        assert!(oc.supports_update);
        assert!(oc.supports_delete);
    }

    #[test]
    fn test_ad_user_has_primary_identifier() {
        let oc = ad_user_object_class();
        let primary = oc.primary_identifier();
        assert!(primary.is_some());
        let guid = primary.unwrap();
        assert_eq!(guid.name, "objectGUID");
        assert_eq!(guid.data_type, AttributeDataType::Binary);
        assert!(guid.required);
        assert!(!guid.writable); // read-only
    }

    #[test]
    fn test_ad_user_has_required_attributes() {
        let oc = ad_user_object_class();
        let required: Vec<&str> = oc
            .required_attributes()
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert!(required.contains(&"objectGUID"));
        assert!(required.contains(&"sAMAccountName"));
        assert!(required.contains(&"cn"));
    }

    #[test]
    fn test_ad_user_has_identity_attributes() {
        let oc = ad_user_object_class();
        // All attributes from data-model.md attribute mapping reference
        let expected = [
            "objectGUID",
            "sAMAccountName",
            "userPrincipalName",
            "cn",
            "displayName",
            "givenName",
            "sn",
            "mail",
            "department",
            "title",
            "employeeID",
            "manager",
            "userAccountControl",
            "memberOf",
        ];
        for attr_name in &expected {
            assert!(
                oc.has_attribute(attr_name),
                "Missing user attribute: {}",
                attr_name
            );
        }
    }

    #[test]
    fn test_ad_user_has_change_tracking_attributes() {
        let oc = ad_user_object_class();
        let tracking = ["uSNChanged", "uSNCreated", "whenCreated", "whenChanged"];
        for attr_name in &tracking {
            let attr = oc.get_attribute(attr_name);
            assert!(attr.is_some(), "Missing tracking attribute: {}", attr_name);
            assert!(!attr.unwrap().writable, "{} should be read-only", attr_name);
        }
    }

    #[test]
    fn test_ad_user_usn_volatile() {
        let oc = ad_user_object_class();
        let usn = oc.get_attribute("uSNChanged").unwrap();
        assert!(usn.volatile);
        assert!(!usn.writable);
        assert_eq!(usn.data_type, AttributeDataType::Long);
    }

    #[test]
    fn test_ad_user_password_write_only() {
        let oc = ad_user_object_class();
        let pwd = oc.get_attribute("unicodePwd").unwrap();
        assert!(!pwd.readable);
        assert!(!pwd.returned_by_default);
        assert_eq!(pwd.data_type, AttributeDataType::Binary);
    }

    #[test]
    fn test_ad_user_member_of_multi_valued_readonly() {
        let oc = ad_user_object_class();
        let member_of = oc.get_attribute("memberOf").unwrap();
        assert!(member_of.multi_valued);
        assert!(!member_of.writable);
        assert_eq!(member_of.data_type, AttributeDataType::Dn);
    }

    #[test]
    fn test_ad_user_parent_classes() {
        let oc = ad_user_object_class();
        assert!(oc.parent_classes.contains(&"person".to_string()));
        assert!(oc
            .parent_classes
            .contains(&"organizationalPerson".to_string()));
        assert!(oc.parent_classes.contains(&"top".to_string()));
    }

    #[test]
    fn test_ad_group_object_class_basic() {
        let oc = ad_group_object_class();
        assert_eq!(oc.name, "group");
        assert_eq!(oc.native_name, "group");
        assert_eq!(oc.display_name, Some("Active Directory Group".to_string()));
        assert_eq!(oc.object_class_type, ObjectClassType::Structural);
    }

    #[test]
    fn test_ad_group_has_primary_identifier() {
        let oc = ad_group_object_class();
        let primary = oc.primary_identifier();
        assert!(primary.is_some());
        let guid = primary.unwrap();
        assert_eq!(guid.name, "objectGUID");
        assert_eq!(guid.data_type, AttributeDataType::Binary);
    }

    #[test]
    fn test_ad_group_has_required_attributes() {
        let oc = ad_group_object_class();
        let required: Vec<&str> = oc
            .required_attributes()
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert!(required.contains(&"objectGUID"));
        assert!(required.contains(&"sAMAccountName"));
        assert!(required.contains(&"cn"));
    }

    #[test]
    fn test_ad_group_has_membership_attributes() {
        let oc = ad_group_object_class();
        // member is writable (for outbound)
        let member = oc.get_attribute("member").unwrap();
        assert!(member.multi_valued);
        assert!(member.writable);
        assert_eq!(member.data_type, AttributeDataType::Dn);

        // memberOf is read-only (computed by AD)
        let member_of = oc.get_attribute("memberOf").unwrap();
        assert!(member_of.multi_valued);
        assert!(!member_of.writable);
    }

    #[test]
    fn test_ad_group_has_group_type() {
        let oc = ad_group_object_class();
        let gt = oc.get_attribute("groupType").unwrap();
        assert_eq!(gt.data_type, AttributeDataType::Integer);
        assert!(gt.description.is_some());
    }

    #[test]
    fn test_ad_group_has_change_tracking() {
        let oc = ad_group_object_class();
        assert!(oc.has_attribute("uSNChanged"));
        assert!(oc.has_attribute("whenCreated"));
        assert!(oc.has_attribute("whenChanged"));
    }

    #[test]
    fn test_ad_default_schema() {
        let schema = ad_default_schema();
        assert!(schema.has_object_class("user"));
        assert!(schema.has_object_class("group"));
        assert_eq!(schema.object_classes.len(), 2);
    }

    #[test]
    fn test_ad_default_schema_config() {
        let schema = ad_default_schema();
        let config = schema.config();
        assert!(config.case_ignore_attribute_names);
        assert!(config.preserve_native_naming);
        assert_eq!(config.primary_identifier, Some("objectGUID".to_string()));
        assert!(config
            .secondary_identifiers
            .contains(&"distinguishedName".to_string()));
        assert!(config
            .secondary_identifiers
            .contains(&"sAMAccountName".to_string()));
    }

    #[test]
    fn test_ad_default_schema_volatile_attributes() {
        let schema = ad_default_schema();
        let config = schema.config();
        assert!(config
            .volatile_attributes
            .contains(&"uSNChanged".to_string()));
        assert!(config
            .volatile_attributes
            .contains(&"whenChanged".to_string()));
    }

    #[test]
    fn test_ad_schema_case_insensitive_lookup() {
        let schema = ad_default_schema();
        // Case-aware lookup should find "user" regardless of case
        assert!(schema.get_object_class_case_aware("User").is_some());
        assert!(schema.get_object_class_case_aware("USER").is_some());
        assert!(schema.get_object_class_case_aware("group").is_some());
    }

    #[test]
    fn test_group_type_security() {
        assert!(group_type::is_security_group(
            group_type::SECURITY | group_type::GLOBAL
        ));
        assert!(!group_type::is_security_group(group_type::GLOBAL));
        assert!(!group_type::is_security_group(group_type::UNIVERSAL));
    }

    #[test]
    fn test_group_type_scope() {
        assert_eq!(
            group_type::scope_name(group_type::SECURITY | group_type::GLOBAL),
            "global"
        );
        assert_eq!(
            group_type::scope_name(group_type::SECURITY | group_type::DOMAIN_LOCAL),
            "domain_local"
        );
        assert_eq!(
            group_type::scope_name(group_type::SECURITY | group_type::UNIVERSAL),
            "universal"
        );
        assert_eq!(group_type::scope_name(0), "unknown");
    }

    #[test]
    fn test_typical_ad_security_global_group() {
        // Most common AD group type: Security + Global = 0x80000002 = -2147483646
        let gt = group_type::SECURITY | group_type::GLOBAL;
        assert!(group_type::is_security_group(gt));
        assert_eq!(group_type::scope_name(gt), "global");
    }

    #[test]
    fn test_typical_ad_distribution_universal_group() {
        // Distribution + Universal = 0x8 = 8
        let gt = group_type::UNIVERSAL;
        assert!(!group_type::is_security_group(gt));
        assert_eq!(group_type::scope_name(gt), "universal");
    }
}
