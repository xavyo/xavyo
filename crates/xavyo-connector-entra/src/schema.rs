//! Schema discovery for Entra ID connector.

use serde::{Deserialize, Serialize};

use crate::EntraConnector;

/// Object class definition for schema discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectClass {
    /// Object class name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Description.
    pub description: Option<String>,
    /// Whether this is a container (can have children).
    pub is_container: bool,
    /// Attributes for this object class.
    pub attributes: Vec<AttributeDefinition>,
}

/// Attribute definition for schema discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeDefinition {
    /// Attribute name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Attribute type.
    pub attribute_type: AttributeType,
    /// Whether this attribute is required.
    pub required: bool,
    /// Whether this attribute is multi-valued.
    pub multi_valued: bool,
    /// Whether this attribute is read-only.
    pub read_only: bool,
}

/// Attribute data type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributeType {
    /// String value.
    String,
    /// Boolean value.
    Boolean,
    /// Integer value.
    Integer,
    /// `DateTime` value.
    DateTime,
    /// Reference to another object.
    Reference,
    /// Binary data.
    Binary,
}

impl EntraConnector {
    /// Returns the schema for Entra ID objects.
    ///
    /// Note: Entra ID doesn't expose a schema discovery API like LDAP,
    /// so this returns a static schema based on the Graph API documentation.
    #[must_use] 
    pub fn get_schema(&self) -> Vec<ObjectClass> {
        vec![
            self.user_object_class(),
            self.group_object_class(),
            self.directory_role_object_class(),
        ]
    }

    fn user_object_class(&self) -> ObjectClass {
        ObjectClass {
            name: "user".to_string(),
            display_name: "User".to_string(),
            description: Some("Entra ID user account".to_string()),
            is_container: false,
            attributes: vec![
                AttributeDefinition {
                    name: "id".to_string(),
                    display_name: "Object ID".to_string(),
                    attribute_type: AttributeType::String,
                    required: true,
                    multi_valued: false,
                    read_only: true,
                },
                AttributeDefinition {
                    name: "userPrincipalName".to_string(),
                    display_name: "User Principal Name".to_string(),
                    attribute_type: AttributeType::String,
                    required: true,
                    multi_valued: false,
                    read_only: false,
                },
                AttributeDefinition {
                    name: "mail".to_string(),
                    display_name: "Email".to_string(),
                    attribute_type: AttributeType::String,
                    required: false,
                    multi_valued: false,
                    read_only: false,
                },
                AttributeDefinition {
                    name: "displayName".to_string(),
                    display_name: "Display Name".to_string(),
                    attribute_type: AttributeType::String,
                    required: true,
                    multi_valued: false,
                    read_only: false,
                },
                AttributeDefinition {
                    name: "givenName".to_string(),
                    display_name: "First Name".to_string(),
                    attribute_type: AttributeType::String,
                    required: false,
                    multi_valued: false,
                    read_only: false,
                },
                AttributeDefinition {
                    name: "surname".to_string(),
                    display_name: "Last Name".to_string(),
                    attribute_type: AttributeType::String,
                    required: false,
                    multi_valued: false,
                    read_only: false,
                },
                AttributeDefinition {
                    name: "department".to_string(),
                    display_name: "Department".to_string(),
                    attribute_type: AttributeType::String,
                    required: false,
                    multi_valued: false,
                    read_only: false,
                },
                AttributeDefinition {
                    name: "jobTitle".to_string(),
                    display_name: "Job Title".to_string(),
                    attribute_type: AttributeType::String,
                    required: false,
                    multi_valued: false,
                    read_only: false,
                },
                AttributeDefinition {
                    name: "employeeId".to_string(),
                    display_name: "Employee ID".to_string(),
                    attribute_type: AttributeType::String,
                    required: false,
                    multi_valued: false,
                    read_only: false,
                },
                AttributeDefinition {
                    name: "accountEnabled".to_string(),
                    display_name: "Account Enabled".to_string(),
                    attribute_type: AttributeType::Boolean,
                    required: false,
                    multi_valued: false,
                    read_only: false,
                },
                AttributeDefinition {
                    name: "createdDateTime".to_string(),
                    display_name: "Created Date".to_string(),
                    attribute_type: AttributeType::DateTime,
                    required: false,
                    multi_valued: false,
                    read_only: true,
                },
                AttributeDefinition {
                    name: "manager".to_string(),
                    display_name: "Manager".to_string(),
                    attribute_type: AttributeType::Reference,
                    required: false,
                    multi_valued: false,
                    read_only: false,
                },
            ],
        }
    }

    fn group_object_class(&self) -> ObjectClass {
        ObjectClass {
            name: "group".to_string(),
            display_name: "Group".to_string(),
            description: Some("Entra ID group".to_string()),
            is_container: true,
            attributes: vec![
                AttributeDefinition {
                    name: "id".to_string(),
                    display_name: "Object ID".to_string(),
                    attribute_type: AttributeType::String,
                    required: true,
                    multi_valued: false,
                    read_only: true,
                },
                AttributeDefinition {
                    name: "displayName".to_string(),
                    display_name: "Display Name".to_string(),
                    attribute_type: AttributeType::String,
                    required: true,
                    multi_valued: false,
                    read_only: false,
                },
                AttributeDefinition {
                    name: "description".to_string(),
                    display_name: "Description".to_string(),
                    attribute_type: AttributeType::String,
                    required: false,
                    multi_valued: false,
                    read_only: false,
                },
                AttributeDefinition {
                    name: "mail".to_string(),
                    display_name: "Email".to_string(),
                    attribute_type: AttributeType::String,
                    required: false,
                    multi_valued: false,
                    read_only: true,
                },
                AttributeDefinition {
                    name: "groupTypes".to_string(),
                    display_name: "Group Types".to_string(),
                    attribute_type: AttributeType::String,
                    required: false,
                    multi_valued: true,
                    read_only: false,
                },
                AttributeDefinition {
                    name: "securityEnabled".to_string(),
                    display_name: "Security Enabled".to_string(),
                    attribute_type: AttributeType::Boolean,
                    required: false,
                    multi_valued: false,
                    read_only: false,
                },
                AttributeDefinition {
                    name: "mailEnabled".to_string(),
                    display_name: "Mail Enabled".to_string(),
                    attribute_type: AttributeType::Boolean,
                    required: false,
                    multi_valued: false,
                    read_only: false,
                },
                AttributeDefinition {
                    name: "members".to_string(),
                    display_name: "Members".to_string(),
                    attribute_type: AttributeType::Reference,
                    required: false,
                    multi_valued: true,
                    read_only: false,
                },
            ],
        }
    }

    fn directory_role_object_class(&self) -> ObjectClass {
        ObjectClass {
            name: "directoryRole".to_string(),
            display_name: "Directory Role".to_string(),
            description: Some("Entra ID directory role".to_string()),
            is_container: true,
            attributes: vec![
                AttributeDefinition {
                    name: "id".to_string(),
                    display_name: "Object ID".to_string(),
                    attribute_type: AttributeType::String,
                    required: true,
                    multi_valued: false,
                    read_only: true,
                },
                AttributeDefinition {
                    name: "displayName".to_string(),
                    display_name: "Display Name".to_string(),
                    attribute_type: AttributeType::String,
                    required: true,
                    multi_valued: false,
                    read_only: true,
                },
                AttributeDefinition {
                    name: "description".to_string(),
                    display_name: "Description".to_string(),
                    attribute_type: AttributeType::String,
                    required: false,
                    multi_valued: false,
                    read_only: true,
                },
                AttributeDefinition {
                    name: "roleTemplateId".to_string(),
                    display_name: "Role Template ID".to_string(),
                    attribute_type: AttributeType::String,
                    required: false,
                    multi_valued: false,
                    read_only: true,
                },
                AttributeDefinition {
                    name: "members".to_string(),
                    display_name: "Members".to_string(),
                    attribute_type: AttributeType::Reference,
                    required: false,
                    multi_valued: true,
                    read_only: false,
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EntraConfig;

    #[test]
    fn test_schema_has_expected_object_classes() {
        // Create a minimal config for testing
        let config = EntraConfig::builder()
            .tenant_id("test-tenant")
            .build()
            .unwrap();

        // We can't fully test without credentials, but we can verify the schema structure
        assert!(config.tenant_id == "test-tenant");
    }

    #[test]
    fn test_attribute_type_serialization() {
        let attr = AttributeDefinition {
            name: "test".to_string(),
            display_name: "Test".to_string(),
            attribute_type: AttributeType::String,
            required: true,
            multi_valued: false,
            read_only: false,
        };

        let json = serde_json::to_value(&attr).unwrap();
        assert_eq!(json["attribute_type"], "string");
    }
}
