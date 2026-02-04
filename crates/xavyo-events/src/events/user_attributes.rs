//! User attribute events (F081).
//!
//! Events emitted when tenant attribute definitions or user custom attribute values change.

use crate::event::Event;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Published when a new attribute definition is created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeDefinitionCreated {
    /// The new definition's ID.
    pub definition_id: Uuid,
    /// Attribute name (slug).
    pub name: String,
    /// Human-readable display label.
    pub display_label: String,
    /// Data type (string, number, boolean, date, json, enum).
    pub data_type: String,
    /// Whether the attribute is required.
    pub required: bool,
    /// Whether this is a well-known (seeded) attribute.
    pub is_well_known: bool,
    /// Well-known catalog slug (if seeded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub well_known_slug: Option<String>,
    /// Admin who created the definition.
    pub created_by: Option<Uuid>,
}

impl Event for AttributeDefinitionCreated {
    const TOPIC: &'static str = "xavyo.idp.attribute_definition.created";
    const EVENT_TYPE: &'static str = "xavyo.idp.attribute_definition.created";
}

/// Published when an attribute definition is updated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeDefinitionUpdated {
    /// The updated definition's ID.
    pub definition_id: Uuid,
    /// Attribute name (slug).
    pub name: String,
    /// Map of `field_name` to `new_value` for changed fields.
    pub changes: HashMap<String, serde_json::Value>,
    /// Admin who updated the definition.
    pub updated_by: Option<Uuid>,
}

impl Event for AttributeDefinitionUpdated {
    const TOPIC: &'static str = "xavyo.idp.attribute_definition.updated";
    const EVENT_TYPE: &'static str = "xavyo.idp.attribute_definition.updated";
}

/// Published when an attribute definition is deactivated (soft-deleted) or hard-deleted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeDefinitionDeactivated {
    /// The deactivated definition's ID.
    pub definition_id: Uuid,
    /// Attribute name (slug).
    pub name: String,
    /// Whether this was a hard delete (true) or soft deactivation (false).
    pub hard_delete: bool,
    /// Admin who deactivated the definition.
    pub deactivated_by: Option<Uuid>,
}

impl Event for AttributeDefinitionDeactivated {
    const TOPIC: &'static str = "xavyo.idp.attribute_definition.deactivated";
    const EVENT_TYPE: &'static str = "xavyo.idp.attribute_definition.deactivated";
}

/// Published when a bulk attribute update operation completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkAttributeUpdateCompleted {
    /// The attribute that was bulk-updated.
    pub attribute_name: String,
    /// The new value applied to all matched users.
    pub new_value: serde_json::Value,
    /// Total users matching the filter.
    pub total_matched: i64,
    /// Total users successfully updated.
    pub total_updated: i64,
    /// Total users that failed to update.
    pub total_failed: i64,
    /// Admin who initiated the bulk update.
    pub initiated_by: Option<Uuid>,
}

impl Event for BulkAttributeUpdateCompleted {
    const TOPIC: &'static str = "xavyo.idp.user.custom_attributes.bulk_updated";
    const EVENT_TYPE: &'static str = "xavyo.idp.user.custom_attributes.bulk_updated";
}

/// Published when a user's custom attributes are modified (set, patch, or bulk update).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomAttributesUpdated {
    /// The user whose attributes changed.
    pub user_id: Uuid,
    /// List of attribute names that changed.
    pub changed_attributes: Vec<String>,
    /// Previous values for changed attributes (key → old value).
    #[serde(default)]
    pub old_values: HashMap<String, serde_json::Value>,
    /// New values for changed attributes (key → new value).
    #[serde(default)]
    pub new_values: HashMap<String, serde_json::Value>,
    /// Actor who made the change (admin user ID, SCIM client, etc.).
    pub changed_by: Option<Uuid>,
}

impl Event for CustomAttributesUpdated {
    const TOPIC: &'static str = "xavyo.idp.user.custom_attributes.updated";
    const EVENT_TYPE: &'static str = "xavyo.idp.user.custom_attributes.updated";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_definition_created_serialization() {
        let event = AttributeDefinitionCreated {
            definition_id: Uuid::new_v4(),
            name: "department".to_string(),
            display_label: "Department".to_string(),
            data_type: "string".to_string(),
            required: false,
            is_well_known: true,
            well_known_slug: Some("department".to_string()),
            created_by: Some(Uuid::new_v4()),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: AttributeDefinitionCreated = serde_json::from_str(&json).unwrap();

        assert_eq!(event.definition_id, restored.definition_id);
        assert_eq!(event.name, restored.name);
        assert_eq!(event.data_type, restored.data_type);
        assert!(restored.is_well_known);
        assert_eq!(restored.well_known_slug, Some("department".to_string()));
    }

    #[test]
    fn test_attribute_definition_created_topic() {
        assert_eq!(
            AttributeDefinitionCreated::TOPIC,
            "xavyo.idp.attribute_definition.created"
        );
        assert_eq!(
            AttributeDefinitionCreated::EVENT_TYPE,
            "xavyo.idp.attribute_definition.created"
        );
    }

    #[test]
    fn test_attribute_definition_updated_serialization() {
        let mut changes = HashMap::new();
        changes.insert("display_label".to_string(), serde_json::json!("New Label"));
        changes.insert("required".to_string(), serde_json::json!(true));

        let event = AttributeDefinitionUpdated {
            definition_id: Uuid::new_v4(),
            name: "department".to_string(),
            changes,
            updated_by: Some(Uuid::new_v4()),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: AttributeDefinitionUpdated = serde_json::from_str(&json).unwrap();

        assert_eq!(event.definition_id, restored.definition_id);
        assert_eq!(restored.changes.len(), 2);
        assert!(restored.changes.contains_key("display_label"));
    }

    #[test]
    fn test_attribute_definition_updated_topic() {
        assert_eq!(
            AttributeDefinitionUpdated::TOPIC,
            "xavyo.idp.attribute_definition.updated"
        );
    }

    #[test]
    fn test_attribute_definition_deactivated_serialization() {
        let event = AttributeDefinitionDeactivated {
            definition_id: Uuid::new_v4(),
            name: "old_field".to_string(),
            hard_delete: false,
            deactivated_by: Some(Uuid::new_v4()),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: AttributeDefinitionDeactivated = serde_json::from_str(&json).unwrap();

        assert_eq!(event.definition_id, restored.definition_id);
        assert!(!restored.hard_delete);
    }

    #[test]
    fn test_attribute_definition_deactivated_topic() {
        assert_eq!(
            AttributeDefinitionDeactivated::TOPIC,
            "xavyo.idp.attribute_definition.deactivated"
        );
    }

    #[test]
    fn test_custom_attributes_updated_serialization() {
        let mut old_values = HashMap::new();
        old_values.insert("department".to_string(), serde_json::json!("Engineering"));

        let mut new_values = HashMap::new();
        new_values.insert(
            "department".to_string(),
            serde_json::json!("Platform Engineering"),
        );

        let event = CustomAttributesUpdated {
            user_id: Uuid::new_v4(),
            changed_attributes: vec!["department".to_string()],
            old_values,
            new_values,
            changed_by: Some(Uuid::new_v4()),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: CustomAttributesUpdated = serde_json::from_str(&json).unwrap();

        assert_eq!(event.user_id, restored.user_id);
        assert_eq!(restored.changed_attributes, vec!["department"]);
        assert_eq!(
            restored.old_values.get("department"),
            Some(&serde_json::json!("Engineering"))
        );
        assert_eq!(
            restored.new_values.get("department"),
            Some(&serde_json::json!("Platform Engineering"))
        );
    }

    #[test]
    fn test_custom_attributes_updated_topic() {
        assert_eq!(
            CustomAttributesUpdated::TOPIC,
            "xavyo.idp.user.custom_attributes.updated"
        );
    }

    #[test]
    fn test_bulk_attribute_update_completed_serialization() {
        let event = BulkAttributeUpdateCompleted {
            attribute_name: "department".to_string(),
            new_value: serde_json::json!("Platform Engineering"),
            total_matched: 150,
            total_updated: 148,
            total_failed: 2,
            initiated_by: Some(Uuid::new_v4()),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: BulkAttributeUpdateCompleted = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.attribute_name, "department");
        assert_eq!(restored.total_matched, 150);
        assert_eq!(restored.total_updated, 148);
        assert_eq!(restored.total_failed, 2);
    }

    #[test]
    fn test_bulk_attribute_update_completed_topic() {
        assert_eq!(
            BulkAttributeUpdateCompleted::TOPIC,
            "xavyo.idp.user.custom_attributes.bulk_updated"
        );
    }

    #[test]
    fn test_custom_attributes_updated_defaults() {
        let json = r#"{"user_id":"550e8400-e29b-41d4-a716-446655440000","changed_attributes":["department"],"changed_by":null}"#;
        let event: CustomAttributesUpdated = serde_json::from_str(json).unwrap();

        assert!(event.old_values.is_empty());
        assert!(event.new_values.is_empty());
        assert!(event.changed_by.is_none());
    }
}
