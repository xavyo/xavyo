//! User lifecycle events.

use crate::event::Event;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Published when a new user is created in the IDP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCreated {
    /// The new user's ID.
    pub user_id: Uuid,
    /// User's email address.
    pub email: String,
    /// User's display name (optional).
    pub display_name: Option<String>,
    /// Initial roles assigned to the user.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Admin who created the user (null for self-registration).
    pub created_by: Option<Uuid>,
}

impl Event for UserCreated {
    const TOPIC: &'static str = "xavyo.idp.user.created";
    const EVENT_TYPE: &'static str = "xavyo.idp.user.created";
}

/// Published when user attributes are modified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserUpdated {
    /// The updated user's ID.
    pub user_id: Uuid,
    /// Map of field_name to new_value for changed fields.
    pub changes: HashMap<String, serde_json::Value>,
    /// Map of field_name to old_value for changed fields.
    #[serde(default)]
    pub previous: Option<HashMap<String, serde_json::Value>>,
}

impl Event for UserUpdated {
    const TOPIC: &'static str = "xavyo.idp.user.updated";
    const EVENT_TYPE: &'static str = "xavyo.idp.user.updated";
}

/// Published when a user is soft-deleted/deactivated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDeleted {
    /// The deleted user's ID.
    pub user_id: Uuid,
    /// Reason for deletion (optional).
    pub reason: Option<String>,
    /// True if permanently deleted (default: false).
    #[serde(default)]
    pub hard_delete: bool,
}

impl Event for UserDeleted {
    const TOPIC: &'static str = "xavyo.idp.user.deleted";
    const EVENT_TYPE: &'static str = "xavyo.idp.user.deleted";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_created_serialization() {
        let event = UserCreated {
            user_id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            roles: vec!["user".to_string(), "admin".to_string()],
            created_by: None,
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: UserCreated = serde_json::from_str(&json).unwrap();

        assert_eq!(event.user_id, restored.user_id);
        assert_eq!(event.email, restored.email);
        assert_eq!(event.roles, restored.roles);
    }

    #[test]
    fn test_user_created_topic() {
        assert_eq!(UserCreated::TOPIC, "xavyo.idp.user.created");
        assert_eq!(UserCreated::EVENT_TYPE, "xavyo.idp.user.created");
    }

    #[test]
    fn test_user_updated_serialization() {
        let mut changes = HashMap::new();
        changes.insert("email".to_string(), serde_json::json!("new@example.com"));

        let event = UserUpdated {
            user_id: Uuid::new_v4(),
            changes,
            previous: None,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("email"));
    }

    #[test]
    fn test_user_deleted_defaults() {
        let json = r#"{"user_id": "550e8400-e29b-41d4-a716-446655440000"}"#;
        let event: UserDeleted = serde_json::from_str(json).unwrap();

        assert!(!event.hard_delete);
        assert!(event.reason.is_none());
    }
}
