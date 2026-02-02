//! Group lifecycle events.
//!
//! Published when groups are created, deleted, or membership changes occur.

use crate::event::Event;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Published when a new group is created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCreated {
    /// The new group's ID.
    pub group_id: Uuid,
    /// Group's display name.
    pub display_name: String,
    /// Initial member user IDs.
    #[serde(default)]
    pub member_ids: Vec<Uuid>,
    /// Admin who created the group.
    pub created_by: Option<Uuid>,
}

impl Event for GroupCreated {
    const TOPIC: &'static str = "xavyo.idp.group.created";
    const EVENT_TYPE: &'static str = "xavyo.idp.group.created";
}

/// Published when a group is deleted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupDeleted {
    /// The deleted group's ID.
    pub group_id: Uuid,
    /// Reason for deletion (optional).
    pub reason: Option<String>,
}

impl Event for GroupDeleted {
    const TOPIC: &'static str = "xavyo.idp.group.deleted";
    const EVENT_TYPE: &'static str = "xavyo.idp.group.deleted";
}

/// Published when a member is added to a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMemberAdded {
    /// The group's ID.
    pub group_id: Uuid,
    /// The user ID that was added.
    pub user_id: Uuid,
    /// Who performed the action.
    pub added_by: Option<Uuid>,
}

impl Event for GroupMemberAdded {
    const TOPIC: &'static str = "xavyo.idp.group.member.added";
    const EVENT_TYPE: &'static str = "xavyo.idp.group.member.added";
}

/// Published when a member is removed from a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMemberRemoved {
    /// The group's ID.
    pub group_id: Uuid,
    /// The user ID that was removed.
    pub user_id: Uuid,
    /// Who performed the action.
    pub removed_by: Option<Uuid>,
}

impl Event for GroupMemberRemoved {
    const TOPIC: &'static str = "xavyo.idp.group.member.removed";
    const EVENT_TYPE: &'static str = "xavyo.idp.group.member.removed";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_created_serialization() {
        let event = GroupCreated {
            group_id: Uuid::new_v4(),
            display_name: "Engineering".to_string(),
            member_ids: vec![Uuid::new_v4()],
            created_by: None,
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: GroupCreated = serde_json::from_str(&json).unwrap();
        assert_eq!(event.group_id, restored.group_id);
        assert_eq!(event.display_name, restored.display_name);
    }

    #[test]
    fn test_group_created_topic() {
        assert_eq!(GroupCreated::TOPIC, "xavyo.idp.group.created");
    }

    #[test]
    fn test_group_deleted_topic() {
        assert_eq!(GroupDeleted::TOPIC, "xavyo.idp.group.deleted");
    }

    #[test]
    fn test_group_member_added_topic() {
        assert_eq!(GroupMemberAdded::TOPIC, "xavyo.idp.group.member.added");
    }

    #[test]
    fn test_group_member_removed_topic() {
        assert_eq!(GroupMemberRemoved::TOPIC, "xavyo.idp.group.member.removed");
    }
}
