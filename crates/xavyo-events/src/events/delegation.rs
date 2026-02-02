//! Delegation events for F053 Deputy & Power of Attorney.
//!
//! Events for delegation lifecycle changes:
//! - Created, Activated, Expiring, Expired, Revoked
//! - Deputy actions performed on behalf of delegators

use crate::event::Event;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Published when a new delegation is created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationCreated {
    /// The delegation ID.
    pub delegation_id: Uuid,
    /// The delegator (person delegating authority).
    pub delegator_id: Uuid,
    /// The deputy (person receiving authority).
    pub deputy_id: Uuid,
    /// When the delegation becomes active.
    pub starts_at: DateTime<Utc>,
    /// When the delegation ends.
    pub ends_at: DateTime<Utc>,
    /// Whether this is a scoped delegation.
    pub is_scoped: bool,
    /// Scope ID if scoped.
    pub scope_id: Option<Uuid>,
}

impl Event for DelegationCreated {
    const TOPIC: &'static str = "xavyo.governance.delegation.created";
    const EVENT_TYPE: &'static str = "xavyo.governance.delegation.created";
}

/// Published when a pending delegation becomes active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationActivated {
    /// The delegation ID.
    pub delegation_id: Uuid,
    /// The delegator.
    pub delegator_id: Uuid,
    /// The deputy.
    pub deputy_id: Uuid,
    /// When the delegation ends.
    pub ends_at: DateTime<Utc>,
}

impl Event for DelegationActivated {
    const TOPIC: &'static str = "xavyo.governance.delegation.activated";
    const EVENT_TYPE: &'static str = "xavyo.governance.delegation.activated";
}

/// Published when a delegation is about to expire (warning).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationExpiring {
    /// The delegation ID.
    pub delegation_id: Uuid,
    /// The delegator.
    pub delegator_id: Uuid,
    /// The deputy.
    pub deputy_id: Uuid,
    /// When the delegation ends.
    pub ends_at: DateTime<Utc>,
    /// Hours until expiration.
    pub hours_remaining: i64,
}

impl Event for DelegationExpiring {
    const TOPIC: &'static str = "xavyo.governance.delegation.expiring";
    const EVENT_TYPE: &'static str = "xavyo.governance.delegation.expiring";
}

/// Published when a delegation expires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationExpired {
    /// The delegation ID.
    pub delegation_id: Uuid,
    /// The delegator.
    pub delegator_id: Uuid,
    /// The deputy.
    pub deputy_id: Uuid,
    /// When the delegation ended.
    pub ended_at: DateTime<Utc>,
}

impl Event for DelegationExpired {
    const TOPIC: &'static str = "xavyo.governance.delegation.expired";
    const EVENT_TYPE: &'static str = "xavyo.governance.delegation.expired";
}

/// Published when a delegation is revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRevoked {
    /// The delegation ID.
    pub delegation_id: Uuid,
    /// The delegator.
    pub delegator_id: Uuid,
    /// The deputy.
    pub deputy_id: Uuid,
    /// User who revoked the delegation (usually the delegator).
    pub revoked_by: Uuid,
    /// When the delegation was revoked.
    pub revoked_at: DateTime<Utc>,
}

impl Event for DelegationRevoked {
    const TOPIC: &'static str = "xavyo.governance.delegation.revoked";
    const EVENT_TYPE: &'static str = "xavyo.governance.delegation.revoked";
}

/// Published when a delegation is extended.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationExtended {
    /// The delegation ID.
    pub delegation_id: Uuid,
    /// The delegator.
    pub delegator_id: Uuid,
    /// The deputy.
    pub deputy_id: Uuid,
    /// Previous end date.
    pub previous_ends_at: DateTime<Utc>,
    /// New end date.
    pub new_ends_at: DateTime<Utc>,
}

impl Event for DelegationExtended {
    const TOPIC: &'static str = "xavyo.governance.delegation.extended";
    const EVENT_TYPE: &'static str = "xavyo.governance.delegation.extended";
}

/// Published when a deputy performs an action on behalf of a delegator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeputyActionPerformed {
    /// The delegation ID that authorized this action.
    pub delegation_id: Uuid,
    /// The deputy who performed the action.
    pub deputy_id: Uuid,
    /// The delegator on whose behalf the action was taken.
    pub delegator_id: Uuid,
    /// Type of action (approve_request, reject_request, certify_access, etc.).
    pub action_type: String,
    /// The work item that was actioned.
    pub work_item_id: Uuid,
    /// Type of work item (access_request, certification, state_transition).
    pub work_item_type: String,
}

impl Event for DeputyActionPerformed {
    const TOPIC: &'static str = "xavyo.governance.delegation.deputy_action";
    const EVENT_TYPE: &'static str = "xavyo.governance.delegation.deputy_action";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegation_created_serialization() {
        let event = DelegationCreated {
            delegation_id: Uuid::new_v4(),
            delegator_id: Uuid::new_v4(),
            deputy_id: Uuid::new_v4(),
            starts_at: Utc::now(),
            ends_at: Utc::now(),
            is_scoped: true,
            scope_id: Some(Uuid::new_v4()),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: DelegationCreated = serde_json::from_str(&json).unwrap();
        assert_eq!(event.delegation_id, restored.delegation_id);
        assert_eq!(event.is_scoped, restored.is_scoped);
    }

    #[test]
    fn test_delegation_activated_serialization() {
        let event = DelegationActivated {
            delegation_id: Uuid::new_v4(),
            delegator_id: Uuid::new_v4(),
            deputy_id: Uuid::new_v4(),
            ends_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: DelegationActivated = serde_json::from_str(&json).unwrap();
        assert_eq!(event.delegation_id, restored.delegation_id);
    }

    #[test]
    fn test_delegation_expiring_serialization() {
        let event = DelegationExpiring {
            delegation_id: Uuid::new_v4(),
            delegator_id: Uuid::new_v4(),
            deputy_id: Uuid::new_v4(),
            ends_at: Utc::now(),
            hours_remaining: 24,
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: DelegationExpiring = serde_json::from_str(&json).unwrap();
        assert_eq!(event.hours_remaining, restored.hours_remaining);
    }

    #[test]
    fn test_delegation_revoked_serialization() {
        let event = DelegationRevoked {
            delegation_id: Uuid::new_v4(),
            delegator_id: Uuid::new_v4(),
            deputy_id: Uuid::new_v4(),
            revoked_by: Uuid::new_v4(),
            revoked_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: DelegationRevoked = serde_json::from_str(&json).unwrap();
        assert_eq!(event.delegation_id, restored.delegation_id);
    }

    #[test]
    fn test_deputy_action_performed_serialization() {
        let event = DeputyActionPerformed {
            delegation_id: Uuid::new_v4(),
            deputy_id: Uuid::new_v4(),
            delegator_id: Uuid::new_v4(),
            action_type: "approve_request".to_string(),
            work_item_id: Uuid::new_v4(),
            work_item_type: "access_request".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: DeputyActionPerformed = serde_json::from_str(&json).unwrap();
        assert_eq!(event.action_type, restored.action_type);
    }

    #[test]
    fn test_delegation_topics() {
        assert_eq!(
            DelegationCreated::TOPIC,
            "xavyo.governance.delegation.created"
        );
        assert_eq!(
            DelegationActivated::TOPIC,
            "xavyo.governance.delegation.activated"
        );
        assert_eq!(
            DelegationExpiring::TOPIC,
            "xavyo.governance.delegation.expiring"
        );
        assert_eq!(
            DelegationExpired::TOPIC,
            "xavyo.governance.delegation.expired"
        );
        assert_eq!(
            DelegationRevoked::TOPIC,
            "xavyo.governance.delegation.revoked"
        );
        assert_eq!(
            DelegationExtended::TOPIC,
            "xavyo.governance.delegation.extended"
        );
        assert_eq!(
            DeputyActionPerformed::TOPIC,
            "xavyo.governance.delegation.deputy_action"
        );
    }

    #[test]
    fn test_all_delegation_topics_follow_convention() {
        assert!(DelegationCreated::TOPIC.starts_with("xavyo."));
        assert!(DelegationActivated::TOPIC.starts_with("xavyo."));
        assert!(DelegationExpiring::TOPIC.starts_with("xavyo."));
        assert!(DelegationExpired::TOPIC.starts_with("xavyo."));
        assert!(DelegationRevoked::TOPIC.starts_with("xavyo."));
        assert!(DelegationExtended::TOPIC.starts_with("xavyo."));
        assert!(DeputyActionPerformed::TOPIC.starts_with("xavyo."));
    }
}
