//! NHI Delegation events for RFC 8693 Token Exchange delegation.
//!
//! Events for NHI delegation grant lifecycle:
//! - Grant created, revoked, exercised, expired

use crate::event::Event;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Published when a new NHI delegation grant is created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiDelegationGrantCreated {
    /// The delegation grant ID.
    pub grant_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The principal (user or NHI) granting delegation.
    pub principal_id: Uuid,
    /// Type of principal (`user`, `service_account`, etc.).
    pub principal_type: String,
    /// The NHI that will act on behalf of the principal.
    pub actor_nhi_id: Uuid,
    /// Scopes the NHI is allowed to use under this delegation.
    pub allowed_scopes: Vec<String>,
    /// Resource types the NHI is allowed to access.
    pub allowed_resource_types: Vec<String>,
    /// Maximum depth of delegation chaining.
    pub max_delegation_depth: i32,
    /// When the grant expires (if any).
    pub expires_at: Option<DateTime<Utc>>,
    /// Who created/approved the grant (if different from principal).
    pub granted_by: Option<Uuid>,
    /// When the grant was created.
    pub created_at: DateTime<Utc>,
}

impl Event for NhiDelegationGrantCreated {
    const TOPIC: &'static str = "xavyo.governance.nhi_delegation.grant_created";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi_delegation.grant_created";
}

/// Published when an NHI delegation grant is revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiDelegationGrantRevoked {
    /// The delegation grant ID.
    pub grant_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The principal whose delegation is revoked.
    pub principal_id: Uuid,
    /// The NHI that was acting on behalf of the principal.
    pub actor_nhi_id: Uuid,
    /// Who revoked the grant.
    pub revoked_by: Option<Uuid>,
    /// When the grant was revoked.
    pub revoked_at: DateTime<Utc>,
}

impl Event for NhiDelegationGrantRevoked {
    const TOPIC: &'static str = "xavyo.governance.nhi_delegation.grant_revoked";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi_delegation.grant_revoked";
}

/// Published when a delegation grant is exercised (token exchange performed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiDelegationExercised {
    /// The delegation grant ID.
    pub grant_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The principal on whose behalf the action is taken.
    pub principal_id: Uuid,
    /// The NHI exercising the delegation.
    pub actor_nhi_id: Uuid,
    /// The scope used in this token exchange.
    pub scope_used: String,
    /// Current depth in the delegation chain.
    pub delegation_depth: i32,
    /// When the delegation was exercised.
    pub exercised_at: DateTime<Utc>,
}

impl Event for NhiDelegationExercised {
    const TOPIC: &'static str = "xavyo.governance.nhi_delegation.exercised";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi_delegation.exercised";
}

/// Published when a delegation grant expires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiDelegationExpired {
    /// The delegation grant ID.
    pub grant_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The principal whose delegation expired.
    pub principal_id: Uuid,
    /// The NHI whose delegation expired.
    pub actor_nhi_id: Uuid,
    /// When the delegation expired.
    pub expired_at: DateTime<Utc>,
}

impl Event for NhiDelegationExpired {
    const TOPIC: &'static str = "xavyo.governance.nhi_delegation.expired";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi_delegation.expired";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nhi_delegation_grant_created_serialization() {
        let event = NhiDelegationGrantCreated {
            grant_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
            principal_type: "user".to_string(),
            actor_nhi_id: Uuid::new_v4(),
            allowed_scopes: vec!["read".to_string(), "write".to_string()],
            allowed_resource_types: vec!["api".to_string()],
            max_delegation_depth: 2,
            expires_at: Some(Utc::now()),
            granted_by: Some(Uuid::new_v4()),
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: NhiDelegationGrantCreated = serde_json::from_str(&json).unwrap();
        assert_eq!(event.grant_id, restored.grant_id);
        assert_eq!(event.principal_type, restored.principal_type);
        assert_eq!(event.allowed_scopes, restored.allowed_scopes);
        assert_eq!(event.max_delegation_depth, restored.max_delegation_depth);
    }

    #[test]
    fn test_nhi_delegation_grant_revoked_serialization() {
        let event = NhiDelegationGrantRevoked {
            grant_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
            actor_nhi_id: Uuid::new_v4(),
            revoked_by: Some(Uuid::new_v4()),
            revoked_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: NhiDelegationGrantRevoked = serde_json::from_str(&json).unwrap();
        assert_eq!(event.grant_id, restored.grant_id);
    }

    #[test]
    fn test_nhi_delegation_exercised_serialization() {
        let event = NhiDelegationExercised {
            grant_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
            actor_nhi_id: Uuid::new_v4(),
            scope_used: "read".to_string(),
            delegation_depth: 1,
            exercised_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: NhiDelegationExercised = serde_json::from_str(&json).unwrap();
        assert_eq!(event.grant_id, restored.grant_id);
        assert_eq!(event.scope_used, restored.scope_used);
        assert_eq!(event.delegation_depth, restored.delegation_depth);
    }

    #[test]
    fn test_nhi_delegation_expired_serialization() {
        let event = NhiDelegationExpired {
            grant_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
            actor_nhi_id: Uuid::new_v4(),
            expired_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: NhiDelegationExpired = serde_json::from_str(&json).unwrap();
        assert_eq!(event.grant_id, restored.grant_id);
    }

    #[test]
    fn test_nhi_delegation_event_topics() {
        assert_eq!(
            NhiDelegationGrantCreated::TOPIC,
            "xavyo.governance.nhi_delegation.grant_created"
        );
        assert_eq!(
            NhiDelegationGrantCreated::EVENT_TYPE,
            "xavyo.governance.nhi_delegation.grant_created"
        );
        assert_eq!(
            NhiDelegationGrantRevoked::TOPIC,
            "xavyo.governance.nhi_delegation.grant_revoked"
        );
        assert_eq!(
            NhiDelegationGrantRevoked::EVENT_TYPE,
            "xavyo.governance.nhi_delegation.grant_revoked"
        );
        assert_eq!(
            NhiDelegationExercised::TOPIC,
            "xavyo.governance.nhi_delegation.exercised"
        );
        assert_eq!(
            NhiDelegationExercised::EVENT_TYPE,
            "xavyo.governance.nhi_delegation.exercised"
        );
        assert_eq!(
            NhiDelegationExpired::TOPIC,
            "xavyo.governance.nhi_delegation.expired"
        );
        assert_eq!(
            NhiDelegationExpired::EVENT_TYPE,
            "xavyo.governance.nhi_delegation.expired"
        );
    }

    #[test]
    fn test_all_nhi_delegation_topics_follow_convention() {
        assert!(NhiDelegationGrantCreated::TOPIC.starts_with("xavyo."));
        assert!(NhiDelegationGrantRevoked::TOPIC.starts_with("xavyo."));
        assert!(NhiDelegationExercised::TOPIC.starts_with("xavyo."));
        assert!(NhiDelegationExpired::TOPIC.starts_with("xavyo."));
    }
}
