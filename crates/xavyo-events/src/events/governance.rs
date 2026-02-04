//! Governance events for F055 Micro-certification triggers.
//!
//! Events for governance operations that can trigger micro-certifications:
//! - Entitlement assignment events (high-risk assignment trigger)
//! - `SoD` violation events (`SoD` violation trigger)
//!
//! These events are consumed by micro-certification consumers to automatically
//! create certifications when relevant governance actions occur.

use crate::event::Event;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Published when an entitlement assignment is created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementAssignmentCreated {
    /// The assignment ID.
    pub assignment_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The entitlement being assigned.
    pub entitlement_id: Uuid,
    /// The entitlement name.
    pub entitlement_name: String,
    /// The application ID.
    pub application_id: Uuid,
    /// The user receiving the assignment.
    pub user_id: Uuid,
    /// The risk level of the entitlement.
    pub risk_level: String,
    /// Who created the assignment.
    pub assigned_by: Uuid,
    /// When the assignment was created.
    pub created_at: DateTime<Utc>,
}

impl Event for EntitlementAssignmentCreated {
    const TOPIC: &'static str = "xavyo.governance.assignment.created";
    const EVENT_TYPE: &'static str = "xavyo.governance.assignment.created";
}

/// Published when an entitlement assignment is revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementAssignmentRevoked {
    /// The assignment ID.
    pub assignment_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The entitlement that was revoked.
    pub entitlement_id: Uuid,
    /// The user who lost the assignment.
    pub user_id: Uuid,
    /// Reason for revocation.
    pub reason: String,
    /// Who revoked the assignment.
    pub revoked_by: Option<Uuid>,
    /// When the assignment was revoked.
    pub revoked_at: DateTime<Utc>,
}

impl Event for EntitlementAssignmentRevoked {
    const TOPIC: &'static str = "xavyo.governance.assignment.revoked";
    const EVENT_TYPE: &'static str = "xavyo.governance.assignment.revoked";
}

/// Published when an `SoD` violation is detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodViolationDetected {
    /// The violation ID.
    pub violation_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The `SoD` rule that was violated.
    pub rule_id: Uuid,
    /// The `SoD` rule name.
    pub rule_name: String,
    /// The user who has the violation.
    pub user_id: Uuid,
    /// The first conflicting entitlement.
    pub entitlement_a_id: Uuid,
    /// The second conflicting entitlement (the triggering one).
    pub entitlement_b_id: Uuid,
    /// The assignment that triggered the violation.
    pub triggering_assignment_id: Uuid,
    /// The severity of the `SoD` rule.
    pub severity: String,
    /// When the violation was detected.
    pub detected_at: DateTime<Utc>,
}

impl Event for SodViolationDetected {
    const TOPIC: &'static str = "xavyo.governance.sod.violation_detected";
    const EVENT_TYPE: &'static str = "xavyo.governance.sod.violation_detected";
}

/// Published when an `SoD` violation is resolved (exemption granted or assignment revoked).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodViolationResolved {
    /// The violation ID.
    pub violation_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The `SoD` rule that was violated.
    pub rule_id: Uuid,
    /// The user who had the violation.
    pub user_id: Uuid,
    /// How the violation was resolved.
    pub resolution: SodResolutionType,
    /// Who resolved the violation.
    pub resolved_by: Option<Uuid>,
    /// When the violation was resolved.
    pub resolved_at: DateTime<Utc>,
}

impl Event for SodViolationResolved {
    const TOPIC: &'static str = "xavyo.governance.sod.violation_resolved";
    const EVENT_TYPE: &'static str = "xavyo.governance.sod.violation_resolved";
}

/// How an `SoD` violation was resolved.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SodResolutionType {
    /// An exemption was granted.
    ExemptionGranted,
    /// The triggering assignment was revoked.
    AssignmentRevoked,
    /// The violation was auto-resolved (e.g., user left, entitlement removed).
    AutoResolved,
}

// =============================================================================
// Meta-Role Events (F056)
// =============================================================================

/// Published when a meta-role is updated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRoleUpdated {
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The meta-role ID.
    pub meta_role_id: Uuid,
    /// The fields that changed.
    pub changes: Vec<String>,
    /// When the update occurred.
    pub updated_at: DateTime<Utc>,
}

impl Event for MetaRoleUpdated {
    const TOPIC: &'static str = "xavyo.governance.meta_role.updated";
    const EVENT_TYPE: &'static str = "xavyo.governance.meta_role.updated";
}

/// Published when a meta-role cascade operation is completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRoleCascadeCompleted {
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The meta-role ID.
    pub meta_role_id: Uuid,
    /// Total affected roles/users.
    pub total_affected: usize,
    /// Number of successful operations.
    pub succeeded: usize,
    /// Number of failed operations.
    pub failed: usize,
    /// When the cascade completed.
    pub completed_at: DateTime<Utc>,
}

impl Event for MetaRoleCascadeCompleted {
    const TOPIC: &'static str = "xavyo.governance.meta_role.cascade_completed";
    const EVENT_TYPE: &'static str = "xavyo.governance.meta_role.cascade_completed";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entitlement_assignment_created_serialization() {
        let event = EntitlementAssignmentCreated {
            assignment_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            entitlement_name: "Admin Access".to_string(),
            application_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            risk_level: "high".to_string(),
            assigned_by: Uuid::new_v4(),
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: EntitlementAssignmentCreated = serde_json::from_str(&json).unwrap();
        assert_eq!(event.assignment_id, restored.assignment_id);
        assert_eq!(event.risk_level, restored.risk_level);
    }

    #[test]
    fn test_sod_violation_detected_serialization() {
        let event = SodViolationDetected {
            violation_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            rule_id: Uuid::new_v4(),
            rule_name: "SoD-001".to_string(),
            user_id: Uuid::new_v4(),
            entitlement_a_id: Uuid::new_v4(),
            entitlement_b_id: Uuid::new_v4(),
            triggering_assignment_id: Uuid::new_v4(),
            severity: "critical".to_string(),
            detected_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: SodViolationDetected = serde_json::from_str(&json).unwrap();
        assert_eq!(event.violation_id, restored.violation_id);
    }

    #[test]
    fn test_sod_violation_resolved_serialization() {
        let event = SodViolationResolved {
            violation_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            rule_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            resolution: SodResolutionType::ExemptionGranted,
            resolved_by: Some(Uuid::new_v4()),
            resolved_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: SodViolationResolved = serde_json::from_str(&json).unwrap();
        assert_eq!(event.violation_id, restored.violation_id);
    }

    #[test]
    fn test_governance_event_topics() {
        assert_eq!(
            EntitlementAssignmentCreated::TOPIC,
            "xavyo.governance.assignment.created"
        );
        assert_eq!(
            EntitlementAssignmentRevoked::TOPIC,
            "xavyo.governance.assignment.revoked"
        );
        assert_eq!(
            SodViolationDetected::TOPIC,
            "xavyo.governance.sod.violation_detected"
        );
        assert_eq!(
            SodViolationResolved::TOPIC,
            "xavyo.governance.sod.violation_resolved"
        );
    }

    #[test]
    fn test_resolution_type_serialization() {
        let exemption = SodResolutionType::ExemptionGranted;
        let json = serde_json::to_string(&exemption).unwrap();
        assert_eq!(json, "\"exemption_granted\"");

        let revoked = SodResolutionType::AssignmentRevoked;
        let json = serde_json::to_string(&revoked).unwrap();
        assert_eq!(json, "\"assignment_revoked\"");
    }
}
