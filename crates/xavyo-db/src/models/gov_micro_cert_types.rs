//! Micro-certification type definitions (F055).
//!
//! Shared enums for micro-certification trigger rules, certifications, and events.

use serde::{Deserialize, Serialize};

/// Trigger types for micro-certifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "micro_cert_trigger_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MicroCertTriggerType {
    /// Entitlement with `risk_level` = high/critical assigned.
    HighRiskAssignment,
    /// `SoD` rule violation detected.
    SodViolation,
    /// User's manager changed.
    ManagerChange,
    /// Scheduled re-certification.
    PeriodicRecert,
    /// Manually triggered by admin.
    Manual,
}

/// Scope types for trigger rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "micro_cert_scope_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MicroCertScopeType {
    /// Applies to all entitlements in tenant.
    Tenant,
    /// Applies to entitlements in specific application.
    Application,
    /// Applies to specific entitlement only.
    Entitlement,
}

/// Reviewer types for determining who reviews.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "micro_cert_reviewer_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MicroCertReviewerType {
    /// User's direct manager.
    UserManager,
    /// Owner of the entitlement.
    EntitlementOwner,
    /// Owner of the application.
    ApplicationOwner,
    /// Specific user from trigger rule.
    SpecificUser,
}

/// Status for micro-certifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "micro_cert_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MicroCertStatus {
    /// Awaiting reviewer decision.
    Pending,
    /// Reviewer approved, access remains.
    Approved,
    /// Reviewer rejected, access revoked.
    Revoked,
    /// System auto-revoked due to timeout (distinct from manual revoke).
    AutoRevoked,
    /// Flagged for investigation (Reduce decision), access remains but monitored.
    FlaggedForReview,
    /// Deadline passed, no decision made (`auto_revoke=false`).
    Expired,
    /// Assignment deleted before decision.
    Skipped,
}

/// Decision types for micro-certifications.
/// Follows IGA patterns: Accept, Revoke, Reduce, Delegate, No Response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "micro_cert_decision", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MicroCertDecision {
    /// Certify the access (IGA pattern: Accept).
    Approve,
    /// Reject/revoke the access (IGA pattern: Revoke).
    Revoke,
    /// Flag for investigation without immediate revocation (IGA pattern: Reduce).
    /// Access remains but is marked as requiring further review.
    Reduce,
    /// Transfer decision responsibility to another reviewer (IGA pattern: Delegate).
    Delegate,
}

/// Event types for audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "micro_cert_event_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MicroCertEventType {
    /// Certification created.
    Created,
    /// Reminder notification sent.
    ReminderSent,
    /// Escalated to backup reviewer.
    Escalated,
    /// Reviewer approved.
    Approved,
    /// Reviewer rejected (manual revoke).
    Rejected,
    /// Reviewer flagged for investigation (Reduce decision).
    FlaggedForReview,
    /// Decision delegated to another reviewer.
    Delegated,
    /// System revoked due to timeout.
    AutoRevoked,
    /// Deadline passed, no action taken.
    Expired,
    /// Assignment deleted.
    Skipped,
    /// Entitlement assignment was revoked.
    AssignmentRevoked,
}

impl MicroCertTriggerType {
    /// Check if this trigger type is event-driven (vs scheduled).
    #[must_use]
    pub fn is_event_driven(&self) -> bool {
        !matches!(self, Self::PeriodicRecert)
    }

    /// Get the Kafka topic that triggers this certification type.
    #[must_use]
    pub fn trigger_topic(&self) -> Option<&'static str> {
        match self {
            Self::HighRiskAssignment => Some("xavyo.governance.entitlement.assigned"),
            Self::SodViolation => Some("xavyo.governance.sod.violation_detected"),
            Self::ManagerChange => Some("xavyo.user.manager_changed"),
            Self::PeriodicRecert => None, // Scheduled, not event-driven
            Self::Manual => None,         // Manually triggered via API
        }
    }
}

impl MicroCertScopeType {
    /// Check if `scope_id` is required for this scope type.
    #[must_use]
    pub fn requires_scope_id(&self) -> bool {
        matches!(self, Self::Application | Self::Entitlement)
    }
}

impl MicroCertReviewerType {
    /// Check if `specific_reviewer_id` is required for this reviewer type.
    #[must_use]
    pub fn requires_specific_reviewer(&self) -> bool {
        matches!(self, Self::SpecificUser)
    }
}

impl MicroCertStatus {
    /// Check if this status represents a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Pending)
    }

    /// Check if this status means access was revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked | Self::AutoRevoked)
    }

    /// Check if a decision was made (vs timeout/skip).
    #[must_use]
    pub fn has_decision(&self) -> bool {
        matches!(
            self,
            Self::Approved | Self::Revoked | Self::FlaggedForReview
        )
    }

    /// Check if this status requires follow-up action.
    #[must_use]
    pub fn requires_followup(&self) -> bool {
        matches!(self, Self::FlaggedForReview | Self::Expired)
    }
}

impl MicroCertDecision {
    /// Convert decision to resulting status.
    /// Note: Delegate doesn't change status (certification remains Pending with new reviewer).
    #[must_use]
    pub fn to_status(&self) -> Option<MicroCertStatus> {
        match self {
            Self::Approve => Some(MicroCertStatus::Approved),
            Self::Revoke => Some(MicroCertStatus::Revoked),
            Self::Reduce => Some(MicroCertStatus::FlaggedForReview),
            Self::Delegate => None, // Status remains Pending, reviewer changes
        }
    }

    /// Check if this decision terminates the certification.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Approve | Self::Revoke | Self::Reduce)
    }

    /// Check if this decision requires a `delegate_to` user ID.
    #[must_use]
    pub fn requires_delegate_to(&self) -> bool {
        matches!(self, Self::Delegate)
    }

    /// Check if this decision revokes access.
    #[must_use]
    pub fn revokes_access(&self) -> bool {
        matches!(self, Self::Revoke)
    }
}

impl MicroCertEventType {
    /// Check if this event type represents a status change.
    #[must_use]
    pub fn is_status_change(&self) -> bool {
        matches!(
            self,
            Self::Approved
                | Self::Rejected
                | Self::FlaggedForReview
                | Self::AutoRevoked
                | Self::Expired
                | Self::Skipped
        )
    }

    /// Check if this event type requires an actor (not system-generated).
    #[must_use]
    pub fn requires_actor(&self) -> bool {
        matches!(
            self,
            Self::Approved | Self::Rejected | Self::FlaggedForReview | Self::Delegated
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trigger_type_serialization() {
        let high_risk = MicroCertTriggerType::HighRiskAssignment;
        let json = serde_json::to_string(&high_risk).unwrap();
        assert_eq!(json, "\"high_risk_assignment\"");

        let sod = MicroCertTriggerType::SodViolation;
        let json = serde_json::to_string(&sod).unwrap();
        assert_eq!(json, "\"sod_violation\"");

        let manager = MicroCertTriggerType::ManagerChange;
        let json = serde_json::to_string(&manager).unwrap();
        assert_eq!(json, "\"manager_change\"");
    }

    #[test]
    fn test_trigger_type_deserialization() {
        let high_risk: MicroCertTriggerType =
            serde_json::from_str("\"high_risk_assignment\"").unwrap();
        assert_eq!(high_risk, MicroCertTriggerType::HighRiskAssignment);

        let manual: MicroCertTriggerType = serde_json::from_str("\"manual\"").unwrap();
        assert_eq!(manual, MicroCertTriggerType::Manual);
    }

    #[test]
    fn test_scope_type_serialization() {
        let tenant = MicroCertScopeType::Tenant;
        let json = serde_json::to_string(&tenant).unwrap();
        assert_eq!(json, "\"tenant\"");

        let app = MicroCertScopeType::Application;
        let json = serde_json::to_string(&app).unwrap();
        assert_eq!(json, "\"application\"");
    }

    #[test]
    fn test_reviewer_type_serialization() {
        let manager = MicroCertReviewerType::UserManager;
        let json = serde_json::to_string(&manager).unwrap();
        assert_eq!(json, "\"user_manager\"");

        let specific = MicroCertReviewerType::SpecificUser;
        let json = serde_json::to_string(&specific).unwrap();
        assert_eq!(json, "\"specific_user\"");
    }

    #[test]
    fn test_status_serialization() {
        let pending = MicroCertStatus::Pending;
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(json, "\"pending\"");

        let approved = MicroCertStatus::Approved;
        let json = serde_json::to_string(&approved).unwrap();
        assert_eq!(json, "\"approved\"");

        let revoked = MicroCertStatus::Revoked;
        let json = serde_json::to_string(&revoked).unwrap();
        assert_eq!(json, "\"revoked\"");
    }

    #[test]
    fn test_decision_serialization() {
        let approve = MicroCertDecision::Approve;
        let json = serde_json::to_string(&approve).unwrap();
        assert_eq!(json, "\"approve\"");

        let revoke = MicroCertDecision::Revoke;
        let json = serde_json::to_string(&revoke).unwrap();
        assert_eq!(json, "\"revoke\"");

        let reduce = MicroCertDecision::Reduce;
        let json = serde_json::to_string(&reduce).unwrap();
        assert_eq!(json, "\"reduce\"");

        let delegate = MicroCertDecision::Delegate;
        let json = serde_json::to_string(&delegate).unwrap();
        assert_eq!(json, "\"delegate\"");
    }

    #[test]
    fn test_event_type_serialization() {
        let created = MicroCertEventType::Created;
        let json = serde_json::to_string(&created).unwrap();
        assert_eq!(json, "\"created\"");

        let reminder = MicroCertEventType::ReminderSent;
        let json = serde_json::to_string(&reminder).unwrap();
        assert_eq!(json, "\"reminder_sent\"");

        let auto_revoked = MicroCertEventType::AutoRevoked;
        let json = serde_json::to_string(&auto_revoked).unwrap();
        assert_eq!(json, "\"auto_revoked\"");
    }

    #[test]
    fn test_trigger_type_is_event_driven() {
        assert!(MicroCertTriggerType::HighRiskAssignment.is_event_driven());
        assert!(MicroCertTriggerType::SodViolation.is_event_driven());
        assert!(MicroCertTriggerType::ManagerChange.is_event_driven());
        assert!(!MicroCertTriggerType::PeriodicRecert.is_event_driven());
        assert!(MicroCertTriggerType::Manual.is_event_driven());
    }

    #[test]
    fn test_trigger_type_topic() {
        assert!(MicroCertTriggerType::HighRiskAssignment
            .trigger_topic()
            .is_some());
        assert!(MicroCertTriggerType::SodViolation.trigger_topic().is_some());
        assert!(MicroCertTriggerType::ManagerChange
            .trigger_topic()
            .is_some());
        assert!(MicroCertTriggerType::PeriodicRecert
            .trigger_topic()
            .is_none());
        assert!(MicroCertTriggerType::Manual.trigger_topic().is_none());
    }

    #[test]
    fn test_scope_type_requires_scope_id() {
        assert!(!MicroCertScopeType::Tenant.requires_scope_id());
        assert!(MicroCertScopeType::Application.requires_scope_id());
        assert!(MicroCertScopeType::Entitlement.requires_scope_id());
    }

    #[test]
    fn test_reviewer_type_requires_specific_reviewer() {
        assert!(!MicroCertReviewerType::UserManager.requires_specific_reviewer());
        assert!(!MicroCertReviewerType::EntitlementOwner.requires_specific_reviewer());
        assert!(!MicroCertReviewerType::ApplicationOwner.requires_specific_reviewer());
        assert!(MicroCertReviewerType::SpecificUser.requires_specific_reviewer());
    }

    #[test]
    fn test_status_is_terminal() {
        assert!(!MicroCertStatus::Pending.is_terminal());
        assert!(MicroCertStatus::Approved.is_terminal());
        assert!(MicroCertStatus::Revoked.is_terminal());
        assert!(MicroCertStatus::Expired.is_terminal());
        assert!(MicroCertStatus::Skipped.is_terminal());
    }

    #[test]
    fn test_status_is_revoked() {
        assert!(!MicroCertStatus::Pending.is_revoked());
        assert!(!MicroCertStatus::Approved.is_revoked());
        assert!(MicroCertStatus::Revoked.is_revoked());
        assert!(MicroCertStatus::AutoRevoked.is_revoked());
        assert!(!MicroCertStatus::FlaggedForReview.is_revoked());
        assert!(!MicroCertStatus::Expired.is_revoked());
        assert!(!MicroCertStatus::Skipped.is_revoked());
    }

    #[test]
    fn test_status_has_decision() {
        assert!(!MicroCertStatus::Pending.has_decision());
        assert!(MicroCertStatus::Approved.has_decision());
        assert!(MicroCertStatus::Revoked.has_decision());
        assert!(MicroCertStatus::FlaggedForReview.has_decision());
        assert!(!MicroCertStatus::AutoRevoked.has_decision());
        assert!(!MicroCertStatus::Expired.has_decision());
        assert!(!MicroCertStatus::Skipped.has_decision());
    }

    #[test]
    fn test_status_requires_followup() {
        assert!(!MicroCertStatus::Pending.requires_followup());
        assert!(!MicroCertStatus::Approved.requires_followup());
        assert!(!MicroCertStatus::Revoked.requires_followup());
        assert!(MicroCertStatus::FlaggedForReview.requires_followup());
        assert!(MicroCertStatus::Expired.requires_followup());
        assert!(!MicroCertStatus::Skipped.requires_followup());
    }

    #[test]
    fn test_decision_to_status() {
        assert_eq!(
            MicroCertDecision::Approve.to_status(),
            Some(MicroCertStatus::Approved)
        );
        assert_eq!(
            MicroCertDecision::Revoke.to_status(),
            Some(MicroCertStatus::Revoked)
        );
        assert_eq!(
            MicroCertDecision::Reduce.to_status(),
            Some(MicroCertStatus::FlaggedForReview)
        );
        assert_eq!(MicroCertDecision::Delegate.to_status(), None);
    }

    #[test]
    fn test_decision_is_terminal() {
        assert!(MicroCertDecision::Approve.is_terminal());
        assert!(MicroCertDecision::Revoke.is_terminal());
        assert!(MicroCertDecision::Reduce.is_terminal());
        assert!(!MicroCertDecision::Delegate.is_terminal());
    }

    #[test]
    fn test_decision_requires_delegate_to() {
        assert!(!MicroCertDecision::Approve.requires_delegate_to());
        assert!(!MicroCertDecision::Revoke.requires_delegate_to());
        assert!(!MicroCertDecision::Reduce.requires_delegate_to());
        assert!(MicroCertDecision::Delegate.requires_delegate_to());
    }

    #[test]
    fn test_event_type_is_status_change() {
        assert!(!MicroCertEventType::Created.is_status_change());
        assert!(!MicroCertEventType::ReminderSent.is_status_change());
        assert!(!MicroCertEventType::Escalated.is_status_change());
        assert!(MicroCertEventType::Approved.is_status_change());
        assert!(MicroCertEventType::Rejected.is_status_change());
        assert!(MicroCertEventType::FlaggedForReview.is_status_change());
        assert!(!MicroCertEventType::Delegated.is_status_change());
        assert!(MicroCertEventType::AutoRevoked.is_status_change());
        assert!(MicroCertEventType::Expired.is_status_change());
        assert!(MicroCertEventType::Skipped.is_status_change());
        assert!(!MicroCertEventType::AssignmentRevoked.is_status_change());
    }

    #[test]
    fn test_event_type_requires_actor() {
        assert!(!MicroCertEventType::Created.requires_actor());
        assert!(!MicroCertEventType::ReminderSent.requires_actor());
        assert!(!MicroCertEventType::Escalated.requires_actor());
        assert!(MicroCertEventType::Approved.requires_actor());
        assert!(MicroCertEventType::Rejected.requires_actor());
        assert!(MicroCertEventType::FlaggedForReview.requires_actor());
        assert!(MicroCertEventType::Delegated.requires_actor());
        assert!(!MicroCertEventType::AutoRevoked.requires_actor());
        assert!(!MicroCertEventType::Expired.requires_actor());
        assert!(!MicroCertEventType::Skipped.requires_actor());
    }
}
