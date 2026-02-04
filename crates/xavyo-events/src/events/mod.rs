//! Built-in event types for xavyo.
//!
//! This module provides the standard event types for IDP operations:
//! - User lifecycle events (created, updated, deleted)
//! - Authentication events (login, logout)
//! - Tenant events (created)
//! - Sync events (change detection, processing, conflicts)
//! - Reconciliation events (runs, discrepancies, remediation)
//! - Lifecycle state events (transitions, bulk operations, rollbacks)
//! - Delegation events (created, activated, expiring, expired, revoked) - F053
//! - Escalation events (warning, occurred, cancelled, reset, exhausted) - F054
//! - Micro-certification events (created, reminder, decided, auto-revoked) - F055
//! - Governance events (assignments, `SoD` violations) - F055 triggers
//! - NHI events (lifecycle, credentials, risk, suspension, requests) - F061
//! - License events (assigned, reclaimed, expired, expiring, bulk, capacity) - F065
//! - User attribute events (definition created/updated/deactivated, custom attributes updated) - F081
//! - Credential events (requested, issued, denied, revoked, expired, `rate_limited`) - F120

pub mod auth;
pub mod credentials;
pub mod delegation;
pub mod escalation;
pub mod governance;
pub mod group;
pub mod license;
pub mod lifecycle;
pub mod micro_certification;
pub mod nhi;
pub mod reconciliation;
pub mod sync;
pub mod tenant;
pub mod user;
pub mod user_attributes;

// Re-export all events for convenience
pub use auth::{AuthLogin, AuthLogout, AuthMethod, LogoutReason};
pub use credentials::{
    CredentialDenialReason, CredentialDenied, CredentialExpired, CredentialIssued,
    CredentialRateLimited, CredentialRequested, CredentialRevoked,
};
pub use delegation::{
    DelegationActivated, DelegationCreated, DelegationExpired, DelegationExpiring,
    DelegationExtended, DelegationRevoked, DeputyActionPerformed,
};
pub use escalation::{
    EscalationCancelled, EscalationExhausted, EscalationOccurred, EscalationReason,
    EscalationReset, EscalationTargetType as EscalationTargetTypeEvent, EscalationWarning,
    FinalFallbackAction as FinalFallbackActionEvent,
};
pub use governance::{
    EntitlementAssignmentCreated, EntitlementAssignmentRevoked, MetaRoleCascadeCompleted,
    MetaRoleUpdated, SodResolutionType, SodViolationDetected, SodViolationResolved,
};
pub use group::{GroupCreated, GroupDeleted, GroupMemberAdded, GroupMemberRemoved};
pub use license::{
    LicenseAssigned, LicenseBulkOperation, LicenseCapacityWarning, LicensePoolExpired,
    LicensePoolExpiringWarning, LicenseReclaimed,
};
pub use lifecycle::{
    BulkOperationCompleted, BulkOperationFailed, BulkOperationProgress, BulkOperationStarted,
    GracePeriodExpired, ScheduledTransitionCancelled, ScheduledTransitionDue,
    StateAccessRulesApplied, StateAccessRulesReversed, StateTransitionApproved,
    StateTransitionExecuted, StateTransitionRejected, StateTransitionRequested,
    StateTransitionRolledBack,
};
pub use micro_certification::{
    MicroCertAssignmentRevoked, MicroCertDecision as MicroCertDecisionEvent,
    MicroCertReviewerType as MicroCertReviewerTypeEvent,
    MicroCertTriggerType as MicroCertTriggerTypeEvent, MicroCertificationAutoRevoked,
    MicroCertificationCreated, MicroCertificationDecided, MicroCertificationEscalated,
    MicroCertificationExpired, MicroCertificationReminder, MicroCertificationSkipped,
};
pub use nhi::{
    NhiCertificationCampaignLaunched, NhiCertificationDecisionMade, NhiCertificationRequired,
    NhiCertified, NhiCreated, NhiCredentialRevoked, NhiCredentialsExpiring, NhiCredentialsRotated,
    NhiDeleted, NhiExpirationWarning, NhiInactivityWarning, NhiOwnershipTransferred,
    NhiReactivated, NhiRequestApproved, NhiRequestRejected, NhiRequestSubmitted,
    NhiRiskScoreChanged, NhiSuspended, NhiSuspensionReason as NhiSuspensionReasonEvent, NhiUpdated,
    NhiUsageRecorded, RotationType,
};
pub use reconciliation::{
    DiscrepancyDetected, DiscrepancyIgnored, ReconciliationCancelled, ReconciliationCompleted,
    ReconciliationFailed, ReconciliationStarted, RemediationExecuted,
    ScheduledReconciliationTriggered,
};
pub use sync::{
    InboundChangeDetected, InboundChangeFailed, InboundChangeProcessed, SyncConflictDetected,
    SyncConflictResolved, SyncCycleCompleted,
};
pub use tenant::{SubscriptionPlan, TenantCreated};
pub use user::{UserCreated, UserDeleted, UserUpdated};
pub use user_attributes::{
    AttributeDefinitionCreated, AttributeDefinitionDeactivated, AttributeDefinitionUpdated,
    BulkAttributeUpdateCompleted, CustomAttributesUpdated,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;

    #[test]
    fn test_all_events_have_topics() {
        // Verify all events implement Event trait with valid topics
        assert!(!UserCreated::TOPIC.is_empty());
        assert!(!UserUpdated::TOPIC.is_empty());
        assert!(!UserDeleted::TOPIC.is_empty());
        assert!(!AuthLogin::TOPIC.is_empty());
        assert!(!AuthLogout::TOPIC.is_empty());
        assert!(!TenantCreated::TOPIC.is_empty());
        // Delegation events (F053)
        assert!(!DelegationCreated::TOPIC.is_empty());
        assert!(!DelegationActivated::TOPIC.is_empty());
        assert!(!DelegationExpiring::TOPIC.is_empty());
        assert!(!DelegationExpired::TOPIC.is_empty());
        assert!(!DelegationRevoked::TOPIC.is_empty());
        assert!(!DelegationExtended::TOPIC.is_empty());
        assert!(!DeputyActionPerformed::TOPIC.is_empty());
        // Escalation events (F054)
        assert!(!EscalationWarning::TOPIC.is_empty());
        assert!(!EscalationOccurred::TOPIC.is_empty());
        assert!(!EscalationCancelled::TOPIC.is_empty());
        assert!(!EscalationReset::TOPIC.is_empty());
        assert!(!EscalationExhausted::TOPIC.is_empty());
        // Micro-certification events (F055)
        assert!(!MicroCertificationCreated::TOPIC.is_empty());
        assert!(!MicroCertificationReminder::TOPIC.is_empty());
        assert!(!MicroCertificationEscalated::TOPIC.is_empty());
        assert!(!MicroCertificationDecided::TOPIC.is_empty());
        assert!(!MicroCertificationAutoRevoked::TOPIC.is_empty());
        assert!(!MicroCertificationExpired::TOPIC.is_empty());
        assert!(!MicroCertificationSkipped::TOPIC.is_empty());
        assert!(!MicroCertAssignmentRevoked::TOPIC.is_empty());
        // Governance events (F055 triggers)
        assert!(!EntitlementAssignmentCreated::TOPIC.is_empty());
        assert!(!EntitlementAssignmentRevoked::TOPIC.is_empty());
        assert!(!SodViolationDetected::TOPIC.is_empty());
        assert!(!SodViolationResolved::TOPIC.is_empty());
        // Meta-role events (F056)
        assert!(!MetaRoleUpdated::TOPIC.is_empty());
        assert!(!MetaRoleCascadeCompleted::TOPIC.is_empty());
        // NHI events (F061)
        assert!(!NhiCreated::TOPIC.is_empty());
        assert!(!NhiUpdated::TOPIC.is_empty());
        assert!(!NhiDeleted::TOPIC.is_empty());
        assert!(!NhiCredentialsRotated::TOPIC.is_empty());
        assert!(!NhiCredentialRevoked::TOPIC.is_empty());
        assert!(!NhiCredentialsExpiring::TOPIC.is_empty());
        assert!(!NhiRiskScoreChanged::TOPIC.is_empty());
        assert!(!NhiSuspended::TOPIC.is_empty());
        assert!(!NhiReactivated::TOPIC.is_empty());
        assert!(!NhiRequestSubmitted::TOPIC.is_empty());
        assert!(!NhiRequestApproved::TOPIC.is_empty());
        assert!(!NhiRequestRejected::TOPIC.is_empty());
        assert!(!NhiOwnershipTransferred::TOPIC.is_empty());
        assert!(!NhiCertificationRequired::TOPIC.is_empty());
        assert!(!NhiCertified::TOPIC.is_empty());
        assert!(!NhiInactivityWarning::TOPIC.is_empty());
        assert!(!NhiExpirationWarning::TOPIC.is_empty());
        assert!(!NhiUsageRecorded::TOPIC.is_empty());
        // License events (F065)
        assert!(!LicenseAssigned::TOPIC.is_empty());
        assert!(!LicenseReclaimed::TOPIC.is_empty());
        assert!(!LicensePoolExpired::TOPIC.is_empty());
        assert!(!LicensePoolExpiringWarning::TOPIC.is_empty());
        assert!(!LicenseBulkOperation::TOPIC.is_empty());
        assert!(!LicenseCapacityWarning::TOPIC.is_empty());
        // User attribute events (F081)
        assert!(!AttributeDefinitionCreated::TOPIC.is_empty());
        assert!(!AttributeDefinitionUpdated::TOPIC.is_empty());
        assert!(!AttributeDefinitionDeactivated::TOPIC.is_empty());
        assert!(!CustomAttributesUpdated::TOPIC.is_empty());
        assert!(!BulkAttributeUpdateCompleted::TOPIC.is_empty());
        // Group events (F087)
        assert!(!GroupCreated::TOPIC.is_empty());
        assert!(!GroupDeleted::TOPIC.is_empty());
        assert!(!GroupMemberAdded::TOPIC.is_empty());
        assert!(!GroupMemberRemoved::TOPIC.is_empty());
        // Sync events
        assert!(!InboundChangeDetected::TOPIC.is_empty());
        assert!(!InboundChangeProcessed::TOPIC.is_empty());
        assert!(!InboundChangeFailed::TOPIC.is_empty());
        assert!(!SyncConflictDetected::TOPIC.is_empty());
        assert!(!SyncConflictResolved::TOPIC.is_empty());
        assert!(!SyncCycleCompleted::TOPIC.is_empty());
        // Reconciliation events
        assert!(!ReconciliationStarted::TOPIC.is_empty());
        assert!(!ReconciliationCompleted::TOPIC.is_empty());
        assert!(!ReconciliationFailed::TOPIC.is_empty());
        assert!(!ReconciliationCancelled::TOPIC.is_empty());
        assert!(!DiscrepancyDetected::TOPIC.is_empty());
        assert!(!RemediationExecuted::TOPIC.is_empty());
        assert!(!DiscrepancyIgnored::TOPIC.is_empty());
        assert!(!ScheduledReconciliationTriggered::TOPIC.is_empty());
        // Lifecycle events
        assert!(!StateTransitionRequested::TOPIC.is_empty());
        assert!(!StateTransitionApproved::TOPIC.is_empty());
        assert!(!StateTransitionExecuted::TOPIC.is_empty());
        assert!(!StateTransitionRejected::TOPIC.is_empty());
        assert!(!StateTransitionRolledBack::TOPIC.is_empty());
        assert!(!BulkOperationStarted::TOPIC.is_empty());
        assert!(!BulkOperationProgress::TOPIC.is_empty());
        assert!(!BulkOperationCompleted::TOPIC.is_empty());
        assert!(!BulkOperationFailed::TOPIC.is_empty());
        assert!(!ScheduledTransitionDue::TOPIC.is_empty());
        assert!(!ScheduledTransitionCancelled::TOPIC.is_empty());
        assert!(!StateAccessRulesApplied::TOPIC.is_empty());
        assert!(!StateAccessRulesReversed::TOPIC.is_empty());
        assert!(!GracePeriodExpired::TOPIC.is_empty());
    }

    #[test]
    fn test_all_topics_follow_convention() {
        // All topics should start with "xavyo."
        assert!(UserCreated::TOPIC.starts_with("xavyo."));
        assert!(UserUpdated::TOPIC.starts_with("xavyo."));
        assert!(UserDeleted::TOPIC.starts_with("xavyo."));
        assert!(AuthLogin::TOPIC.starts_with("xavyo."));
        assert!(AuthLogout::TOPIC.starts_with("xavyo."));
        assert!(TenantCreated::TOPIC.starts_with("xavyo."));
        // Sync events
        assert!(InboundChangeDetected::TOPIC.starts_with("xavyo."));
        assert!(InboundChangeProcessed::TOPIC.starts_with("xavyo."));
        assert!(InboundChangeFailed::TOPIC.starts_with("xavyo."));
        assert!(SyncConflictDetected::TOPIC.starts_with("xavyo."));
        assert!(SyncConflictResolved::TOPIC.starts_with("xavyo."));
        assert!(SyncCycleCompleted::TOPIC.starts_with("xavyo."));
        // Reconciliation events
        assert!(ReconciliationStarted::TOPIC.starts_with("xavyo."));
        assert!(ReconciliationCompleted::TOPIC.starts_with("xavyo."));
        assert!(ReconciliationFailed::TOPIC.starts_with("xavyo."));
        assert!(ReconciliationCancelled::TOPIC.starts_with("xavyo."));
        assert!(DiscrepancyDetected::TOPIC.starts_with("xavyo."));
        assert!(RemediationExecuted::TOPIC.starts_with("xavyo."));
        assert!(DiscrepancyIgnored::TOPIC.starts_with("xavyo."));
        assert!(ScheduledReconciliationTriggered::TOPIC.starts_with("xavyo."));
        // Lifecycle events
        assert!(StateTransitionRequested::TOPIC.starts_with("xavyo."));
        assert!(StateTransitionApproved::TOPIC.starts_with("xavyo."));
        assert!(StateTransitionExecuted::TOPIC.starts_with("xavyo."));
        assert!(StateTransitionRejected::TOPIC.starts_with("xavyo."));
        assert!(StateTransitionRolledBack::TOPIC.starts_with("xavyo."));
        assert!(BulkOperationStarted::TOPIC.starts_with("xavyo."));
        assert!(BulkOperationProgress::TOPIC.starts_with("xavyo."));
        assert!(BulkOperationCompleted::TOPIC.starts_with("xavyo."));
        assert!(BulkOperationFailed::TOPIC.starts_with("xavyo."));
        assert!(ScheduledTransitionDue::TOPIC.starts_with("xavyo."));
        assert!(ScheduledTransitionCancelled::TOPIC.starts_with("xavyo."));
        assert!(StateAccessRulesApplied::TOPIC.starts_with("xavyo."));
        assert!(StateAccessRulesReversed::TOPIC.starts_with("xavyo."));
        assert!(GracePeriodExpired::TOPIC.starts_with("xavyo."));
        // Delegation events (F053)
        assert!(DelegationCreated::TOPIC.starts_with("xavyo."));
        assert!(DelegationActivated::TOPIC.starts_with("xavyo."));
        assert!(DelegationExpiring::TOPIC.starts_with("xavyo."));
        assert!(DelegationExpired::TOPIC.starts_with("xavyo."));
        assert!(DelegationRevoked::TOPIC.starts_with("xavyo."));
        assert!(DelegationExtended::TOPIC.starts_with("xavyo."));
        assert!(DeputyActionPerformed::TOPIC.starts_with("xavyo."));
        // Escalation events (F054)
        assert!(EscalationWarning::TOPIC.starts_with("xavyo."));
        assert!(EscalationOccurred::TOPIC.starts_with("xavyo."));
        assert!(EscalationCancelled::TOPIC.starts_with("xavyo."));
        assert!(EscalationReset::TOPIC.starts_with("xavyo."));
        assert!(EscalationExhausted::TOPIC.starts_with("xavyo."));
        // Micro-certification events (F055)
        assert!(MicroCertificationCreated::TOPIC.starts_with("xavyo."));
        assert!(MicroCertificationReminder::TOPIC.starts_with("xavyo."));
        assert!(MicroCertificationEscalated::TOPIC.starts_with("xavyo."));
        assert!(MicroCertificationDecided::TOPIC.starts_with("xavyo."));
        assert!(MicroCertificationAutoRevoked::TOPIC.starts_with("xavyo."));
        assert!(MicroCertificationExpired::TOPIC.starts_with("xavyo."));
        assert!(MicroCertificationSkipped::TOPIC.starts_with("xavyo."));
        assert!(MicroCertAssignmentRevoked::TOPIC.starts_with("xavyo."));
        // Governance events (F055 triggers)
        assert!(EntitlementAssignmentCreated::TOPIC.starts_with("xavyo."));
        assert!(EntitlementAssignmentRevoked::TOPIC.starts_with("xavyo."));
        assert!(SodViolationDetected::TOPIC.starts_with("xavyo."));
        assert!(SodViolationResolved::TOPIC.starts_with("xavyo."));
        // Meta-role events (F056)
        assert!(MetaRoleUpdated::TOPIC.starts_with("xavyo."));
        assert!(MetaRoleCascadeCompleted::TOPIC.starts_with("xavyo."));
        // NHI events (F061)
        assert!(NhiCreated::TOPIC.starts_with("xavyo."));
        assert!(NhiUpdated::TOPIC.starts_with("xavyo."));
        assert!(NhiDeleted::TOPIC.starts_with("xavyo."));
        assert!(NhiCredentialsRotated::TOPIC.starts_with("xavyo."));
        assert!(NhiCredentialRevoked::TOPIC.starts_with("xavyo."));
        assert!(NhiCredentialsExpiring::TOPIC.starts_with("xavyo."));
        assert!(NhiRiskScoreChanged::TOPIC.starts_with("xavyo."));
        assert!(NhiSuspended::TOPIC.starts_with("xavyo."));
        assert!(NhiReactivated::TOPIC.starts_with("xavyo."));
        assert!(NhiRequestSubmitted::TOPIC.starts_with("xavyo."));
        assert!(NhiRequestApproved::TOPIC.starts_with("xavyo."));
        assert!(NhiRequestRejected::TOPIC.starts_with("xavyo."));
        assert!(NhiOwnershipTransferred::TOPIC.starts_with("xavyo."));
        assert!(NhiCertificationRequired::TOPIC.starts_with("xavyo."));
        assert!(NhiCertified::TOPIC.starts_with("xavyo."));
        assert!(NhiInactivityWarning::TOPIC.starts_with("xavyo."));
        assert!(NhiExpirationWarning::TOPIC.starts_with("xavyo."));
        assert!(NhiUsageRecorded::TOPIC.starts_with("xavyo."));
        // License events (F065)
        assert!(LicenseAssigned::TOPIC.starts_with("xavyo."));
        assert!(LicenseReclaimed::TOPIC.starts_with("xavyo."));
        assert!(LicensePoolExpired::TOPIC.starts_with("xavyo."));
        assert!(LicensePoolExpiringWarning::TOPIC.starts_with("xavyo."));
        assert!(LicenseBulkOperation::TOPIC.starts_with("xavyo."));
        assert!(LicenseCapacityWarning::TOPIC.starts_with("xavyo."));
        // User attribute events (F081)
        assert!(AttributeDefinitionCreated::TOPIC.starts_with("xavyo."));
        assert!(AttributeDefinitionUpdated::TOPIC.starts_with("xavyo."));
        assert!(AttributeDefinitionDeactivated::TOPIC.starts_with("xavyo."));
        assert!(CustomAttributesUpdated::TOPIC.starts_with("xavyo."));
        assert!(BulkAttributeUpdateCompleted::TOPIC.starts_with("xavyo."));
        // Group events (F087)
        assert!(GroupCreated::TOPIC.starts_with("xavyo."));
        assert!(GroupDeleted::TOPIC.starts_with("xavyo."));
        assert!(GroupMemberAdded::TOPIC.starts_with("xavyo."));
        assert!(GroupMemberRemoved::TOPIC.starts_with("xavyo."));
    }
}
