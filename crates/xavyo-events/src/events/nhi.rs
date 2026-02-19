//! NHI (Non-Human Identity) lifecycle events for F061.
//!
//! Events for NHI governance operations:
//! - NHI lifecycle (created, updated, deleted)
//! - Usage and risk events
//! - Request workflow events
//! - Suspension and reactivation events

use crate::event::Event;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// NHI Lifecycle Events
// =============================================================================

/// Published when an NHI is created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiCreated {
    /// The NHI ID (service account ID).
    pub nhi_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The NHI name.
    pub name: String,
    /// The NHI purpose/description.
    pub purpose: Option<String>,
    /// The primary owner.
    pub owner_id: Uuid,
    /// The backup owner (if any).
    pub backup_owner_id: Option<Uuid>,
    /// Expiration date (if any).
    pub expires_at: Option<DateTime<Utc>>,
    /// Who created the NHI.
    pub created_by: Uuid,
    /// When the NHI was created.
    pub created_at: DateTime<Utc>,
}

impl Event for NhiCreated {
    const TOPIC: &'static str = "xavyo.governance.nhi.created";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.created";
}

/// Published when an NHI is updated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiUpdated {
    /// The NHI ID.
    pub nhi_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The NHI name.
    pub name: String,
    /// Fields that were changed.
    pub changed_fields: Vec<String>,
    /// Who updated the NHI.
    pub updated_by: Uuid,
    /// When the NHI was updated.
    pub updated_at: DateTime<Utc>,
}

impl Event for NhiUpdated {
    const TOPIC: &'static str = "xavyo.governance.nhi.updated";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.updated";
}

/// Published when an NHI is deleted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiDeleted {
    /// The NHI ID.
    pub nhi_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The NHI name (for audit).
    pub name: String,
    /// Who deleted the NHI.
    pub deleted_by: Uuid,
    /// Reason for deletion.
    pub reason: Option<String>,
    /// When the NHI was deleted.
    pub deleted_at: DateTime<Utc>,
}

impl Event for NhiDeleted {
    const TOPIC: &'static str = "xavyo.governance.nhi.deleted";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.deleted";
}

// =============================================================================
// Risk Events
// =============================================================================

/// Published when an NHI's risk score changes significantly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiRiskScoreChanged {
    /// The NHI ID.
    pub nhi_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The NHI name.
    pub name: String,
    /// Previous risk score.
    pub previous_score: i32,
    /// New risk score.
    pub new_score: i32,
    /// Previous risk level.
    pub previous_level: String,
    /// New risk level.
    pub new_level: String,
    /// Primary contributing factors.
    pub contributing_factors: Vec<String>,
    /// When the score changed.
    pub changed_at: DateTime<Utc>,
}

impl Event for NhiRiskScoreChanged {
    const TOPIC: &'static str = "xavyo.governance.nhi.risk_score_changed";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.risk_score_changed";
}

// =============================================================================
// Suspension Events
// =============================================================================

/// Published when an NHI is suspended.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiSuspended {
    /// The NHI ID.
    pub nhi_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The NHI name.
    pub name: String,
    /// Reason for suspension.
    pub reason: NhiSuspensionReason,
    /// Additional details.
    pub details: Option<String>,
    /// Who suspended the NHI (None for automatic).
    pub suspended_by: Option<Uuid>,
    /// When the NHI was suspended.
    pub suspended_at: DateTime<Utc>,
}

impl Event for NhiSuspended {
    const TOPIC: &'static str = "xavyo.governance.nhi.suspended";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.suspended";
}

/// Reason for NHI suspension.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NhiSuspensionReason {
    /// NHI expired (past expiration date).
    Expired,
    /// NHI was inactive beyond threshold.
    Inactive,
    /// Certification was revoked.
    CertificationRevoked,
    /// Emergency suspension (security incident).
    Emergency,
    /// Manual suspension by administrator.
    Manual,
}

/// Published when an NHI is reactivated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiReactivated {
    /// The NHI ID.
    pub nhi_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The NHI name.
    pub name: String,
    /// Reason/justification for reactivation.
    pub reason: Option<String>,
    /// Who reactivated the NHI.
    pub reactivated_by: Uuid,
    /// When the NHI was reactivated.
    pub reactivated_at: DateTime<Utc>,
}

impl Event for NhiReactivated {
    const TOPIC: &'static str = "xavyo.governance.nhi.reactivated";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.reactivated";
}

// =============================================================================
// Request Workflow Events
// =============================================================================

/// Published when an NHI request is submitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiRequestSubmitted {
    /// The request ID.
    pub request_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The requester.
    pub requester_id: Uuid,
    /// Requested NHI name.
    pub requested_name: String,
    /// Purpose/justification.
    pub purpose: String,
    /// When the request expires.
    pub expires_at: DateTime<Utc>,
    /// When submitted.
    pub submitted_at: DateTime<Utc>,
}

impl Event for NhiRequestSubmitted {
    const TOPIC: &'static str = "xavyo.governance.nhi.request_submitted";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.request_submitted";
}

/// Published when an NHI request is approved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiRequestApproved {
    /// The request ID.
    pub request_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The requester.
    pub requester_id: Uuid,
    /// The approver.
    pub approver_id: Uuid,
    /// The created NHI ID.
    pub nhi_id: Uuid,
    /// When approved.
    pub approved_at: DateTime<Utc>,
}

impl Event for NhiRequestApproved {
    const TOPIC: &'static str = "xavyo.governance.nhi.request_approved";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.request_approved";
}

/// Published when an NHI request is rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiRequestRejected {
    /// The request ID.
    pub request_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The requester.
    pub requester_id: Uuid,
    /// The approver who rejected.
    pub rejected_by: Uuid,
    /// Reason for rejection.
    pub reason: String,
    /// When rejected.
    pub rejected_at: DateTime<Utc>,
}

impl Event for NhiRequestRejected {
    const TOPIC: &'static str = "xavyo.governance.nhi.request_rejected";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.request_rejected";
}

// =============================================================================
// Ownership Events
// =============================================================================

/// Published when NHI ownership is transferred.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiOwnershipTransferred {
    /// The NHI ID.
    pub nhi_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The NHI name.
    pub name: String,
    /// Previous owner.
    pub from_owner_id: Uuid,
    /// New owner.
    pub to_owner_id: Uuid,
    /// Reason for transfer.
    pub reason: Option<String>,
    /// Who initiated the transfer.
    pub transferred_by: Uuid,
    /// When the transfer occurred.
    pub transferred_at: DateTime<Utc>,
}

impl Event for NhiOwnershipTransferred {
    const TOPIC: &'static str = "xavyo.governance.nhi.ownership_transferred";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.ownership_transferred";
}

// =============================================================================
// Certification Events
// =============================================================================

/// Published when an NHI certification is required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiCertificationRequired {
    /// The NHI ID.
    pub nhi_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The NHI name.
    pub name: String,
    /// The certification campaign ID.
    pub campaign_id: Uuid,
    /// The owner who needs to certify.
    pub certifier_id: Uuid,
    /// Due date for certification.
    pub due_at: DateTime<Utc>,
}

impl Event for NhiCertificationRequired {
    const TOPIC: &'static str = "xavyo.governance.nhi.certification_required";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.certification_required";
}

/// Published when an NHI is certified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiCertified {
    /// The NHI ID.
    pub nhi_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The NHI name.
    pub name: String,
    /// The certification campaign ID.
    pub campaign_id: Uuid,
    /// Who certified.
    pub certified_by: Uuid,
    /// When certified.
    pub certified_at: DateTime<Utc>,
}

impl Event for NhiCertified {
    const TOPIC: &'static str = "xavyo.governance.nhi.certified";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.certified";
}

/// Published when an NHI certification campaign is launched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiCertificationCampaignLaunched {
    /// The campaign ID.
    pub campaign_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// Number of NHIs included in the campaign.
    pub item_count: u64,
    /// When the campaign was launched.
    pub launched_at: DateTime<Utc>,
}

impl Event for NhiCertificationCampaignLaunched {
    const TOPIC: &'static str = "xavyo.governance.nhi.certification_campaign_launched";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.certification_campaign_launched";
}

/// Published when an NHI certification decision is made.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiCertificationDecisionMade {
    /// The certification item ID.
    pub item_id: Uuid,
    /// The campaign ID.
    pub campaign_id: Uuid,
    /// The NHI ID.
    pub nhi_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The decision made (certify, revoke, delegate).
    pub decision: String,
    /// Who made the decision.
    pub decided_by: Uuid,
    /// When the decision was made.
    pub decided_at: DateTime<Utc>,
    /// Whether the NHI was suspended as a result.
    pub nhi_suspended: bool,
}

impl Event for NhiCertificationDecisionMade {
    const TOPIC: &'static str = "xavyo.governance.nhi.certification_decision_made";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.certification_decision_made";
}

// =============================================================================
// Warning Events
// =============================================================================

/// Published when an NHI has been inactive (warning before suspension).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiInactivityWarning {
    /// The NHI ID.
    pub nhi_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The NHI name.
    pub name: String,
    /// Days inactive.
    pub days_inactive: i32,
    /// The inactivity threshold.
    pub threshold_days: i32,
    /// When suspension will occur if still inactive.
    pub suspension_scheduled_at: DateTime<Utc>,
    /// The owner to notify.
    pub owner_id: Uuid,
}

impl Event for NhiInactivityWarning {
    const TOPIC: &'static str = "xavyo.governance.nhi.inactivity_warning";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.inactivity_warning";
}

/// Published when an NHI is approaching expiration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiExpirationWarning {
    /// The NHI ID.
    pub nhi_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The NHI name.
    pub name: String,
    /// When the NHI expires.
    pub expires_at: DateTime<Utc>,
    /// Days until expiration.
    pub days_until_expiry: i32,
    /// The owner to notify.
    pub owner_id: Uuid,
}

impl Event for NhiExpirationWarning {
    const TOPIC: &'static str = "xavyo.governance.nhi.expiration_warning";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.expiration_warning";
}

// =============================================================================
// Usage Events
// =============================================================================

/// Published when NHI usage is recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiUsageRecorded {
    /// The NHI ID.
    pub nhi_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The NHI name.
    pub name: String,
    /// The action performed.
    pub action: String,
    /// The resource accessed.
    pub resource: String,
    /// The outcome of the action.
    pub outcome: String,
    /// When the usage was recorded.
    pub recorded_at: DateTime<Utc>,
}

impl Event for NhiUsageRecorded {
    const TOPIC: &'static str = "xavyo.governance.nhi.usage_recorded";
    const EVENT_TYPE: &'static str = "xavyo.governance.nhi.usage_recorded";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nhi_created_serialization() {
        let event = NhiCreated {
            nhi_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "ci-pipeline-bot".to_string(),
            purpose: Some("CI/CD pipeline automation".to_string()),
            owner_id: Uuid::new_v4(),
            backup_owner_id: None,
            expires_at: None,
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: NhiCreated = serde_json::from_str(&json).unwrap();
        assert_eq!(event.nhi_id, restored.nhi_id);
        assert_eq!(event.name, restored.name);
    }

    #[test]
    fn test_nhi_suspended_serialization() {
        let event = NhiSuspended {
            nhi_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "old-service".to_string(),
            reason: NhiSuspensionReason::Inactive,
            details: Some("No activity for 90+ days".to_string()),
            suspended_by: None,
            suspended_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: NhiSuspended = serde_json::from_str(&json).unwrap();
        assert_eq!(event.nhi_id, restored.nhi_id);
    }

    #[test]
    fn test_suspension_reason_serialization() {
        let expired = NhiSuspensionReason::Expired;
        let json = serde_json::to_string(&expired).unwrap();
        assert_eq!(json, "\"expired\"");

        let inactive = NhiSuspensionReason::Inactive;
        let json = serde_json::to_string(&inactive).unwrap();
        assert_eq!(json, "\"inactive\"");
    }

    #[test]
    fn test_nhi_event_topics() {
        assert_eq!(NhiCreated::TOPIC, "xavyo.governance.nhi.created");
        assert_eq!(NhiUpdated::TOPIC, "xavyo.governance.nhi.updated");
        assert_eq!(NhiDeleted::TOPIC, "xavyo.governance.nhi.deleted");
        assert_eq!(
            NhiRiskScoreChanged::TOPIC,
            "xavyo.governance.nhi.risk_score_changed"
        );
        assert_eq!(NhiSuspended::TOPIC, "xavyo.governance.nhi.suspended");
        assert_eq!(NhiReactivated::TOPIC, "xavyo.governance.nhi.reactivated");
        assert_eq!(
            NhiRequestSubmitted::TOPIC,
            "xavyo.governance.nhi.request_submitted"
        );
        assert_eq!(
            NhiRequestApproved::TOPIC,
            "xavyo.governance.nhi.request_approved"
        );
        assert_eq!(
            NhiRequestRejected::TOPIC,
            "xavyo.governance.nhi.request_rejected"
        );
        assert_eq!(
            NhiOwnershipTransferred::TOPIC,
            "xavyo.governance.nhi.ownership_transferred"
        );
        assert_eq!(
            NhiCertificationRequired::TOPIC,
            "xavyo.governance.nhi.certification_required"
        );
        assert_eq!(NhiCertified::TOPIC, "xavyo.governance.nhi.certified");
        assert_eq!(
            NhiInactivityWarning::TOPIC,
            "xavyo.governance.nhi.inactivity_warning"
        );
        assert_eq!(
            NhiExpirationWarning::TOPIC,
            "xavyo.governance.nhi.expiration_warning"
        );
    }

    #[test]
    fn test_all_topics_follow_convention() {
        assert!(NhiCreated::TOPIC.starts_with("xavyo."));
        assert!(NhiUpdated::TOPIC.starts_with("xavyo."));
        assert!(NhiDeleted::TOPIC.starts_with("xavyo."));
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
    }
}
