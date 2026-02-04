//! Escalation type definitions (F054).
//!
//! Shared enums for workflow escalation.

use serde::{Deserialize, Serialize};

/// Escalation target types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_escalation_target_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum EscalationTargetType {
    /// Escalate to a specific user.
    SpecificUser,
    /// Escalate to all members of an approval group.
    ApprovalGroup,
    /// Escalate to the approver's direct manager.
    Manager,
    /// Escalate up the manager chain (configurable depth).
    ManagerChain,
    /// Escalate to tenant administrators.
    TenantAdmin,
}

/// Final fallback actions when all escalation levels are exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_final_fallback_action", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum FinalFallbackAction {
    /// Escalate to tenant admin.
    EscalateAdmin,
    /// Automatically approve the request.
    AutoApprove,
    /// Automatically reject the request.
    AutoReject,
    /// Keep pending with admin alert.
    RemainPending,
}

/// Reason for escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_escalation_reason", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum EscalationReason {
    /// Escalated due to timeout.
    Timeout,
    /// Manually escalated by admin.
    ManualEscalation,
    /// Previous target was unavailable.
    TargetUnavailable,
}

impl EscalationTargetType {
    /// Check if `target_id` is required for this target type.
    #[must_use] 
    pub fn requires_target_id(&self) -> bool {
        matches!(self, Self::SpecificUser | Self::ApprovalGroup)
    }
}

impl FinalFallbackAction {
    /// Check if this action automatically completes the request.
    #[must_use] 
    pub fn auto_completes(&self) -> bool {
        matches!(self, Self::AutoApprove | Self::AutoReject)
    }

    /// Check if this action requires notification.
    #[must_use] 
    pub fn requires_notification(&self) -> bool {
        true // All fallback actions require some form of notification
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_type_serialization() {
        let specific = EscalationTargetType::SpecificUser;
        let json = serde_json::to_string(&specific).unwrap();
        assert_eq!(json, "\"specific_user\"");

        let manager_chain = EscalationTargetType::ManagerChain;
        let json = serde_json::to_string(&manager_chain).unwrap();
        assert_eq!(json, "\"manager_chain\"");
    }

    #[test]
    fn test_fallback_action_serialization() {
        let auto_reject = FinalFallbackAction::AutoReject;
        let json = serde_json::to_string(&auto_reject).unwrap();
        assert_eq!(json, "\"auto_reject\"");
    }

    #[test]
    fn test_reason_serialization() {
        let timeout = EscalationReason::Timeout;
        let json = serde_json::to_string(&timeout).unwrap();
        assert_eq!(json, "\"timeout\"");
    }

    #[test]
    fn test_target_type_requires_target_id() {
        assert!(EscalationTargetType::SpecificUser.requires_target_id());
        assert!(EscalationTargetType::ApprovalGroup.requires_target_id());
        assert!(!EscalationTargetType::Manager.requires_target_id());
        assert!(!EscalationTargetType::ManagerChain.requires_target_id());
        assert!(!EscalationTargetType::TenantAdmin.requires_target_id());
    }

    #[test]
    fn test_fallback_auto_completes() {
        assert!(FinalFallbackAction::AutoApprove.auto_completes());
        assert!(FinalFallbackAction::AutoReject.auto_completes());
        assert!(!FinalFallbackAction::EscalateAdmin.auto_completes());
        assert!(!FinalFallbackAction::RemainPending.auto_completes());
    }
}
