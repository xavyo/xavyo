//! Semi-manual resource types for governance (F064).

use serde::{Deserialize, Serialize};

/// Type of ticketing system integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_ticketing_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TicketingType {
    /// ServiceNow ITSM integration.
    ServiceNow,
    /// Atlassian Jira integration.
    Jira,
    /// Custom webhook integration.
    Webhook,
}

impl std::fmt::Display for TicketingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServiceNow => write!(f, "ServiceNow"),
            Self::Jira => write!(f, "Jira"),
            Self::Webhook => write!(f, "Webhook"),
        }
    }
}

/// Type of provisioning operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_provisioning_operation", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ManualTaskOperation {
    /// Grant new access.
    Grant,
    /// Revoke existing access.
    Revoke,
    /// Modify existing access (e.g., parameter change).
    Modify,
}

impl std::fmt::Display for ManualTaskOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Grant => write!(f, "Grant"),
            Self::Revoke => write!(f, "Revoke"),
            Self::Modify => write!(f, "Modify"),
        }
    }
}

/// Status of a manual provisioning task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_manual_task_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ManualTaskStatus {
    /// Task created, awaiting processing.
    Pending,
    /// Ticket creation in progress.
    PendingTicket,
    /// Ticket created in external system, awaiting fulfillment.
    TicketCreated,
    /// Ticket creation failed (will retry).
    TicketFailed,
    /// IT staff working on the task.
    InProgress,
    /// Task partially completed.
    PartiallyCompleted,
    /// Task successfully completed.
    Completed,
    /// Task rejected by IT staff.
    Rejected,
    /// Task cancelled by requester/admin.
    Cancelled,
    /// Max retries exceeded, needs manual intervention.
    FailedPermanent,
}

impl ManualTaskStatus {
    /// Check if the task is in a pending/active state.
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Pending
                | Self::PendingTicket
                | Self::TicketCreated
                | Self::TicketFailed
                | Self::InProgress
                | Self::PartiallyCompleted
        )
    }

    /// Check if the task is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Rejected | Self::Cancelled | Self::FailedPermanent
        )
    }

    /// Check if the task can be confirmed (manual fulfillment).
    pub fn can_confirm(&self) -> bool {
        matches!(
            self,
            Self::Pending | Self::TicketCreated | Self::InProgress | Self::PartiallyCompleted
        )
    }

    /// Check if the task can be retried.
    pub fn can_retry(&self) -> bool {
        matches!(self, Self::TicketFailed | Self::FailedPermanent)
    }
}

/// Normalized category for external ticket status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_ticket_status_category", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TicketStatusCategory {
    /// Ticket is open/new.
    Open,
    /// Work in progress.
    InProgress,
    /// Waiting on something.
    Pending,
    /// Completed successfully.
    Resolved,
    /// Closed (may or may not be resolved).
    Closed,
    /// Rejected/cancelled.
    Rejected,
}

impl TicketStatusCategory {
    /// Check if this is a completion category.
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Resolved | Self::Closed)
    }

    /// Check if this is a rejection/cancellation category.
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected)
    }

    /// Map from ServiceNow state.
    pub fn from_servicenow_state(state: i32) -> Self {
        match state {
            1 => Self::Open,       // New
            2 => Self::InProgress, // In Progress
            3 => Self::Pending,    // On Hold
            6 => Self::Resolved,   // Resolved
            7 => Self::Closed,     // Closed
            8 => Self::Rejected,   // Cancelled
            _ => Self::Open,
        }
    }

    /// Map from Jira status category.
    pub fn from_jira_category(category: &str) -> Self {
        match category.to_lowercase().as_str() {
            "new" | "to do" | "todo" => Self::Open,
            "indeterminate" | "in progress" => Self::InProgress,
            "done" | "complete" | "resolved" => Self::Resolved,
            "closed" => Self::Closed,
            "cancelled" | "rejected" | "won't do" => Self::Rejected,
            _ => Self::Open,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manual_task_status_is_active() {
        assert!(ManualTaskStatus::Pending.is_active());
        assert!(ManualTaskStatus::TicketCreated.is_active());
        assert!(ManualTaskStatus::InProgress.is_active());
        assert!(!ManualTaskStatus::Completed.is_active());
        assert!(!ManualTaskStatus::Rejected.is_active());
    }

    #[test]
    fn test_manual_task_status_is_terminal() {
        assert!(ManualTaskStatus::Completed.is_terminal());
        assert!(ManualTaskStatus::Rejected.is_terminal());
        assert!(ManualTaskStatus::Cancelled.is_terminal());
        assert!(ManualTaskStatus::FailedPermanent.is_terminal());
        assert!(!ManualTaskStatus::Pending.is_terminal());
    }

    #[test]
    fn test_manual_task_status_can_confirm() {
        assert!(ManualTaskStatus::Pending.can_confirm());
        assert!(ManualTaskStatus::TicketCreated.can_confirm());
        assert!(ManualTaskStatus::InProgress.can_confirm());
        assert!(!ManualTaskStatus::Completed.can_confirm());
        assert!(!ManualTaskStatus::TicketFailed.can_confirm());
    }

    #[test]
    fn test_ticket_status_from_servicenow() {
        assert_eq!(
            TicketStatusCategory::from_servicenow_state(1),
            TicketStatusCategory::Open
        );
        assert_eq!(
            TicketStatusCategory::from_servicenow_state(6),
            TicketStatusCategory::Resolved
        );
        assert_eq!(
            TicketStatusCategory::from_servicenow_state(7),
            TicketStatusCategory::Closed
        );
    }

    #[test]
    fn test_ticket_status_from_jira() {
        assert_eq!(
            TicketStatusCategory::from_jira_category("To Do"),
            TicketStatusCategory::Open
        );
        assert_eq!(
            TicketStatusCategory::from_jira_category("Done"),
            TicketStatusCategory::Resolved
        );
        assert_eq!(
            TicketStatusCategory::from_jira_category("In Progress"),
            TicketStatusCategory::InProgress
        );
    }

    #[test]
    fn test_ticketing_type_display() {
        assert_eq!(TicketingType::ServiceNow.to_string(), "ServiceNow");
        assert_eq!(TicketingType::Jira.to_string(), "Jira");
        assert_eq!(TicketingType::Webhook.to_string(), "Webhook");
    }

    #[test]
    fn test_provisioning_operation_display() {
        assert_eq!(ManualTaskOperation::Grant.to_string(), "Grant");
        assert_eq!(ManualTaskOperation::Revoke.to_string(), "Revoke");
        assert_eq!(ManualTaskOperation::Modify.to_string(), "Modify");
    }
}
