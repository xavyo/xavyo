//! Reconciliation types and enums.
//!
//! Core type definitions for the reconciliation engine.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Mode of reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationMode {
    /// Full reconciliation - compare all accounts with all identities.
    Full,
    /// Delta reconciliation - only process changes since last run.
    Delta,
}

impl fmt::Display for ReconciliationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Delta => write!(f, "delta"),
        }
    }
}

impl std::str::FromStr for ReconciliationMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "full" => Ok(Self::Full),
            "delta" => Ok(Self::Delta),
            _ => Err(format!("Invalid reconciliation mode: {}", s)),
        }
    }
}

/// Status of a reconciliation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Run is queued but not yet started.
    Pending,
    /// Run is currently executing.
    Running,
    /// Run completed successfully.
    Completed,
    /// Run failed with an error.
    Failed,
    /// Run was cancelled by user.
    Cancelled,
}

impl RunStatus {
    /// Check if the run is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    /// Check if the run can be cancelled.
    pub fn can_cancel(&self) -> bool {
        matches!(self, Self::Pending | Self::Running)
    }

    /// Check if the run can be resumed.
    pub fn can_resume(&self) -> bool {
        matches!(self, Self::Failed)
    }
}

impl fmt::Display for RunStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for RunStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(format!("Invalid run status: {}", s)),
        }
    }
}

/// Type of discrepancy detected during reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscrepancyType {
    /// Identity exists in xavyo but no account in target system.
    Missing,
    /// Account exists in target but no matching identity in xavyo.
    Orphan,
    /// Account linked to identity but attributes differ.
    Mismatch,
    /// Multiple identities match one account (correlation collision).
    Collision,
    /// Account exists, owner found by correlation but no shadow link.
    Unlinked,
    /// Shadow link exists but account no longer in target system.
    Deleted,
}

impl DiscrepancyType {
    /// Get the suggested remediation actions for this discrepancy type.
    pub fn suggested_actions(&self) -> Vec<ActionType> {
        match self {
            Self::Missing => vec![ActionType::Create],
            Self::Orphan => vec![
                ActionType::Delete,
                ActionType::Link,
                ActionType::InactivateIdentity,
            ],
            Self::Mismatch => vec![ActionType::Update],
            Self::Collision => vec![], // Requires manual resolution
            Self::Unlinked => vec![ActionType::Link],
            Self::Deleted => vec![ActionType::Unlink],
        }
    }

    /// Check if this discrepancy type requires an identity reference.
    pub fn requires_identity(&self) -> bool {
        matches!(self, Self::Missing | Self::Mismatch | Self::Unlinked)
    }
}

impl fmt::Display for DiscrepancyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => write!(f, "missing"),
            Self::Orphan => write!(f, "orphan"),
            Self::Mismatch => write!(f, "mismatch"),
            Self::Collision => write!(f, "collision"),
            Self::Unlinked => write!(f, "unlinked"),
            Self::Deleted => write!(f, "deleted"),
        }
    }
}

impl std::str::FromStr for DiscrepancyType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "missing" => Ok(Self::Missing),
            "orphan" => Ok(Self::Orphan),
            "mismatch" => Ok(Self::Mismatch),
            "collision" => Ok(Self::Collision),
            "unlinked" => Ok(Self::Unlinked),
            "deleted" => Ok(Self::Deleted),
            _ => Err(format!("Invalid discrepancy type: {}", s)),
        }
    }
}

/// Resolution status of a discrepancy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStatus {
    /// Discrepancy has not been resolved.
    Pending,
    /// Discrepancy was resolved by a remediation action.
    Resolved,
    /// Discrepancy was marked as ignored.
    Ignored,
}

impl fmt::Display for ResolutionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Resolved => write!(f, "resolved"),
            Self::Ignored => write!(f, "ignored"),
        }
    }
}

impl std::str::FromStr for ResolutionStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "resolved" => Ok(Self::Resolved),
            "ignored" => Ok(Self::Ignored),
            _ => Err(format!("Invalid resolution status: {}", s)),
        }
    }
}

/// Type of remediation action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    /// Create account in target system.
    Create,
    /// Update account attributes.
    Update,
    /// Delete account from target system.
    Delete,
    /// Establish shadow link between identity and account.
    Link,
    /// Remove shadow link.
    Unlink,
    /// Disable identity in xavyo.
    InactivateIdentity,
}

impl fmt::Display for ActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create => write!(f, "create"),
            Self::Update => write!(f, "update"),
            Self::Delete => write!(f, "delete"),
            Self::Link => write!(f, "link"),
            Self::Unlink => write!(f, "unlink"),
            Self::InactivateIdentity => write!(f, "inactivate_identity"),
        }
    }
}

impl std::str::FromStr for ActionType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "create" => Ok(Self::Create),
            "update" => Ok(Self::Update),
            "delete" => Ok(Self::Delete),
            "link" => Ok(Self::Link),
            "unlink" => Ok(Self::Unlink),
            "inactivate_identity" => Ok(Self::InactivateIdentity),
            _ => Err(format!("Invalid action type: {}", s)),
        }
    }
}

/// Direction for update remediation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationDirection {
    /// Update target system with xavyo values.
    #[default]
    XavyoToTarget,
    /// Update xavyo with target system values.
    TargetToXavyo,
}

impl fmt::Display for RemediationDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XavyoToTarget => write!(f, "xavyo_to_target"),
            Self::TargetToXavyo => write!(f, "target_to_xavyo"),
        }
    }
}

/// Result of a remediation action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionResult {
    /// Action completed successfully.
    Success,
    /// Action failed.
    Failure,
}

impl fmt::Display for ActionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failure => write!(f, "failure"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reconciliation_mode_display() {
        assert_eq!(ReconciliationMode::Full.to_string(), "full");
        assert_eq!(ReconciliationMode::Delta.to_string(), "delta");
    }

    #[test]
    fn test_reconciliation_mode_parse() {
        assert_eq!(
            "full".parse::<ReconciliationMode>().unwrap(),
            ReconciliationMode::Full
        );
        assert_eq!(
            "delta".parse::<ReconciliationMode>().unwrap(),
            ReconciliationMode::Delta
        );
        assert_eq!(
            "FULL".parse::<ReconciliationMode>().unwrap(),
            ReconciliationMode::Full
        );
        assert!("invalid".parse::<ReconciliationMode>().is_err());
    }

    #[test]
    fn test_run_status_terminal() {
        assert!(!RunStatus::Pending.is_terminal());
        assert!(!RunStatus::Running.is_terminal());
        assert!(RunStatus::Completed.is_terminal());
        assert!(RunStatus::Failed.is_terminal());
        assert!(RunStatus::Cancelled.is_terminal());
    }

    #[test]
    fn test_run_status_can_cancel() {
        assert!(RunStatus::Pending.can_cancel());
        assert!(RunStatus::Running.can_cancel());
        assert!(!RunStatus::Completed.can_cancel());
        assert!(!RunStatus::Failed.can_cancel());
        assert!(!RunStatus::Cancelled.can_cancel());
    }

    #[test]
    fn test_discrepancy_suggested_actions() {
        assert_eq!(
            DiscrepancyType::Missing.suggested_actions(),
            vec![ActionType::Create]
        );
        assert_eq!(
            DiscrepancyType::Orphan.suggested_actions(),
            vec![
                ActionType::Delete,
                ActionType::Link,
                ActionType::InactivateIdentity
            ]
        );
        assert_eq!(
            DiscrepancyType::Mismatch.suggested_actions(),
            vec![ActionType::Update]
        );
        assert!(DiscrepancyType::Collision.suggested_actions().is_empty());
        assert_eq!(
            DiscrepancyType::Unlinked.suggested_actions(),
            vec![ActionType::Link]
        );
        assert_eq!(
            DiscrepancyType::Deleted.suggested_actions(),
            vec![ActionType::Unlink]
        );
    }

    #[test]
    fn test_discrepancy_requires_identity() {
        assert!(DiscrepancyType::Missing.requires_identity());
        assert!(!DiscrepancyType::Orphan.requires_identity());
        assert!(DiscrepancyType::Mismatch.requires_identity());
        assert!(!DiscrepancyType::Collision.requires_identity());
        assert!(DiscrepancyType::Unlinked.requires_identity());
        assert!(!DiscrepancyType::Deleted.requires_identity());
    }
}
