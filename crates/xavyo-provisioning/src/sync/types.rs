//! Common types for live synchronization.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Type of change detected in an external system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    /// New account/object created.
    Create,
    /// Existing account/object updated.
    Update,
    /// Account/object deleted.
    Delete,
}

impl ChangeType {
    /// Convert to string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            ChangeType::Create => "create",
            ChangeType::Update => "update",
            ChangeType::Delete => "delete",
        }
    }
}

impl fmt::Display for ChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ChangeType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "create" => Ok(ChangeType::Create),
            "update" => Ok(ChangeType::Update),
            "delete" => Ok(ChangeType::Delete),
            _ => Err(format!("Unknown change type: {s}")),
        }
    }
}

/// Processing status for an inbound change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingStatus {
    /// Waiting to be processed.
    Pending,
    /// Currently being processed.
    Processing,
    /// Successfully processed.
    Completed,
    /// Processing failed (may be retried).
    Failed,
    /// Conflict detected with outbound operation.
    Conflict,
}

impl ProcessingStatus {
    /// Convert to string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            ProcessingStatus::Pending => "pending",
            ProcessingStatus::Processing => "processing",
            ProcessingStatus::Completed => "completed",
            ProcessingStatus::Failed => "failed",
            ProcessingStatus::Conflict => "conflict",
        }
    }

    /// Check if this is a terminal status.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ProcessingStatus::Completed | ProcessingStatus::Conflict
        )
    }

    /// Check if this status allows retry.
    #[must_use]
    pub fn is_retriable(&self) -> bool {
        matches!(self, ProcessingStatus::Failed)
    }
}

impl fmt::Display for ProcessingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ProcessingStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(ProcessingStatus::Pending),
            "processing" => Ok(ProcessingStatus::Processing),
            "completed" => Ok(ProcessingStatus::Completed),
            "failed" => Ok(ProcessingStatus::Failed),
            "conflict" => Ok(ProcessingStatus::Conflict),
            _ => Err(format!("Unknown processing status: {s}")),
        }
    }
}

/// Conflict type for inbound changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictType {
    /// Both inbound and outbound changing same attribute.
    ConcurrentUpdate,
    /// Inbound data is older than current state.
    StaleData,
    /// Conflicting values for specific attributes.
    AttributeConflict,
    /// Correlation mismatch between systems.
    IdentityMismatch,
}

impl ConflictType {
    /// Convert to string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            ConflictType::ConcurrentUpdate => "concurrent_update",
            ConflictType::StaleData => "stale_data",
            ConflictType::AttributeConflict => "attribute_conflict",
            ConflictType::IdentityMismatch => "identity_mismatch",
        }
    }
}

impl fmt::Display for ConflictType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ConflictType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "concurrent_update" => Ok(ConflictType::ConcurrentUpdate),
            "stale_data" => Ok(ConflictType::StaleData),
            "attribute_conflict" => Ok(ConflictType::AttributeConflict),
            "identity_mismatch" => Ok(ConflictType::IdentityMismatch),
            _ => Err(format!("Unknown conflict type: {s}")),
        }
    }
}

/// Resolution strategy for sync conflicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStrategy {
    /// Inbound change wins.
    InboundWins,
    /// Outbound change wins.
    OutboundWins,
    /// Merge non-conflicting attributes.
    Merge,
    /// Require manual resolution.
    Manual,
    /// Awaiting resolution.
    Pending,
}

impl ResolutionStrategy {
    /// Convert to string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            ResolutionStrategy::InboundWins => "inbound_wins",
            ResolutionStrategy::OutboundWins => "outbound_wins",
            ResolutionStrategy::Merge => "merge",
            ResolutionStrategy::Manual => "manual",
            ResolutionStrategy::Pending => "pending",
        }
    }

    /// Check if this is a final resolution.
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        !matches!(self, ResolutionStrategy::Pending)
    }
}

impl fmt::Display for ResolutionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ResolutionStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "inbound_wins" => Ok(ResolutionStrategy::InboundWins),
            "outbound_wins" => Ok(ResolutionStrategy::OutboundWins),
            "merge" => Ok(ResolutionStrategy::Merge),
            "manual" => Ok(ResolutionStrategy::Manual),
            "pending" => Ok(ResolutionStrategy::Pending),
            _ => Err(format!("Unknown resolution strategy: {s}")),
        }
    }
}

/// Sync state for a connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    /// Not currently syncing.
    Idle,
    /// Actively syncing.
    Syncing,
    /// Sync paused.
    Paused,
    /// Sync error occurred.
    Error,
    /// Rate limited.
    Throttled,
}

impl SyncState {
    /// Convert to string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            SyncState::Idle => "idle",
            SyncState::Syncing => "syncing",
            SyncState::Paused => "paused",
            SyncState::Error => "error",
            SyncState::Throttled => "throttled",
        }
    }

    /// Check if sync is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self, SyncState::Syncing)
    }

    /// Check if sync can be started.
    #[must_use]
    pub fn can_start(&self) -> bool {
        matches!(self, SyncState::Idle | SyncState::Error)
    }
}

impl fmt::Display for SyncState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for SyncState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "idle" => Ok(SyncState::Idle),
            "syncing" => Ok(SyncState::Syncing),
            "paused" => Ok(SyncState::Paused),
            "error" => Ok(SyncState::Error),
            "throttled" => Ok(SyncState::Throttled),
            _ => Err(format!("Unknown sync state: {s}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_type_roundtrip() {
        for ct in [ChangeType::Create, ChangeType::Update, ChangeType::Delete] {
            let s = ct.as_str();
            let parsed: ChangeType = s.parse().unwrap();
            assert_eq!(ct, parsed);
        }
    }

    #[test]
    fn test_processing_status_roundtrip() {
        for status in [
            ProcessingStatus::Pending,
            ProcessingStatus::Processing,
            ProcessingStatus::Completed,
            ProcessingStatus::Failed,
            ProcessingStatus::Conflict,
        ] {
            let s = status.as_str();
            let parsed: ProcessingStatus = s.parse().unwrap();
            assert_eq!(status, parsed);
        }
    }

    #[test]
    fn test_processing_status_properties() {
        assert!(ProcessingStatus::Completed.is_terminal());
        assert!(ProcessingStatus::Conflict.is_terminal());
        assert!(!ProcessingStatus::Failed.is_terminal());

        assert!(ProcessingStatus::Failed.is_retriable());
        assert!(!ProcessingStatus::Completed.is_retriable());
    }

    #[test]
    fn test_conflict_type_roundtrip() {
        for ct in [
            ConflictType::ConcurrentUpdate,
            ConflictType::StaleData,
            ConflictType::AttributeConflict,
            ConflictType::IdentityMismatch,
        ] {
            let s = ct.as_str();
            let parsed: ConflictType = s.parse().unwrap();
            assert_eq!(ct, parsed);
        }
    }

    #[test]
    fn test_resolution_strategy_roundtrip() {
        for rs in [
            ResolutionStrategy::InboundWins,
            ResolutionStrategy::OutboundWins,
            ResolutionStrategy::Merge,
            ResolutionStrategy::Manual,
            ResolutionStrategy::Pending,
        ] {
            let s = rs.as_str();
            let parsed: ResolutionStrategy = s.parse().unwrap();
            assert_eq!(rs, parsed);
        }
    }

    #[test]
    fn test_resolution_strategy_is_resolved() {
        assert!(ResolutionStrategy::InboundWins.is_resolved());
        assert!(ResolutionStrategy::Manual.is_resolved());
        assert!(!ResolutionStrategy::Pending.is_resolved());
    }

    #[test]
    fn test_sync_state_roundtrip() {
        for state in [
            SyncState::Idle,
            SyncState::Syncing,
            SyncState::Paused,
            SyncState::Error,
            SyncState::Throttled,
        ] {
            let s = state.as_str();
            let parsed: SyncState = s.parse().unwrap();
            assert_eq!(state, parsed);
        }
    }

    #[test]
    fn test_sync_state_properties() {
        assert!(SyncState::Syncing.is_active());
        assert!(!SyncState::Idle.is_active());

        assert!(SyncState::Idle.can_start());
        assert!(SyncState::Error.can_start());
        assert!(!SyncState::Syncing.can_start());
        assert!(!SyncState::Paused.can_start());
    }
}
