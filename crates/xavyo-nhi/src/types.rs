//! Core type definitions for Non-Human Identities.
//!
//! This module provides the fundamental types used throughout the NHI system:
//!
//! - [`NhiType`]: Discriminator for NHI categories (service accounts, agents, tools)
//! - [`NhiLifecycleState`]: Lifecycle state values (active, inactive, suspended, deprecated, archived)
//! - [`NhiRiskLevel`]: Risk level categories derived from risk scores
//!
//! # Serialization
//!
//! All types implement `Serialize` and `Deserialize` with `snake_case` naming:
//!
//! ```rust
//! use xavyo_nhi::{NhiType, NhiLifecycleState, NhiRiskLevel};
//!
//! // Serialize to JSON
//! let json = serde_json::to_string(&NhiType::ServiceAccount).unwrap();
//! assert_eq!(json, "\"service_account\"");
//!
//! // Deserialize from JSON
//! let nhi_type: NhiType = serde_json::from_str("\"agent\"").unwrap();
//! assert_eq!(nhi_type, NhiType::Agent);
//! ```
//!
//! # String Parsing
//!
//! Types implement `FromStr` for parsing from strings (case-insensitive):
//!
//! ```rust
//! use xavyo_nhi::{NhiType, NhiLifecycleState};
//!
//! // Parse NHI types (with aliases)
//! let t1: NhiType = "service_account".parse().unwrap();
//! let t2: NhiType = "agent".parse().unwrap();
//! let t3: NhiType = "ai_agent".parse().unwrap(); // Backward-compat alias for Agent
//!
//! // Parse lifecycle states
//! let s1: NhiLifecycleState = "active".parse().unwrap();
//! let s2: NhiLifecycleState = "deprecated".parse().unwrap();
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Type of non-human identity.
///
/// Distinguishes between different categories of automated identities
/// that require governance and lifecycle management. Each type has
/// different risk profiles and compliance requirements.
///
/// # Variants
///
/// - `ServiceAccount`: Traditional machine-to-machine credentials
/// - `Agent`: AI/ML agent with tool access permissions
/// - `Tool`: An invocable tool that agents can use
///
/// # Serialization
///
/// Serializes to `snake_case` strings for JSON/database storage:
///
/// ```rust
/// use xavyo_nhi::NhiType;
///
/// assert_eq!(serde_json::to_string(&NhiType::ServiceAccount).unwrap(), "\"service_account\"");
/// assert_eq!(serde_json::to_string(&NhiType::Agent).unwrap(), "\"agent\"");
/// assert_eq!(serde_json::to_string(&NhiType::Tool).unwrap(), "\"tool\"");
/// ```
///
/// # Parsing
///
/// Parses from strings with multiple aliases (case-insensitive):
///
/// ```rust
/// use xavyo_nhi::NhiType;
///
/// assert_eq!("service_account".parse::<NhiType>().unwrap(), NhiType::ServiceAccount);
/// assert_eq!("agent".parse::<NhiType>().unwrap(), NhiType::Agent);
/// assert_eq!("ai_agent".parse::<NhiType>().unwrap(), NhiType::Agent); // backward compat
/// assert_eq!("tool".parse::<NhiType>().unwrap(), NhiType::Tool);
/// assert_eq!("SERVICE_ACCOUNT".parse::<NhiType>().unwrap(), NhiType::ServiceAccount);
/// assert!("invalid".parse::<NhiType>().is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "text", rename_all = "snake_case"))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum NhiType {
    /// Traditional service account for machine-to-machine authentication.
    ServiceAccount,

    /// AI/ML agent with tool access permissions.
    Agent,

    /// An invocable tool that agents can use.
    Tool,
}

impl NhiType {
    /// Returns all known NHI types.
    #[must_use]
    pub fn all() -> &'static [NhiType] {
        &[NhiType::ServiceAccount, NhiType::Agent, NhiType::Tool]
    }

    /// Returns the string representation used in database queries.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            NhiType::ServiceAccount => "service_account",
            NhiType::Agent => "agent",
            NhiType::Tool => "tool",
        }
    }
}

impl fmt::Display for NhiType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for NhiType {
    type Err = NhiTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "service_account" | "serviceaccount" => Ok(NhiType::ServiceAccount),
            "agent" | "ai_agent" | "aiagent" => Ok(NhiType::Agent),
            "tool" => Ok(NhiType::Tool),
            _ => Err(NhiTypeParseError(s.to_string())),
        }
    }
}

/// Error returned when parsing an invalid NHI type string.
///
/// # Example
///
/// ```rust
/// use xavyo_nhi::NhiType;
/// use std::str::FromStr;
///
/// let err = NhiType::from_str("invalid_type").unwrap_err();
/// assert!(err.to_string().contains("invalid NHI type"));
/// assert!(err.to_string().contains("invalid_type"));
/// ```
#[derive(Debug, Clone)]
pub struct NhiTypeParseError(pub String);

impl fmt::Display for NhiTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid NHI type '{}': expected 'service_account', 'agent', or 'tool'",
            self.0
        )
    }
}

impl std::error::Error for NhiTypeParseError {}

/// Lifecycle state for non-human identities.
///
/// Models a state machine with defined valid transitions:
///
/// - `Active` -> `Inactive`, `Suspended`, `Deprecated`
/// - `Inactive` -> `Active`
/// - `Suspended` -> `Active`
/// - `Deprecated` -> `Archived`
/// - `Archived` -> (terminal, no transitions out)
///
/// # Serialization
///
/// ```rust
/// use xavyo_nhi::NhiLifecycleState;
///
/// assert_eq!(serde_json::to_string(&NhiLifecycleState::Active).unwrap(), "\"active\"");
/// assert_eq!(serde_json::to_string(&NhiLifecycleState::Deprecated).unwrap(), "\"deprecated\"");
///
/// let state: NhiLifecycleState = serde_json::from_str("\"suspended\"").unwrap();
/// assert_eq!(state, NhiLifecycleState::Suspended);
/// ```
///
/// # State Helpers
///
/// ```rust
/// use xavyo_nhi::NhiLifecycleState;
///
/// assert!(NhiLifecycleState::Active.is_usable());
/// assert!(!NhiLifecycleState::Suspended.is_usable());
/// assert!(NhiLifecycleState::Archived.is_terminal());
/// assert!(!NhiLifecycleState::Active.is_terminal());
/// assert!(NhiLifecycleState::Active.can_transition_to(NhiLifecycleState::Suspended));
/// assert!(!NhiLifecycleState::Archived.can_transition_to(NhiLifecycleState::Active));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "text", rename_all = "snake_case"))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum NhiLifecycleState {
    /// Identity is active and can be used.
    Active,

    /// Identity exists but is not currently in use.
    Inactive,

    /// Identity has been suspended (manual or automatic).
    Suspended,

    /// Identity is deprecated and pending archival.
    Deprecated,

    /// Identity has been archived. Terminal state.
    Archived,
}

impl NhiLifecycleState {
    /// Returns the string representation used in database queries.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            NhiLifecycleState::Active => "active",
            NhiLifecycleState::Inactive => "inactive",
            NhiLifecycleState::Suspended => "suspended",
            NhiLifecycleState::Deprecated => "deprecated",
            NhiLifecycleState::Archived => "archived",
        }
    }

    /// Returns true if this state allows the identity to be used.
    ///
    /// Only `Active` is usable.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        matches!(self, NhiLifecycleState::Active)
    }

    /// Returns true if this is a terminal state (no transitions out).
    ///
    /// Only `Archived` is terminal.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, NhiLifecycleState::Archived)
    }

    /// Returns the set of valid states this state can transition to.
    ///
    /// Per the NHI lifecycle state machine:
    /// - `Active` -> `[Inactive, Suspended, Deprecated]`
    /// - `Inactive` -> `[Active]`
    /// - `Suspended` -> `[Active]`
    /// - `Deprecated` -> `[Archived]`
    /// - `Archived` -> `[]` (terminal)
    #[must_use]
    pub fn valid_transitions(&self) -> Vec<NhiLifecycleState> {
        match self {
            NhiLifecycleState::Active => vec![
                NhiLifecycleState::Inactive,
                NhiLifecycleState::Suspended,
                NhiLifecycleState::Deprecated,
            ],
            NhiLifecycleState::Inactive => vec![NhiLifecycleState::Active],
            NhiLifecycleState::Suspended => vec![NhiLifecycleState::Active],
            NhiLifecycleState::Deprecated => vec![NhiLifecycleState::Archived],
            NhiLifecycleState::Archived => vec![],
        }
    }

    /// Returns true if transitioning from this state to `target` is valid.
    #[must_use]
    pub fn can_transition_to(&self, target: NhiLifecycleState) -> bool {
        self.valid_transitions().contains(&target)
    }
}

impl fmt::Display for NhiLifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for NhiLifecycleState {
    type Err = NhiLifecycleStateParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(NhiLifecycleState::Active),
            "inactive" => Ok(NhiLifecycleState::Inactive),
            "suspended" => Ok(NhiLifecycleState::Suspended),
            "deprecated" => Ok(NhiLifecycleState::Deprecated),
            "archived" => Ok(NhiLifecycleState::Archived),
            _ => Err(NhiLifecycleStateParseError(s.to_string())),
        }
    }
}

/// Error returned when parsing an invalid lifecycle state string.
///
/// # Example
///
/// ```rust
/// use xavyo_nhi::NhiLifecycleState;
/// use std::str::FromStr;
///
/// let err = NhiLifecycleState::from_str("invalid").unwrap_err();
/// assert!(err.to_string().contains("invalid NHI lifecycle state"));
/// ```
#[derive(Debug, Clone)]
pub struct NhiLifecycleStateParseError(pub String);

impl fmt::Display for NhiLifecycleStateParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid NHI lifecycle state '{}': expected one of: active, inactive, suspended, deprecated, archived",
            self.0
        )
    }
}

impl std::error::Error for NhiLifecycleStateParseError {}

/// Backward-compatibility type alias.
///
/// `NhiStatus` was renamed to `NhiLifecycleState` in the unified NHI data model.
/// This alias allows existing code to compile without changes.
#[deprecated(note = "use NhiLifecycleState instead")]
pub type NhiStatus = NhiLifecycleState;

/// Risk level derived from a numeric risk score.
///
/// Risk scores are normalized to a 0-100 scale and then
/// categorized into discrete levels for reporting and alerting.
/// This enum implements [`Ord`], so risk levels can be compared directly.
///
/// # Serialization
///
/// ```rust
/// use xavyo_nhi::NhiRiskLevel;
///
/// assert_eq!(serde_json::to_string(&NhiRiskLevel::Low).unwrap(), "\"low\"");
/// assert_eq!(serde_json::to_string(&NhiRiskLevel::Critical).unwrap(), "\"critical\"");
///
/// let level: NhiRiskLevel = serde_json::from_str("\"high\"").unwrap();
/// assert_eq!(level, NhiRiskLevel::High);
/// ```
///
/// # From Score
///
/// ```rust
/// use xavyo_nhi::NhiRiskLevel;
///
/// assert_eq!(NhiRiskLevel::from(0u32), NhiRiskLevel::Low);
/// assert_eq!(NhiRiskLevel::from(25u32), NhiRiskLevel::Low);
/// assert_eq!(NhiRiskLevel::from(26u32), NhiRiskLevel::Medium);
/// assert_eq!(NhiRiskLevel::from(51u32), NhiRiskLevel::High);
/// assert_eq!(NhiRiskLevel::from(76u32), NhiRiskLevel::Critical);
/// assert_eq!(NhiRiskLevel::from(-10i32), NhiRiskLevel::Low);
/// ```
///
/// # Ordering & Alerting
///
/// ```rust
/// use xavyo_nhi::NhiRiskLevel;
///
/// assert!(NhiRiskLevel::Low < NhiRiskLevel::Medium);
/// assert!(NhiRiskLevel::High < NhiRiskLevel::Critical);
/// assert!(!NhiRiskLevel::Low.should_alert());
/// assert!(NhiRiskLevel::High.should_alert());
/// assert_eq!(NhiRiskLevel::Low.min_score(), 0);
/// assert_eq!(NhiRiskLevel::Critical.max_score(), 100);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum NhiRiskLevel {
    /// Low risk (score 0-25): No immediate action required.
    Low,

    /// Medium risk (score 26-50): Monitor and consider remediation.
    Medium,

    /// High risk (score 51-75): Action recommended, triggers alerts.
    High,

    /// Critical risk (score 76-100): Immediate action required, must alert.
    Critical,
}

impl NhiRiskLevel {
    /// Returns the minimum score for this risk level.
    #[must_use]
    pub fn min_score(&self) -> u32 {
        match self {
            NhiRiskLevel::Low => 0,
            NhiRiskLevel::Medium => 26,
            NhiRiskLevel::High => 51,
            NhiRiskLevel::Critical => 76,
        }
    }

    /// Returns the maximum score for this risk level.
    #[must_use]
    pub fn max_score(&self) -> u32 {
        match self {
            NhiRiskLevel::Low => 25,
            NhiRiskLevel::Medium => 50,
            NhiRiskLevel::High => 75,
            NhiRiskLevel::Critical => 100,
        }
    }

    /// Returns the string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            NhiRiskLevel::Low => "low",
            NhiRiskLevel::Medium => "medium",
            NhiRiskLevel::High => "high",
            NhiRiskLevel::Critical => "critical",
        }
    }

    /// Returns true if this risk level should trigger alerts.
    #[must_use]
    pub fn should_alert(&self) -> bool {
        matches!(self, NhiRiskLevel::High | NhiRiskLevel::Critical)
    }
}

impl From<u32> for NhiRiskLevel {
    fn from(score: u32) -> Self {
        match score {
            0..=25 => NhiRiskLevel::Low,
            26..=50 => NhiRiskLevel::Medium,
            51..=75 => NhiRiskLevel::High,
            _ => NhiRiskLevel::Critical,
        }
    }
}

impl From<i32> for NhiRiskLevel {
    fn from(score: i32) -> Self {
        NhiRiskLevel::from(score.max(0) as u32)
    }
}

impl fmt::Display for NhiRiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // NhiType tests
    // =========================================================================

    #[test]
    fn test_nhi_type_all() {
        let all = NhiType::all();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0], NhiType::ServiceAccount);
        assert_eq!(all[1], NhiType::Agent);
        assert_eq!(all[2], NhiType::Tool);
    }

    #[test]
    fn test_nhi_type_as_str() {
        assert_eq!(NhiType::ServiceAccount.as_str(), "service_account");
        assert_eq!(NhiType::Agent.as_str(), "agent");
        assert_eq!(NhiType::Tool.as_str(), "tool");
    }

    #[test]
    fn test_nhi_type_display() {
        assert_eq!(NhiType::ServiceAccount.to_string(), "service_account");
        assert_eq!(NhiType::Agent.to_string(), "agent");
        assert_eq!(NhiType::Tool.to_string(), "tool");
    }

    #[test]
    fn test_nhi_type_serialization() {
        assert_eq!(
            serde_json::to_string(&NhiType::ServiceAccount).unwrap(),
            "\"service_account\""
        );
        assert_eq!(serde_json::to_string(&NhiType::Agent).unwrap(), "\"agent\"");
        assert_eq!(serde_json::to_string(&NhiType::Tool).unwrap(), "\"tool\"");
    }

    #[test]
    fn test_nhi_type_deserialization() {
        assert_eq!(
            serde_json::from_str::<NhiType>("\"service_account\"").unwrap(),
            NhiType::ServiceAccount
        );
        assert_eq!(
            serde_json::from_str::<NhiType>("\"agent\"").unwrap(),
            NhiType::Agent
        );
        assert_eq!(
            serde_json::from_str::<NhiType>("\"tool\"").unwrap(),
            NhiType::Tool
        );
    }

    #[test]
    fn test_nhi_type_round_trip() {
        for nhi_type in NhiType::all() {
            let json = serde_json::to_string(nhi_type).unwrap();
            let deserialized: NhiType = serde_json::from_str(&json).unwrap();
            assert_eq!(
                *nhi_type, deserialized,
                "NhiType round-trip failed for {nhi_type:?}"
            );
        }
    }

    #[test]
    fn test_nhi_type_from_str() {
        // Standard forms
        assert_eq!(
            "service_account".parse::<NhiType>().unwrap(),
            NhiType::ServiceAccount
        );
        assert_eq!("agent".parse::<NhiType>().unwrap(), NhiType::Agent);
        assert_eq!("tool".parse::<NhiType>().unwrap(), NhiType::Tool);

        // Aliases
        assert_eq!(
            "serviceaccount".parse::<NhiType>().unwrap(),
            NhiType::ServiceAccount
        );
        assert_eq!("ai_agent".parse::<NhiType>().unwrap(), NhiType::Agent);
        assert_eq!("aiagent".parse::<NhiType>().unwrap(), NhiType::Agent);

        // Case insensitive
        assert_eq!(
            "SERVICE_ACCOUNT".parse::<NhiType>().unwrap(),
            NhiType::ServiceAccount
        );
        assert_eq!("AGENT".parse::<NhiType>().unwrap(), NhiType::Agent);
        assert_eq!("Tool".parse::<NhiType>().unwrap(), NhiType::Tool);
        assert_eq!("AI_AGENT".parse::<NhiType>().unwrap(), NhiType::Agent);

        // Invalid
        assert!("invalid".parse::<NhiType>().is_err());
        assert!("".parse::<NhiType>().is_err());
    }

    #[test]
    fn test_nhi_type_parse_error_message() {
        let err = "invalid_type".parse::<NhiType>().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid NHI type"));
        assert!(msg.contains("invalid_type"));
        assert!(msg.contains("service_account"));
        assert!(msg.contains("agent"));
        assert!(msg.contains("tool"));
    }

    // =========================================================================
    // NhiLifecycleState tests
    // =========================================================================

    #[test]
    fn test_lifecycle_state_as_str() {
        assert_eq!(NhiLifecycleState::Active.as_str(), "active");
        assert_eq!(NhiLifecycleState::Inactive.as_str(), "inactive");
        assert_eq!(NhiLifecycleState::Suspended.as_str(), "suspended");
        assert_eq!(NhiLifecycleState::Deprecated.as_str(), "deprecated");
        assert_eq!(NhiLifecycleState::Archived.as_str(), "archived");
    }

    #[test]
    fn test_lifecycle_state_display() {
        assert_eq!(NhiLifecycleState::Active.to_string(), "active");
        assert_eq!(NhiLifecycleState::Inactive.to_string(), "inactive");
        assert_eq!(NhiLifecycleState::Suspended.to_string(), "suspended");
        assert_eq!(NhiLifecycleState::Deprecated.to_string(), "deprecated");
        assert_eq!(NhiLifecycleState::Archived.to_string(), "archived");
    }

    #[test]
    fn test_lifecycle_state_serialization() {
        assert_eq!(
            serde_json::to_string(&NhiLifecycleState::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&NhiLifecycleState::Inactive).unwrap(),
            "\"inactive\""
        );
        assert_eq!(
            serde_json::to_string(&NhiLifecycleState::Suspended).unwrap(),
            "\"suspended\""
        );
        assert_eq!(
            serde_json::to_string(&NhiLifecycleState::Deprecated).unwrap(),
            "\"deprecated\""
        );
        assert_eq!(
            serde_json::to_string(&NhiLifecycleState::Archived).unwrap(),
            "\"archived\""
        );
    }

    #[test]
    fn test_lifecycle_state_deserialization() {
        assert_eq!(
            serde_json::from_str::<NhiLifecycleState>("\"active\"").unwrap(),
            NhiLifecycleState::Active
        );
        assert_eq!(
            serde_json::from_str::<NhiLifecycleState>("\"archived\"").unwrap(),
            NhiLifecycleState::Archived
        );
    }

    #[test]
    fn test_lifecycle_state_round_trip() {
        let all = [
            NhiLifecycleState::Active,
            NhiLifecycleState::Inactive,
            NhiLifecycleState::Suspended,
            NhiLifecycleState::Deprecated,
            NhiLifecycleState::Archived,
        ];
        for state in &all {
            let json = serde_json::to_string(state).unwrap();
            let deserialized: NhiLifecycleState = serde_json::from_str(&json).unwrap();
            assert_eq!(
                *state, deserialized,
                "NhiLifecycleState round-trip failed for {state:?}"
            );
        }
    }

    #[test]
    fn test_lifecycle_state_from_str() {
        assert_eq!(
            "active".parse::<NhiLifecycleState>().unwrap(),
            NhiLifecycleState::Active
        );
        assert_eq!(
            "inactive".parse::<NhiLifecycleState>().unwrap(),
            NhiLifecycleState::Inactive
        );
        assert_eq!(
            "suspended".parse::<NhiLifecycleState>().unwrap(),
            NhiLifecycleState::Suspended
        );
        assert_eq!(
            "deprecated".parse::<NhiLifecycleState>().unwrap(),
            NhiLifecycleState::Deprecated
        );
        assert_eq!(
            "archived".parse::<NhiLifecycleState>().unwrap(),
            NhiLifecycleState::Archived
        );

        // Case insensitive
        assert_eq!(
            "ACTIVE".parse::<NhiLifecycleState>().unwrap(),
            NhiLifecycleState::Active
        );
        assert_eq!(
            "Suspended".parse::<NhiLifecycleState>().unwrap(),
            NhiLifecycleState::Suspended
        );

        // Invalid
        assert!("invalid".parse::<NhiLifecycleState>().is_err());
        assert!("".parse::<NhiLifecycleState>().is_err());
        assert!("pending_certification"
            .parse::<NhiLifecycleState>()
            .is_err());
    }

    #[test]
    fn test_lifecycle_state_parse_error_message() {
        let err = "bad_state".parse::<NhiLifecycleState>().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid NHI lifecycle state"));
        assert!(msg.contains("bad_state"));
        assert!(msg.contains("active"));
        assert!(msg.contains("archived"));
    }

    #[test]
    fn test_lifecycle_state_is_usable() {
        assert!(NhiLifecycleState::Active.is_usable());
        assert!(!NhiLifecycleState::Inactive.is_usable());
        assert!(!NhiLifecycleState::Suspended.is_usable());
        assert!(!NhiLifecycleState::Deprecated.is_usable());
        assert!(!NhiLifecycleState::Archived.is_usable());
    }

    #[test]
    fn test_lifecycle_state_is_terminal() {
        assert!(!NhiLifecycleState::Active.is_terminal());
        assert!(!NhiLifecycleState::Inactive.is_terminal());
        assert!(!NhiLifecycleState::Suspended.is_terminal());
        assert!(!NhiLifecycleState::Deprecated.is_terminal());
        assert!(NhiLifecycleState::Archived.is_terminal());
    }

    #[test]
    fn test_lifecycle_state_valid_transitions() {
        // Active can go to Inactive, Suspended, Deprecated
        let active_transitions = NhiLifecycleState::Active.valid_transitions();
        assert_eq!(active_transitions.len(), 3);
        assert!(active_transitions.contains(&NhiLifecycleState::Inactive));
        assert!(active_transitions.contains(&NhiLifecycleState::Suspended));
        assert!(active_transitions.contains(&NhiLifecycleState::Deprecated));

        // Inactive can go to Active
        let inactive_transitions = NhiLifecycleState::Inactive.valid_transitions();
        assert_eq!(inactive_transitions.len(), 1);
        assert!(inactive_transitions.contains(&NhiLifecycleState::Active));

        // Suspended can go to Active
        let suspended_transitions = NhiLifecycleState::Suspended.valid_transitions();
        assert_eq!(suspended_transitions.len(), 1);
        assert!(suspended_transitions.contains(&NhiLifecycleState::Active));

        // Deprecated can go to Archived
        let deprecated_transitions = NhiLifecycleState::Deprecated.valid_transitions();
        assert_eq!(deprecated_transitions.len(), 1);
        assert!(deprecated_transitions.contains(&NhiLifecycleState::Archived));

        // Archived has no transitions (terminal)
        let archived_transitions = NhiLifecycleState::Archived.valid_transitions();
        assert!(archived_transitions.is_empty());
    }

    #[test]
    fn test_lifecycle_state_can_transition_to() {
        // Active transitions
        assert!(NhiLifecycleState::Active.can_transition_to(NhiLifecycleState::Inactive));
        assert!(NhiLifecycleState::Active.can_transition_to(NhiLifecycleState::Suspended));
        assert!(NhiLifecycleState::Active.can_transition_to(NhiLifecycleState::Deprecated));
        assert!(!NhiLifecycleState::Active.can_transition_to(NhiLifecycleState::Archived));
        assert!(!NhiLifecycleState::Active.can_transition_to(NhiLifecycleState::Active));

        // Inactive transitions
        assert!(NhiLifecycleState::Inactive.can_transition_to(NhiLifecycleState::Active));
        assert!(!NhiLifecycleState::Inactive.can_transition_to(NhiLifecycleState::Suspended));

        // Suspended transitions
        assert!(NhiLifecycleState::Suspended.can_transition_to(NhiLifecycleState::Active));
        assert!(!NhiLifecycleState::Suspended.can_transition_to(NhiLifecycleState::Deprecated));

        // Deprecated transitions
        assert!(NhiLifecycleState::Deprecated.can_transition_to(NhiLifecycleState::Archived));
        assert!(!NhiLifecycleState::Deprecated.can_transition_to(NhiLifecycleState::Active));

        // Archived transitions (none)
        assert!(!NhiLifecycleState::Archived.can_transition_to(NhiLifecycleState::Active));
        assert!(!NhiLifecycleState::Archived.can_transition_to(NhiLifecycleState::Inactive));
    }

    // =========================================================================
    // NhiRiskLevel tests
    // =========================================================================

    #[test]
    fn test_nhi_risk_level_from_score() {
        assert_eq!(NhiRiskLevel::from(0u32), NhiRiskLevel::Low);
        assert_eq!(NhiRiskLevel::from(25u32), NhiRiskLevel::Low);
        assert_eq!(NhiRiskLevel::from(26u32), NhiRiskLevel::Medium);
        assert_eq!(NhiRiskLevel::from(50u32), NhiRiskLevel::Medium);
        assert_eq!(NhiRiskLevel::from(51u32), NhiRiskLevel::High);
        assert_eq!(NhiRiskLevel::from(75u32), NhiRiskLevel::High);
        assert_eq!(NhiRiskLevel::from(76u32), NhiRiskLevel::Critical);
        assert_eq!(NhiRiskLevel::from(100u32), NhiRiskLevel::Critical);
    }

    #[test]
    fn test_nhi_risk_level_from_i32() {
        assert_eq!(NhiRiskLevel::from(-10i32), NhiRiskLevel::Low);
        assert_eq!(NhiRiskLevel::from(50i32), NhiRiskLevel::Medium);
    }

    #[test]
    fn test_nhi_risk_level_should_alert() {
        assert!(!NhiRiskLevel::Low.should_alert());
        assert!(!NhiRiskLevel::Medium.should_alert());
        assert!(NhiRiskLevel::High.should_alert());
        assert!(NhiRiskLevel::Critical.should_alert());
    }

    #[test]
    fn test_nhi_risk_level_ordering() {
        assert!(NhiRiskLevel::Low < NhiRiskLevel::Medium);
        assert!(NhiRiskLevel::Medium < NhiRiskLevel::High);
        assert!(NhiRiskLevel::High < NhiRiskLevel::Critical);
    }

    #[test]
    fn test_nhi_risk_level_serialization() {
        assert_eq!(
            serde_json::to_string(&NhiRiskLevel::Low).unwrap(),
            "\"low\""
        );
        assert_eq!(
            serde_json::to_string(&NhiRiskLevel::Medium).unwrap(),
            "\"medium\""
        );
        assert_eq!(
            serde_json::to_string(&NhiRiskLevel::High).unwrap(),
            "\"high\""
        );
        assert_eq!(
            serde_json::to_string(&NhiRiskLevel::Critical).unwrap(),
            "\"critical\""
        );
    }

    #[test]
    fn test_nhi_risk_level_round_trip() {
        let all = [
            NhiRiskLevel::Low,
            NhiRiskLevel::Medium,
            NhiRiskLevel::High,
            NhiRiskLevel::Critical,
        ];
        for level in &all {
            let json = serde_json::to_string(level).unwrap();
            let deserialized: NhiRiskLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(
                *level, deserialized,
                "NhiRiskLevel round-trip failed for {level:?}"
            );
        }
    }

    #[test]
    fn test_nhi_risk_level_score_ranges() {
        assert_eq!(NhiRiskLevel::Low.min_score(), 0);
        assert_eq!(NhiRiskLevel::Low.max_score(), 25);
        assert_eq!(NhiRiskLevel::Medium.min_score(), 26);
        assert_eq!(NhiRiskLevel::Medium.max_score(), 50);
        assert_eq!(NhiRiskLevel::High.min_score(), 51);
        assert_eq!(NhiRiskLevel::High.max_score(), 75);
        assert_eq!(NhiRiskLevel::Critical.min_score(), 76);
        assert_eq!(NhiRiskLevel::Critical.max_score(), 100);
    }
}
