//! Core type definitions for Non-Human Identities.
//!
//! This module provides the fundamental types used throughout the NHI system:
//!
//! - [`NhiType`]: Discriminator for NHI categories (service accounts, AI agents)
//! - [`NhiStatus`]: Lifecycle status values (active, suspended, expired, etc.)
//! - [`NhiRiskLevel`]: Risk level categories derived from risk scores
//!
//! # Serialization
//!
//! All types implement `Serialize` and `Deserialize` with `snake_case` naming:
//!
//! ```rust
//! use xavyo_nhi::{NhiType, NhiStatus, NhiRiskLevel};
//!
//! // Serialize to JSON
//! let json = serde_json::to_string(&NhiType::ServiceAccount).unwrap();
//! assert_eq!(json, "\"service_account\"");
//!
//! // Deserialize from JSON
//! let nhi_type: NhiType = serde_json::from_str("\"ai_agent\"").unwrap();
//! assert_eq!(nhi_type, NhiType::AiAgent);
//! ```
//!
//! # String Parsing
//!
//! Types implement `FromStr` for parsing from strings (case-insensitive):
//!
//! ```rust
//! use xavyo_nhi::{NhiType, NhiStatus};
//!
//! // Parse NHI types (with aliases)
//! let t1: NhiType = "service_account".parse().unwrap();
//! let t2: NhiType = "agent".parse().unwrap(); // Alias for AiAgent
//!
//! // Parse NHI status
//! let s1: NhiStatus = "active".parse().unwrap();
//! let s2: NhiStatus = "pending_certification".parse().unwrap();
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
/// # Serialization
///
/// Serializes to `snake_case` strings for JSON/database storage:
///
/// ```rust
/// use xavyo_nhi::NhiType;
///
/// // To JSON
/// let json = serde_json::to_string(&NhiType::ServiceAccount).unwrap();
/// assert_eq!(json, "\"service_account\"");
///
/// let json = serde_json::to_string(&NhiType::AiAgent).unwrap();
/// assert_eq!(json, "\"ai_agent\"");
///
/// // From JSON
/// let t: NhiType = serde_json::from_str("\"service_account\"").unwrap();
/// assert_eq!(t, NhiType::ServiceAccount);
/// ```
///
/// # Parsing
///
/// Parses from strings with multiple aliases (case-insensitive):
///
/// ```rust
/// use xavyo_nhi::NhiType;
///
/// // Standard forms
/// assert_eq!("service_account".parse::<NhiType>().unwrap(), NhiType::ServiceAccount);
/// assert_eq!("ai_agent".parse::<NhiType>().unwrap(), NhiType::AiAgent);
///
/// // Aliases
/// assert_eq!("serviceaccount".parse::<NhiType>().unwrap(), NhiType::ServiceAccount);
/// assert_eq!("aiagent".parse::<NhiType>().unwrap(), NhiType::AiAgent);
/// assert_eq!("agent".parse::<NhiType>().unwrap(), NhiType::AiAgent);
///
/// // Case insensitive
/// assert_eq!("SERVICE_ACCOUNT".parse::<NhiType>().unwrap(), NhiType::ServiceAccount);
///
/// // Invalid values return error
/// assert!("invalid".parse::<NhiType>().is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NhiType {
    /// Traditional service account for machine-to-machine authentication.
    ///
    /// Service accounts are long-lived credentials used by applications,
    /// scripts, and automated processes. They typically have:
    /// - API keys or client certificates
    /// - Fixed permissions assigned at creation
    /// - Periodic credential rotation requirements
    ServiceAccount,

    /// AI/ML agent with tool access permissions.
    ///
    /// AI agents are autonomous systems that can invoke tools and make
    /// decisions. They require additional governance:
    /// - Tool permission boundaries
    /// - Human-in-the-loop controls
    /// - Audit logging of all actions
    AiAgent,
    // Future extensions:
    // RpaBot,
    // IotDevice,
    // KubernetesWorkload,
}

impl NhiType {
    /// Returns all known NHI types.
    #[must_use]
    pub fn all() -> &'static [NhiType] {
        &[NhiType::ServiceAccount, NhiType::AiAgent]
    }

    /// Returns the string representation used in database queries.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            NhiType::ServiceAccount => "service_account",
            NhiType::AiAgent => "ai_agent",
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
            "ai_agent" | "aiagent" | "agent" => Ok(NhiType::AiAgent),
            _ => Err(NhiTypeParseError(s.to_string())),
        }
    }
}

/// Error returned when parsing an invalid NHI type string.
///
/// This error is returned by [`NhiType::from_str`] when the input string
/// doesn't match any known NHI type or alias.
///
/// # Example
///
/// ```rust
/// use xavyo_nhi::NhiType;
/// use std::str::FromStr;
///
/// // Valid parsing succeeds
/// assert!(NhiType::from_str("service_account").is_ok());
/// assert!(NhiType::from_str("agent").is_ok()); // alias
///
/// // Invalid parsing returns error with helpful message
/// let err = NhiType::from_str("invalid_type").unwrap_err();
/// assert!(err.to_string().contains("invalid NHI type"));
/// assert!(err.to_string().contains("invalid_type"));
/// assert!(err.to_string().contains("service_account"));
/// assert!(err.to_string().contains("ai_agent"));
///
/// // Empty string also fails
/// let err = NhiType::from_str("").unwrap_err();
/// assert!(err.to_string().contains("invalid NHI type"));
/// ```
#[derive(Debug, Clone)]
pub struct NhiTypeParseError(pub String);

impl fmt::Display for NhiTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid NHI type '{}': expected 'service_account' or 'ai_agent'",
            self.0
        )
    }
}

impl std::error::Error for NhiTypeParseError {}

/// Normalized status across all NHI types.
///
/// Provides a unified status model that maps from type-specific
/// status enums used by service accounts and AI agents. This enables
/// consistent governance workflows regardless of NHI type.
///
/// # Serialization
///
/// Serializes to `snake_case` strings:
///
/// ```rust
/// use xavyo_nhi::NhiStatus;
///
/// // All status values
/// assert_eq!(serde_json::to_string(&NhiStatus::Active).unwrap(), "\"active\"");
/// assert_eq!(serde_json::to_string(&NhiStatus::Inactive).unwrap(), "\"inactive\"");
/// assert_eq!(serde_json::to_string(&NhiStatus::Suspended).unwrap(), "\"suspended\"");
/// assert_eq!(serde_json::to_string(&NhiStatus::PendingCertification).unwrap(), "\"pending_certification\"");
/// assert_eq!(serde_json::to_string(&NhiStatus::Expired).unwrap(), "\"expired\"");
/// assert_eq!(serde_json::to_string(&NhiStatus::Revoked).unwrap(), "\"revoked\"");
///
/// // Round-trip
/// let status: NhiStatus = serde_json::from_str("\"suspended\"").unwrap();
/// assert_eq!(status, NhiStatus::Suspended);
/// ```
///
/// # Parsing
///
/// Parses from strings (case-insensitive, with aliases):
///
/// ```rust
/// use xavyo_nhi::NhiStatus;
///
/// // Standard forms
/// assert_eq!("active".parse::<NhiStatus>().unwrap(), NhiStatus::Active);
/// assert_eq!("pending_certification".parse::<NhiStatus>().unwrap(), NhiStatus::PendingCertification);
///
/// // Alias without underscore
/// assert_eq!("pendingcertification".parse::<NhiStatus>().unwrap(), NhiStatus::PendingCertification);
///
/// // Case insensitive
/// assert_eq!("ACTIVE".parse::<NhiStatus>().unwrap(), NhiStatus::Active);
/// ```
///
/// # Status Helpers
///
/// ```rust
/// use xavyo_nhi::NhiStatus;
///
/// // Check if identity can be used
/// assert!(NhiStatus::Active.is_usable());
/// assert!(!NhiStatus::Suspended.is_usable());
///
/// // Check if admin attention needed
/// assert!(!NhiStatus::Active.requires_attention());
/// assert!(NhiStatus::Suspended.requires_attention());
/// assert!(NhiStatus::PendingCertification.requires_attention());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NhiStatus {
    /// Identity is active and can be used for authentication/authorization.
    Active,

    /// Identity exists but has not been used recently.
    /// May transition to Suspended if staleness exceeds threshold.
    Inactive,

    /// Identity has been suspended (manual or automatic).
    /// Requires admin review to reactivate.
    Suspended,

    /// Identity is awaiting periodic certification review.
    /// Cannot be used until owner re-certifies access.
    PendingCertification,

    /// Identity has passed its expiration date.
    /// Must be renewed or deleted.
    Expired,

    /// Identity has been permanently revoked.
    /// Cannot be reactivated; must create new identity.
    Revoked,
}

impl NhiStatus {
    /// Returns the string representation used in database queries.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            NhiStatus::Active => "active",
            NhiStatus::Inactive => "inactive",
            NhiStatus::Suspended => "suspended",
            NhiStatus::PendingCertification => "pending_certification",
            NhiStatus::Expired => "expired",
            NhiStatus::Revoked => "revoked",
        }
    }

    /// Returns true if this status allows the identity to be used.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        matches!(self, NhiStatus::Active)
    }

    /// Returns true if this status requires attention from administrators.
    #[must_use]
    pub fn requires_attention(&self) -> bool {
        matches!(
            self,
            NhiStatus::Suspended | NhiStatus::PendingCertification | NhiStatus::Expired
        )
    }
}

impl fmt::Display for NhiStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for NhiStatus {
    type Err = NhiStatusParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(NhiStatus::Active),
            "inactive" => Ok(NhiStatus::Inactive),
            "suspended" => Ok(NhiStatus::Suspended),
            "pending_certification" | "pendingcertification" => Ok(NhiStatus::PendingCertification),
            "expired" => Ok(NhiStatus::Expired),
            "revoked" => Ok(NhiStatus::Revoked),
            _ => Err(NhiStatusParseError(s.to_string())),
        }
    }
}

/// Error returned when parsing an invalid NHI status string.
///
/// This error is returned by [`NhiStatus::from_str`] when the input string
/// doesn't match any known status value.
///
/// # Example
///
/// ```rust
/// use xavyo_nhi::NhiStatus;
/// use std::str::FromStr;
///
/// // Valid parsing succeeds
/// assert!(NhiStatus::from_str("active").is_ok());
/// assert!(NhiStatus::from_str("pending_certification").is_ok());
/// assert!(NhiStatus::from_str("pendingcertification").is_ok()); // alias
///
/// // Invalid parsing returns error with helpful message
/// let err = NhiStatus::from_str("invalid_status").unwrap_err();
/// let msg = err.to_string();
/// assert!(msg.contains("invalid NHI status"));
/// assert!(msg.contains("invalid_status"));
/// // Error lists all valid options
/// assert!(msg.contains("active"));
/// assert!(msg.contains("suspended"));
/// assert!(msg.contains("expired"));
///
/// // Empty string also fails
/// let err = NhiStatus::from_str("").unwrap_err();
/// assert!(err.to_string().contains("invalid NHI status"));
/// ```
#[derive(Debug, Clone)]
pub struct NhiStatusParseError(pub String);

impl fmt::Display for NhiStatusParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid NHI status '{}': expected one of: active, inactive, suspended, pending_certification, expired, revoked", self.0)
    }
}

impl std::error::Error for NhiStatusParseError {}

/// Risk level derived from a numeric risk score.
///
/// Risk scores are normalized to a 0-100 scale and then
/// categorized into discrete levels for reporting and alerting.
/// This enum implements [`Ord`], so risk levels can be compared directly.
///
/// # Serialization
///
/// Serializes to `snake_case` strings:
///
/// ```rust
/// use xavyo_nhi::NhiRiskLevel;
///
/// assert_eq!(serde_json::to_string(&NhiRiskLevel::Low).unwrap(), "\"low\"");
/// assert_eq!(serde_json::to_string(&NhiRiskLevel::Medium).unwrap(), "\"medium\"");
/// assert_eq!(serde_json::to_string(&NhiRiskLevel::High).unwrap(), "\"high\"");
/// assert_eq!(serde_json::to_string(&NhiRiskLevel::Critical).unwrap(), "\"critical\"");
///
/// // Round-trip
/// let level: NhiRiskLevel = serde_json::from_str("\"high\"").unwrap();
/// assert_eq!(level, NhiRiskLevel::High);
/// ```
///
/// # From Score
///
/// Convert numeric scores (0-100) to risk levels:
///
/// ```rust
/// use xavyo_nhi::NhiRiskLevel;
///
/// assert_eq!(NhiRiskLevel::from(0u32), NhiRiskLevel::Low);
/// assert_eq!(NhiRiskLevel::from(25u32), NhiRiskLevel::Low);
/// assert_eq!(NhiRiskLevel::from(26u32), NhiRiskLevel::Medium);
/// assert_eq!(NhiRiskLevel::from(51u32), NhiRiskLevel::High);
/// assert_eq!(NhiRiskLevel::from(76u32), NhiRiskLevel::Critical);
///
/// // Negative i32 values clamp to Low
/// assert_eq!(NhiRiskLevel::from(-10i32), NhiRiskLevel::Low);
/// ```
///
/// # Ordering & Alerting
///
/// Risk levels can be compared and used for alerting decisions:
///
/// ```rust
/// use xavyo_nhi::NhiRiskLevel;
///
/// // Levels are ordered Low < Medium < High < Critical
/// assert!(NhiRiskLevel::Low < NhiRiskLevel::Medium);
/// assert!(NhiRiskLevel::Medium < NhiRiskLevel::High);
/// assert!(NhiRiskLevel::High < NhiRiskLevel::Critical);
///
/// // High and Critical should trigger alerts
/// assert!(!NhiRiskLevel::Low.should_alert());
/// assert!(!NhiRiskLevel::Medium.should_alert());
/// assert!(NhiRiskLevel::High.should_alert());
/// assert!(NhiRiskLevel::Critical.should_alert());
///
/// // Score ranges
/// assert_eq!(NhiRiskLevel::Low.min_score(), 0);
/// assert_eq!(NhiRiskLevel::Low.max_score(), 25);
/// assert_eq!(NhiRiskLevel::Critical.min_score(), 76);
/// assert_eq!(NhiRiskLevel::Critical.max_score(), 100);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
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

    #[test]
    fn test_nhi_type_serialization() {
        assert_eq!(
            serde_json::to_string(&NhiType::ServiceAccount).unwrap(),
            "\"service_account\""
        );
        assert_eq!(
            serde_json::to_string(&NhiType::AiAgent).unwrap(),
            "\"ai_agent\""
        );
    }

    #[test]
    fn test_nhi_type_deserialization() {
        assert_eq!(
            serde_json::from_str::<NhiType>("\"service_account\"").unwrap(),
            NhiType::ServiceAccount
        );
        assert_eq!(
            serde_json::from_str::<NhiType>("\"ai_agent\"").unwrap(),
            NhiType::AiAgent
        );
    }

    #[test]
    fn test_nhi_type_from_str() {
        assert_eq!(
            "service_account".parse::<NhiType>().unwrap(),
            NhiType::ServiceAccount
        );
        assert_eq!("ai_agent".parse::<NhiType>().unwrap(), NhiType::AiAgent);
        assert_eq!("agent".parse::<NhiType>().unwrap(), NhiType::AiAgent);
        assert!("invalid".parse::<NhiType>().is_err());
    }

    #[test]
    fn test_nhi_type_display() {
        assert_eq!(NhiType::ServiceAccount.to_string(), "service_account");
        assert_eq!(NhiType::AiAgent.to_string(), "ai_agent");
    }

    #[test]
    fn test_nhi_status_serialization() {
        assert_eq!(
            serde_json::to_string(&NhiStatus::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&NhiStatus::PendingCertification).unwrap(),
            "\"pending_certification\""
        );
    }

    #[test]
    fn test_nhi_status_is_usable() {
        assert!(NhiStatus::Active.is_usable());
        assert!(!NhiStatus::Suspended.is_usable());
        assert!(!NhiStatus::Expired.is_usable());
    }

    #[test]
    fn test_nhi_status_requires_attention() {
        assert!(!NhiStatus::Active.requires_attention());
        assert!(NhiStatus::Suspended.requires_attention());
        assert!(NhiStatus::PendingCertification.requires_attention());
        assert!(NhiStatus::Expired.requires_attention());
    }

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

    // T040: Serialization round-trip test for all types
    #[test]
    fn test_serialization_round_trip_all_types() {
        // NhiType round-trip
        for nhi_type in NhiType::all() {
            let json = serde_json::to_string(nhi_type).unwrap();
            let deserialized: NhiType = serde_json::from_str(&json).unwrap();
            assert_eq!(
                *nhi_type, deserialized,
                "NhiType round-trip failed for {nhi_type:?}"
            );
        }

        // NhiStatus round-trip
        let all_statuses = [
            NhiStatus::Active,
            NhiStatus::Inactive,
            NhiStatus::Suspended,
            NhiStatus::PendingCertification,
            NhiStatus::Expired,
            NhiStatus::Revoked,
        ];
        for status in &all_statuses {
            let json = serde_json::to_string(status).unwrap();
            let deserialized: NhiStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(
                *status, deserialized,
                "NhiStatus round-trip failed for {status:?}"
            );
        }

        // NhiRiskLevel round-trip
        let all_levels = [
            NhiRiskLevel::Low,
            NhiRiskLevel::Medium,
            NhiRiskLevel::High,
            NhiRiskLevel::Critical,
        ];
        for level in &all_levels {
            let json = serde_json::to_string(level).unwrap();
            let deserialized: NhiRiskLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(
                *level, deserialized,
                "NhiRiskLevel round-trip failed for {level:?}"
            );
        }
    }

    // T045: Parsing empty string
    #[test]
    fn test_parse_empty_string() {
        // Empty string should fail for NhiType
        let result = "".parse::<NhiType>();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid NHI type"));

        // Empty string should fail for NhiStatus
        let result = "".parse::<NhiStatus>();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid NHI status"));
    }

    // T046: All alias variants
    #[test]
    fn test_nhi_type_all_aliases() {
        // ServiceAccount aliases
        assert_eq!(
            "service_account".parse::<NhiType>().unwrap(),
            NhiType::ServiceAccount
        );
        assert_eq!(
            "serviceaccount".parse::<NhiType>().unwrap(),
            NhiType::ServiceAccount
        );
        assert_eq!(
            "SERVICE_ACCOUNT".parse::<NhiType>().unwrap(),
            NhiType::ServiceAccount
        );
        assert_eq!(
            "ServiceAccount".parse::<NhiType>().unwrap(),
            NhiType::ServiceAccount
        );

        // AiAgent aliases
        assert_eq!("ai_agent".parse::<NhiType>().unwrap(), NhiType::AiAgent);
        assert_eq!("aiagent".parse::<NhiType>().unwrap(), NhiType::AiAgent);
        assert_eq!("agent".parse::<NhiType>().unwrap(), NhiType::AiAgent);
        assert_eq!("AI_AGENT".parse::<NhiType>().unwrap(), NhiType::AiAgent);
        assert_eq!("AGENT".parse::<NhiType>().unwrap(), NhiType::AiAgent);
    }

    #[test]
    fn test_nhi_status_all_aliases() {
        // All standard status values
        assert_eq!("active".parse::<NhiStatus>().unwrap(), NhiStatus::Active);
        assert_eq!(
            "inactive".parse::<NhiStatus>().unwrap(),
            NhiStatus::Inactive
        );
        assert_eq!(
            "suspended".parse::<NhiStatus>().unwrap(),
            NhiStatus::Suspended
        );
        assert_eq!("expired".parse::<NhiStatus>().unwrap(), NhiStatus::Expired);
        assert_eq!("revoked".parse::<NhiStatus>().unwrap(), NhiStatus::Revoked);

        // PendingCertification aliases
        assert_eq!(
            "pending_certification".parse::<NhiStatus>().unwrap(),
            NhiStatus::PendingCertification
        );
        assert_eq!(
            "pendingcertification".parse::<NhiStatus>().unwrap(),
            NhiStatus::PendingCertification
        );
        assert_eq!(
            "PENDING_CERTIFICATION".parse::<NhiStatus>().unwrap(),
            NhiStatus::PendingCertification
        );
        assert_eq!(
            "PendingCertification".parse::<NhiStatus>().unwrap(),
            NhiStatus::PendingCertification
        );

        // Case insensitivity for all
        assert_eq!("ACTIVE".parse::<NhiStatus>().unwrap(), NhiStatus::Active);
        assert_eq!(
            "SUSPENDED".parse::<NhiStatus>().unwrap(),
            NhiStatus::Suspended
        );
        assert_eq!("Expired".parse::<NhiStatus>().unwrap(), NhiStatus::Expired);
    }

    #[test]
    fn test_nhi_risk_level_serialization_all() {
        // Verify all risk levels serialize correctly
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

        // And deserialize correctly
        assert_eq!(
            serde_json::from_str::<NhiRiskLevel>("\"low\"").unwrap(),
            NhiRiskLevel::Low
        );
        assert_eq!(
            serde_json::from_str::<NhiRiskLevel>("\"medium\"").unwrap(),
            NhiRiskLevel::Medium
        );
        assert_eq!(
            serde_json::from_str::<NhiRiskLevel>("\"high\"").unwrap(),
            NhiRiskLevel::High
        );
        assert_eq!(
            serde_json::from_str::<NhiRiskLevel>("\"critical\"").unwrap(),
            NhiRiskLevel::Critical
        );
    }

    #[test]
    fn test_nhi_status_serialization_all() {
        // Verify all statuses serialize correctly
        assert_eq!(
            serde_json::to_string(&NhiStatus::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&NhiStatus::Inactive).unwrap(),
            "\"inactive\""
        );
        assert_eq!(
            serde_json::to_string(&NhiStatus::Suspended).unwrap(),
            "\"suspended\""
        );
        assert_eq!(
            serde_json::to_string(&NhiStatus::PendingCertification).unwrap(),
            "\"pending_certification\""
        );
        assert_eq!(
            serde_json::to_string(&NhiStatus::Expired).unwrap(),
            "\"expired\""
        );
        assert_eq!(
            serde_json::to_string(&NhiStatus::Revoked).unwrap(),
            "\"revoked\""
        );
    }
}
