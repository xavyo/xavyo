//! Core type definitions for Non-Human Identities.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Type of non-human identity.
///
/// Distinguishes between different categories of automated identities
/// that require governance and lifecycle management.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NhiType {
    /// Traditional service account for machine-to-machine authentication
    ServiceAccount,
    /// AI/ML agent with tool access permissions
    AiAgent,
    // Future extensions:
    // RpaBot,
    // IotDevice,
    // KubernetesWorkload,
}

impl NhiType {
    /// Returns all known NHI types.
    pub fn all() -> &'static [NhiType] {
        &[NhiType::ServiceAccount, NhiType::AiAgent]
    }

    /// Returns the string representation used in database queries.
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
/// status enums used by service accounts and AI agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NhiStatus {
    /// Identity is active and can be used
    Active,
    /// Identity exists but has not been used recently
    Inactive,
    /// Identity has been suspended (manual or automatic)
    Suspended,
    /// Identity is awaiting certification review
    PendingCertification,
    /// Identity has passed its expiration date
    Expired,
    /// Identity has been permanently revoked
    Revoked,
}

impl NhiStatus {
    /// Returns the string representation used in database queries.
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
    pub fn is_usable(&self) -> bool {
        matches!(self, NhiStatus::Active)
    }

    /// Returns true if this status requires attention from administrators.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum NhiRiskLevel {
    /// Low risk (score 0-25)
    Low,
    /// Medium risk (score 26-50)
    Medium,
    /// High risk (score 51-75)
    High,
    /// Critical risk (score 76-100)
    Critical,
}

impl NhiRiskLevel {
    /// Returns the minimum score for this risk level.
    pub fn min_score(&self) -> u32 {
        match self {
            NhiRiskLevel::Low => 0,
            NhiRiskLevel::Medium => 26,
            NhiRiskLevel::High => 51,
            NhiRiskLevel::Critical => 76,
        }
    }

    /// Returns the maximum score for this risk level.
    pub fn max_score(&self) -> u32 {
        match self {
            NhiRiskLevel::Low => 25,
            NhiRiskLevel::Medium => 50,
            NhiRiskLevel::High => 75,
            NhiRiskLevel::Critical => 100,
        }
    }

    /// Returns the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            NhiRiskLevel::Low => "low",
            NhiRiskLevel::Medium => "medium",
            NhiRiskLevel::High => "high",
            NhiRiskLevel::Critical => "critical",
        }
    }

    /// Returns true if this risk level should trigger alerts.
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
}
