//! Connector Framework type definitions
//!
//! Enums and types for connector configuration and operations.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Type of connector for external system integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectorType {
    /// LDAP/Active Directory connector
    Ldap,
    /// Database connector (`PostgreSQL`, `MySQL`, etc.)
    Database,
    /// REST API connector
    Rest,
}

impl ConnectorType {
    /// Get all available connector types.
    #[must_use]
    pub fn all() -> &'static [ConnectorType] {
        &[
            ConnectorType::Ldap,
            ConnectorType::Database,
            ConnectorType::Rest,
        ]
    }

    /// Get the string representation used in the database.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectorType::Ldap => "ldap",
            ConnectorType::Database => "database",
            ConnectorType::Rest => "rest",
        }
    }
}

impl fmt::Display for ConnectorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ConnectorType {
    type Err = ParseConnectorTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ldap" => Ok(ConnectorType::Ldap),
            "database" => Ok(ConnectorType::Database),
            "rest" => Ok(ConnectorType::Rest),
            _ => Err(ParseConnectorTypeError(s.to_string())),
        }
    }
}

/// Error parsing connector type from string.
#[derive(Debug, Clone)]
pub struct ParseConnectorTypeError(String);

impl fmt::Display for ParseConnectorTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid connector type '{}', expected one of: ldap, database, rest",
            self.0
        )
    }
}

impl std::error::Error for ParseConnectorTypeError {}

/// Status of a connector configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConnectorStatus {
    /// Connector is active and can be used for provisioning
    Active,
    /// Connector is inactive (default state)
    #[default]
    Inactive,
    /// Connector is in error state (connection failed)
    Error,
}

impl ConnectorStatus {
    /// Get the string representation used in the database.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectorStatus::Active => "active",
            ConnectorStatus::Inactive => "inactive",
            ConnectorStatus::Error => "error",
        }
    }

    /// Check if the connector is usable for provisioning.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        matches!(self, ConnectorStatus::Active)
    }
}

impl fmt::Display for ConnectorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ConnectorStatus {
    type Err = ParseConnectorStatusError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(ConnectorStatus::Active),
            "inactive" => Ok(ConnectorStatus::Inactive),
            "error" => Ok(ConnectorStatus::Error),
            _ => Err(ParseConnectorStatusError(s.to_string())),
        }
    }
}

/// Error parsing connector status from string.
#[derive(Debug, Clone)]
pub struct ParseConnectorStatusError(String);

impl fmt::Display for ParseConnectorStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid connector status '{}', expected one of: active, inactive, error",
            self.0
        )
    }
}

impl std::error::Error for ParseConnectorStatusError {}

/// Type of provisioning operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperationType {
    /// Create a new object in the target system
    Create,
    /// Update an existing object in the target system
    Update,
    /// Delete an object from the target system
    Delete,
}

impl OperationType {
    /// Get the string representation used in the database.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            OperationType::Create => "create",
            OperationType::Update => "update",
            OperationType::Delete => "delete",
        }
    }
}

impl fmt::Display for OperationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for OperationType {
    type Err = ParseOperationTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "create" => Ok(OperationType::Create),
            "update" => Ok(OperationType::Update),
            "delete" => Ok(OperationType::Delete),
            _ => Err(ParseOperationTypeError(s.to_string())),
        }
    }
}

/// Error parsing operation type from string.
#[derive(Debug, Clone)]
pub struct ParseOperationTypeError(String);

impl fmt::Display for ParseOperationTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid operation type '{}', expected one of: create, update, delete",
            self.0
        )
    }
}

impl std::error::Error for ParseOperationTypeError {}

/// Status of a provisioning operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    /// Operation is queued and waiting to be processed
    #[default]
    Pending,
    /// Operation is currently being executed
    InProgress,
    /// Operation completed successfully
    Completed,
    /// Operation failed (may be retried if transient)
    Failed,
    /// Operation moved to dead letter queue after max retries
    DeadLetter,
    /// Operation is waiting for target system to come online
    AwaitingSystem,
    /// Operation was manually resolved (acknowledged failure)
    Resolved,
    /// Operation was cancelled before execution
    Cancelled,
}

impl OperationStatus {
    /// Get the string representation used in the database.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            OperationStatus::Pending => "pending",
            OperationStatus::InProgress => "in_progress",
            OperationStatus::Completed => "completed",
            OperationStatus::Failed => "failed",
            OperationStatus::DeadLetter => "dead_letter",
            OperationStatus::AwaitingSystem => "awaiting_system",
            OperationStatus::Resolved => "resolved",
            OperationStatus::Cancelled => "cancelled",
        }
    }

    /// Check if the operation is in a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            OperationStatus::Completed
                | OperationStatus::DeadLetter
                | OperationStatus::Resolved
                | OperationStatus::Cancelled
        )
    }

    /// Check if the operation can be retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            OperationStatus::Pending | OperationStatus::Failed | OperationStatus::DeadLetter
        )
    }

    /// Check if the operation is actively being processed.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            OperationStatus::Pending
                | OperationStatus::InProgress
                | OperationStatus::Failed
                | OperationStatus::AwaitingSystem
        )
    }

    /// Check if the operation is waiting for external system.
    #[must_use]
    pub fn is_waiting(&self) -> bool {
        matches!(self, OperationStatus::AwaitingSystem)
    }
}

impl fmt::Display for OperationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for OperationStatus {
    type Err = ParseOperationStatusError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(OperationStatus::Pending),
            "in_progress" => Ok(OperationStatus::InProgress),
            "completed" => Ok(OperationStatus::Completed),
            "failed" => Ok(OperationStatus::Failed),
            "dead_letter" => Ok(OperationStatus::DeadLetter),
            "awaiting_system" => Ok(OperationStatus::AwaitingSystem),
            "resolved" => Ok(OperationStatus::Resolved),
            "cancelled" => Ok(OperationStatus::Cancelled),
            _ => Err(ParseOperationStatusError(s.to_string())),
        }
    }
}

/// Error parsing operation status from string.
#[derive(Debug, Clone)]
pub struct ParseOperationStatusError(String);

impl fmt::Display for ParseOperationStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid operation status '{}', expected one of: pending, in_progress, completed, failed, dead_letter, awaiting_system, resolved, cancelled",
            self.0
        )
    }
}

impl std::error::Error for ParseOperationStatusError {}

/// Health status of a connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Connector is connected and operational
    Connected,
    /// Connector is experiencing issues but still functional
    Degraded,
    /// Connector is disconnected
    #[default]
    Disconnected,
}

impl HealthStatus {
    /// Get the string representation used in the database.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            HealthStatus::Connected => "connected",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Disconnected => "disconnected",
        }
    }

    /// Check if the connector is healthy enough to process operations.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthStatus::Connected | HealthStatus::Degraded)
    }
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for HealthStatus {
    type Err = ParseHealthStatusError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "connected" => Ok(HealthStatus::Connected),
            "degraded" => Ok(HealthStatus::Degraded),
            "disconnected" => Ok(HealthStatus::Disconnected),
            _ => Err(ParseHealthStatusError(s.to_string())),
        }
    }
}

/// Error parsing health status from string.
#[derive(Debug, Clone)]
pub struct ParseHealthStatusError(String);

impl fmt::Display for ParseHealthStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid health status '{}', expected one of: connected, degraded, disconnected",
            self.0
        )
    }
}

impl std::error::Error for ParseHealthStatusError {}

/// Circuit breaker state for connector health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    /// Circuit is closed, operations are processed normally
    #[default]
    Closed,
    /// Circuit is open, operations are rejected
    Open,
    /// Circuit is half-open, probe operations are allowed
    HalfOpen,
}

impl CircuitState {
    /// Get the string representation used in the database.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            CircuitState::Closed => "closed",
            CircuitState::Open => "open",
            CircuitState::HalfOpen => "half_open",
        }
    }

    /// Check if operations should be allowed through.
    #[must_use]
    pub fn allows_operations(&self) -> bool {
        matches!(self, CircuitState::Closed | CircuitState::HalfOpen)
    }
}

impl fmt::Display for CircuitState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for CircuitState {
    type Err = ParseCircuitStateError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "closed" => Ok(CircuitState::Closed),
            "open" => Ok(CircuitState::Open),
            "half_open" => Ok(CircuitState::HalfOpen),
            _ => Err(ParseCircuitStateError(s.to_string())),
        }
    }
}

/// Error parsing circuit state from string.
#[derive(Debug, Clone)]
pub struct ParseCircuitStateError(String);

impl fmt::Display for ParseCircuitStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid circuit state '{}', expected one of: closed, open, half_open",
            self.0
        )
    }
}

impl std::error::Error for ParseCircuitStateError {}

/// Action to take when deprovisioning a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeprovisionAction {
    /// Do nothing (leave account as-is).
    None,
    /// Disable the account in the target system (set status flag).
    #[default]
    Disable,
    /// Delete the account from the target system.
    Delete,
    /// Move to a different container/OU.
    Move,
    /// Rename with a prefix/suffix.
    Rename,
}

impl DeprovisionAction {
    /// Get the string representation used in the database.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            DeprovisionAction::None => "none",
            DeprovisionAction::Disable => "disable",
            DeprovisionAction::Delete => "delete",
            DeprovisionAction::Move => "move",
            DeprovisionAction::Rename => "rename",
        }
    }
}

impl fmt::Display for DeprovisionAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for DeprovisionAction {
    type Err = ParseDeprovisionActionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "disable" => Ok(DeprovisionAction::Disable),
            "delete" => Ok(DeprovisionAction::Delete),
            _ => Err(ParseDeprovisionActionError(s.to_string())),
        }
    }
}

/// Error parsing deprovision action from string.
#[derive(Debug, Clone)]
pub struct ParseDeprovisionActionError(String);

impl fmt::Display for ParseDeprovisionActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid deprovision action '{}', expected one of: disable, delete",
            self.0
        )
    }
}

impl std::error::Error for ParseDeprovisionActionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connector_type_from_str() {
        assert_eq!(
            "ldap".parse::<ConnectorType>().unwrap(),
            ConnectorType::Ldap
        );
        assert_eq!(
            "LDAP".parse::<ConnectorType>().unwrap(),
            ConnectorType::Ldap
        );
        assert_eq!(
            "database".parse::<ConnectorType>().unwrap(),
            ConnectorType::Database
        );
        assert_eq!(
            "rest".parse::<ConnectorType>().unwrap(),
            ConnectorType::Rest
        );
        assert!("invalid".parse::<ConnectorType>().is_err());
    }

    #[test]
    fn test_connector_type_serialization() {
        let ct = ConnectorType::Ldap;
        let json = serde_json::to_string(&ct).unwrap();
        assert_eq!(json, "\"ldap\"");

        let parsed: ConnectorType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ct);
    }

    #[test]
    fn test_connector_status_from_str() {
        assert_eq!(
            "active".parse::<ConnectorStatus>().unwrap(),
            ConnectorStatus::Active
        );
        assert_eq!(
            "inactive".parse::<ConnectorStatus>().unwrap(),
            ConnectorStatus::Inactive
        );
        assert_eq!(
            "error".parse::<ConnectorStatus>().unwrap(),
            ConnectorStatus::Error
        );
    }

    #[test]
    fn test_connector_status_is_usable() {
        assert!(ConnectorStatus::Active.is_usable());
        assert!(!ConnectorStatus::Inactive.is_usable());
        assert!(!ConnectorStatus::Error.is_usable());
    }

    #[test]
    fn test_operation_type_from_str() {
        assert_eq!(
            "create".parse::<OperationType>().unwrap(),
            OperationType::Create
        );
        assert_eq!(
            "update".parse::<OperationType>().unwrap(),
            OperationType::Update
        );
        assert_eq!(
            "delete".parse::<OperationType>().unwrap(),
            OperationType::Delete
        );
    }

    #[test]
    fn test_operation_status_from_str() {
        assert_eq!(
            "pending".parse::<OperationStatus>().unwrap(),
            OperationStatus::Pending
        );
        assert_eq!(
            "in_progress".parse::<OperationStatus>().unwrap(),
            OperationStatus::InProgress
        );
        assert_eq!(
            "completed".parse::<OperationStatus>().unwrap(),
            OperationStatus::Completed
        );
        assert_eq!(
            "failed".parse::<OperationStatus>().unwrap(),
            OperationStatus::Failed
        );
        assert_eq!(
            "dead_letter".parse::<OperationStatus>().unwrap(),
            OperationStatus::DeadLetter
        );
        assert_eq!(
            "awaiting_system".parse::<OperationStatus>().unwrap(),
            OperationStatus::AwaitingSystem
        );
        assert_eq!(
            "resolved".parse::<OperationStatus>().unwrap(),
            OperationStatus::Resolved
        );
        assert_eq!(
            "cancelled".parse::<OperationStatus>().unwrap(),
            OperationStatus::Cancelled
        );
    }

    #[test]
    fn test_operation_status_terminal() {
        assert!(!OperationStatus::Pending.is_terminal());
        assert!(!OperationStatus::InProgress.is_terminal());
        assert!(OperationStatus::Completed.is_terminal());
        assert!(!OperationStatus::Failed.is_terminal());
        assert!(OperationStatus::DeadLetter.is_terminal());
        assert!(!OperationStatus::AwaitingSystem.is_terminal());
        assert!(OperationStatus::Resolved.is_terminal());
        assert!(OperationStatus::Cancelled.is_terminal());
    }

    #[test]
    fn test_operation_status_retryable() {
        assert!(OperationStatus::Pending.is_retryable());
        assert!(!OperationStatus::InProgress.is_retryable());
        assert!(!OperationStatus::Completed.is_retryable());
        assert!(OperationStatus::Failed.is_retryable());
        assert!(OperationStatus::DeadLetter.is_retryable());
        assert!(!OperationStatus::AwaitingSystem.is_retryable());
        assert!(!OperationStatus::Resolved.is_retryable());
        assert!(!OperationStatus::Cancelled.is_retryable());
    }

    #[test]
    fn test_operation_status_waiting() {
        assert!(!OperationStatus::Pending.is_waiting());
        assert!(OperationStatus::AwaitingSystem.is_waiting());
        assert!(!OperationStatus::Failed.is_waiting());
    }

    #[test]
    fn test_health_status_from_str() {
        assert_eq!(
            "connected".parse::<HealthStatus>().unwrap(),
            HealthStatus::Connected
        );
        assert_eq!(
            "degraded".parse::<HealthStatus>().unwrap(),
            HealthStatus::Degraded
        );
        assert_eq!(
            "disconnected".parse::<HealthStatus>().unwrap(),
            HealthStatus::Disconnected
        );
    }

    #[test]
    fn test_health_status_is_healthy() {
        assert!(HealthStatus::Connected.is_healthy());
        assert!(HealthStatus::Degraded.is_healthy());
        assert!(!HealthStatus::Disconnected.is_healthy());
    }

    #[test]
    fn test_circuit_state_from_str() {
        assert_eq!(
            "closed".parse::<CircuitState>().unwrap(),
            CircuitState::Closed
        );
        assert_eq!("open".parse::<CircuitState>().unwrap(), CircuitState::Open);
        assert_eq!(
            "half_open".parse::<CircuitState>().unwrap(),
            CircuitState::HalfOpen
        );
    }

    #[test]
    fn test_circuit_state_allows_operations() {
        assert!(CircuitState::Closed.allows_operations());
        assert!(!CircuitState::Open.allows_operations());
        assert!(CircuitState::HalfOpen.allows_operations());
    }

    #[test]
    fn test_deprovision_action_from_str() {
        assert_eq!(
            "disable".parse::<DeprovisionAction>().unwrap(),
            DeprovisionAction::Disable
        );
        assert_eq!(
            "delete".parse::<DeprovisionAction>().unwrap(),
            DeprovisionAction::Delete
        );
    }
}
