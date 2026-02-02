//! Connector Framework ID types
//!
//! Newtype wrappers for type-safe identifiers.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Unique identifier for a connector configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConnectorId(Uuid);

impl ConnectorId {
    /// Create a new random ConnectorId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a ConnectorId from an existing UUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID value.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Parse from a string representation.
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl Default for ConnectorId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ConnectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for ConnectorId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl From<Uuid> for ConnectorId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<ConnectorId> for Uuid {
    fn from(id: ConnectorId) -> Self {
        id.0
    }
}

/// Unique identifier for a provisioning operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperationId(Uuid);

impl OperationId {
    /// Create a new random OperationId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create an OperationId from an existing UUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID value.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Parse from a string representation.
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl Default for OperationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for OperationId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl From<Uuid> for OperationId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<OperationId> for Uuid {
    fn from(id: OperationId) -> Self {
        id.0
    }
}

/// Unique identifier for a schema entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SchemaId(Uuid);

impl SchemaId {
    /// Create a new random SchemaId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a SchemaId from an existing UUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID value.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Parse from a string representation.
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl Default for SchemaId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SchemaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for SchemaId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl From<Uuid> for SchemaId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<SchemaId> for Uuid {
    fn from(id: SchemaId) -> Self {
        id.0
    }
}

/// Unique identifier for an attribute mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MappingId(Uuid);

impl MappingId {
    /// Create a new random MappingId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a MappingId from an existing UUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID value.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Parse from a string representation.
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl Default for MappingId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MappingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for MappingId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl From<Uuid> for MappingId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<MappingId> for Uuid {
    fn from(id: MappingId) -> Self {
        id.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connector_id_new() {
        let id1 = ConnectorId::new();
        let id2 = ConnectorId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_connector_id_from_uuid() {
        let uuid = Uuid::new_v4();
        let id = ConnectorId::from_uuid(uuid);
        assert_eq!(id.as_uuid(), uuid);
    }

    #[test]
    fn test_connector_id_parse() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let id = ConnectorId::parse(uuid_str).unwrap();
        assert_eq!(id.to_string(), uuid_str);
    }

    #[test]
    fn test_connector_id_from_str() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let id: ConnectorId = uuid_str.parse().unwrap();
        assert_eq!(id.to_string(), uuid_str);
    }

    #[test]
    fn test_connector_id_serialization() {
        let id = ConnectorId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"550e8400-e29b-41d4-a716-446655440000\"");

        let parsed: ConnectorId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn test_operation_id_new() {
        let id1 = OperationId::new();
        let id2 = OperationId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_operation_id_from_uuid() {
        let uuid = Uuid::new_v4();
        let id = OperationId::from_uuid(uuid);
        assert_eq!(id.as_uuid(), uuid);
    }

    #[test]
    fn test_schema_id_new() {
        let id1 = SchemaId::new();
        let id2 = SchemaId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_mapping_id_new() {
        let id1 = MappingId::new();
        let id2 = MappingId::new();
        assert_ne!(id1, id2);
    }
}
