//! # Connector Framework
//!
//! Core abstractions for connecting xavyo to external identity systems.
//!
//! This crate provides the foundation for provisioning users, groups, and
//! other identity objects to external systems like LDAP/Active Directory,
//! databases, and REST APIs.
//!
//! ## Architecture
//!
//! The framework uses a capability-based trait system inspired by `ConnId`:
//!
//! - [`Connector`] - Base trait all connectors implement
//! - [`SchemaDiscovery`] - Discover target system schema
//! - [`CreateOp`], [`UpdateOp`], [`DeleteOp`] - CRUD operations
//! - [`SearchOp`] - Search and retrieve objects
//!
//! ## Example
//!
//! ```ignore
//! use xavyo_connector::prelude::*;
//!
//! // Create a registry and register connector factories
//! let registry = ConnectorRegistry::new();
//! registry.register_factory(ConnectorType::Ldap, ldap_factory).await;
//!
//! // Create a connector instance
//! let connector = registry.get_or_create(
//!     connector_id,
//!     ConnectorType::Ldap,
//!     config_json,
//! ).await?;
//!
//! // Test connection
//! connector.test_connection().await?;
//!
//! // Discover schema
//! let schema = connector.discover_schema().await?;
//!
//! // Create a user
//! let attrs = AttributeSet::new()
//!     .with("email", "user@example.com")
//!     .with("name", "John Doe");
//! let uid = connector.create("user", attrs).await?;
//! ```
//!
//! ## Features
//!
//! - **Capability-based traits**: Connectors only implement what they support
//! - **Per-tenant encryption**: Credentials encrypted with tenant-specific keys
//! - **Schema discovery**: Auto-discover target system schemas
//! - **Type-safe operations**: Strong typing for UIDs, attributes, and filters
//! - **Connection pooling**: Efficient resource management
//!
//! ## Crate Organization
//!
//! - [`ids`] - Type-safe identifiers (`ConnectorId`, `OperationId`, etc.)
//! - [`types`] - Enums and status types
//! - [`error`] - Error types with transient/permanent classification
//! - [`traits`] - Connector capability traits
//! - [`schema`] - Schema types (`ObjectClass`, `SchemaAttribute`)
//! - [`operation`] - Operation types (Uid, `AttributeSet`, Filter)
//! - [`config`] - Configuration types and traits
//! - [`crypto`] - Credential encryption
//! - [`registry`] - Connector factory and instance management

pub mod config;
pub mod crypto;
pub mod error;
pub mod ids;
pub mod mapping;
pub mod operation;
pub mod registry;
pub mod resilience;
pub mod schema;
pub mod traits;
pub mod transform;
pub mod types;

/// Prelude module for convenient imports.
///
/// ```
/// use xavyo_connector::prelude::*;
/// ```
pub mod prelude {
    // IDs
    pub use crate::ids::{ConnectorId, MappingId, OperationId, SchemaId};

    // Types and enums
    pub use crate::types::{
        CircuitState, ConnectorStatus, ConnectorType, DeprovisionAction, HealthStatus,
        OperationStatus, OperationType,
    };

    // Error handling
    pub use crate::error::{ConnectorError, ConnectorResult};

    // Traits
    pub use crate::traits::{
        Connector, CreateOp, DeleteOp, DisableOp, FullCrud, GroupOp, PasswordOp, SchemaDiscovery,
        SearchOp, SyncCapable, SyncChange, SyncChangeType, SyncMode, SyncResult, UpdateOp,
    };

    // Schema
    pub use crate::schema::{AttributeDataType, ObjectClass, Schema, SchemaAttribute};

    // Operations
    pub use crate::operation::{
        AttributeDelta, AttributeSet, AttributeValue, Filter, PageRequest, SearchResult, Uid,
    };

    // Configuration
    pub use crate::config::{AuthConfig, ConnectionSettings, ConnectorConfig, TlsConfig};

    // Registry
    pub use crate::registry::{BoxedConnector, ConnectorFactory, ConnectorRegistry};

    // Crypto
    pub use crate::crypto::CredentialEncryption;

    // Resilience
    pub use crate::resilience::{
        CircuitBreaker, CircuitBreakerConfig, ResilientConnector, RetryConfig, RetryExecutor,
    };

    // Mapping
    pub use crate::mapping::{
        AttributeSource, CorrelationMatchType, CorrelationRule, MappingConfiguration, MappingError,
        MappingResult, MappingRule, Transform,
    };

    // Transform engine
    pub use crate::transform::TransformEngine;
}

// Re-export async_trait for connector implementors
pub use async_trait::async_trait;

#[cfg(test)]
mod tests {
    use super::prelude::*;

    #[test]
    fn test_prelude_imports() {
        // Verify all prelude types are accessible
        let _id = ConnectorId::new();
        let _ct = ConnectorType::Ldap;
        let _cs = ConnectorStatus::Active;
        let _os = OperationStatus::Pending;
        let _ot = OperationType::Create;
        let _uid = Uid::from_dn("cn=test,dc=example,dc=com");
        let _attrs = AttributeSet::new().with("name", "test");
        let _filter = Filter::eq("email", "test@example.com");
    }
}
