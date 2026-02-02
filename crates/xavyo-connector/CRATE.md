# xavyo-connector

> Core abstractions for connecting xavyo to external identity systems (LDAP, REST, etc.).

## Purpose

Provides the foundation for provisioning users, groups, and other identity objects to external systems. Uses a capability-based trait system inspired by ConnId where connectors implement only the operations they support. Includes schema discovery, credential encryption, connection pooling, and retry logic with circuit breakers.

## Layer

domain

## Status

🟢 **stable**

Production-ready with comprehensive test coverage (137 tests). Mature connector framework with 79 public items and complete capability-based trait system.

## Dependencies

### Internal (xavyo)
None (standalone domain crate)

### External (key)
- `tokio` - Async runtime
- `async-trait` - Async trait support
- `aes-gcm` - Credential encryption
- `serde` - Configuration serialization

## Public API

### Types

```rust
/// Unique connector instance ID
pub struct ConnectorId(Uuid);

/// Unique operation ID
pub struct OperationId(Uuid);

/// Connector types supported
pub enum ConnectorType {
    Ldap,
    Database,
    Rest,
    Scim,
    Csv,
    Custom(String),
}

/// Connector lifecycle status
pub enum ConnectorStatus { Active, Disabled, Error }

/// Operation types
pub enum OperationType { Create, Update, Delete, Enable, Disable }

/// Unique identifier in target system
pub struct Uid { value: String }

/// Set of attributes for operations
pub struct AttributeSet { attrs: HashMap<String, AttributeValue> }

/// Search filter
pub enum Filter { Eq(String, String), And(Vec<Filter>), Or(Vec<Filter>), ... }

/// Schema types
pub struct Schema { object_classes: Vec<ObjectClass> }
pub struct ObjectClass { name: String, attributes: Vec<SchemaAttribute> }
pub struct SchemaAttribute { name: String, data_type: AttributeDataType, required: bool }

/// Connector configuration
pub struct ConnectorConfig { ... }

/// Credential encryption helper
pub struct CredentialEncryption { ... }

/// Circuit breaker for resilience
pub struct CircuitBreaker { ... }
```

### Traits

```rust
/// Base trait all connectors implement
#[async_trait]
pub trait Connector: Send + Sync {
    fn connector_type(&self) -> ConnectorType;
    async fn test_connection(&self) -> ConnectorResult<()>;
    async fn dispose(&self) -> ConnectorResult<()>;
}

/// Schema discovery capability
#[async_trait]
pub trait SchemaDiscovery: Connector {
    async fn discover_schema(&self) -> ConnectorResult<Schema>;
}

/// Create operation capability
#[async_trait]
pub trait CreateOp: Connector {
    async fn create(&self, object_class: &str, attrs: AttributeSet) -> ConnectorResult<Uid>;
}

/// Update operation capability
#[async_trait]
pub trait UpdateOp: Connector {
    async fn update(&self, object_class: &str, uid: &Uid, changes: Vec<AttributeDelta>) -> ConnectorResult<Uid>;
}

/// Delete operation capability
#[async_trait]
pub trait DeleteOp: Connector {
    async fn delete(&self, object_class: &str, uid: &Uid) -> ConnectorResult<()>;
}

/// Search operation capability
#[async_trait]
pub trait SearchOp: Connector {
    async fn search(&self, object_class: &str, filter: Filter, page: PageRequest) -> ConnectorResult<SearchResult>;
}

/// Combined CRUD trait
pub trait FullCrud: CreateOp + UpdateOp + DeleteOp + SearchOp {}

/// Incremental sync capability
#[async_trait]
pub trait SyncCapable: Connector {
    async fn sync(&self, object_class: &str, token: Option<String>) -> ConnectorResult<SyncResult>;
}
```

### Functions

```rust
/// Connector factory function type
pub type ConnectorFactory = Box<dyn Fn(ConnectorConfig) -> BoxedConnector + Send + Sync>;

/// Registry for managing connector instances
impl ConnectorRegistry {
    pub fn new() -> Self;
    pub async fn register_factory(&self, ct: ConnectorType, factory: ConnectorFactory);
    pub async fn get_or_create(&self, id: ConnectorId, ct: ConnectorType, config: Value) -> ConnectorResult<Arc<dyn Connector>>;
}

/// Credential encryption
impl CredentialEncryption {
    pub fn new(master_key: &[u8]) -> Self;
    pub fn encrypt(&self, tenant_id: Uuid, plaintext: &[u8]) -> Result<Vec<u8>>;
    pub fn decrypt(&self, tenant_id: Uuid, ciphertext: &[u8]) -> Result<Vec<u8>>;
}
```

## Usage Example

```rust
use xavyo_connector::prelude::*;

// Register connector factory
let registry = ConnectorRegistry::new();
registry.register_factory(ConnectorType::Ldap, ldap_factory).await;

// Get or create connector instance
let connector = registry.get_or_create(
    connector_id,
    ConnectorType::Ldap,
    serde_json::json!({
        "host": "ldap.example.com",
        "port": 636,
        "base_dn": "dc=example,dc=com"
    }),
).await?;

// Test connection
connector.test_connection().await?;

// Create a user
let attrs = AttributeSet::new()
    .with("cn", "John Doe")
    .with("mail", "john@example.com");
let uid = connector.create("user", attrs).await?;
```

## Integration Points

- **Consumed by**: All connector implementations, `xavyo-provisioning`
- **Provides**: Abstraction layer for identity source operations

## Feature Flags

None - all features are enabled by default.

## Anti-Patterns

- Never store connector credentials in plaintext - use `CredentialEncryption`
- Never skip `test_connection` before operations
- Never ignore circuit breaker state
- Never leak target system errors to clients - wrap in `ConnectorError`

## Related Crates

- `xavyo-connector-ldap` - LDAP/AD implementation
- `xavyo-connector-entra` - Microsoft Entra ID implementation
- `xavyo-connector-rest` - Generic REST implementation
- `xavyo-provisioning` - Uses connectors for provisioning operations
