# xavyo-connector-ldap

> LDAP/Active Directory connector for xavyo provisioning.

## Purpose

Implements the xavyo-connector traits for LDAP directories and Active Directory domains. Enables user and group provisioning to on-premise directory services. Supports LDAP v3 protocol, SSL/TLS, STARTTLS, schema discovery, connection pooling, and paged search results.

## Layer

connector

## Dependencies

### Internal (xavyo)
- `xavyo-connector` - Connector framework traits

### External (key)
- `ldap3` - LDAP v3 client library
- `tokio` - Async runtime
- `base64` - Binary attribute encoding

## Public API

### Types

```rust
/// LDAP connector configuration
pub struct LdapConfig {
    pub host: String,
    pub port: u16,
    pub base_dn: String,
    pub bind_dn: String,
    pub password: Option<String>,
    pub use_ssl: bool,
    pub use_starttls: bool,
    pub timeout_secs: u64,
}

/// Active Directory specific configuration
pub struct ActiveDirectoryConfig {
    pub ldap: LdapConfig,
    pub domain: String,
    pub user_search_base: Option<String>,
    pub group_search_base: Option<String>,
}

/// LDAP connector implementing Connector traits
pub struct LdapConnector { ... }

/// Active Directory connector with AD-specific features
pub struct AdConnector { ... }
```

### Trait Implementations

```rust
// LdapConnector implements:
impl Connector for LdapConnector { ... }
impl SchemaDiscovery for LdapConnector { ... }
impl CreateOp for LdapConnector { ... }
impl UpdateOp for LdapConnector { ... }
impl DeleteOp for LdapConnector { ... }
impl SearchOp for LdapConnector { ... }
impl SyncCapable for LdapConnector { ... }
impl PasswordOp for LdapConnector { ... }
impl DisableOp for LdapConnector { ... }
impl GroupOp for LdapConnector { ... }
```

## Usage Example

```rust
use xavyo_connector_ldap::{LdapConfig, LdapConnector};
use xavyo_connector::prelude::*;

// Configure LDAP connection
let config = LdapConfig::new(
    "ldap.example.com",
    "dc=example,dc=com",
    "cn=admin,dc=example,dc=com",
)
.with_password("secret")
.with_ssl()
.with_port(636);

// Create connector
let connector = LdapConnector::new(config)?;

// Test connection
connector.test_connection().await?;

// Discover schema
let schema = connector.discover_schema().await?;
println!("Found {} object classes", schema.object_classes.len());

// Create a user
let attrs = AttributeSet::new()
    .with("cn", "John Doe")
    .with("sn", "Doe")
    .with("givenName", "John")
    .with("mail", "john.doe@example.com")
    .with("userPassword", "initial-password");

let uid = connector.create("inetOrgPerson", attrs).await?;
println!("Created user with DN: {}", uid.value());

// Search users
let filter = Filter::and(vec![
    Filter::eq("objectClass", "inetOrgPerson"),
    Filter::contains("mail", "@example.com"),
]);
let results = connector.search("inetOrgPerson", filter, PageRequest::default()).await?;
```

## Integration Points

- **Consumed by**: `xavyo-provisioning`, `xavyo-api-connectors`
- **Connects to**: LDAP v3 directories, Active Directory
- **Standard ports**: 389 (LDAP), 636 (LDAPS), 3268 (AD Global Catalog)

## Feature Flags

None - all features are enabled by default.

## Anti-Patterns

- Never store bind passwords in plaintext - use `xavyo-connector::CredentialEncryption`
- Never skip certificate verification in production (use proper CA certs)
- Never use simple bind over unencrypted connections
- Never hardcode DNs - use schema discovery for attribute names

## Related Crates

- `xavyo-connector` - Framework traits and types
- `xavyo-provisioning` - Uses connector for provisioning operations
- `xavyo-api-connectors` - REST API for connector management
