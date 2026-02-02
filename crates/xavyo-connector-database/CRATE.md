# xavyo-connector-database

> Database connector for xavyo provisioning.

## Purpose

Implements the xavyo-connector traits for SQL databases, enabling provisioning to identity tables in PostgreSQL, MySQL, MS SQL Server, and Oracle. Supports schema discovery from INFORMATION_SCHEMA, connection pooling, SSL/TLS, and parameterized queries for security.

## Layer

connector

## Status

🔴 **alpha**

Experimental with skeleton implementation (33 tests, 4 public items). Configuration types defined; operations not yet implemented.

## Dependencies

### Internal (xavyo)
- `xavyo-connector` - Connector framework traits

### External (key)
- `sqlx` - Async database client
- `tokio` - Async runtime

## Public API

### Types

```rust
/// Database connector configuration
pub struct DatabaseConfig {
    pub driver: DatabaseDriver,
    pub host: String,
    pub port: Option<u16>,
    pub database: String,
    pub username: String,
    pub password: Option<String>,
    pub ssl_mode: SslMode,
    pub pool_size: u32,
    pub timeout_secs: u64,
    pub table_mappings: HashMap<String, TableMapping>,
}

/// Supported database drivers
pub enum DatabaseDriver {
    PostgreSQL,
    MySQL,
    MsSql,
    Oracle,
}

/// SSL/TLS mode
pub enum SslMode {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

/// Table mapping configuration
pub struct TableMapping {
    pub table_name: String,
    pub schema_name: Option<String>,
    pub uid_column: String,
    pub column_mappings: HashMap<String, String>,
}

/// Database connector implementing Connector traits
pub struct DatabaseConnector { ... }
```

### Trait Implementations

```rust
// DatabaseConnector implements:
impl Connector for DatabaseConnector { ... }
impl SchemaDiscovery for DatabaseConnector { ... }  // Via INFORMATION_SCHEMA
impl CreateOp for DatabaseConnector { ... }
impl UpdateOp for DatabaseConnector { ... }
impl DeleteOp for DatabaseConnector { ... }
impl SearchOp for DatabaseConnector { ... }
```

## Usage Example

```rust
use xavyo_connector_database::{DatabaseConfig, DatabaseDriver, DatabaseConnector, SslMode};
use xavyo_connector::prelude::*;

// Configure database connection
let config = DatabaseConfig::new(
    DatabaseDriver::PostgreSQL,
    "db.example.com",
    "identity_db",
    "provisioner",
)
.with_password("secret")
.with_ssl_mode(SslMode::Require)
.with_port(5432)
.with_table_mapping("user", TableMapping {
    table_name: "users".to_string(),
    schema_name: Some("identity".to_string()),
    uid_column: "id".to_string(),
    column_mappings: [
        ("email".to_string(), "email_address".to_string()),
        ("firstName".to_string(), "first_name".to_string()),
        ("lastName".to_string(), "last_name".to_string()),
    ].into_iter().collect(),
});

// Create connector
let connector = DatabaseConnector::new(config).await?;

// Test connection
connector.test_connection().await?;

// Discover schema
let schema = connector.discover_schema().await?;
for class in schema.object_classes {
    println!("Table: {} with {} columns", class.name, class.attributes.len());
}

// Create user
let attrs = AttributeSet::new()
    .with("email", "john@example.com")
    .with("firstName", "John")
    .with("lastName", "Doe");

let uid = connector.create("user", attrs).await?;
// Executes: INSERT INTO identity.users (email_address, first_name, last_name) VALUES ($1, $2, $3) RETURNING id

// Search users
let filter = Filter::contains("email", "@example.com");
let results = connector.search("user", filter, PageRequest::default()).await?;
// Executes: SELECT * FROM identity.users WHERE email_address LIKE $1 LIMIT $2 OFFSET $3
```

## Integration Points

- **Consumed by**: `xavyo-provisioning`, `xavyo-api-connectors`
- **Connects to**: PostgreSQL, MySQL, MS SQL Server, Oracle
- **Standard ports**: 5432 (PostgreSQL), 3306 (MySQL), 1433 (MSSQL), 1521 (Oracle)

## Feature Flags

None - all features are enabled by default.

## Anti-Patterns

- Never store database credentials in plaintext - use `xavyo-connector::CredentialEncryption`
- Never disable SSL for production connections
- Never use string concatenation for queries - always use parameterized queries
- Never grant more permissions than necessary to the provisioner account

## Related Crates

- `xavyo-connector` - Framework traits and types
- `xavyo-provisioning` - Uses connector for provisioning operations
- `xavyo-db` - xavyo's own PostgreSQL layer (different purpose)
