# xavyo-connector-rest

> Generic REST API connector for xavyo provisioning.

## Purpose

Implements the xavyo-connector traits for generic REST APIs, enabling provisioning to any system with a REST interface. Supports multiple authentication methods (Basic, Bearer, API Key, OAuth2), flexible endpoint configuration, various pagination styles, and configurable request/response parsing.

## Layer

connector

## Dependencies

### Internal (xavyo)
- `xavyo-connector` - Connector framework traits

### External (key)
- `reqwest` - HTTP client
- `tokio` - Async runtime
- `url` - URL parsing

## Public API

### Types

```rust
/// REST connector configuration
pub struct RestConfig {
    pub base_url: String,
    pub auth: AuthConfig,
    pub endpoints: HashMap<String, EndpointConfig>,
    pub timeout_secs: u64,
    pub tls_verify: bool,
    pub custom_headers: HashMap<String, String>,
}

/// Authentication configuration
pub enum AuthConfig {
    None,
    Basic { username: String, password: String },
    Bearer { token: String },
    ApiKey { header: String, value: String },
    OAuth2 {
        client_id: String,
        client_secret: String,
        token_url: String,
        scopes: Vec<String>,
    },
}

/// Endpoint configuration
pub struct EndpointConfig {
    pub path: String,
    pub method: HttpMethod,
    pub pagination: Option<PaginationConfig>,
    pub response: ResponseConfig,
}

/// HTTP methods
pub enum HttpMethod { Get, Post, Put, Patch, Delete }

/// Pagination styles
pub enum PaginationStyle {
    Offset,          // ?offset=0&limit=100
    Page,            // ?page=1&pageSize=100
    Cursor,          // ?cursor=abc123
    LinkHeader,      // Link: <url>; rel="next"
}

/// Pagination configuration
pub struct PaginationConfig {
    pub style: PaginationStyle,
    pub page_size: u32,
    pub page_param: String,
    pub size_param: String,
}

/// Response parsing configuration
pub struct ResponseConfig {
    pub data_path: String,        // JSONPath to data array
    pub uid_field: String,        // Field name for unique ID
    pub total_path: Option<String>, // JSONPath to total count
}

/// REST connector implementing Connector traits
pub struct RestConnector { ... }
```

### Trait Implementations

```rust
// RestConnector implements:
impl Connector for RestConnector { ... }
impl SchemaDiscovery for RestConnector { ... }  // Via introspection endpoint if available
impl CreateOp for RestConnector { ... }
impl UpdateOp for RestConnector { ... }
impl DeleteOp for RestConnector { ... }
impl SearchOp for RestConnector { ... }
```

## Usage Example

```rust
use xavyo_connector_rest::{RestConfig, RestConnector, AuthConfig, EndpointConfig, HttpMethod};
use xavyo_connector::prelude::*;

// Configure REST API connection
let config = RestConfig::new("https://api.example.com/v1")
    .with_auth(AuthConfig::Bearer {
        token: "my-api-token".to_string(),
    })
    .with_header("X-Custom-Header", "value")
    .with_endpoint("user", EndpointConfig {
        path: "/users".to_string(),
        method: HttpMethod::Get,
        pagination: Some(PaginationConfig::offset(100)),
        response: ResponseConfig {
            data_path: "$.data".to_string(),
            uid_field: "id".to_string(),
            total_path: Some("$.meta.total".to_string()),
        },
    });

// Create connector
let connector = RestConnector::new(config)?;

// Test connection
connector.test_connection().await?;

// Search users
let filter = Filter::eq("status", "active");
let results = connector.search("user", filter, PageRequest::default()).await?;

// Create user
let attrs = AttributeSet::new()
    .with("email", "john@example.com")
    .with("firstName", "John")
    .with("lastName", "Doe");

let uid = connector.create("user", attrs).await?;

// Update user
let changes = vec![
    AttributeDelta::replace("lastName", "Smith"),
];
connector.update("user", &uid, changes).await?;
```

## Integration Points

- **Consumed by**: `xavyo-provisioning`, `xavyo-api-connectors`
- **Connects to**: Any REST API (SaaS apps, custom systems)
- **Supports**: JSON request/response bodies

## Feature Flags

None - all features are enabled by default.

## Anti-Patterns

- Never store API credentials in plaintext - use `xavyo-connector::CredentialEncryption`
- Never disable TLS verification in production
- Never hardcode base URLs - use configuration
- Never ignore rate limits - implement backoff

## Related Crates

- `xavyo-connector` - Framework traits and types
- `xavyo-provisioning` - Uses connector for provisioning operations
- `xavyo-scim-client` - SCIM-specific REST client
