# xavyo-connector-rest

> Generic REST API connector for xavyo provisioning with rate limiting and retry support.

## Purpose

Implements the xavyo-connector traits for generic REST APIs, enabling provisioning to any system with a REST interface. Supports multiple authentication methods (Basic, Bearer, API Key, OAuth2), flexible endpoint configuration, various pagination styles, configurable request/response parsing, rate limiting with per-endpoint configuration, and automatic retry with exponential backoff.

## Layer

connector

## Status

🟢 **stable**

Production-ready REST connector with comprehensive test coverage (114 tests: 73 unit + 41 integration). Core operations implemented: create, update, delete, search. Rate limiting uses token bucket algorithm with per-endpoint configuration. Retry logic supports exponential backoff with jitter and Retry-After header parsing. SSRF protection blocks internal/private IP addresses by default. Integration tests cover CRUD operations, authentication methods, pagination styles, retry/rate-limit behavior, and security validations.

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
    pub tls: TlsConfig,
    pub connection: ConnectionSettings,
    pub default_headers: HashMap<String, String>,
    pub content_type: String,
    pub accept: String,
    pub endpoints: EndpointConfig,
    pub pagination: PaginationConfig,
    pub response: ResponseConfig,
    pub openapi_url: Option<String>,
    pub rate_limit: RateLimitConfig,
    pub retry: RetryConfig,
    pub log_verbosity: LogVerbosity,
}

/// Rate limiting configuration
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_second: u32,    // Default: 10
    pub max_concurrent: u32,          // Default: 5
    pub max_queue_depth: u32,         // Default: 100
    pub endpoint_limits: HashMap<String, EndpointRateLimit>,
}

/// Per-endpoint rate limit override
pub struct EndpointRateLimit {
    pub requests_per_second: u32,
    pub max_concurrent: u32,
}

/// Retry configuration with exponential backoff
pub struct RetryConfig {
    pub max_retries: u32,             // Default: 3
    pub initial_backoff_ms: u64,      // Default: 100
    pub max_backoff_ms: u64,          // Default: 30000
    pub backoff_multiplier: f64,      // Default: 2.0
    pub use_jitter: bool,             // Default: true
    pub retry_status_codes: Vec<u16>, // Default: [429, 502, 503, 504]
}

/// Logging verbosity levels
pub enum LogVerbosity {
    Quiet,   // No request/response logging
    Normal,  // Log URL and status only (default)
    Verbose, // Log headers
    Debug,   // Log headers and bodies
}

/// HTTP methods
pub enum HttpMethod { Get, Post, Put, Patch, Delete }

/// Pagination styles
pub enum PaginationStyle {
    PageBased,    // ?page=1&pageSize=100
    OffsetBased,  // ?offset=0&limit=100
    CursorBased,  // ?cursor=abc123
    None,         // No pagination
}

/// REST connector implementing Connector traits
pub struct RestConnector { ... }
```

### Trait Implementations

```rust
// RestConnector implements:
impl Connector for RestConnector { ... }
impl SchemaDiscovery for RestConnector { ... }  // Via OpenAPI or generic schema
impl CreateOp for RestConnector { ... }
impl UpdateOp for RestConnector { ... }
impl DeleteOp for RestConnector { ... }
impl SearchOp for RestConnector { ... }
```

## Usage Example

```rust
use xavyo_connector_rest::{
    RestConfig, RestConnector, RateLimitConfig, RetryConfig,
    EndpointRateLimit, LogVerbosity
};
use xavyo_connector::prelude::*;

// Configure REST API connection with rate limiting
let config = RestConfig::new("https://api.example.com/v1")
    .with_bearer_token("my-api-token")
    .with_header("X-Custom-Header", "value")
    // Configure rate limiting (10 RPS, 5 concurrent)
    .with_rate_limit(
        RateLimitConfig::new(10)
            .with_max_concurrent(5)
            .with_endpoint_limit("/users", EndpointRateLimit::new(5))
    )
    // Configure retry with custom backoff
    .with_retry(
        RetryConfig::new(5)
            .with_initial_backoff(200)
            .with_max_backoff(60000)
    )
    // Enable verbose logging
    .with_log_verbosity(LogVerbosity::Verbose);

// Create connector
let connector = RestConnector::new(config)?;

// Test connection
connector.test_connection().await?;

// Search users (rate limited automatically)
let filter = Filter::eq("status", "active");
let results = connector.search("user", Some(filter), None, None).await?;

// Create user (with automatic retry on transient failures)
let attrs = AttributeSet::new()
    .with("email", "john@example.com")
    .with("firstName", "John")
    .with("lastName", "Doe");

let uid = connector.create("user", attrs).await?;

// Check rate limit stats
let stats = connector.rate_limit_stats().await;
println!("Available permits: {}", stats.global_available_permits);
```

## Rate Limiting

The connector implements rate limiting using a token bucket algorithm:

- **Global rate limit**: Configurable requests per second across all endpoints
- **Per-endpoint limits**: Override rate limits for specific endpoints
- **Concurrency control**: Limit concurrent requests via semaphores
- **Request queuing**: Queue requests when rate limited (up to max_queue_depth)
- **Retry-After support**: Respects 429 responses with Retry-After header

## Retry Logic

Automatic retry with exponential backoff for transient failures:

- **Configurable retries**: Set max_retries (default: 3)
- **Exponential backoff**: Delay doubles each retry (default: 100ms, 200ms, 400ms...)
- **Backoff cap**: Maximum backoff delay (default: 30 seconds)
- **Jitter**: Random variation to prevent thundering herd
- **Retry status codes**: Configurable (default: 429, 502, 503, 504)

## Integration Points

- **Consumed by**: `xavyo-provisioning`, `xavyo-api-connectors`
- **Connects to**: Any REST API (SaaS apps, custom systems)
- **Supports**: JSON request/response bodies, OpenAPI schema discovery

## Feature Flags

None - all features are enabled by default.

## Anti-Patterns

- Never store API credentials in plaintext - use `xavyo-connector::CredentialEncryption`
- Never disable TLS verification in production
- Never hardcode base URLs - use configuration
- Never bypass rate limiting - respect API limits
- Never set max_retries too high - may cause request storms

## Related Crates

- `xavyo-connector` - Framework traits and types
- `xavyo-provisioning` - Uses connector for provisioning operations
- `xavyo-scim-client` - SCIM-specific REST client
