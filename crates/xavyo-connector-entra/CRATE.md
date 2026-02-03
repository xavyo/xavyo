# xavyo-connector-entra

> Microsoft Entra ID (Azure AD) connector for xavyo provisioning.

## Purpose

Implements the xavyo-connector traits for Microsoft Entra ID, enabling bidirectional identity synchronization via the Microsoft Graph API. Supports OAuth2 client credentials, full and delta sync, group membership resolution, outbound provisioning, and multi-cloud environments (Commercial, US Government, China, Germany).

## Layer

connector

## Status

🟢 **stable**

Production-ready with comprehensive test coverage (116 tests: 64 unit tests + 52 integration tests). Core Graph API operations complete with robust rate limit handling, circuit breaker pattern, and request queuing.

## Dependencies

### Internal (xavyo)
- `xavyo-connector` - Connector framework traits
- `xavyo-core` - TenantId type

### External (key)
- `reqwest` - HTTP client for Graph API
- `tokio` - Async runtime
- `secrecy` - Secret handling
- `rand` - Random jitter for rate limiting

## Public API

### Types

```rust
/// Entra connector configuration
pub struct EntraConfig {
    pub tenant_id: String,
    pub cloud_environment: EntraCloudEnvironment,
    pub user_filter: Option<String>,
    pub group_filter: Option<String>,
    pub conflict_strategy: EntraConflictStrategy,
}

/// Builder for EntraConfig
pub struct EntraConfigBuilder { ... }

/// OAuth2 credentials
pub struct EntraCredentials {
    pub client_id: String,
    pub client_secret: SecretString,
}

/// Cloud environment selection
pub enum EntraCloudEnvironment {
    Commercial,       // login.microsoftonline.com
    UsGovernment,    // login.microsoftonline.us
    China,           // login.chinacloudapi.cn
    Germany,         // login.microsoftonline.de
}

/// Conflict resolution strategy
pub enum EntraConflictStrategy {
    Skip,
    Overwrite,
    Merge,
}

/// Entra connector implementing Connector traits
pub struct EntraConnector { ... }

/// Graph API client
pub struct GraphClient { ... }

/// Token cache for OAuth2
pub struct TokenCache { ... }

/// Mapped user from Entra
pub struct MappedEntraUser { ... }

/// Mapped group from Entra
pub struct MappedEntraGroup { ... }

/// Rate limit configuration
pub struct RateLimitConfig {
    pub base_delay_ms: u64,      // Default: 1000
    pub max_delay_ms: u64,       // Default: 300000 (5 min)
    pub jitter_factor: f64,      // Default: 0.25 (25%)
    pub max_retries: u32,        // Default: 10
    pub circuit_failure_threshold: u32, // Default: 10
    pub circuit_failure_window_secs: u64, // Default: 300 (5 min)
    pub circuit_open_duration_secs: u64,  // Default: 30
    pub queue_max_depth: usize,  // Default: 100
}

/// Rate limiter for Graph API requests
pub struct RateLimiter { ... }

/// Circuit breaker states
pub enum CircuitBreakerState {
    Closed,   // Normal operation
    Open,     // Failing fast
    HalfOpen, // Testing recovery
}

/// Rate limit metrics
pub struct RateLimitMetrics {
    pub total_requests: u64,
    pub rate_limited_count: u64,
    pub retry_count: u64,
    pub circuit_opens: u64,
    pub current_circuit_state: CircuitBreakerState,
}
```

### Trait Implementations

```rust
// EntraConnector implements:
impl Connector for EntraConnector { ... }
impl SchemaDiscovery for EntraConnector { ... }
impl CreateOp for EntraConnector { ... }
impl UpdateOp for EntraConnector { ... }
impl DeleteOp for EntraConnector { ... }
impl SearchOp for EntraConnector { ... }
impl SyncCapable for EntraConnector { ... }  // Delta sync support
impl DisableOp for EntraConnector { ... }
impl GroupOp for EntraConnector { ... }
```

## Usage Example

```rust
use xavyo_connector_entra::{EntraConnector, EntraConfig, EntraCredentials, EntraCloudEnvironment};
use xavyo_connector::prelude::*;

// Configure Entra connection
let config = EntraConfig::builder()
    .tenant_id("your-tenant-id")
    .cloud_environment(EntraCloudEnvironment::Commercial)
    .user_filter("accountEnabled eq true")
    .build()?;

let credentials = EntraCredentials {
    client_id: "your-client-id".to_string(),
    client_secret: "your-client-secret".to_string().into(),
};

// Create connector (uses default rate limit config)
let connector = EntraConnector::new(config, credentials)?;

// Or with custom rate limit configuration
let rate_config = RateLimitConfig {
    max_retries: 5,
    circuit_failure_threshold: 5,
    ..Default::default()
};
// let connector = EntraConnector::with_rate_limit_config(config, credentials, rate_config)?;

// Test connection
connector.test_connection().await?;

// Full sync
let sync_result = connector.sync("user", None).await?;
for user in sync_result.objects {
    println!("Synced user: {}", user.uid.value());
}

// Delta sync (incremental)
let delta_result = connector.sync("user", Some(sync_result.sync_token)).await?;
for change in delta_result.changes {
    match change.change_type {
        SyncChangeType::Created => { /* handle new user */ }
        SyncChangeType::Updated => { /* handle update */ }
        SyncChangeType::Deleted => { /* handle deletion */ }
    }
}

// Create user in Entra
let attrs = AttributeSet::new()
    .with("userPrincipalName", "john.doe@example.com")
    .with("displayName", "John Doe")
    .with("mailNickname", "john.doe")
    .with("accountEnabled", "true");

let uid = connector.create("user", attrs).await?;

// Access rate limit metrics
let graph_client = connector.graph_client();
let metrics = graph_client.rate_limit_metrics().await;
println!("Rate limited {} times", metrics.rate_limited_count);
println!("Circuit state: {:?}", metrics.current_circuit_state);
```

## Integration Points

- **Consumed by**: `xavyo-provisioning`, `xavyo-api-connectors`
- **Connects to**: Microsoft Graph API (graph.microsoft.com)
- **Required permissions**: User.ReadWrite.All, Group.ReadWrite.All, Directory.ReadWrite.All

## Feature Flags

- `integration` - Enables integration tests (disabled by default)

## Integration Tests

The crate includes 52 integration tests covering real-world scenarios with mock Graph API responses:

### Test Suites

| Suite | Tests | Description |
|-------|-------|-------------|
| `user_sync_tests` | 8 | Full user sync, pagination, disabled users, special characters |
| `delta_sync_tests` | 10 | Delta sync tokens, change detection (create/update/delete), token progression |
| `group_sync_tests` | 9 | Group sync, membership, transitive members, security vs M365 groups |
| `multi_cloud_tests` | 8 | Commercial, US Government, China, Germany cloud endpoints |
| `provisioning_tests` | 10 | User create/update/disable/delete, batch operations, error handling |
| `rate_limit_integration_tests` | 6 | 429 handling, concurrent throttling, recovery scenarios |

### Running Integration Tests

```bash
# Run all integration tests
cargo test -p xavyo-connector-entra --features integration

# Run specific test suite
cargo test -p xavyo-connector-entra --features integration --test user_sync_tests
```

### Test Infrastructure

Integration tests use [wiremock](https://github.com/LukeMathWalker/wiremock-rs) to mock Microsoft Graph API responses, enabling:
- Deterministic testing without live API calls
- Rate limit and error scenario simulation
- Multi-cloud endpoint validation
- Pagination and delta sync token testing

## Rate Limit Handling

The connector implements robust rate limit handling for Microsoft Graph API:

- **Retry-After Header**: Honors `Retry-After` header from 429 responses
- **Exponential Backoff**: Uses `base * 2^attempt` with configurable base (default 1s) and cap (default 5 min)
- **Jitter**: Adds 0-25% random variance to prevent thundering herd
- **Circuit Breaker**: Opens after 10 failures in 5 minutes, fails fast for 30 seconds
- **Request Queuing**: Queues up to 100 requests during throttle (FIFO processing)
- **Metrics**: Exposes rate limit count, retry count, circuit state for observability

## Anti-Patterns

- Never store client secrets in plaintext - use `xavyo-connector::CredentialEncryption`
- Never ignore token expiration - use `TokenCache` for automatic refresh
- Never use delta sync without persisting sync tokens
- Never hard-code tenant IDs in multi-tenant deployments
- Never disable rate limiting in production - use conservative config instead

## Related Crates

- `xavyo-connector` - Framework traits and types
- `xavyo-provisioning` - Uses connector for provisioning operations
- `xavyo-api-oidc-federation` - Entra as OIDC federation source
