# xavyo-connector-entra

> Microsoft Entra ID (Azure AD) connector for xavyo provisioning.

## Purpose

Implements the xavyo-connector traits for Microsoft Entra ID, enabling bidirectional identity synchronization via the Microsoft Graph API. Supports OAuth2 client credentials, full and delta sync, group membership resolution, outbound provisioning, and multi-cloud environments (Commercial, US Government, China, Germany).

## Layer

connector

## Status

🟡 **beta**

Functional with limited test coverage (22 tests). Core Graph API operations complete; needs more comprehensive testing.

## Dependencies

### Internal (xavyo)
- `xavyo-connector` - Connector framework traits
- `xavyo-core` - TenantId type

### External (key)
- `reqwest` - HTTP client for Graph API
- `tokio` - Async runtime
- `secrecy` - Secret handling

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

// Create connector
let connector = EntraConnector::new(config, credentials)?;

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
```

## Integration Points

- **Consumed by**: `xavyo-provisioning`, `xavyo-api-connectors`
- **Connects to**: Microsoft Graph API (graph.microsoft.com)
- **Required permissions**: User.ReadWrite.All, Group.ReadWrite.All, Directory.ReadWrite.All

## Feature Flags

None - all features are enabled by default.

## Anti-Patterns

- Never store client secrets in plaintext - use `xavyo-connector::CredentialEncryption`
- Never ignore token expiration - use `TokenCache` for automatic refresh
- Never use delta sync without persisting sync tokens
- Never hard-code tenant IDs in multi-tenant deployments

## Related Crates

- `xavyo-connector` - Framework traits and types
- `xavyo-provisioning` - Uses connector for provisioning operations
- `xavyo-api-oidc-federation` - Entra as OIDC federation source
