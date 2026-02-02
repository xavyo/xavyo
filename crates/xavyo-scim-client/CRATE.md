# xavyo-scim-client

> SCIM 2.0 outbound provisioning client for xavyo.

## Purpose

Provides outbound SCIM 2.0 provisioning to external identity providers and SaaS applications. Enables xavyo to push user and group changes to downstream systems that support SCIM. Includes automatic retry, reconciliation, and Kafka event consumption for event-driven sync.

## Layer

domain

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId, UserId types
- `xavyo-db` - SCIM target configuration
- `xavyo-connector` - Credential encryption
- `xavyo-webhooks` - Event publishing
- `xavyo-events` - Kafka consumption (optional)
- `xavyo-api-scim` - SCIM types

### External (key)
- `reqwest` - HTTP client
- `tokio` - Async runtime
- `sqlx` - Database access

## Public API

### Types

```rust
/// SCIM client for a single target
pub struct ScimClient {
    base_url: String,
    auth: ScimAuth,
    timeout: Duration,
}

/// SCIM authentication methods
pub enum ScimCredentials {
    Bearer { token: String },
    Basic { username: String, password: String },
    OAuth2 { client_id: String, client_secret: String, token_url: String },
}

/// SCIM authentication handler
pub struct ScimAuth { ... }

/// Provisioner for managing sync operations
pub struct ScimProvisioner {
    pool: PgPool,
    encryption: CredentialEncryption,
}

/// Reconciler for drift detection
pub struct ScimReconciler {
    pool: PgPool,
    client: ScimClient,
}

/// Sync result
pub struct SyncResult {
    pub created: i32,
    pub updated: i32,
    pub deleted: i32,
    pub failed: i32,
    pub errors: Vec<SyncError>,
}
```

### Errors

```rust
pub enum ScimClientError {
    HttpError(reqwest::Error),
    AuthError(String),
    NotFound { resource_type: String, id: String },
    Conflict { message: String },
    ValidationError { details: Value },
    EncryptionError(String),
    InvalidConfig(String),
}

pub type ScimClientResult<T> = Result<T, ScimClientError>;
```

### Functions

```rust
/// Build SCIM client from stored target configuration
pub fn build_scim_client_from_target(
    target: &ScimTarget,
    encryption: &CredentialEncryption,
    tenant_id: Uuid,
) -> ScimClientResult<ScimClient>;

/// Publish webhook event for SCIM operations
pub fn publish_scim_webhook(
    publisher: Option<&EventPublisher>,
    event_type: &str,
    tenant_id: Uuid,
    actor_id: Option<Uuid>,
    data: Value,
);

/// SCIM client operations
impl ScimClient {
    pub async fn create_user(&self, user: ScimUser) -> ScimClientResult<ScimUser>;
    pub async fn get_user(&self, id: &str) -> ScimClientResult<ScimUser>;
    pub async fn update_user(&self, id: &str, user: ScimUser) -> ScimClientResult<ScimUser>;
    pub async fn delete_user(&self, id: &str) -> ScimClientResult<()>;
    pub async fn list_users(&self, filter: Option<&str>) -> ScimClientResult<ListResponse<ScimUser>>;
}
```

## Usage Example

```rust
use xavyo_scim_client::{
    build_scim_client_from_target,
    ScimProvisioner,
};
use xavyo_connector::crypto::CredentialEncryption;

// Build client from stored target
let encryption = CredentialEncryption::new(&master_key);
let client = build_scim_client_from_target(&target, &encryption, tenant_id)?;

// Create user in downstream system
let scim_user = ScimUser {
    user_name: "john.doe@example.com".to_string(),
    name: ScimName {
        given_name: Some("John".to_string()),
        family_name: Some("Doe".to_string()),
        ..Default::default()
    },
    emails: vec![ScimEmail {
        value: "john.doe@example.com".to_string(),
        primary: true,
        ..Default::default()
    }],
    ..Default::default()
};

let created = client.create_user(scim_user).await?;
println!("Created user with ID: {}", created.id.unwrap());
```

## Integration Points

- **Consumed by**: `xavyo-api-connectors`, provisioning pipelines
- **Consumes**: Kafka events when `kafka` feature enabled
- **Pushes to**: SCIM 2.0 compliant endpoints

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `kafka` | Enable Kafka event consumer | xavyo-events/kafka |

## Anti-Patterns

- Never store SCIM credentials unencrypted
- Never ignore rate limits from target systems
- Never skip reconciliation after bulk operations
- Never provision without proper error handling and retry

## Related Crates

- `xavyo-api-scim` - Inbound SCIM server
- `xavyo-connector` - Generic connector framework
- `xavyo-provisioning` - Provisioning queue management
