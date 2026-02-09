# xavyo-secrets

> Pluggable secret provider abstraction for environment, file, Vault, and AWS backends.

## Purpose

Abstracts secret retrieval from multiple backends allowing the platform to load sensitive configuration (JWT keys, database passwords, API tokens) from various sources without code changes. Supports environment variables, files with hot-reload, HashiCorp Vault, and AWS Secrets Manager.

## Layer

foundation

## Status

🟢 **stable**

Production-ready with comprehensive test coverage (51 tests). Multi-provider support (Environment, File, Vault, AWS) fully implemented.

## Dependencies

### Internal (xavyo)
None (standalone foundation crate)

### External (key)
- `tokio` - Async runtime
- `async-trait` - Async trait support
- `notify` - File watching (optional)
- `reqwest` - Vault HTTP client (optional)
- `aws-sdk-secretsmanager` - AWS SDK (optional)

## Public API

### Types

```rust
/// Secret value returned by providers
pub struct SecretValue {
    pub name: String,              // Logical name
    pub value: Vec<u8>,            // Raw bytes
    pub version: Option<String>,   // Provider version
    pub loaded_at: DateTime<Utc>,  // Fetch timestamp
}

/// Provider configuration
pub struct SecretProviderConfig {
    pub provider_type: ProviderType,
    pub secret_mappings: HashMap<String, String>,
    pub cache_ttl_seconds: u64,
}

/// Provider types
pub enum ProviderType {
    Env,   // Environment variables
    File,  // Local filesystem
    Vault, // HashiCorp Vault
    Aws,   // AWS Secrets Manager
}

/// Secret errors
pub enum SecretError {
    NotFound { name: String },
    ProviderUnavailable { provider: String, detail: String },
    InvalidValue { name: String, detail: String },
    ConfigError { detail: String },
    PermissionDenied { detail: String },
}

/// Caching wrapper for providers
pub struct CachedSecretProvider { ... }

/// Dynamic credential request (F120)
pub struct DynamicCredentialRequest { ... }

/// Dynamic credential response
pub struct DynamicCredential { ... }
```

### Traits

```rust
/// All secret providers implement this trait
#[async_trait]
pub trait SecretProvider: Send + Sync {
    /// Retrieve secret by logical name
    async fn get_secret(&self, name: &str) -> Result<SecretValue, SecretError>;

    /// Check provider health
    async fn health_check(&self) -> Result<bool, SecretError>;

    /// Provider type for logging
    fn provider_type(&self) -> &'static str;
}

/// Dynamic secret provisioning (F120)
#[async_trait]
pub trait DynamicSecretProvider: Send + Sync {
    async fn provision_credential(&self, req: DynamicCredentialRequest) -> Result<DynamicCredential, SecretError>;
    async fn revoke_credential(&self, credential_id: &str) -> Result<(), SecretError>;
}
```

### Functions

```rust
/// Build provider from configuration
pub async fn build_provider(config: &SecretProviderConfig) -> Result<Arc<dyn SecretProvider>, SecretError>;

impl SecretValue {
    /// Interpret as UTF-8 string
    pub fn as_str(&self) -> Result<&str, SecretError>;

    /// Interpret as hex-encoded bytes
    pub fn as_hex_bytes(&self) -> Result<Vec<u8>, SecretError>;

    /// Interpret as base64-encoded bytes
    pub fn as_base64_bytes(&self) -> Result<Vec<u8>, SecretError>;
}
```

## Usage Example

```rust
use xavyo_secrets::{SecretProviderConfig, build_provider, SecretProvider};

// Build provider from environment configuration
let config = SecretProviderConfig::from_env()?;
let provider = build_provider(&config).await?;

// Retrieve a secret
let jwt_keys = provider.get_secret("jwt_signing_keys").await?;
let pem_str = jwt_keys.as_str()?;

// Check provider health
if !provider.health_check().await? {
    tracing::warn!("Secret provider degraded");
}
```

## Integration Points

- **Consumed by**: `xavyo-auth` (JWT keys), `xavyo-db` (connection strings), `xavyo-api-agents` (dynamic secrets)
- **Environment variables**:
  - `SECRET_PROVIDER` - Provider type (env, file, vault, aws)
  - `VAULT_ADDR` - Vault server URL
  - `VAULT_TOKEN` - Vault authentication token

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `env-provider` | Enable environment variable provider | - |
| `file-provider` | Enable file provider with hot-reload | notify |
| `vault-provider` | Enable HashiCorp Vault provider | reqwest |
| `aws-provider` | Enable AWS Secrets Manager | aws-sdk-secretsmanager |

Default: `env-provider`, `file-provider`

## Anti-Patterns

- Never log secret values (SecretValue::Debug redacts them)
- Never store secrets in code or config files committed to Git
- Never skip cache TTL - secrets should be refreshed periodically
- Never use plaintext secrets when providers are available

## Related Crates

- `xavyo-auth` - Uses secrets for JWT signing keys
- `xavyo-connector` - Uses secrets for connector credentials
- `xavyo-api-agents` - Dynamic secret provisioning
