//! Secret provider configuration parsed from environment variables.

use std::collections::HashMap;
use std::env;

use crate::SecretError;

/// Which secret provider to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderType {
    /// Read from environment variables (default, backward-compatible).
    Env,
    /// Read from filesystem paths.
    File,
    /// Read from `HashiCorp` Vault KV v2.
    Vault,
    /// Read from AWS Secrets Manager.
    Aws,
}

impl ProviderType {
    /// Parse from string value (case-insensitive).
    pub fn from_str_value(s: &str) -> Result<Self, SecretError> {
        match s.to_lowercase().as_str() {
            "env" | "environment" => Ok(Self::Env),
            "file" | "filesystem" => Ok(Self::File),
            "vault" | "hashicorp" => Ok(Self::Vault),
            "aws" | "secretsmanager" => Ok(Self::Aws),
            other => Err(SecretError::ConfigError {
                detail: format!(
                    "Unknown SECRET_PROVIDER value '{other}'. Valid options: env, file, vault, aws"
                ),
            }),
        }
    }
}

/// Application environment mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEnvironment {
    Development,
    Production,
}

impl AppEnvironment {
    #[must_use] 
    pub fn from_env_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "production" | "prod" => Self::Production,
            _ => Self::Development,
        }
    }

    #[must_use] 
    pub fn is_production(&self) -> bool {
        *self == Self::Production
    }
}

/// `HashiCorp` Vault authentication method.
#[derive(Clone)]
pub enum VaultAuthMethod {
    /// Machine-to-machine auth with `role_id` + `secret_id`.
    AppRole { role_id: String, secret_id: String },
    /// Direct token auth.
    Token { token: String },
}

impl std::fmt::Debug for VaultAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AppRole { role_id, .. } => f
                .debug_struct("AppRole")
                .field("role_id", role_id)
                .field("secret_id", &"[REDACTED]")
                .finish(),
            Self::Token { .. } => f
                .debug_struct("Token")
                .field("token", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Configuration specific to `HashiCorp` Vault.
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Vault server URL.
    pub address: String,
    /// Authentication method.
    pub auth_method: VaultAuthMethod,
    /// Vault namespace for multi-tenant deployments.
    pub namespace: Option<String>,
}

/// Configuration specific to AWS Secrets Manager.
#[derive(Clone)]
pub struct AwsConfig {
    /// AWS region.
    pub region: String,
    /// Explicit access key (None = use IAM role).
    pub access_key_id: Option<String>,
    /// Explicit secret key (None = use IAM role).
    pub secret_access_key: Option<String>,
}

impl std::fmt::Debug for AwsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsConfig")
            .field("region", &self.region)
            .field("access_key_id", &self.access_key_id)
            .field(
                "secret_access_key",
                &self.secret_access_key.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Configuration specific to the file-based provider.
#[derive(Debug, Clone)]
pub struct FileConfig {
    /// Whether to watch files for changes (default: true).
    pub watch_enabled: bool,
    /// Debounce interval for file change events in ms (default: 2000).
    pub watch_debounce_ms: u64,
}

/// Complete secret provider configuration.
#[derive(Debug, Clone)]
pub struct SecretProviderConfig {
    /// Which provider to use.
    pub provider_type: ProviderType,
    /// Maps logical name → provider-specific path.
    pub secret_mappings: HashMap<String, String>,
    /// Cache TTL in seconds (default: 300 = 5 minutes).
    pub cache_ttl_seconds: u64,
    /// Application environment mode.
    pub env: AppEnvironment,
    /// Vault-specific config (if `provider_type` == Vault).
    pub vault: Option<VaultConfig>,
    /// AWS-specific config (if `provider_type` == Aws).
    pub aws: Option<AwsConfig>,
    /// File-specific config (if `provider_type` == File).
    pub file: Option<FileConfig>,
}

impl SecretProviderConfig {
    /// Parse configuration from environment variables.
    ///
    /// Reads:
    /// - `SECRET_PROVIDER` — provider type (default: "env")
    /// - `SECRET_CACHE_TTL_SECONDS` — cache TTL (default: 300)
    /// - `SECRET_MAP_{NAME}` — secret name mappings
    /// - `APP_ENV` — environment mode
    /// - Provider-specific variables (`VAULT_ADDR`, `AWS_REGION`, etc.)
    pub fn from_env() -> Result<Self, SecretError> {
        let app_env = AppEnvironment::from_env_str(
            &env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()),
        );

        let provider_type = match env::var("SECRET_PROVIDER") {
            Ok(s) if !s.is_empty() => ProviderType::from_str_value(&s)?,
            _ => ProviderType::Env,
        };

        let cache_ttl_seconds = env::var("SECRET_CACHE_TTL_SECONDS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(300);

        // Parse SECRET_MAP_* env vars
        let secret_mappings = Self::parse_secret_mappings();

        // Provider-specific config
        let vault = if provider_type == ProviderType::Vault {
            Some(Self::parse_vault_config()?)
        } else {
            None
        };

        let aws = if provider_type == ProviderType::Aws {
            Some(Self::parse_aws_config()?)
        } else {
            None
        };

        let file = if provider_type == ProviderType::File {
            Some(Self::parse_file_config())
        } else {
            None
        };

        Ok(Self {
            provider_type,
            secret_mappings,
            cache_ttl_seconds,
            env: app_env,
            vault,
            aws,
            file,
        })
    }

    /// Parse `SECRET_MAP`_* environment variables into a `HashMap`.
    ///
    /// e.g., `SECRET_MAP_JWT_SIGNING_KEYS=/etc/secrets/jwt` → {"`jwt_signing_keys"`: "/etc/secrets/jwt"}
    fn parse_secret_mappings() -> HashMap<String, String> {
        let mut mappings = HashMap::new();
        for (key, value) in env::vars() {
            if let Some(name) = key.strip_prefix("SECRET_MAP_") {
                let logical_name = name.to_lowercase();
                mappings.insert(logical_name, value);
            }
        }
        mappings
    }

    /// Parse Vault-specific configuration.
    fn parse_vault_config() -> Result<VaultConfig, SecretError> {
        let address = env::var("VAULT_ADDR").map_err(|_| SecretError::ConfigError {
            detail: "VAULT_ADDR is required when SECRET_PROVIDER=vault".to_string(),
        })?;

        let auth_method_str = env::var("VAULT_AUTH_METHOD").unwrap_or_else(|_| "token".to_string());

        let auth_method = match auth_method_str.to_lowercase().as_str() {
            "approle" => {
                let role_id = env::var("VAULT_ROLE_ID").map_err(|_| SecretError::ConfigError {
                    detail: "VAULT_ROLE_ID is required when VAULT_AUTH_METHOD=approle".to_string(),
                })?;
                let secret_id =
                    env::var("VAULT_SECRET_ID").map_err(|_| SecretError::ConfigError {
                        detail: "VAULT_SECRET_ID is required when VAULT_AUTH_METHOD=approle"
                            .to_string(),
                    })?;
                VaultAuthMethod::AppRole { role_id, secret_id }
            }
            "token" => {
                let token = env::var("VAULT_TOKEN").map_err(|_| SecretError::ConfigError {
                    detail: "VAULT_TOKEN is required when VAULT_AUTH_METHOD=token".to_string(),
                })?;
                VaultAuthMethod::Token { token }
            }
            other => {
                return Err(SecretError::ConfigError {
                    detail: format!(
                        "Unknown VAULT_AUTH_METHOD '{other}'. Valid options: approle, token"
                    ),
                });
            }
        };

        let namespace = env::var("VAULT_NAMESPACE").ok().filter(|s| !s.is_empty());

        Ok(VaultConfig {
            address,
            auth_method,
            namespace,
        })
    }

    /// Parse AWS-specific configuration.
    fn parse_aws_config() -> Result<AwsConfig, SecretError> {
        let region = env::var("AWS_REGION")
            .or_else(|_| env::var("AWS_DEFAULT_REGION"))
            .map_err(|_| SecretError::ConfigError {
                detail: "AWS_REGION is required when SECRET_PROVIDER=aws".to_string(),
            })?;

        let access_key_id = env::var("AWS_ACCESS_KEY_ID").ok().filter(|s| !s.is_empty());
        let secret_access_key = env::var("AWS_SECRET_ACCESS_KEY")
            .ok()
            .filter(|s| !s.is_empty());

        Ok(AwsConfig {
            region,
            access_key_id,
            secret_access_key,
        })
    }

    /// Parse file-specific configuration.
    fn parse_file_config() -> FileConfig {
        let watch_enabled = env::var("SECRET_FILE_WATCH_ENABLED")
            .map(|s| !matches!(s.to_lowercase().as_str(), "false" | "0" | "no"))
            .unwrap_or(true);

        let watch_debounce_ms = env::var("SECRET_FILE_WATCH_DEBOUNCE_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(2000);

        FileConfig {
            watch_enabled,
            watch_debounce_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_type_from_str() {
        assert_eq!(
            ProviderType::from_str_value("env").unwrap(),
            ProviderType::Env
        );
        assert_eq!(
            ProviderType::from_str_value("ENV").unwrap(),
            ProviderType::Env
        );
        assert_eq!(
            ProviderType::from_str_value("file").unwrap(),
            ProviderType::File
        );
        assert_eq!(
            ProviderType::from_str_value("vault").unwrap(),
            ProviderType::Vault
        );
        assert_eq!(
            ProviderType::from_str_value("aws").unwrap(),
            ProviderType::Aws
        );
        assert_eq!(
            ProviderType::from_str_value("secretsmanager").unwrap(),
            ProviderType::Aws
        );
        assert!(ProviderType::from_str_value("invalid").is_err());
    }

    #[test]
    fn test_app_environment_from_str() {
        assert_eq!(
            AppEnvironment::from_env_str("production"),
            AppEnvironment::Production
        );
        assert_eq!(
            AppEnvironment::from_env_str("prod"),
            AppEnvironment::Production
        );
        assert_eq!(
            AppEnvironment::from_env_str("development"),
            AppEnvironment::Development
        );
        assert_eq!(
            AppEnvironment::from_env_str("anything"),
            AppEnvironment::Development
        );
    }

    #[test]
    fn test_app_environment_is_production() {
        assert!(AppEnvironment::Production.is_production());
        assert!(!AppEnvironment::Development.is_production());
    }
}
