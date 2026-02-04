//! `HashiCorp` Vault KV v2 secret provider.
//!
//! Supports `AppRole` and token authentication with automatic token renewal.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::config::{SecretProviderConfig, VaultAuthMethod};
use crate::{SecretError, SecretProvider, SecretValue};

/// Vault token state.
#[derive(Debug, Clone)]
struct VaultToken {
    /// The client token.
    token: String,
    /// Token TTL in seconds (for renewal scheduling).
    ttl_seconds: Option<u64>,
}

/// Secret provider that reads from `HashiCorp` Vault KV v2.
pub struct VaultSecretProvider {
    client: reqwest::Client,
    address: String,
    namespace: Option<String>,
    token: Arc<RwLock<Option<VaultToken>>>,
    mappings: HashMap<String, String>,
    /// Handle for background token renewal task.
    _renewal_handle: Option<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for VaultSecretProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSecretProvider")
            .field("address", &self.address)
            .field("namespace", &self.namespace)
            .finish()
    }
}

impl VaultSecretProvider {
    /// Create a new `VaultSecretProvider` from configuration.
    ///
    /// Authenticates to Vault immediately and starts background token renewal.
    pub async fn new(config: &SecretProviderConfig) -> Result<Self, SecretError> {
        let vault_config = config.vault.as_ref().ok_or(SecretError::ConfigError {
            detail: "Vault configuration is required when SECRET_PROVIDER=vault".to_string(),
        })?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| SecretError::ConfigError {
                detail: format!("Failed to create HTTP client: {e}"),
            })?;

        let address = vault_config.address.trim_end_matches('/').to_string();
        let namespace = vault_config.namespace.clone();
        let token_state: Arc<RwLock<Option<VaultToken>>> = Arc::new(RwLock::new(None));

        // Authenticate
        let initial_token = match &vault_config.auth_method {
            VaultAuthMethod::AppRole { role_id, secret_id } => {
                Self::approle_login(&client, &address, &namespace, role_id, secret_id).await?
            }
            VaultAuthMethod::Token { token } => {
                tracing::info!("Vault: Using direct token authentication");
                VaultToken {
                    token: token.clone(),
                    ttl_seconds: None,
                }
            }
        };

        {
            let mut state = token_state.write().await;
            *state = Some(initial_token.clone());
        }

        // Start background token renewal if we have a TTL
        let renewal_handle = if let Some(ttl) = initial_token.ttl_seconds {
            if ttl > 0 {
                let handle = Self::spawn_renewal_task(
                    client.clone(),
                    address.clone(),
                    namespace.clone(),
                    token_state.clone(),
                    ttl,
                );
                Some(handle)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            client,
            address,
            namespace,
            token: token_state,
            mappings: config.secret_mappings.clone(),
            _renewal_handle: renewal_handle,
        })
    }

    /// Authenticate via `AppRole`.
    async fn approle_login(
        client: &reqwest::Client,
        address: &str,
        namespace: &Option<String>,
        role_id: &str,
        secret_id: &str,
    ) -> Result<VaultToken, SecretError> {
        let url = format!("{address}/v1/auth/approle/login");
        let body = serde_json::json!({
            "role_id": role_id,
            "secret_id": secret_id,
        });

        let mut req = client.post(&url).json(&body);
        if let Some(ns) = namespace {
            req = req.header("X-Vault-Namespace", ns);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| SecretError::ProviderUnavailable {
                provider: "vault".to_string(),
                detail: format!("Failed to connect to Vault at {address}: {e}"),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(SecretError::ProviderUnavailable {
                provider: "vault".to_string(),
                detail: format!("Vault AppRole login failed (HTTP {status}): {body_text}"),
            });
        }

        let json: serde_json::Value =
            resp.json()
                .await
                .map_err(|e| SecretError::ProviderUnavailable {
                    provider: "vault".to_string(),
                    detail: format!("Invalid Vault login response: {e}"),
                })?;

        let token = json["auth"]["client_token"]
            .as_str()
            .ok_or(SecretError::ProviderUnavailable {
                provider: "vault".to_string(),
                detail: "Missing client_token in Vault AppRole response".to_string(),
            })?
            .to_string();

        let ttl_seconds = json["auth"]["lease_duration"].as_u64();

        tracing::info!(
            ttl_seconds = ?ttl_seconds,
            "Vault: AppRole authentication successful"
        );

        Ok(VaultToken { token, ttl_seconds })
    }

    /// Spawn a background task to renew the Vault token at 75% of TTL.
    fn spawn_renewal_task(
        client: reqwest::Client,
        address: String,
        namespace: Option<String>,
        token_state: Arc<RwLock<Option<VaultToken>>>,
        initial_ttl: u64,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut current_ttl = initial_ttl;
            let mut consecutive_failures: u32 = 0;
            loop {
                // Renew at 75% of TTL
                let wait_secs = (current_ttl as f64 * 0.75) as u64;
                let wait_secs = wait_secs.max(1); // At least 1 second
                tracing::debug!(
                    wait_secs = wait_secs,
                    ttl = current_ttl,
                    "Vault: Scheduling token renewal"
                );
                tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;

                let current_token = {
                    let state = token_state.read().await;
                    state.as_ref().map(|t| t.token.clone())
                };

                let Some(token) = current_token else {
                    tracing::warn!("Vault: No token available for renewal, stopping renewal task");
                    break;
                };

                match Self::renew_token(&client, &address, &namespace, &token).await {
                    Ok(new_ttl) => {
                        current_ttl = new_ttl;
                        consecutive_failures = 0;
                        tracing::info!(new_ttl = new_ttl, "Vault: Token renewed successfully");
                    }
                    Err(e) => {
                        consecutive_failures += 1;
                        let backoff = std::cmp::min(5 * (1u64 << consecutive_failures.min(6)), 300);
                        tracing::error!(
                            error = %e,
                            consecutive_failures = consecutive_failures,
                            retry_in_secs = backoff,
                            "Vault: Token renewal failed, will retry with backoff"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                    }
                }
            }
        })
    }

    /// Renew the current Vault token.
    async fn renew_token(
        client: &reqwest::Client,
        address: &str,
        namespace: &Option<String>,
        token: &str,
    ) -> Result<u64, SecretError> {
        let url = format!("{address}/v1/auth/token/renew-self");
        let mut req = client.post(&url).header("X-Vault-Token", token);
        if let Some(ns) = namespace {
            req = req.header("X-Vault-Namespace", ns);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| SecretError::ProviderUnavailable {
                provider: "vault".to_string(),
                detail: format!("Token renewal request failed: {e}"),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            return Err(SecretError::ProviderUnavailable {
                provider: "vault".to_string(),
                detail: format!("Token renewal failed with HTTP {status}"),
            });
        }

        let json: serde_json::Value =
            resp.json()
                .await
                .map_err(|e| SecretError::ProviderUnavailable {
                    provider: "vault".to_string(),
                    detail: format!("Invalid renewal response: {e}"),
                })?;

        let new_ttl = json["auth"]["lease_duration"].as_u64().unwrap_or(3600);
        Ok(new_ttl)
    }

    /// Get the current token.
    async fn current_token(&self) -> Result<String, SecretError> {
        let state = self.token.read().await;
        state
            .as_ref()
            .map(|t| t.token.clone())
            .ok_or(SecretError::ProviderUnavailable {
                provider: "vault".to_string(),
                detail: "No Vault token available".to_string(),
            })
    }
}

impl Drop for VaultSecretProvider {
    fn drop(&mut self) {
        if let Some(handle) = self._renewal_handle.take() {
            handle.abort();
        }
    }
}

#[async_trait]
impl SecretProvider for VaultSecretProvider {
    async fn get_secret(&self, name: &str) -> Result<SecretValue, SecretError> {
        let vault_path = self
            .mappings
            .get(name)
            .ok_or_else(|| SecretError::NotFound {
                name: name.to_string(),
            })?;

        let token = self.current_token().await?;
        let url = format!("{}/v1/{}", self.address, vault_path);

        let mut req = self.client.get(&url).header("X-Vault-Token", &token);
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| SecretError::ProviderUnavailable {
                provider: "vault".to_string(),
                detail: format!("Failed to fetch secret '{name}' from Vault: {e}"),
            })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(SecretError::NotFound {
                name: name.to_string(),
            });
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(SecretError::ProviderUnavailable {
                provider: "vault".to_string(),
                detail: format!("Vault returned HTTP {status} for '{name}': {body_text}"),
            });
        }

        let json: serde_json::Value = resp.json().await.map_err(|e| SecretError::InvalidValue {
            name: name.to_string(),
            detail: format!("Invalid Vault response JSON: {e}"),
        })?;

        // KV v2: data is under data.data
        let secret_data = json
            .get("data")
            .and_then(|d| d.get("data"))
            .ok_or_else(|| SecretError::InvalidValue {
                name: name.to_string(),
                detail: "Missing data.data in Vault KV v2 response".to_string(),
            })?;

        // Extract the "value" field from the secret data, or serialize the whole object
        let value_str = if let Some(v) = secret_data.get("value").and_then(|v| v.as_str()) {
            v.to_string()
        } else {
            serde_json::to_string(secret_data).unwrap_or_default()
        };

        let version = json
            .get("data")
            .and_then(|d| d.get("metadata"))
            .and_then(|m| m.get("version"))
            .and_then(serde_json::Value::as_u64)
            .map(|v| v.to_string());

        tracing::info!(
            secret_name = name,
            vault_path = %vault_path,
            version = ?version,
            "Secret loaded from Vault"
        );

        let mut sv = SecretValue::new(name, value_str.into_bytes());
        sv.version = version;
        Ok(sv)
    }

    async fn health_check(&self) -> Result<bool, SecretError> {
        let url = format!("{}/v1/sys/health", self.address);
        let resp =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| SecretError::ProviderUnavailable {
                    provider: "vault".to_string(),
                    detail: format!("Vault health check failed: {e}"),
                })?;

        // Vault health endpoint returns:
        // 200 = initialized, unsealed, active
        // 429 = unsealed, standby
        // 472 = data recovery replication secondary
        // 473 = performance standby
        // 501 = not initialized
        // 503 = sealed
        let status = resp.status().as_u16();
        match status {
            200 | 429 | 472 | 473 => Ok(true),
            _ => Ok(false),
        }
    }

    fn provider_type(&self) -> &'static str {
        "vault"
    }
}
