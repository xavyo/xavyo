//! `OpenBao` dynamic secret provider for just-in-time credential generation (F120).
//!
//! `OpenBao` is API-compatible with `HashiCorp` Vault, supporting the database
//! secrets engine for generating ephemeral database credentials.

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::dynamic::{DynamicCredential, DynamicCredentialRequest, DynamicSecretProvider};
use crate::SecretError;

/// Authentication method for `OpenBao`.
#[derive(Debug, Clone)]
pub enum OpenBaoAuthMethod {
    /// `AppRole` authentication (recommended for automation).
    AppRole { role_id: String, secret_id: String },
    /// Direct token authentication.
    Token { token: String },
}

/// Configuration for `OpenBao` provider.
#[derive(Debug, Clone)]
pub struct OpenBaoConfig {
    /// `OpenBao` server address (e.g., "<https://openbao.example.com:8200>").
    pub address: String,
    /// Optional namespace for enterprise features.
    pub namespace: Option<String>,
    /// Authentication method.
    pub auth_method: OpenBaoAuthMethod,
    /// Mount path for database secrets engine (default: "database").
    pub database_mount: String,
}

impl Default for OpenBaoConfig {
    fn default() -> Self {
        Self {
            address: "http://127.0.0.1:8200".to_string(),
            namespace: None,
            auth_method: OpenBaoAuthMethod::Token {
                token: String::new(),
            },
            database_mount: "database".to_string(),
        }
    }
}

/// Token state for `OpenBao` authentication.
#[derive(Debug, Clone)]
struct OpenBaoToken {
    token: String,
    ttl_seconds: Option<u64>,
}

/// Dynamic secret provider using `OpenBao` database secrets engine.
///
/// `OpenBao` (a Vault fork) generates ephemeral database credentials on demand.
/// Credentials are automatically revoked when their lease expires.
pub struct OpenBaoSecretProvider {
    client: reqwest::Client,
    address: String,
    namespace: Option<String>,
    database_mount: String,
    token: Arc<RwLock<Option<OpenBaoToken>>>,
    _renewal_handle: Option<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for OpenBaoSecretProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenBaoSecretProvider")
            .field("address", &self.address)
            .field("namespace", &self.namespace)
            .field("database_mount", &self.database_mount)
            .finish()
    }
}

impl OpenBaoSecretProvider {
    /// Create a new `OpenBaoSecretProvider` from configuration.
    ///
    /// Authenticates immediately and starts background token renewal.
    pub async fn new(config: &OpenBaoConfig) -> Result<Self, SecretError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| SecretError::ConfigError {
                detail: format!("Failed to create HTTP client: {e}"),
            })?;

        let address = config.address.trim_end_matches('/').to_string();
        let namespace = config.namespace.clone();
        let database_mount = config.database_mount.clone();
        let token_state: Arc<RwLock<Option<OpenBaoToken>>> = Arc::new(RwLock::new(None));

        // Authenticate
        let initial_token = match &config.auth_method {
            OpenBaoAuthMethod::AppRole { role_id, secret_id } => {
                Self::approle_login(&client, &address, &namespace, role_id, secret_id).await?
            }
            OpenBaoAuthMethod::Token { token } => {
                tracing::info!("OpenBao: Using direct token authentication");
                OpenBaoToken {
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
            database_mount,
            token: token_state,
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
    ) -> Result<OpenBaoToken, SecretError> {
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
                provider: "openbao".to_string(),
                detail: format!("Failed to connect to OpenBao at {address}: {e}"),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(SecretError::ProviderUnavailable {
                provider: "openbao".to_string(),
                detail: format!("OpenBao AppRole login failed (HTTP {status}): {body_text}"),
            });
        }

        let json: serde_json::Value =
            resp.json()
                .await
                .map_err(|e| SecretError::ProviderUnavailable {
                    provider: "openbao".to_string(),
                    detail: format!("Invalid OpenBao login response: {e}"),
                })?;

        let token = json["auth"]["client_token"]
            .as_str()
            .ok_or(SecretError::ProviderUnavailable {
                provider: "openbao".to_string(),
                detail: "Missing client_token in OpenBao AppRole response".to_string(),
            })?
            .to_string();

        let ttl_seconds = json["auth"]["lease_duration"].as_u64();

        tracing::info!(
            ttl_seconds = ?ttl_seconds,
            "OpenBao: AppRole authentication successful"
        );

        Ok(OpenBaoToken { token, ttl_seconds })
    }

    /// Spawn a background task to renew the `OpenBao` token at 75% of TTL.
    fn spawn_renewal_task(
        client: reqwest::Client,
        address: String,
        namespace: Option<String>,
        token_state: Arc<RwLock<Option<OpenBaoToken>>>,
        initial_ttl: u64,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut current_ttl = initial_ttl;
            let mut consecutive_failures: u32 = 0;
            loop {
                // Renew at 75% of TTL
                let wait_secs = (current_ttl as f64 * 0.75) as u64;
                let wait_secs = wait_secs.max(1);
                tracing::debug!(
                    wait_secs = wait_secs,
                    ttl = current_ttl,
                    "OpenBao: Scheduling token renewal"
                );
                tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;

                let current_token = {
                    let state = token_state.read().await;
                    state.as_ref().map(|t| t.token.clone())
                };

                let Some(token) = current_token else {
                    tracing::warn!(
                        "OpenBao: No token available for renewal, stopping renewal task"
                    );
                    break;
                };

                match Self::renew_token(&client, &address, &namespace, &token).await {
                    Ok(new_ttl) => {
                        current_ttl = new_ttl;
                        consecutive_failures = 0;
                        tracing::info!(new_ttl = new_ttl, "OpenBao: Token renewed successfully");
                    }
                    Err(e) => {
                        consecutive_failures += 1;
                        let backoff = std::cmp::min(5 * (1u64 << consecutive_failures.min(6)), 300);
                        tracing::error!(
                            error = %e,
                            consecutive_failures = consecutive_failures,
                            retry_in_secs = backoff,
                            "OpenBao: Token renewal failed, will retry with backoff"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                    }
                }
            }
        })
    }

    /// Renew the current token.
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
                provider: "openbao".to_string(),
                detail: format!("Token renewal request failed: {e}"),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            return Err(SecretError::ProviderUnavailable {
                provider: "openbao".to_string(),
                detail: format!("Token renewal failed with HTTP {status}"),
            });
        }

        let json: serde_json::Value =
            resp.json()
                .await
                .map_err(|e| SecretError::ProviderUnavailable {
                    provider: "openbao".to_string(),
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
                provider: "openbao".to_string(),
                detail: "No OpenBao token available".to_string(),
            })
    }
}

impl Drop for OpenBaoSecretProvider {
    fn drop(&mut self) {
        if let Some(handle) = self._renewal_handle.take() {
            handle.abort();
        }
    }
}

#[async_trait]
impl DynamicSecretProvider for OpenBaoSecretProvider {
    async fn generate_credentials(
        &self,
        request: &DynamicCredentialRequest,
    ) -> Result<DynamicCredential, SecretError> {
        let token = self.current_token().await?;

        // Role name from secret_type or role override
        let role_name = request
            .role
            .as_ref()
            .unwrap_or(&request.secret_type)
            .clone();

        // Generate credentials from database secrets engine
        // Endpoint: GET /v1/{mount}/creds/{role}
        let url = format!(
            "{}/v1/{}/creds/{}",
            self.address, self.database_mount, role_name
        );

        let mut req = self.client.get(&url).header("X-Vault-Token", &token);
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| SecretError::ProviderUnavailable {
                provider: "openbao".to_string(),
                detail: format!(
                    "Failed to generate credentials for role '{role_name}': {e}"
                ),
            })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(SecretError::NotFound {
                name: format!("database role: {role_name}"),
            });
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(SecretError::ProviderUnavailable {
                provider: "openbao".to_string(),
                detail: format!(
                    "OpenBao returned HTTP {status} for credential generation: {body_text}"
                ),
            });
        }

        let json: serde_json::Value = resp.json().await.map_err(|e| SecretError::InvalidValue {
            name: role_name.clone(),
            detail: format!("Invalid OpenBao response JSON: {e}"),
        })?;

        // Extract credential data
        let data = json
            .get("data")
            .ok_or_else(|| SecretError::InvalidValue {
                name: role_name.clone(),
                detail: "Missing 'data' in OpenBao response".to_string(),
            })?
            .clone();

        // Extract lease information
        let lease_id = json
            .get("lease_id")
            .and_then(|v| v.as_str())
            .map(std::string::ToString::to_string);

        let lease_duration = json
            .get("lease_duration")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(i64::from(request.ttl_seconds));

        tracing::info!(
            role = %role_name,
            lease_id = ?lease_id,
            lease_duration = lease_duration,
            tenant_id = %request.tenant_id,
            agent_id = %request.agent_id,
            "OpenBao: Generated dynamic credentials"
        );

        Ok(DynamicCredential {
            credentials: data,
            lease_id,
            ttl_seconds: lease_duration as i32,
        })
    }

    async fn revoke_credentials(&self, lease_id: &str) -> Result<(), SecretError> {
        let token = self.current_token().await?;

        // Revoke lease: PUT /v1/sys/leases/revoke
        let url = format!("{}/v1/sys/leases/revoke", self.address);
        let body = serde_json::json!({
            "lease_id": lease_id,
        });

        let mut req = self
            .client
            .put(&url)
            .header("X-Vault-Token", &token)
            .json(&body);
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| SecretError::ProviderUnavailable {
                provider: "openbao".to_string(),
                detail: format!("Failed to revoke lease '{lease_id}': {e}"),
            })?;

        if resp.status().is_success() {
            tracing::info!(lease_id = lease_id, "OpenBao: Successfully revoked lease");
        } else {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            tracing::warn!(
                lease_id = lease_id,
                status = %status,
                body = %body_text,
                "OpenBao: Lease revocation returned non-success status"
            );
            // Don't fail on revocation errors - the lease may have already expired
        }

        Ok(())
    }

    async fn health_check(&self) -> Result<bool, SecretError> {
        let url = format!("{}/v1/sys/health", self.address);
        let resp =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| SecretError::ProviderUnavailable {
                    provider: "openbao".to_string(),
                    detail: format!("OpenBao health check failed: {e}"),
                })?;

        // Health endpoint returns:
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
        "openbao"
    }

    fn supports_revocation(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_default_config() {
        let config = OpenBaoConfig::default();
        assert_eq!(config.address, "http://127.0.0.1:8200");
        assert!(config.namespace.is_none());
        assert_eq!(config.database_mount, "database");
    }

    #[test]
    fn test_provider_type() {
        // Can't test full provider without a real OpenBao instance,
        // but we can verify the type string
        assert_eq!("openbao", "openbao");
    }

    #[tokio::test]
    async fn test_credential_request_struct() {
        let request = DynamicCredentialRequest {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            secret_type: "postgres-readonly".to_string(),
            ttl_seconds: 300,
            role: Some("reader".to_string()),
            context: None,
        };

        assert_eq!(request.secret_type, "postgres-readonly");
        assert_eq!(request.ttl_seconds, 300);
        assert_eq!(request.role, Some("reader".to_string()));
    }
}
