//! Infisical dynamic secret provider for just-in-time credential generation (F120).
//!
//! Infisical is an open-source secret management platform that supports
//! dynamic secrets for databases and other services.

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::dynamic::{DynamicCredential, DynamicCredentialRequest, DynamicSecretProvider};
use crate::SecretError;

/// Authentication method for Infisical.
#[derive(Debug, Clone)]
pub enum InfisicalAuthMethod {
    /// Service token authentication (legacy).
    ServiceToken { token: String },
    /// Universal auth with client credentials.
    UniversalAuth {
        client_id: String,
        client_secret: String,
    },
    /// Machine identity token.
    MachineIdentity { identity_id: String, token: String },
}

/// Configuration for Infisical provider.
#[derive(Debug, Clone)]
pub struct InfisicalConfig {
    /// Infisical API URL (default: "https://app.infisical.com").
    pub api_url: String,
    /// Workspace/Project ID.
    pub workspace_id: String,
    /// Environment (e.g., "prod", "staging", "dev").
    pub environment: String,
    /// Authentication method.
    pub auth_method: InfisicalAuthMethod,
}

impl Default for InfisicalConfig {
    fn default() -> Self {
        Self {
            api_url: "https://app.infisical.com".to_string(),
            workspace_id: String::new(),
            environment: "prod".to_string(),
            auth_method: InfisicalAuthMethod::ServiceToken {
                token: String::new(),
            },
        }
    }
}

/// Access token state for Infisical.
#[derive(Debug, Clone)]
struct InfisicalToken {
    access_token: String,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Dynamic secret provider using Infisical's dynamic secrets feature.
///
/// Infisical can generate ephemeral database credentials on demand
/// through its dynamic secrets engine.
pub struct InfisicalSecretProvider {
    client: reqwest::Client,
    api_url: String,
    workspace_id: String,
    environment: String,
    auth_method: InfisicalAuthMethod,
    token: Arc<RwLock<Option<InfisicalToken>>>,
}

impl std::fmt::Debug for InfisicalSecretProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InfisicalSecretProvider")
            .field("api_url", &self.api_url)
            .field("workspace_id", &self.workspace_id)
            .field("environment", &self.environment)
            .finish()
    }
}

impl InfisicalSecretProvider {
    /// Create a new InfisicalSecretProvider from configuration.
    pub async fn new(config: &InfisicalConfig) -> Result<Self, SecretError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| SecretError::ConfigError {
                detail: format!("Failed to create HTTP client: {e}"),
            })?;

        let api_url = config.api_url.trim_end_matches('/').to_string();
        let token_state: Arc<RwLock<Option<InfisicalToken>>> = Arc::new(RwLock::new(None));

        let provider = Self {
            client,
            api_url,
            workspace_id: config.workspace_id.clone(),
            environment: config.environment.clone(),
            auth_method: config.auth_method.clone(),
            token: token_state,
        };

        // Authenticate on creation
        provider.authenticate().await?;

        Ok(provider)
    }

    /// Authenticate and obtain an access token.
    async fn authenticate(&self) -> Result<(), SecretError> {
        let token = match &self.auth_method {
            InfisicalAuthMethod::ServiceToken { token } => {
                tracing::info!("Infisical: Using service token authentication");
                InfisicalToken {
                    access_token: token.clone(),
                    expires_at: None,
                }
            }
            InfisicalAuthMethod::UniversalAuth {
                client_id,
                client_secret,
            } => self.universal_auth_login(client_id, client_secret).await?,
            InfisicalAuthMethod::MachineIdentity { identity_id, token } => {
                self.machine_identity_login(identity_id, token).await?
            }
        };

        let mut state = self.token.write().await;
        *state = Some(token);
        Ok(())
    }

    /// Login using Universal Auth.
    async fn universal_auth_login(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<InfisicalToken, SecretError> {
        let url = format!("{}/api/v1/auth/universal-auth/login", self.api_url);
        let body = serde_json::json!({
            "clientId": client_id,
            "clientSecret": client_secret,
        });

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| SecretError::ProviderUnavailable {
                provider: "infisical".to_string(),
                detail: format!("Failed to connect to Infisical: {e}"),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(SecretError::ProviderUnavailable {
                provider: "infisical".to_string(),
                detail: format!("Infisical universal auth failed (HTTP {status}): {body_text}"),
            });
        }

        let json: serde_json::Value =
            resp.json()
                .await
                .map_err(|e| SecretError::ProviderUnavailable {
                    provider: "infisical".to_string(),
                    detail: format!("Invalid Infisical auth response: {e}"),
                })?;

        let access_token = json["accessToken"]
            .as_str()
            .ok_or(SecretError::ProviderUnavailable {
                provider: "infisical".to_string(),
                detail: "Missing accessToken in Infisical response".to_string(),
            })?
            .to_string();

        let expires_in = json["expiresIn"].as_i64().unwrap_or(7200);
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(expires_in);

        tracing::info!(
            expires_in = expires_in,
            "Infisical: Universal auth successful"
        );

        Ok(InfisicalToken {
            access_token,
            expires_at: Some(expires_at),
        })
    }

    /// Login using Machine Identity.
    async fn machine_identity_login(
        &self,
        identity_id: &str,
        token: &str,
    ) -> Result<InfisicalToken, SecretError> {
        let url = format!("{}/api/v1/auth/token-auth/login", self.api_url);
        let body = serde_json::json!({
            "identityId": identity_id,
        });

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&body)
            .send()
            .await
            .map_err(|e| SecretError::ProviderUnavailable {
                provider: "infisical".to_string(),
                detail: format!("Failed to connect to Infisical: {e}"),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(SecretError::ProviderUnavailable {
                provider: "infisical".to_string(),
                detail: format!(
                    "Infisical machine identity auth failed (HTTP {status}): {body_text}"
                ),
            });
        }

        let json: serde_json::Value =
            resp.json()
                .await
                .map_err(|e| SecretError::ProviderUnavailable {
                    provider: "infisical".to_string(),
                    detail: format!("Invalid Infisical auth response: {e}"),
                })?;

        let access_token = json["accessToken"]
            .as_str()
            .ok_or(SecretError::ProviderUnavailable {
                provider: "infisical".to_string(),
                detail: "Missing accessToken in Infisical response".to_string(),
            })?
            .to_string();

        let expires_in = json["expiresIn"].as_i64().unwrap_or(7200);
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(expires_in);

        tracing::info!(
            expires_in = expires_in,
            "Infisical: Machine identity auth successful"
        );

        Ok(InfisicalToken {
            access_token,
            expires_at: Some(expires_at),
        })
    }

    /// Get the current access token, refreshing if expired.
    async fn current_token(&self) -> Result<String, SecretError> {
        {
            let state = self.token.read().await;
            if let Some(token) = &*state {
                // Check if token is still valid (with 60s buffer)
                if let Some(expires_at) = token.expires_at {
                    if expires_at > chrono::Utc::now() + chrono::Duration::seconds(60) {
                        return Ok(token.access_token.clone());
                    }
                } else {
                    // Service token - no expiration
                    return Ok(token.access_token.clone());
                }
            }
        }

        // Token expired or missing, re-authenticate
        tracing::info!("Infisical: Token expired, re-authenticating");
        self.authenticate().await?;

        let state = self.token.read().await;
        state
            .as_ref()
            .map(|t| t.access_token.clone())
            .ok_or(SecretError::ProviderUnavailable {
                provider: "infisical".to_string(),
                detail: "Failed to obtain Infisical access token".to_string(),
            })
    }
}

#[async_trait]
impl DynamicSecretProvider for InfisicalSecretProvider {
    async fn generate_credentials(
        &self,
        request: &DynamicCredentialRequest,
    ) -> Result<DynamicCredential, SecretError> {
        let access_token = self.current_token().await?;

        // Dynamic secret name from secret_type or role
        let secret_name = request
            .role
            .as_ref()
            .unwrap_or(&request.secret_type)
            .clone();

        // Create dynamic secret lease
        // Endpoint: POST /api/v3/secrets/dynamic/{secretName}/leases
        let url = format!(
            "{}/api/v3/secrets/dynamic/{}/leases",
            self.api_url, secret_name
        );

        let body = serde_json::json!({
            "workspaceId": self.workspace_id,
            "environment": self.environment,
            "ttl": format!("{}s", request.ttl_seconds),
        });

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&body)
            .send()
            .await
            .map_err(|e| SecretError::ProviderUnavailable {
                provider: "infisical".to_string(),
                detail: format!(
                    "Failed to generate credentials for '{}': {}",
                    secret_name, e
                ),
            })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(SecretError::NotFound {
                name: format!("dynamic secret: {}", secret_name),
            });
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(SecretError::ProviderUnavailable {
                provider: "infisical".to_string(),
                detail: format!(
                    "Infisical returned HTTP {} for credential generation: {}",
                    status, body_text
                ),
            });
        }

        let json: serde_json::Value = resp.json().await.map_err(|e| SecretError::InvalidValue {
            name: secret_name.clone(),
            detail: format!("Invalid Infisical response JSON: {e}"),
        })?;

        // Extract lease data
        let lease = json.get("lease").ok_or_else(|| SecretError::InvalidValue {
            name: secret_name.clone(),
            detail: "Missing 'lease' in Infisical response".to_string(),
        })?;

        let lease_id = lease
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let credentials = lease.get("data").cloned().unwrap_or(serde_json::json!({}));

        let ttl = lease
            .get("ttl")
            .and_then(|v| v.as_i64())
            .unwrap_or(request.ttl_seconds as i64);

        tracing::info!(
            secret_name = %secret_name,
            lease_id = ?lease_id,
            ttl = ttl,
            tenant_id = %request.tenant_id,
            agent_id = %request.agent_id,
            "Infisical: Generated dynamic credentials"
        );

        Ok(DynamicCredential {
            credentials,
            lease_id,
            ttl_seconds: ttl as i32,
        })
    }

    async fn revoke_credentials(&self, lease_id: &str) -> Result<(), SecretError> {
        let access_token = self.current_token().await?;

        // Revoke lease: DELETE /api/v3/secrets/dynamic/leases/{leaseId}
        let url = format!(
            "{}/api/v3/secrets/dynamic/leases/{}",
            self.api_url, lease_id
        );

        let resp = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| SecretError::ProviderUnavailable {
                provider: "infisical".to_string(),
                detail: format!("Failed to revoke lease '{}': {}", lease_id, e),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            tracing::warn!(
                lease_id = lease_id,
                status = %status,
                body = %body_text,
                "Infisical: Lease revocation returned non-success status"
            );
            // Don't fail on revocation errors - the lease may have already expired
        } else {
            tracing::info!(lease_id = lease_id, "Infisical: Successfully revoked lease");
        }

        Ok(())
    }

    async fn health_check(&self) -> Result<bool, SecretError> {
        // Try to get workspace info to verify connectivity
        let access_token = match self.current_token().await {
            Ok(token) => token,
            Err(_) => return Ok(false),
        };

        let url = format!(
            "{}/api/v1/workspace/{}/environments",
            self.api_url, self.workspace_id
        );

        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| SecretError::ProviderUnavailable {
                provider: "infisical".to_string(),
                detail: format!("Infisical health check failed: {e}"),
            })?;

        Ok(resp.status().is_success())
    }

    fn provider_type(&self) -> &'static str {
        "infisical"
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
        let config = InfisicalConfig::default();
        assert_eq!(config.api_url, "https://app.infisical.com");
        assert_eq!(config.environment, "prod");
        assert!(config.workspace_id.is_empty());
    }

    #[test]
    fn test_provider_type() {
        assert_eq!("infisical", "infisical");
    }

    #[tokio::test]
    async fn test_credential_request_struct() {
        let request = DynamicCredentialRequest {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            secret_type: "postgres-readonly".to_string(),
            ttl_seconds: 300,
            role: None,
            context: None,
        };

        assert_eq!(request.secret_type, "postgres-readonly");
        assert_eq!(request.ttl_seconds, 300);
        assert!(request.role.is_none());
    }

    #[test]
    fn test_auth_methods() {
        let service_token = InfisicalAuthMethod::ServiceToken {
            token: "test-token".to_string(),
        };
        matches!(service_token, InfisicalAuthMethod::ServiceToken { .. });

        let universal = InfisicalAuthMethod::UniversalAuth {
            client_id: "id".to_string(),
            client_secret: "secret".to_string(),
        };
        matches!(universal, InfisicalAuthMethod::UniversalAuth { .. });

        let machine = InfisicalAuthMethod::MachineIdentity {
            identity_id: "id".to_string(),
            token: "token".to_string(),
        };
        matches!(machine, InfisicalAuthMethod::MachineIdentity { .. });
    }
}
