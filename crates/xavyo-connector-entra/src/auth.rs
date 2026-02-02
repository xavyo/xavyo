//! OAuth2 authentication for Microsoft Graph API.

use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, instrument};

use crate::{EntraCloudEnvironment, EntraCredentials, EntraError, EntraResult};

/// OAuth2 token response from Azure AD.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
    #[allow(dead_code)]
    token_type: String,
}

/// Cached OAuth2 access token.
#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expires_at: DateTime<Utc>,
}

impl CachedToken {
    /// Returns true if the token is expired or will expire within the grace period.
    fn is_expired(&self, grace_period: Duration) -> bool {
        Utc::now() + grace_period >= self.expires_at
    }
}

/// Token cache for managing OAuth2 access tokens.
#[derive(Debug)]
pub struct TokenCache {
    credentials: EntraCredentials,
    cloud_environment: EntraCloudEnvironment,
    tenant_id: String,
    http_client: reqwest::Client,
    cached_token: Arc<RwLock<Option<CachedToken>>>,
    /// Grace period before expiry to trigger refresh (default: 5 minutes).
    grace_period: Duration,
}

impl TokenCache {
    /// Creates a new token cache.
    pub fn new(
        credentials: EntraCredentials,
        cloud_environment: EntraCloudEnvironment,
        tenant_id: String,
    ) -> Self {
        Self {
            credentials,
            cloud_environment,
            tenant_id,
            http_client: reqwest::Client::new(),
            cached_token: Arc::new(RwLock::new(None)),
            grace_period: Duration::minutes(5),
        }
    }

    /// Gets a valid access token, refreshing if necessary.
    #[instrument(skip(self), fields(tenant_id = %self.tenant_id))]
    pub async fn get_token(&self) -> EntraResult<String> {
        // Check if we have a valid cached token
        {
            let cache = self.cached_token.read().await;
            if let Some(ref token) = *cache {
                if !token.is_expired(self.grace_period) {
                    debug!("Using cached token");
                    return Ok(token.access_token.clone());
                }
            }
        }

        // Need to refresh
        debug!("Refreshing access token");
        let new_token = self.acquire_token().await?;

        // Update cache
        {
            let mut cache = self.cached_token.write().await;
            *cache = Some(new_token.clone());
        }

        Ok(new_token.access_token)
    }

    /// Acquires a new access token using client credentials flow.
    #[instrument(skip(self))]
    async fn acquire_token(&self) -> EntraResult<CachedToken> {
        use secrecy::ExposeSecret;

        let token_url = format!(
            "{}/{}/oauth2/v2.0/token",
            self.cloud_environment.login_endpoint(),
            self.tenant_id
        );

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.credentials.client_id),
            (
                "client_secret",
                self.credentials.client_secret.expose_secret(),
            ),
            (
                "scope",
                &format!("{}/.default", self.cloud_environment.graph_endpoint()),
            ),
        ];

        let response = self
            .http_client
            .post(&token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| EntraError::Auth(format!("Token request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(EntraError::Auth(format!(
                "Token request failed with status {}: {}",
                status, body
            )));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| EntraError::Auth(format!("Failed to parse token response: {}", e)))?;

        let expires_at = Utc::now() + Duration::seconds(token_response.expires_in);

        debug!(
            "Acquired new token, expires at {}",
            expires_at.format("%Y-%m-%d %H:%M:%S UTC")
        );

        Ok(CachedToken {
            access_token: token_response.access_token,
            expires_at,
        })
    }

    /// Invalidates the cached token, forcing a refresh on next use.
    pub async fn invalidate(&self) {
        let mut cache = self.cached_token.write().await;
        *cache = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_token_expiry() {
        let token = CachedToken {
            access_token: "test".to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
        };

        // Not expired with 5 minute grace
        assert!(!token.is_expired(Duration::minutes(5)));

        // Expired with 15 minute grace
        assert!(token.is_expired(Duration::minutes(15)));
    }

    #[test]
    fn test_cached_token_already_expired() {
        let token = CachedToken {
            access_token: "test".to_string(),
            expires_at: Utc::now() - Duration::minutes(1),
        };

        assert!(token.is_expired(Duration::minutes(0)));
    }
}
