//! HTTP client wrapper for xavyo API

use crate::config::Config;
use crate::config::ConfigPaths;
use crate::credentials::{get_credential_store, CredentialStore};
use crate::error::{CliError, CliResult};
use crate::models::{Credentials, Session};
use chrono::Utc;
use reqwest::Client;
use std::time::Duration;
use uuid::Uuid;

/// API client for making authenticated requests
pub struct ApiClient {
    client: Client,
    config: Config,
    paths: ConfigPaths,
}

impl ApiClient {
    /// Create an API client from default config paths
    pub fn from_defaults() -> CliResult<Self> {
        let paths = ConfigPaths::new()?;
        let config = Config::load(&paths)?;
        Self::new(config, paths)
    }

    /// Create a new API client
    pub fn new(config: Config, paths: ConfigPaths) -> CliResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| CliError::Network(format!("Failed to create HTTP client: {e}")))?;

        Ok(Self {
            client,
            config,
            paths,
        })
    }

    /// Get a reference to the config
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get a reference to the paths
    pub fn paths(&self) -> &ConfigPaths {
        &self.paths
    }

    /// Get the current tenant ID from the session (if set)
    fn get_tenant_id(&self) -> Option<Uuid> {
        Session::load(&self.paths)
            .ok()
            .flatten()
            .and_then(|s| s.tenant_id)
    }

    /// Get credentials, refreshing if needed
    pub async fn get_valid_credentials(&self) -> CliResult<Credentials> {
        let store = get_credential_store(&self.paths);
        let credentials = store.load()?.ok_or(CliError::NotAuthenticated)?;

        // Check if token is expired (with 5 minute buffer)
        let now = Utc::now();
        let buffer = chrono::Duration::minutes(5);

        if credentials.expires_at <= now + buffer {
            // Token expired or about to expire, try to refresh
            self.refresh_token(&credentials, store.as_ref()).await
        } else {
            Ok(credentials)
        }
    }

    /// Refresh the access token using the refresh token
    async fn refresh_token(
        &self,
        credentials: &Credentials,
        store: &dyn CredentialStore,
    ) -> CliResult<Credentials> {
        let response = self
            .client
            .post(self.config.token_url())
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", &self.config.client_id),
                ("refresh_token", &credentials.refresh_token),
            ])
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(CliError::TokenExpired);
        }

        let token_response: crate::models::TokenResponse = response.json().await?;
        let new_credentials = Credentials::from_token_response(token_response);

        // Store the new credentials
        store.store(&new_credentials)?;

        Ok(new_credentials)
    }

    /// Make an authenticated POST request with JSON body
    pub async fn post_json<T: serde::Serialize>(
        &self,
        url: &str,
        body: &T,
    ) -> CliResult<reqwest::Response> {
        let credentials = self.get_valid_credentials().await?;
        let mut request = self
            .client
            .post(url)
            .bearer_auth(&credentials.access_token)
            .json(body);

        // Add tenant header if available
        if let Some(tenant_id) = self.get_tenant_id() {
            request = request.header("X-Tenant-ID", tenant_id.to_string());
        }

        request.send().await.map_err(Into::into)
    }

    /// Make an unauthenticated GET request
    pub async fn get_unauthenticated(&self, url: &str) -> CliResult<reqwest::Response> {
        self.client.get(url).send().await.map_err(Into::into)
    }

    /// Make an authenticated GET request
    pub async fn get_authenticated(&self, url: &str) -> CliResult<reqwest::Response> {
        let credentials = self.get_valid_credentials().await?;
        let mut request = self.client.get(url).bearer_auth(&credentials.access_token);

        // Add tenant header if available
        if let Some(tenant_id) = self.get_tenant_id() {
            request = request.header("X-Tenant-ID", tenant_id.to_string());
        }

        request.send().await.map_err(Into::into)
    }

    /// Make an authenticated DELETE request
    pub async fn delete_authenticated(&self, url: &str) -> CliResult<reqwest::Response> {
        let credentials = self.get_valid_credentials().await?;
        let mut request = self
            .client
            .delete(url)
            .bearer_auth(&credentials.access_token);

        // Add tenant header if available
        if let Some(tenant_id) = self.get_tenant_id() {
            request = request.header("X-Tenant-ID", tenant_id.to_string());
        }

        request.send().await.map_err(Into::into)
    }

    /// Make an authenticated PUT request with JSON body
    pub async fn put_json<T: serde::Serialize>(
        &self,
        url: &str,
        body: &T,
    ) -> CliResult<reqwest::Response> {
        let credentials = self.get_valid_credentials().await?;
        let mut request = self
            .client
            .put(url)
            .bearer_auth(&credentials.access_token)
            .json(body);

        // Add tenant header if available
        if let Some(tenant_id) = self.get_tenant_id() {
            request = request.header("X-Tenant-ID", tenant_id.to_string());
        }

        request.send().await.map_err(Into::into)
    }

    /// Get the current access token (refreshing if needed)
    pub async fn get_access_token(&self) -> CliResult<String> {
        let credentials = self.get_valid_credentials().await?;
        Ok(credentials.access_token)
    }

    /// Make an authenticated PATCH request with JSON body (F-051)
    pub async fn patch_json<T: serde::Serialize>(
        &self,
        url: &str,
        body: &T,
    ) -> CliResult<reqwest::Response> {
        let credentials = self.get_valid_credentials().await?;
        let mut request = self
            .client
            .patch(url)
            .bearer_auth(&credentials.access_token)
            .json(body);

        // Add tenant header if available
        if let Some(tenant_id) = self.get_tenant_id() {
            request = request.header("X-Tenant-ID", tenant_id.to_string());
        }

        request.send().await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_client_creation() {
        let config = Config::default();
        let paths = ConfigPaths {
            config_dir: std::path::PathBuf::from("/tmp/xavyo-test"),
            config_file: std::path::PathBuf::from("/tmp/xavyo-test/config.json"),
            session_file: std::path::PathBuf::from("/tmp/xavyo-test/session.json"),
            credentials_file: std::path::PathBuf::from("/tmp/xavyo-test/credentials.enc"),
            cache_dir: std::path::PathBuf::from("/tmp/xavyo-test/cache"),
            history_file: std::path::PathBuf::from("/tmp/xavyo-test/shell_history"),
            version_history_dir: std::path::PathBuf::from("/tmp/xavyo-test/history"),
        };

        let client = ApiClient::new(config, paths).unwrap();
        assert_eq!(client.config().client_id, "xavyo-cli");
    }
}
