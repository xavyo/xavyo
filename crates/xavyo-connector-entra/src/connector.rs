//! Entra ID connector implementation.

use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, info};
use xavyo_connector::error::{ConnectorError, ConnectorResult};
use xavyo_connector::traits::Connector;
use xavyo_connector::types::ConnectorType;

use crate::{EntraConfig, EntraCredentials, EntraResult, GraphClient, TokenCache};

/// Microsoft Entra ID connector.
#[derive(Debug)]
pub struct EntraConnector {
    config: EntraConfig,
    #[allow(dead_code)]
    token_cache: Arc<TokenCache>,
    graph_client: GraphClient,
}

impl EntraConnector {
    /// Creates a new Entra connector.
    ///
    /// This constructor is synchronous - token acquisition is deferred
    /// to the first API call (lazy initialization).
    pub fn new(config: EntraConfig, credentials: EntraCredentials) -> EntraResult<Self> {
        config.validate()?;

        let token_cache = Arc::new(TokenCache::new(
            credentials,
            config.cloud_environment,
            config.tenant_id.clone(),
        ));

        let graph_client = GraphClient::new(
            Arc::clone(&token_cache),
            config.cloud_environment,
            config.graph_api_version.clone(),
        )?;

        Ok(Self {
            config,
            token_cache,
            graph_client,
        })
    }

    /// Returns the connector configuration.
    pub fn config(&self) -> &EntraConfig {
        &self.config
    }

    /// Returns a reference to the Graph client.
    pub fn graph_client(&self) -> &GraphClient {
        &self.graph_client
    }

    /// Updates the stored delta link for user sync.
    pub fn set_user_delta_link(&mut self, delta_link: Option<String>) {
        self.config.delta_link_user = delta_link;
    }

    /// Updates the stored delta link for group sync.
    pub fn set_group_delta_link(&mut self, delta_link: Option<String>) {
        self.config.delta_link_group = delta_link;
    }
}

#[async_trait]
impl Connector for EntraConnector {
    fn connector_type(&self) -> ConnectorType {
        ConnectorType::Rest
    }

    fn display_name(&self) -> &str {
        "Microsoft Entra ID"
    }

    async fn test_connection(&self) -> ConnectorResult<()> {
        info!(
            "Testing connection to Entra ID tenant {}",
            self.config.tenant_id
        );

        // Try to get a token and fetch organization info
        let url = format!("{}/organization", self.graph_client.base_url());

        #[derive(serde::Deserialize)]
        struct OrgResponse {
            value: Vec<serde_json::Value>,
        }

        let response: OrgResponse =
            self.graph_client
                .get(&url)
                .await
                .map_err(|e| ConnectorError::ConnectionFailed {
                    message: format!("Failed to fetch organization: {}", e),
                    source: None,
                })?;

        if response.value.is_empty() {
            return Err(ConnectorError::ConnectionFailed {
                message: "No organization found".to_string(),
                source: None,
            });
        }

        debug!(
            "Connection test successful, found {} organization(s)",
            response.value.len()
        );

        Ok(())
    }

    async fn dispose(&self) -> ConnectorResult<()> {
        // Nothing to dispose - HTTP client handles its own cleanup
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EntraCloudEnvironment;

    #[test]
    fn test_connector_name_and_type() {
        // We can't fully test new() without mocking, but we can test basic properties
        let config = EntraConfig::builder()
            .tenant_id("test-tenant")
            .build()
            .unwrap();

        assert_eq!(config.tenant_id, "test-tenant");
        assert_eq!(config.cloud_environment, EntraCloudEnvironment::Commercial);
    }
}
