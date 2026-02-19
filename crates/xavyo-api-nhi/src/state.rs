//! Application state for the unified NHI API.

use crate::services::mcp_discovery_service::McpDiscoveryService;
use crate::services::vault_service::VaultService;
use sqlx::PgPool;
#[cfg(feature = "kafka")]
use std::sync::Arc;
use xavyo_api_oauth::services::OAuth2ClientService;

/// Application state for the unified NHI API.
///
/// Contains the database pool and will hold service instances
/// as they are implemented in later phases.
#[derive(Clone)]
pub struct NhiState {
    /// Database connection pool.
    pub pool: PgPool,
    /// OAuth2 client service for provisioning.
    pub oauth_client_service: OAuth2ClientService,
    /// Kafka event producer for delegation lifecycle events.
    #[cfg(feature = "kafka")]
    pub event_producer: Option<Arc<xavyo_events::EventProducer>>,
    /// MCP discovery service for AgentGateway integration.
    pub mcp_discovery_service: McpDiscoveryService,
    /// Vault service for encrypted secret management (None if VAULT_MASTER_KEY not set).
    pub vault_service: Option<VaultService>,
}

impl NhiState {
    /// Creates a new `NhiState` with the given database pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        let oauth_client_service = OAuth2ClientService::new(pool.clone());
        Self {
            pool,
            oauth_client_service,
            #[cfg(feature = "kafka")]
            event_producer: None,
            mcp_discovery_service: McpDiscoveryService::new(None),
            vault_service: None,
        }
    }

    /// Creates a new `NhiState` with an event producer for Kafka events.
    #[cfg(feature = "kafka")]
    #[must_use]
    pub fn with_event_producer(pool: PgPool, producer: Arc<xavyo_events::EventProducer>) -> Self {
        let oauth_client_service = OAuth2ClientService::new(pool.clone());
        Self {
            pool,
            oauth_client_service,
            event_producer: Some(producer),
            mcp_discovery_service: McpDiscoveryService::new(None),
            vault_service: None,
        }
    }

    /// Sets the system-level AgentGateway MCP URL for discovery.
    #[must_use]
    pub fn with_mcp_discovery(mut self, system_url: Option<String>) -> Self {
        self.mcp_discovery_service = McpDiscoveryService::new(system_url);
        self
    }

    /// Sets the vault service for encrypted secret management.
    #[must_use]
    pub fn with_vault(mut self, vault_service: VaultService) -> Self {
        self.vault_service = Some(vault_service);
        self
    }
}
