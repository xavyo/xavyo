//! Microsoft Entra ID Connector for xavyo
//!
//! This crate implements the xavyo-connector traits for Microsoft Entra ID (formerly Azure AD),
//! enabling bidirectional identity synchronization via the Microsoft Graph API.
//!
//! # Features
//!
//! - `OAuth2` client credentials authentication
//! - Full and delta (incremental) user sync
//! - Group sync with transitive membership resolution
//! - Outbound provisioning (create/update/disable users)
//! - Directory role and license mapping
//! - Multi-cloud support (Commercial, US Government, China, Germany)
//!
//! # Example
//!
//! ```no_run
//! use xavyo_connector::traits::Connector;
//! use xavyo_connector_entra::{EntraConnector, EntraConfig, EntraCredentials};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = EntraConfig::builder()
//!     .tenant_id("your-tenant-id")
//!     .build()?;
//!
//! let credentials = EntraCredentials {
//!     client_id: "your-client-id".to_string(),
//!     client_secret: "your-client-secret".to_string().into(),
//! };
//!
//! let connector = EntraConnector::new(config, credentials)?;
//! connector.test_connection().await?;
//! # Ok(())
//! # }
//! ```

mod auth;
mod circuit_breaker;
mod config;
mod connector;
mod error;
mod graph_client;
mod groups;
mod metrics;
mod provisioning;
mod rate_limit;
mod request_queue;
mod roles;
mod schema;
mod sync;

// Re-exports
pub use auth::TokenCache;
pub use circuit_breaker::{CircuitBreaker, CircuitBreakerState};
pub use config::{
    EntraCloudEnvironment, EntraConfig, EntraConfigBuilder, EntraConflictStrategy, EntraCredentials,
};
pub use connector::EntraConnector;
pub use error::{EntraError, EntraResult};
pub use graph_client::GraphClient;
pub use groups::MappedEntraGroup;
pub use metrics::RateLimitMetrics;
pub use rate_limit::{RateLimitConfig, RateLimitState, RateLimiter};
pub use request_queue::RequestQueue;
pub use sync::MappedEntraUser;
