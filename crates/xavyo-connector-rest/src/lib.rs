//! # REST Connector
//!
//! Generic REST API connector for xavyo provisioning.
//!
//! This crate provides the ability to connect to REST APIs for user and
//! group provisioning. Supports various authentication methods and
//! flexible endpoint configuration.
//!
//! ## Features
//!
//! - Multiple authentication methods (Basic, Bearer, API Key, OAuth2)
//! - Flexible endpoint configuration
//! - Multiple pagination styles
//! - Configurable request/response parsing
//! - SSL/TLS support
//!
//! ## Example
//!
//! ```ignore
//! use xavyo_connector_rest::{RestConfig, RestConnector};
//! use xavyo_connector::prelude::*;
//!
//! let config = RestConfig::new("https://api.example.com/v1")
//!     .with_bearer_token("my-api-token")
//!     .with_header("X-Custom-Header", "value");
//!
//! let connector = RestConnector::new(config)?;
//! connector.test_connection().await?;
//! ```

pub mod config;
pub mod connector;
pub mod rate_limit;

// Re-exports
pub use config::{
    EndpointConfig, HttpMethod, PaginationConfig, PaginationStyle, ResponseConfig, RestConfig,
};
pub use connector::RestConnector;
pub use rate_limit::{
    EndpointRateLimit, LogVerbosity, RateLimitConfig, RateLimitError, RateLimiter, RetryConfig,
};
