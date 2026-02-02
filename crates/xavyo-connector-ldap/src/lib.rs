//! # LDAP Connector
//!
//! LDAP/Active Directory connector for xavyo provisioning.
//!
//! This crate provides the ability to connect to LDAP directories and
//! Active Directory domains for user and group provisioning.
//!
//! ## Features
//!
//! - LDAP v3 protocol support
//! - SSL/TLS and STARTTLS
//! - Active Directory specific features
//! - Schema discovery
//! - Connection pooling
//! - Paged search results
//!
//! ## Example
//!
//! ```ignore
//! use xavyo_connector_ldap::{LdapConfig, LdapConnector};
//! use xavyo_connector::prelude::*;
//!
//! let config = LdapConfig::new(
//!     "ldap.example.com",
//!     "dc=example,dc=com",
//!     "cn=admin,dc=example,dc=com",
//! )
//! .with_password("secret")
//! .with_ssl();
//!
//! let connector = LdapConnector::new(config)?;
//! connector.test_connection().await?;
//! ```

pub mod ad;
pub mod config;
pub mod connector;
mod schema_definitions;

// Re-exports
pub use ad::AdConnector;
pub use config::{ActiveDirectoryConfig, LdapConfig};
pub use connector::LdapConnector;
