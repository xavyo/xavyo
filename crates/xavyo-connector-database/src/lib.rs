//! # Database Connector
//!
//! Database connector for xavyo provisioning.
//!
//! This crate provides the ability to connect to databases for user and
//! group provisioning. Supports PostgreSQL, MySQL, MS SQL Server, and Oracle.
//!
//! ## Features
//!
//! - Multiple database support (PostgreSQL, MySQL, MSSQL, Oracle)
//! - Schema discovery from INFORMATION_SCHEMA
//! - Connection pooling
//! - SSL/TLS support
//! - Parameterized queries for security
//!
//! ## Example
//!
//! ```ignore
//! use xavyo_connector_database::{DatabaseConfig, DatabaseDriver, DatabaseConnector};
//! use xavyo_connector::prelude::*;
//!
//! let config = DatabaseConfig::new(
//!     DatabaseDriver::PostgreSQL,
//!     "db.example.com",
//!     "identity_db",
//!     "admin",
//! )
//! .with_password("secret")
//! .with_ssl_mode(SslMode::Require);
//!
//! let connector = DatabaseConnector::new(config)?;
//! connector.test_connection().await?;
//! ```

pub mod config;
pub mod connector;

// Re-exports
pub use config::{DatabaseConfig, DatabaseDriver, SslMode};
pub use connector::DatabaseConnector;
