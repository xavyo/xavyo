//! Connection pool management for `PostgreSQL`.
//!
//! Provides a configurable connection pool using `SQLx`'s `PgPool`.

use crate::error::DbError;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

/// A wrapper around `SQLx`'s `PostgreSQL` connection pool.
///
/// # Example
///
/// ```rust,ignore
/// use xavyo_db::DbPool;
///
/// #[tokio::main]
/// async fn main() -> Result<(), xavyo_db::DbError> {
///     let pool = DbPool::connect("postgres://localhost/mydb").await?;
///     // Use pool for queries...
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct DbPool {
    inner: PgPool,
}

impl DbPool {
    /// Connect to `PostgreSQL` using the provided database URL.
    ///
    /// Uses default pool options (min: 1, max: 10, timeout: 5s).
    ///
    /// # Arguments
    ///
    /// * `database_url` - `PostgreSQL` connection string (e.g., `postgres://user:pass@host/db`)
    ///
    /// # Errors
    ///
    /// Returns `DbError::ConnectionFailed` if the connection cannot be established.
    pub async fn connect(database_url: &str) -> Result<Self, DbError> {
        Self::connect_with_options(database_url, DbPoolOptions::default()).await
    }

    /// Connect to `PostgreSQL` with custom pool options.
    ///
    /// # Arguments
    ///
    /// * `database_url` - `PostgreSQL` connection string
    /// * `options` - Custom pool configuration options
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use xavyo_db::{DbPool, DbPoolOptions};
    /// use std::time::Duration;
    ///
    /// let options = DbPoolOptions {
    ///     min_connections: 5,
    ///     max_connections: 20,
    ///     acquire_timeout: Duration::from_secs(10),
    /// };
    ///
    /// let pool = DbPool::connect_with_options("postgres://localhost/mydb", options).await?;
    /// ```
    pub async fn connect_with_options(
        database_url: &str,
        options: DbPoolOptions,
    ) -> Result<Self, DbError> {
        let pool = PgPoolOptions::new()
            .min_connections(options.min_connections)
            .max_connections(options.max_connections)
            .acquire_timeout(options.acquire_timeout)
            .connect(database_url)
            .await
            .map_err(DbError::ConnectionFailed)?;

        Ok(Self { inner: pool })
    }

    /// Wrap an existing `SQLx` `PgPool`.
    ///
    /// Useful when the pool is already created externally (e.g., in `main.rs`).
    #[must_use]
    pub fn from_raw(pool: PgPool) -> Self {
        Self { inner: pool }
    }

    /// Get a reference to the inner `SQLx` pool.
    ///
    /// This allows direct access to `SQLx`'s `PgPool` for advanced use cases.
    #[must_use]
    pub fn inner(&self) -> &PgPool {
        &self.inner
    }

    /// Begin a new database transaction.
    ///
    /// # Errors
    ///
    /// Returns `DbError::QueryFailed` if the transaction cannot be started.
    pub async fn begin(&self) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, DbError> {
        self.inner.begin().await.map_err(DbError::QueryFailed)
    }

    /// Acquire a connection from the pool.
    ///
    /// # Errors
    ///
    /// Returns `DbError::ConnectionFailed` if a connection cannot be acquired.
    pub async fn acquire(&self) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>, DbError> {
        self.inner
            .acquire()
            .await
            .map_err(DbError::ConnectionFailed)
    }

    /// Close all connections in the pool.
    pub async fn close(&self) {
        self.inner.close().await;
    }

    /// Check if the pool is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }
}

/// Configuration options for the database connection pool.
///
/// # Example
///
/// ```rust
/// use xavyo_db::DbPoolOptions;
/// use std::time::Duration;
///
/// let options = DbPoolOptions {
///     min_connections: 2,
///     max_connections: 50,
///     acquire_timeout: Duration::from_secs(30),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct DbPoolOptions {
    /// Minimum number of connections to maintain in the pool.
    ///
    /// Default: 1
    pub min_connections: u32,

    /// Maximum number of connections allowed in the pool.
    ///
    /// Default: 10
    pub max_connections: u32,

    /// Maximum time to wait when acquiring a connection.
    ///
    /// Default: 5 seconds
    pub acquire_timeout: Duration,
}

impl Default for DbPoolOptions {
    fn default() -> Self {
        Self {
            min_connections: 1,
            max_connections: 10,
            acquire_timeout: Duration::from_secs(5),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_pool_options() {
        let options = DbPoolOptions::default();
        assert_eq!(options.min_connections, 1);
        assert_eq!(options.max_connections, 10);
        assert_eq!(options.acquire_timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_custom_pool_options() {
        let options = DbPoolOptions {
            min_connections: 5,
            max_connections: 100,
            acquire_timeout: Duration::from_secs(30),
        };
        assert_eq!(options.min_connections, 5);
        assert_eq!(options.max_connections, 100);
        assert_eq!(options.acquire_timeout, Duration::from_secs(30));
    }
}
