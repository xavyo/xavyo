//! Database migration management.
//!
//! Provides functions to run and manage versioned SQL migrations.

use crate::error::DbError;
use crate::pool::DbPool;

/// Run all pending database migrations.
///
/// Migrations are embedded at compile time from the `migrations/` directory.
/// Each migration is run in order based on its filename prefix (001_, 002_, etc.).
///
/// # Arguments
///
/// * `pool` - The database connection pool
///
/// # Example
///
/// ```rust,ignore
/// use xavyo_db::{DbPool, run_migrations};
///
/// let pool = DbPool::connect("postgres://localhost/mydb").await?;
/// run_migrations(&pool).await?;
/// println!("Migrations complete!");
/// ```
///
/// # Errors
///
/// Returns `DbError::MigrationFailed` if any migration fails to apply.
pub async fn run_migrations(pool: &DbPool) -> Result<(), DbError> {
    tracing::info!("Running database migrations...");

    sqlx::migrate!("./migrations")
        .run(pool.inner())
        .await
        .map_err(DbError::MigrationFailed)?;

    tracing::info!("Migrations completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    // Migration tests require a real database and are in integration tests
}
