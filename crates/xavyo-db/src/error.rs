//! Error types for the xavyo-db crate.
//!
//! Provides a unified error type that wraps `SQLx` errors with additional context.

use thiserror::Error;

/// Database operation errors.
///
/// This enum wraps all possible database errors with clear, actionable messages.
///
/// # Example
///
/// ```rust
/// use xavyo_db::DbError;
///
/// fn handle_error(err: DbError) {
///     match err {
///         DbError::ConnectionFailed(e) => eprintln!("Cannot connect: {}", e),
///         DbError::MigrationFailed(e) => eprintln!("Migration error: {}", e),
///         DbError::QueryFailed(e) => eprintln!("Query error: {}", e),
///         DbError::TenantContextMissing => eprintln!("No tenant context set"),
///         DbError::NotFound(msg) => eprintln!("Not found: {}", msg),
///         DbError::ValidationFailed(msg) => eprintln!("Validation: {}", msg),
///     }
/// }
/// ```
#[derive(Debug, Error)]
pub enum DbError {
    /// Failed to establish or acquire a database connection.
    ///
    /// This typically indicates network issues, invalid credentials,
    /// or the database server being unavailable.
    #[error("Database connection failed: {0}")]
    ConnectionFailed(#[source] sqlx::Error),

    /// A database migration failed to apply.
    ///
    /// Check the migration SQL for syntax errors or constraint violations.
    #[error("Migration failed: {0}")]
    MigrationFailed(#[source] sqlx::migrate::MigrateError),

    /// A database query failed to execute.
    ///
    /// This can indicate SQL syntax errors, constraint violations,
    /// or issues with the query parameters.
    #[error("Query failed: {0}")]
    QueryFailed(#[source] sqlx::Error),

    /// Attempted to perform a tenant-scoped operation without setting tenant context.
    ///
    /// Call `set_tenant_context()` before executing tenant-scoped queries.
    #[error("Tenant context required but not set")]
    TenantContextMissing,

    /// Resource not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Validation failed.
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
}

impl DbError {
    /// Check if this error indicates a connection problem.
    #[must_use]
    pub fn is_connection_error(&self) -> bool {
        matches!(self, DbError::ConnectionFailed(_))
    }

    /// Check if this error indicates a migration problem.
    #[must_use]
    pub fn is_migration_error(&self) -> bool {
        matches!(self, DbError::MigrationFailed(_))
    }

    /// Check if this error indicates a query problem.
    #[must_use]
    pub fn is_query_error(&self) -> bool {
        matches!(self, DbError::QueryFailed(_))
    }

    /// Check if this error indicates missing tenant context.
    #[must_use]
    pub fn is_tenant_context_missing(&self) -> bool {
        matches!(self, DbError::TenantContextMissing)
    }

    /// Check if this error indicates a not found error.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, DbError::NotFound(_))
    }

    /// Check if this error indicates a validation error.
    #[must_use]
    pub fn is_validation_failed(&self) -> bool {
        matches!(self, DbError::ValidationFailed(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_tenant_context_missing() {
        let err = DbError::TenantContextMissing;
        assert_eq!(err.to_string(), "Tenant context required but not set");
    }

    #[test]
    fn test_is_tenant_context_missing() {
        let err = DbError::TenantContextMissing;
        assert!(err.is_tenant_context_missing());
        assert!(!err.is_connection_error());
        assert!(!err.is_migration_error());
        assert!(!err.is_query_error());
    }
}
