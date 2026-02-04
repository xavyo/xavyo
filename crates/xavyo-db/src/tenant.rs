//! Tenant context injection for Row-Level Security.
//!
//! This module provides functions to set and manage tenant context
//! in `PostgreSQL` sessions, enabling automatic RLS filtering.

use crate::error::DbError;
use sqlx::{Executor, Postgres};
use xavyo_core::TenantId;

/// Set the tenant context for the current transaction.
///
/// This sets the `PostgreSQL` session variable `app.current_tenant` which is
/// used by Row-Level Security policies to filter data by tenant.
///
/// Uses `SET LOCAL` so the context is automatically cleared when the
/// transaction ends (commit or rollback).
///
/// # Arguments
///
/// * `executor` - A database executor (connection or transaction)
/// * `tenant_id` - The tenant ID to set as context
///
/// # Example
///
/// ```rust,ignore
/// use xavyo_db::{DbPool, set_tenant_context};
/// use xavyo_core::TenantId;
///
/// let pool = DbPool::connect("postgres://localhost/mydb").await?;
/// let mut tx = pool.begin().await?;
///
/// let tenant_id = TenantId::new();
/// set_tenant_context(&mut *tx, tenant_id).await?;
///
/// // All subsequent queries in this transaction are filtered by tenant_id
/// tx.commit().await?;
/// ```
///
/// # Errors
///
/// Returns `DbError::QueryFailed` if the SET command fails.
pub async fn set_tenant_context<'e, E>(executor: E, tenant_id: TenantId) -> Result<(), DbError>
where
    E: Executor<'e, Database = Postgres>,
{
    // SECURITY: Use parameterized set_config() to prevent SQL injection.
    // set_config(setting, value, is_local) with is_local=true is equivalent to SET LOCAL
    // but accepts the value as a parameter, preventing injection attacks.
    sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.as_uuid().to_string())
        .execute(executor)
        .await
        .map_err(DbError::QueryFailed)?;
    Ok(())
}

/// Clear the tenant context for the current session.
///
/// This resets the `app.current_tenant` session variable. After clearing,
/// queries on tenant-scoped tables will return zero rows (fail-safe default).
///
/// # Arguments
///
/// * `executor` - A database executor (connection or transaction)
///
/// # Errors
///
/// Returns `DbError::QueryFailed` if the RESET command fails.
pub async fn clear_tenant_context<'e, E>(executor: E) -> Result<(), DbError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query("RESET app.current_tenant")
        .execute(executor)
        .await
        .map_err(DbError::QueryFailed)?;
    Ok(())
}

/// Get the current tenant context from the session.
///
/// Returns `None` if no tenant context is set.
///
/// # Arguments
///
/// * `executor` - A database executor (connection or transaction)
///
/// # Example
///
/// ```rust,ignore
/// use xavyo_db::{DbPool, set_tenant_context, get_current_tenant};
/// use xavyo_core::TenantId;
///
/// let pool = DbPool::connect("postgres://localhost/mydb").await?;
/// let mut tx = pool.begin().await?;
///
/// // Initially no context
/// assert!(get_current_tenant(&mut *tx).await?.is_none());
///
/// // Set context
/// let tenant_id = TenantId::new();
/// set_tenant_context(&mut *tx, tenant_id).await?;
///
/// // Now context is set
/// let current = get_current_tenant(&mut *tx).await?;
/// assert_eq!(current, Some(tenant_id));
/// ```
///
/// # Errors
///
/// Returns `DbError::QueryFailed` if the query fails.
pub async fn get_current_tenant<'e, E>(executor: E) -> Result<Option<TenantId>, DbError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row: (Option<String>,) =
        sqlx::query_as("SELECT current_setting('app.current_tenant', true)")
            .fetch_one(executor)
            .await
            .map_err(DbError::QueryFailed)?;

    match row.0 {
        Some(uuid_str) if !uuid_str.is_empty() => {
            let tenant_id: TenantId = uuid_str
                .parse()
                .map_err(|e| DbError::QueryFailed(sqlx::Error::Decode(Box::new(e))))?;
            Ok(Some(tenant_id))
        }
        _ => Ok(None),
    }
}

/// A wrapper that holds a connection with tenant context.
///
/// This struct ensures that tenant context is set when the connection
/// is acquired and provides convenient access to the underlying connection.
///
/// # Example
///
/// ```rust,ignore
/// use xavyo_db::{DbPool, TenantConnection};
/// use xavyo_core::TenantId;
///
/// let pool = DbPool::connect("postgres://localhost/mydb").await?;
/// let tenant_id = TenantId::new();
///
/// // Create a connection with tenant context
/// let conn = TenantConnection::new(&pool, tenant_id).await?;
///
/// // Use the connection - all queries filtered by tenant
/// // conn.inner() gives access to the underlying connection
/// ```
pub struct TenantConnection<'a> {
    tx: sqlx::Transaction<'a, Postgres>,
    tenant_id: TenantId,
}

impl<'a> TenantConnection<'a> {
    /// Create a new tenant connection with context already set.
    ///
    /// # Arguments
    ///
    /// * `pool` - The database pool to acquire a connection from
    /// * `tenant_id` - The tenant ID to set as context
    ///
    /// # Errors
    ///
    /// Returns `DbError` if connection acquisition or context setting fails.
    pub async fn new(pool: &'a crate::DbPool, tenant_id: TenantId) -> Result<Self, DbError> {
        let mut tx = pool.begin().await?;
        set_tenant_context(&mut *tx, tenant_id).await?;
        Ok(Self { tx, tenant_id })
    }

    /// Get the tenant ID associated with this connection.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Get mutable access to the underlying transaction.
    pub fn inner(&mut self) -> &mut sqlx::Transaction<'a, Postgres> {
        &mut self.tx
    }

    /// Commit the transaction.
    ///
    /// # Errors
    ///
    /// Returns `DbError::QueryFailed` if the commit fails.
    pub async fn commit(self) -> Result<(), DbError> {
        self.tx.commit().await.map_err(DbError::QueryFailed)
    }

    /// Rollback the transaction.
    ///
    /// # Errors
    ///
    /// Returns `DbError::QueryFailed` if the rollback fails.
    pub async fn rollback(self) -> Result<(), DbError> {
        self.tx.rollback().await.map_err(DbError::QueryFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_id_uuid_format() {
        // Verify TenantId produces valid UUID format for parameterized queries
        let tenant_id = TenantId::new();
        let uuid_str = tenant_id.as_uuid().to_string();
        // UUID should be valid format (8-4-4-4-12)
        assert_eq!(uuid_str.len(), 36);
        assert_eq!(uuid_str.chars().filter(|c| *c == '-').count(), 4);
        // All chars should be hex digits or hyphens
        assert!(uuid_str.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
    }

    #[test]
    fn test_tenant_id_no_sql_injection_chars() {
        // Verify UUID string doesn't contain SQL injection characters
        let tenant_id = TenantId::new();
        let uuid_str = tenant_id.as_uuid().to_string();
        // UUID format naturally prevents injection, but verify no special chars
        assert!(!uuid_str.contains('\''));
        assert!(!uuid_str.contains('"'));
        assert!(!uuid_str.contains(';'));
        assert!(!uuid_str.contains('\\'));
    }
}
