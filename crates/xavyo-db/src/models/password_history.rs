//! Password history model for tracking previous password hashes.
//!
//! Used to prevent password reuse based on tenant policy.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A record of a user's previous password hash.
///
/// Used to prevent password reuse when history_count > 0 in the tenant policy.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct PasswordHistory {
    /// Unique identifier for this history entry.
    pub id: Uuid,

    /// The user this password belonged to.
    pub user_id: Uuid,

    /// The tenant for RLS isolation.
    pub tenant_id: Uuid,

    /// The Argon2id hash of the previous password.
    pub password_hash: String,

    /// When this password was set.
    pub created_at: DateTime<Utc>,
}

impl PasswordHistory {
    /// Add a password to history.
    pub async fn create<'e, E>(
        executor: E,
        user_id: Uuid,
        tenant_id: Uuid,
        password_hash: &str,
    ) -> Result<Self, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            INSERT INTO password_history (user_id, tenant_id, password_hash)
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(password_hash)
        .fetch_one(executor)
        .await
    }

    /// Get the N most recent passwords for a user.
    pub async fn get_recent<'e, E>(
        executor: E,
        user_id: Uuid,
        tenant_id: Uuid,
        limit: i32,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM password_history
            WHERE user_id = $1 AND tenant_id = $2
            ORDER BY created_at DESC
            LIMIT $3
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(executor)
        .await
    }

    /// Delete old password history entries beyond the limit.
    ///
    /// Keeps only the most recent `keep_count` entries for the user.
    pub async fn prune<'e, E>(
        executor: E,
        user_id: Uuid,
        tenant_id: Uuid,
        keep_count: i32,
    ) -> Result<u64, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let result = sqlx::query(
            r#"
            DELETE FROM password_history
            WHERE user_id = $1 AND tenant_id = $2
            AND id NOT IN (
                SELECT id FROM password_history
                WHERE user_id = $1 AND tenant_id = $2
                ORDER BY created_at DESC
                LIMIT $3
            )
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(keep_count)
        .execute(executor)
        .await?;

        Ok(result.rows_affected())
    }

    /// Delete all password history for a user.
    pub async fn delete_for_user<'e, E>(
        executor: E,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<u64, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let result = sqlx::query(
            r#"
            DELETE FROM password_history
            WHERE user_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .execute(executor)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count password history entries for a user.
    pub async fn count_for_user<'e, E>(
        executor: E,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<i64, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM password_history
            WHERE user_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_history_struct() {
        let history = PasswordHistory {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            password_hash: "argon2hash".to_string(),
            created_at: Utc::now(),
        };
        assert!(!history.password_hash.is_empty());
    }
}
