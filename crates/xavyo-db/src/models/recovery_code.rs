//! MFA recovery code model.
//!
//! Recovery codes allow users to complete MFA if they lose access to their authenticator app.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// A recovery code for MFA account recovery.
///
/// Each code can only be used once. Codes are stored as SHA-256 hashes.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct UserRecoveryCode {
    /// Unique identifier for this recovery code.
    pub id: Uuid,

    /// The user this code belongs to.
    pub user_id: Uuid,

    /// The tenant this user belongs to.
    pub tenant_id: Uuid,

    /// SHA-256 hash of the recovery code.
    #[serde(skip_serializing)]
    pub code_hash: String,

    /// When this code was used (NULL if unused).
    pub used_at: Option<DateTime<Utc>>,

    /// When this code was created.
    pub created_at: DateTime<Utc>,
}

impl UserRecoveryCode {
    /// Create multiple recovery codes for a user.
    pub async fn create_batch<'e, E>(
        executor: E,
        user_id: Uuid,
        tenant_id: Uuid,
        code_hashes: &[String],
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        // Use unnest for bulk insert
        let code_hashes_vec: Vec<&str> = code_hashes.iter().map(std::string::String::as_str).collect();

        sqlx::query_as(
            r"
            INSERT INTO user_recovery_codes (user_id, tenant_id, code_hash)
            SELECT $1, $2, unnest($3::text[])
            RETURNING *
            ",
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(&code_hashes_vec)
        .fetch_all(executor)
        .await
    }

    /// Find all unused recovery codes for a user.
    pub async fn find_unused_by_user<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as("SELECT * FROM user_recovery_codes WHERE user_id = $1 AND used_at IS NULL")
            .bind(user_id)
            .fetch_all(executor)
            .await
    }

    /// Count unused recovery codes for a user.
    pub async fn count_unused<'e, E>(executor: E, user_id: Uuid) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(executor)
        .await?;
        Ok(result.0)
    }

    /// Mark a recovery code as used.
    /// Returns true if a matching unused code was found and marked.
    pub async fn mark_used<'e, E>(
        executor: E,
        user_id: Uuid,
        code_hash: &str,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query(
            r"
            UPDATE user_recovery_codes
            SET used_at = NOW()
            WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
            ",
        )
        .bind(user_id)
        .bind(code_hash)
        .execute(executor)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete all recovery codes for a user (for regeneration or MFA disable).
    pub async fn delete_all_for_user<'e, E>(executor: E, user_id: Uuid) -> Result<u64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_code_struct() {
        let code = UserRecoveryCode {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            code_hash: "abc123".to_string(),
            used_at: None,
            created_at: Utc::now(),
        };
        assert!(code.used_at.is_none());
    }

    #[test]
    fn test_recovery_code_used() {
        let code = UserRecoveryCode {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            code_hash: "abc123".to_string(),
            used_at: Some(Utc::now()),
            created_at: Utc::now(),
        };
        assert!(code.used_at.is_some());
    }
}
