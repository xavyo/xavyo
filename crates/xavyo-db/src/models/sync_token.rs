//! Sync Token model for tracking synchronization progress.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::fmt;
use uuid::Uuid;

/// Token type indicating precision of resumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SyncTokenType {
    /// Can resume from exact position.
    Precise,
    /// Must restart from batch beginning on failure.
    Batch,
}

impl fmt::Display for SyncTokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncTokenType::Precise => write!(f, "precise"),
            SyncTokenType::Batch => write!(f, "batch"),
        }
    }
}

impl std::str::FromStr for SyncTokenType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "precise" => Ok(SyncTokenType::Precise),
            "batch" => Ok(SyncTokenType::Batch),
            _ => Err(format!("Unknown token type: {s}")),
        }
    }
}

/// Sync token for tracking synchronization progress.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SyncToken {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub connector_id: Uuid,
    pub token_value: String,
    pub token_type: String,
    pub sequence_number: i64,
    pub last_processed_at: Option<DateTime<Utc>>,
    pub is_valid: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SyncToken {
    /// Get the token type enum.
    #[must_use] 
    pub fn token_type(&self) -> SyncTokenType {
        self.token_type.parse().unwrap_or(SyncTokenType::Batch)
    }

    /// Create a new sync token.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        input: &CreateSyncToken,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_sync_tokens (
                tenant_id, connector_id, token_value, token_type, sequence_number
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(&input.token_value)
        .bind(input.token_type.to_string())
        .bind(input.sequence_number)
        .fetch_one(pool)
        .await
    }

    /// Find token by connector ID.
    pub async fn find_by_connector(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sync_tokens
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(pool)
        .await
    }

    /// Find valid token by connector ID.
    pub async fn find_valid_by_connector(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sync_tokens
            WHERE tenant_id = $1 AND connector_id = $2 AND is_valid = true
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(pool)
        .await
    }

    /// Update token value after successful processing.
    pub async fn update_token(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        token_value: &str,
        sequence_number: i64,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sync_tokens
            SET token_value = $3,
                sequence_number = $4,
                last_processed_at = NOW(),
                updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(token_value)
        .bind(sequence_number)
        .fetch_optional(pool)
        .await
    }

    /// Mark token as invalid (requires full resync).
    pub async fn invalidate(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sync_tokens
            SET is_valid = false, updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(pool)
        .await
    }

    /// Reset token (triggers full resync).
    pub async fn reset(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_sync_tokens
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Upsert token (atomic create or update).
    pub async fn upsert(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        input: &CreateSyncToken,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_sync_tokens (
                tenant_id, connector_id, token_value, token_type, sequence_number
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (tenant_id, connector_id) DO UPDATE SET
                token_value = EXCLUDED.token_value,
                token_type = EXCLUDED.token_type,
                sequence_number = EXCLUDED.sequence_number,
                is_valid = true,
                last_processed_at = NOW(),
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(&input.token_value)
        .bind(input.token_type.to_string())
        .bind(input.sequence_number)
        .fetch_one(pool)
        .await
    }

    /// Atomically update token only if sequence matches (optimistic locking).
    pub async fn update_if_sequence_matches(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        expected_sequence: i64,
        new_token_value: &str,
        new_sequence: i64,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sync_tokens
            SET token_value = $4,
                sequence_number = $5,
                last_processed_at = NOW(),
                updated_at = NOW()
            WHERE tenant_id = $1
                AND connector_id = $2
                AND sequence_number = $3
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(expected_sequence)
        .bind(new_token_value)
        .bind(new_sequence)
        .fetch_optional(pool)
        .await
    }
}

/// Input for creating a sync token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSyncToken {
    pub token_value: String,
    pub token_type: SyncTokenType,
    pub sequence_number: i64,
}

impl CreateSyncToken {
    /// Create a new initial token.
    #[must_use] 
    pub fn initial(token_value: String, token_type: SyncTokenType) -> Self {
        Self {
            token_value,
            token_type,
            sequence_number: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_type_roundtrip() {
        for token_type in [SyncTokenType::Precise, SyncTokenType::Batch] {
            let s = token_type.to_string();
            let parsed: SyncTokenType = s.parse().unwrap();
            assert_eq!(token_type, parsed);
        }
    }

    #[test]
    fn test_create_sync_token_initial() {
        let token = CreateSyncToken::initial("abc123".to_string(), SyncTokenType::Batch);
        assert_eq!(token.token_value, "abc123");
        assert_eq!(token.token_type, SyncTokenType::Batch);
        assert_eq!(token.sequence_number, 0);
    }
}
