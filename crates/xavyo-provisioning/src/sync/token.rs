//! Sync token management for resumable synchronization.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use super::error::SyncResult;

/// Token type indicating precision of resumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    /// Can resume from exact position (e.g., LDAP sync cookie).
    Precise,
    /// Must restart from batch beginning on failure (e.g., page token).
    Batch,
}

impl TokenType {
    /// Convert to string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenType::Precise => "precise",
            TokenType::Batch => "batch",
        }
    }
}

impl std::fmt::Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for TokenType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "precise" => Ok(TokenType::Precise),
            "batch" => Ok(TokenType::Batch),
            _ => Err(format!("Unknown token type: {s}")),
        }
    }
}

/// Sync token for tracking synchronization progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncToken {
    /// Token ID.
    pub id: Uuid,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Connector ID.
    pub connector_id: Uuid,
    /// Token value from the external system.
    pub token_value: String,
    /// Token type.
    pub token_type: TokenType,
    /// Sequence number for optimistic locking.
    pub sequence_number: i64,
    /// When the token was last processed.
    pub last_processed_at: Option<DateTime<Utc>>,
    /// Whether the token is valid.
    pub is_valid: bool,
    /// When the token was created.
    pub created_at: DateTime<Utc>,
    /// When the token was last updated.
    pub updated_at: DateTime<Utc>,
}

impl SyncToken {
    /// Create a new sync token.
    #[must_use]
    pub fn new(
        tenant_id: Uuid,
        connector_id: Uuid,
        token_value: String,
        token_type: TokenType,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            connector_id,
            token_value,
            token_type,
            sequence_number: 0,
            last_processed_at: None,
            is_valid: true,
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if this token can be used for resumable sync.
    #[must_use]
    pub fn can_resume(&self) -> bool {
        self.is_valid && !self.token_value.is_empty()
    }

    /// Invalidate the token (requires full resync).
    pub fn invalidate(&mut self) {
        self.is_valid = false;
        self.updated_at = Utc::now();
    }
}

/// Manager for sync tokens.
#[derive(Debug, Clone)]
pub struct SyncTokenManager {
    pool: PgPool,
}

impl SyncTokenManager {
    /// Create a new sync token manager.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the current token for a connector.
    #[instrument(skip(self))]
    pub async fn get(&self, tenant_id: Uuid, connector_id: Uuid) -> SyncResult<Option<SyncToken>> {
        let result = sqlx::query_as::<_, SyncTokenRow>(
            r"
            SELECT id, tenant_id, connector_id, token_value, token_type,
                   sequence_number, last_processed_at, is_valid, created_at, updated_at
            FROM gov_sync_tokens
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(SyncTokenRow::into_token))
    }

    /// Get a valid token (returns None if token is invalid).
    #[instrument(skip(self))]
    pub async fn get_valid(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> SyncResult<Option<SyncToken>> {
        let result = sqlx::query_as::<_, SyncTokenRow>(
            r"
            SELECT id, tenant_id, connector_id, token_value, token_type,
                   sequence_number, last_processed_at, is_valid, created_at, updated_at
            FROM gov_sync_tokens
            WHERE tenant_id = $1 AND connector_id = $2 AND is_valid = true
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(SyncTokenRow::into_token))
    }

    /// Create or update a token.
    #[instrument(skip(self))]
    pub async fn upsert(&self, token: &SyncToken) -> SyncResult<SyncToken> {
        let result = sqlx::query_as::<_, SyncTokenRow>(
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
            RETURNING id, tenant_id, connector_id, token_value, token_type,
                      sequence_number, last_processed_at, is_valid, created_at, updated_at
            ",
        )
        .bind(token.tenant_id)
        .bind(token.connector_id)
        .bind(&token.token_value)
        .bind(token.token_type.as_str())
        .bind(token.sequence_number)
        .fetch_one(&self.pool)
        .await?;

        Ok(result.into_token())
    }

    /// Update the token with optimistic locking.
    /// Returns None if the sequence number doesn't match (concurrent modification).
    #[instrument(skip(self))]
    pub async fn update_if_sequence_matches(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        expected_sequence: i64,
        new_token_value: &str,
        new_sequence: i64,
    ) -> SyncResult<Option<SyncToken>> {
        let result = sqlx::query_as::<_, SyncTokenRow>(
            r"
            UPDATE gov_sync_tokens
            SET token_value = $4,
                sequence_number = $5,
                last_processed_at = NOW(),
                updated_at = NOW()
            WHERE tenant_id = $1
                AND connector_id = $2
                AND sequence_number = $3
            RETURNING id, tenant_id, connector_id, token_value, token_type,
                      sequence_number, last_processed_at, is_valid, created_at, updated_at
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(expected_sequence)
        .bind(new_token_value)
        .bind(new_sequence)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(SyncTokenRow::into_token))
    }

    /// Invalidate a token (triggers full resync on next sync).
    #[instrument(skip(self))]
    pub async fn invalidate(&self, tenant_id: Uuid, connector_id: Uuid) -> SyncResult<bool> {
        let result = sqlx::query(
            r"
            UPDATE gov_sync_tokens
            SET is_valid = false, updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Reset token (delete to trigger full resync).
    #[instrument(skip(self))]
    pub async fn reset(&self, tenant_id: Uuid, connector_id: Uuid) -> SyncResult<bool> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_sync_tokens
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Initialize a token for a new connector.
    #[instrument(skip(self))]
    pub async fn initialize(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        initial_token: &str,
        token_type: TokenType,
    ) -> SyncResult<SyncToken> {
        let token = SyncToken::new(
            tenant_id,
            connector_id,
            initial_token.to_string(),
            token_type,
        );
        self.upsert(&token).await
    }
}

/// Database row for sync token.
#[derive(Debug, sqlx::FromRow)]
struct SyncTokenRow {
    id: Uuid,
    tenant_id: Uuid,
    connector_id: Uuid,
    token_value: String,
    token_type: String,
    sequence_number: i64,
    last_processed_at: Option<DateTime<Utc>>,
    is_valid: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl SyncTokenRow {
    fn into_token(self) -> SyncToken {
        SyncToken {
            id: self.id,
            tenant_id: self.tenant_id,
            connector_id: self.connector_id,
            token_value: self.token_value,
            token_type: self.token_type.parse().unwrap_or(TokenType::Batch),
            sequence_number: self.sequence_number,
            last_processed_at: self.last_processed_at,
            is_valid: self.is_valid,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_type_roundtrip() {
        for tt in [TokenType::Precise, TokenType::Batch] {
            let s = tt.as_str();
            let parsed: TokenType = s.parse().unwrap();
            assert_eq!(tt, parsed);
        }
    }

    #[test]
    fn test_sync_token_new() {
        let tenant_id = Uuid::new_v4();
        let connector_id = Uuid::new_v4();

        let token = SyncToken::new(
            tenant_id,
            connector_id,
            "cookie123".to_string(),
            TokenType::Precise,
        );

        assert_eq!(token.tenant_id, tenant_id);
        assert_eq!(token.connector_id, connector_id);
        assert_eq!(token.token_value, "cookie123");
        assert_eq!(token.token_type, TokenType::Precise);
        assert!(token.can_resume());
        assert!(token.is_valid);
    }

    #[test]
    fn test_token_invalidation() {
        let mut token = SyncToken::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "token".to_string(),
            TokenType::Batch,
        );

        assert!(token.can_resume());

        token.invalidate();
        assert!(!token.can_resume());
        assert!(!token.is_valid);
    }

    #[test]
    fn test_empty_token_cannot_resume() {
        let token = SyncToken::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            String::new(),
            TokenType::Batch,
        );

        assert!(!token.can_resume());
    }
}
