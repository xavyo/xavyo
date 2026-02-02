//! WebAuthn challenge model.
//!
//! Stores temporary challenges for WebAuthn registration and authentication ceremonies.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// Type of WebAuthn ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum CeremonyType {
    /// Registration ceremony for new credentials.
    Registration,
    /// Authentication ceremony for existing credentials.
    Authentication,
}

impl std::fmt::Display for CeremonyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registration => write!(f, "registration"),
            Self::Authentication => write!(f, "authentication"),
        }
    }
}

/// Challenge expiry time in minutes.
pub const CHALLENGE_EXPIRY_MINUTES: i64 = 5;

/// A WebAuthn challenge for registration or authentication ceremonies.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct WebAuthnChallenge {
    /// Unique identifier for this challenge.
    pub id: Uuid,

    /// The user this challenge is for.
    pub user_id: Uuid,

    /// The tenant this user belongs to.
    pub tenant_id: Uuid,

    /// Random challenge bytes (32 bytes minimum).
    #[serde(skip_serializing)]
    pub challenge: Vec<u8>,

    /// Type of ceremony (registration or authentication).
    pub ceremony_type: String,

    /// Serialized webauthn-rs state (PasskeyRegistration or PasskeyAuthentication).
    #[serde(skip_serializing)]
    pub state_json: serde_json::Value,

    /// User-provided name for the credential (registration only).
    pub credential_name: Option<String>,

    /// When this challenge was created.
    pub created_at: DateTime<Utc>,

    /// When this challenge expires.
    pub expires_at: DateTime<Utc>,
}

/// Data required to create a new WebAuthn challenge.
#[derive(Debug)]
pub struct CreateWebAuthnChallenge {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub challenge: Vec<u8>,
    pub ceremony_type: CeremonyType,
    pub state_json: serde_json::Value,
    pub credential_name: Option<String>,
}

impl WebAuthnChallenge {
    /// Check if the challenge has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Create a new WebAuthn challenge.
    pub async fn create<'e, E>(
        executor: E,
        data: CreateWebAuthnChallenge,
    ) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            INSERT INTO webauthn_challenges (
                user_id, tenant_id, challenge, ceremony_type, state_json, credential_name
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(data.user_id)
        .bind(data.tenant_id)
        .bind(&data.challenge)
        .bind(data.ceremony_type.to_string())
        .bind(&data.state_json)
        .bind(&data.credential_name)
        .fetch_one(executor)
        .await
    }

    /// Find an active challenge by user ID and ceremony type.
    pub async fn find_active<'e, E>(
        executor: E,
        user_id: Uuid,
        ceremony_type: CeremonyType,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM webauthn_challenges
            WHERE user_id = $1 AND ceremony_type = $2 AND expires_at > NOW()
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .bind(ceremony_type.to_string())
        .fetch_optional(executor)
        .await
    }

    /// Find a challenge by ID (for verification).
    pub async fn find_by_id<'e, E>(executor: E, id: Uuid) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as("SELECT * FROM webauthn_challenges WHERE id = $1")
            .bind(id)
            .fetch_optional(executor)
            .await
    }

    /// Delete a challenge after use (prevents replay).
    pub async fn delete<'e, E>(executor: E, id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query("DELETE FROM webauthn_challenges WHERE id = $1")
            .bind(id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete all challenges for a user (cleanup on new ceremony start).
    pub async fn delete_by_user_and_type<'e, E>(
        executor: E,
        user_id: Uuid,
        ceremony_type: CeremonyType,
    ) -> Result<u64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query(
            "DELETE FROM webauthn_challenges WHERE user_id = $1 AND ceremony_type = $2",
        )
        .bind(user_id)
        .bind(ceremony_type.to_string())
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }

    /// Delete all expired challenges (cleanup job).
    pub async fn delete_expired<'e, E>(executor: E) -> Result<u64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query("DELETE FROM webauthn_challenges WHERE expires_at < NOW()")
            .execute(executor)
            .await?;
        Ok(result.rows_affected())
    }

    /// Check if a user has a pending challenge of a specific type.
    pub async fn has_pending<'e, E>(
        executor: E,
        user_id: Uuid,
        ceremony_type: CeremonyType,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result: (bool,) = sqlx::query_as(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM webauthn_challenges
                WHERE user_id = $1 AND ceremony_type = $2 AND expires_at > NOW()
            )
            "#,
        )
        .bind(user_id)
        .bind(ceremony_type.to_string())
        .fetch_one(executor)
        .await?;
        Ok(result.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ceremony_type_display() {
        assert_eq!(CeremonyType::Registration.to_string(), "registration");
        assert_eq!(CeremonyType::Authentication.to_string(), "authentication");
    }

    #[test]
    fn test_is_expired() {
        let now = Utc::now();

        // Not expired
        let challenge = WebAuthnChallenge {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            challenge: vec![0; 32],
            ceremony_type: "registration".to_string(),
            state_json: serde_json::json!({}),
            credential_name: None,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(5),
        };
        assert!(!challenge.is_expired());

        // Expired
        let expired_challenge = WebAuthnChallenge {
            expires_at: now - chrono::Duration::minutes(1),
            ..challenge
        };
        assert!(expired_challenge.is_expired());
    }
}
