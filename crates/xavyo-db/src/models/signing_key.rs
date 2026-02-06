//! Signing key model for DB-backed JWT key rotation (F082).
//!
//! Stores RSA signing key pairs with lifecycle states (active/retiring/revoked).
//! At most one key per tenant may be in `active` state at any time.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A JWT signing key stored in the database.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SigningKey {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub kid: String,
    pub algorithm: String,
    #[serde(skip_serializing)]
    pub private_key_pem: String,
    pub public_key_pem: String,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
}

/// Input for creating a new signing key record.
#[derive(Debug, Clone)]
pub struct CreateSigningKey {
    pub tenant_id: Uuid,
    pub kid: String,
    pub algorithm: String,
    pub private_key_pem: String,
    pub public_key_pem: String,
    pub created_by: Option<Uuid>,
}

impl SigningKey {
    /// Insert a new signing key (defaults to 'active' state).
    pub async fn insert<'e, E>(executor: E, input: CreateSigningKey) -> Result<Self, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            INSERT INTO signing_keys (tenant_id, kid, algorithm, private_key_pem, public_key_pem, created_by)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(input.tenant_id)
        .bind(&input.kid)
        .bind(&input.algorithm)
        .bind(&input.private_key_pem)
        .bind(&input.public_key_pem)
        .bind(input.created_by)
        .fetch_one(executor)
        .await
    }

    /// Find a signing key by its kid.
    pub async fn find_by_kid<'e, E>(executor: E, kid: &str) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            SELECT * FROM signing_keys WHERE kid = $1
            ",
        )
        .bind(kid)
        .fetch_optional(executor)
        .await
    }

    /// Find the active signing key for a tenant.
    pub async fn find_active_by_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            SELECT * FROM signing_keys
            WHERE tenant_id = $1 AND state = 'active'
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .fetch_optional(executor)
        .await
    }

    /// Find all non-revoked keys for a tenant (active + retiring).
    pub async fn find_non_revoked_by_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            SELECT * FROM signing_keys
            WHERE tenant_id = $1 AND state IN ('active', 'retiring')
            ORDER BY created_at DESC
            ",
        )
        .bind(tenant_id)
        .fetch_all(executor)
        .await
    }

    /// List all signing keys for a tenant (all states).
    pub async fn list_by_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            SELECT * FROM signing_keys
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            ",
        )
        .bind(tenant_id)
        .fetch_all(executor)
        .await
    }

    /// Transition a key's state (e.g., active → retiring, retiring → revoked).
    pub async fn update_state<'e, E>(
        executor: E,
        kid: &str,
        tenant_id: Uuid,
        new_state: &str,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let now = Utc::now();
        let (rotated_at, revoked_at) = match new_state {
            "retiring" => (Some(now), None),
            "revoked" => (None, Some(now)),
            _ => (None, None),
        };

        // Build update dynamically based on new state
        if new_state == "retiring" {
            sqlx::query_as(
                r"
                UPDATE signing_keys
                SET state = $1, rotated_at = $2
                WHERE kid = $3 AND tenant_id = $4
                RETURNING *
                ",
            )
            .bind(new_state)
            .bind(rotated_at)
            .bind(kid)
            .bind(tenant_id)
            .fetch_optional(executor)
            .await
        } else if new_state == "revoked" {
            sqlx::query_as(
                r"
                UPDATE signing_keys
                SET state = $1, revoked_at = $2
                WHERE kid = $3 AND tenant_id = $4
                RETURNING *
                ",
            )
            .bind(new_state)
            .bind(revoked_at)
            .bind(kid)
            .bind(tenant_id)
            .fetch_optional(executor)
            .await
        } else {
            sqlx::query_as(
                r"
                UPDATE signing_keys
                SET state = $1
                WHERE kid = $2 AND tenant_id = $3
                RETURNING *
                ",
            )
            .bind(new_state)
            .bind(kid)
            .bind(tenant_id)
            .fetch_optional(executor)
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_signing_key_fields() {
        let input = CreateSigningKey {
            tenant_id: Uuid::new_v4(),
            kid: "key-2026-01-27-abc123".to_string(),
            algorithm: "RS256".to_string(),
            private_key_pem: "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
                .to_string(),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                .to_string(),
            created_by: Some(Uuid::new_v4()),
        };

        assert!(!input.kid.is_empty());
        assert_eq!(input.algorithm, "RS256");
        assert!(input.created_by.is_some());
    }
}
