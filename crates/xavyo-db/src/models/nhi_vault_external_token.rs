//! Database model for NHI vault external OAuth provider tokens.
//!
//! Stores encrypted OAuth tokens from external providers (CRM, Google, etc.)
//! so agents can act on behalf of users with provider-scoped credentials.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// An encrypted external OAuth token bound to an NHI+user pair.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct NhiVaultExternalToken {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub nhi_id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_client_id: Option<String>,
    #[serde(skip_serializing)]
    pub encrypted_access_token: Vec<u8>,
    #[serde(skip_serializing)]
    pub access_token_nonce: Vec<u8>,
    #[serde(skip_serializing)]
    pub access_token_key_id: String,
    #[serde(skip_serializing)]
    pub encrypted_refresh_token: Option<Vec<u8>>,
    #[serde(skip_serializing)]
    pub refresh_token_nonce: Option<Vec<u8>>,
    #[serde(skip_serializing)]
    pub refresh_token_key_id: Option<String>,
    pub token_type: String,
    pub scopes: Vec<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub last_refreshed_at: Option<DateTime<Utc>>,
    pub token_endpoint: Option<String>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Metadata view of an external token (no encrypted fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalTokenMetadata {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub nhi_id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_client_id: Option<String>,
    pub token_type: String,
    pub scopes: Vec<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub last_refreshed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<NhiVaultExternalToken> for ExternalTokenMetadata {
    fn from(t: NhiVaultExternalToken) -> Self {
        Self {
            id: t.id,
            tenant_id: t.tenant_id,
            nhi_id: t.nhi_id,
            user_id: t.user_id,
            provider: t.provider,
            provider_client_id: t.provider_client_id,
            token_type: t.token_type,
            scopes: t.scopes,
            access_token_expires_at: t.access_token_expires_at,
            refresh_token_expires_at: t.refresh_token_expires_at,
            last_refreshed_at: t.last_refreshed_at,
            created_at: t.created_at,
            updated_at: t.updated_at,
        }
    }
}

/// Input for storing an external token.
#[derive(Debug, Clone)]
pub struct CreateExternalToken {
    pub nhi_id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_client_id: Option<String>,
    pub encrypted_access_token: Vec<u8>,
    pub access_token_nonce: Vec<u8>,
    pub access_token_key_id: String,
    pub encrypted_refresh_token: Option<Vec<u8>>,
    pub refresh_token_nonce: Option<Vec<u8>>,
    pub refresh_token_key_id: Option<String>,
    pub token_type: String,
    pub scopes: Vec<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub token_endpoint: Option<String>,
    pub created_by: Option<Uuid>,
}

impl NhiVaultExternalToken {
    /// Store or update an external token (upsert on tenant+nhi+user+provider).
    pub async fn upsert(
        pool: &PgPool,
        tenant_id: Uuid,
        input: CreateExternalToken,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO nhi_vault_external_tokens (
                tenant_id, nhi_id, user_id, provider, provider_client_id,
                encrypted_access_token, access_token_nonce, access_token_key_id,
                encrypted_refresh_token, refresh_token_nonce, refresh_token_key_id,
                token_type, scopes,
                access_token_expires_at, refresh_token_expires_at,
                token_endpoint, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            ON CONFLICT (tenant_id, nhi_id, user_id, provider)
            DO UPDATE SET
                provider_client_id = EXCLUDED.provider_client_id,
                encrypted_access_token = EXCLUDED.encrypted_access_token,
                access_token_nonce = EXCLUDED.access_token_nonce,
                access_token_key_id = EXCLUDED.access_token_key_id,
                encrypted_refresh_token = EXCLUDED.encrypted_refresh_token,
                refresh_token_nonce = EXCLUDED.refresh_token_nonce,
                refresh_token_key_id = EXCLUDED.refresh_token_key_id,
                token_type = EXCLUDED.token_type,
                scopes = EXCLUDED.scopes,
                access_token_expires_at = EXCLUDED.access_token_expires_at,
                refresh_token_expires_at = EXCLUDED.refresh_token_expires_at,
                token_endpoint = EXCLUDED.token_endpoint,
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.nhi_id)
        .bind(input.user_id)
        .bind(&input.provider)
        .bind(&input.provider_client_id)
        .bind(&input.encrypted_access_token)
        .bind(&input.access_token_nonce)
        .bind(&input.access_token_key_id)
        .bind(&input.encrypted_refresh_token)
        .bind(&input.refresh_token_nonce)
        .bind(&input.refresh_token_key_id)
        .bind(&input.token_type)
        .bind(&input.scopes)
        .bind(input.access_token_expires_at)
        .bind(input.refresh_token_expires_at)
        .bind(&input.token_endpoint)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Find a token by NHI + user + provider.
    pub async fn find_by_nhi_user_provider(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        user_id: Uuid,
        provider: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM nhi_vault_external_tokens
            WHERE tenant_id = $1 AND nhi_id = $2 AND user_id = $3 AND provider = $4
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .bind(user_id)
        .bind(provider)
        .fetch_optional(pool)
        .await
    }

    /// Find a token by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM nhi_vault_external_tokens
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List tokens for an NHI identity.
    pub async fn list_for_nhi(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM nhi_vault_external_tokens
            WHERE tenant_id = $1 AND nhi_id = $2
            ORDER BY provider, user_id
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .fetch_all(pool)
        .await
    }

    /// Update the encrypted tokens after a refresh.
    pub async fn update_after_refresh(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        encrypted_access_token: &[u8],
        access_token_nonce: &[u8],
        access_token_key_id: &str,
        access_token_expires_at: Option<DateTime<Utc>>,
        encrypted_refresh_token: Option<&[u8]>,
        refresh_token_nonce: Option<&[u8]>,
        refresh_token_key_id: Option<&str>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE nhi_vault_external_tokens
            SET encrypted_access_token = $3,
                access_token_nonce = $4,
                access_token_key_id = $5,
                access_token_expires_at = $6,
                encrypted_refresh_token = COALESCE($7, encrypted_refresh_token),
                refresh_token_nonce = COALESCE($8, refresh_token_nonce),
                refresh_token_key_id = COALESCE($9, refresh_token_key_id),
                last_refreshed_at = NOW(),
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(encrypted_access_token)
        .bind(access_token_nonce)
        .bind(access_token_key_id)
        .bind(access_token_expires_at)
        .bind(encrypted_refresh_token)
        .bind(refresh_token_nonce)
        .bind(refresh_token_key_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a token.
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM nhi_vault_external_tokens
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete all tokens for an NHI identity (cascade on NHI lifecycle transitions).
    pub async fn delete_all_for_nhi(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM nhi_vault_external_tokens
            WHERE tenant_id = $1 AND nhi_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_from_token_strips_encrypted_fields() {
        let token = NhiVaultExternalToken {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            nhi_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            provider: "salesforce".into(),
            provider_client_id: Some("sf-client-123".into()),
            encrypted_access_token: vec![1, 2, 3],
            access_token_nonce: vec![4, 5, 6],
            access_token_key_id: "v1".into(),
            encrypted_refresh_token: Some(vec![7, 8, 9]),
            refresh_token_nonce: Some(vec![10, 11, 12]),
            refresh_token_key_id: Some("v1".into()),
            token_type: "bearer".into(),
            scopes: vec!["api".into(), "refresh_token".into()],
            access_token_expires_at: Some(Utc::now()),
            refresh_token_expires_at: None,
            last_refreshed_at: None,
            token_endpoint: Some("https://login.salesforce.com/services/oauth2/token".into()),
            created_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let meta = ExternalTokenMetadata::from(token.clone());
        assert_eq!(meta.provider, "salesforce");
        assert_eq!(meta.scopes.len(), 2);
        assert_eq!(meta.nhi_id, token.nhi_id);
        assert_eq!(meta.user_id, token.user_id);

        // Verify metadata serialization doesn't contain encrypted fields
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("encrypted_access_token"));
        assert!(!json.contains("encrypted_refresh_token"));
    }

    #[test]
    fn token_serialization_skips_encrypted_fields() {
        let token = NhiVaultExternalToken {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            nhi_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            provider: "google".into(),
            provider_client_id: None,
            encrypted_access_token: vec![1, 2, 3],
            access_token_nonce: vec![4, 5, 6],
            access_token_key_id: "v1".into(),
            encrypted_refresh_token: None,
            refresh_token_nonce: None,
            refresh_token_key_id: None,
            token_type: "bearer".into(),
            scopes: vec![],
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            last_refreshed_at: None,
            token_endpoint: None,
            created_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&token).unwrap();
        assert!(!json.contains("encrypted_access_token"));
        assert!(!json.contains("access_token_nonce"));
        assert!(!json.contains("access_token_key_id"));
        assert!(json.contains("google"));
    }

    #[test]
    fn create_input_constructs() {
        let input = CreateExternalToken {
            nhi_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            provider: "hubspot".into(),
            provider_client_id: None,
            encrypted_access_token: vec![1, 2, 3],
            access_token_nonce: vec![4, 5, 6],
            access_token_key_id: "v1".into(),
            encrypted_refresh_token: None,
            refresh_token_nonce: None,
            refresh_token_key_id: None,
            token_type: "bearer".into(),
            scopes: vec!["contacts".into()],
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            token_endpoint: None,
            created_by: None,
        };

        assert_eq!(input.provider, "hubspot");
        assert_eq!(input.scopes, vec!["contacts"]);
    }
}
