//! Token Vault service for external OAuth provider token management.
//!
//! Provides the exchange API: an agent presents its credential and a user ID,
//! and receives a user-scoped access token for an external provider.
//! Handles auto-refresh when tokens are expired.

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroize;

use super::vault_crypto::{VaultCrypto, VaultCryptoError};
use crate::error::NhiApiError;
use xavyo_db::models::{CreateExternalToken, ExternalTokenMetadata, NhiVaultExternalToken};

/// Parameters for storing an external provider token.
pub struct StoreExternalTokenParams {
    pub nhi_id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_client_id: Option<String>,
    pub access_token: Vec<u8>,
    pub refresh_token: Option<Vec<u8>>,
    pub token_type: String,
    pub scopes: Vec<String>,
    pub access_token_expires_at: Option<chrono::DateTime<Utc>>,
    pub refresh_token_expires_at: Option<chrono::DateTime<Utc>>,
    pub token_endpoint: Option<String>,
    pub created_by: Option<Uuid>,
}

/// Result of a token exchange: a decrypted access token ready for use.
pub struct ExchangedToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: Option<chrono::DateTime<Utc>>,
    pub provider: String,
    pub refreshed: bool,
}

/// Service for external OAuth token vault operations.
#[derive(Clone)]
pub struct TokenVaultService {
    crypto: VaultCrypto,
    http_client: reqwest::Client,
}

impl TokenVaultService {
    pub fn new(crypto: VaultCrypto) -> Self {
        Self {
            crypto,
            http_client: reqwest::Client::new(),
        }
    }

    /// Store an external provider token (encrypts before persisting).
    pub async fn store_token(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        mut params: StoreExternalTokenParams,
    ) -> Result<ExternalTokenMetadata, NhiApiError> {
        // Encrypt access token
        let (enc_at, nonce_at, kid_at) = self
            .crypto
            .encrypt(&params.access_token)
            .map_err(crypto_err)?;
        params.access_token.zeroize();

        // Encrypt refresh token if present
        let (enc_rt, nonce_rt, kid_rt) = if let Some(ref mut rt) = params.refresh_token {
            let (enc, nonce, kid) = self.crypto.encrypt(rt).map_err(crypto_err)?;
            rt.zeroize();
            (Some(enc), Some(nonce), Some(kid))
        } else {
            (None, None, None)
        };

        let token = NhiVaultExternalToken::upsert(
            pool,
            tenant_id,
            CreateExternalToken {
                nhi_id: params.nhi_id,
                user_id: params.user_id,
                provider: params.provider,
                provider_client_id: params.provider_client_id,
                encrypted_access_token: enc_at,
                access_token_nonce: nonce_at,
                access_token_key_id: kid_at,
                encrypted_refresh_token: enc_rt,
                refresh_token_nonce: nonce_rt,
                refresh_token_key_id: kid_rt,
                token_type: params.token_type,
                scopes: params.scopes,
                access_token_expires_at: params.access_token_expires_at,
                refresh_token_expires_at: params.refresh_token_expires_at,
                token_endpoint: params.token_endpoint,
                created_by: params.created_by,
            },
        )
        .await
        .map_err(NhiApiError::Database)?;

        Ok(ExternalTokenMetadata::from(token))
    }

    /// List external tokens for an NHI (metadata only).
    pub async fn list_tokens(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<Vec<ExternalTokenMetadata>, NhiApiError> {
        let tokens = NhiVaultExternalToken::list_for_nhi(pool, tenant_id, nhi_id)
            .await
            .map_err(NhiApiError::Database)?;
        Ok(tokens
            .into_iter()
            .map(ExternalTokenMetadata::from)
            .collect())
    }

    /// Delete an external token.
    pub async fn delete_token(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        token_id: Uuid,
    ) -> Result<bool, NhiApiError> {
        let existing = NhiVaultExternalToken::find_by_id(pool, tenant_id, token_id)
            .await
            .map_err(NhiApiError::Database)?
            .ok_or(NhiApiError::NotFound)?;

        if existing.nhi_id != nhi_id {
            return Err(NhiApiError::NotFound);
        }

        NhiVaultExternalToken::delete(pool, tenant_id, token_id)
            .await
            .map_err(NhiApiError::Database)
    }

    /// Exchange: agent requests a user-scoped access token for a provider.
    ///
    /// If the token is expired and a refresh token + token endpoint are available,
    /// auto-refreshes and persists the new tokens before returning.
    pub async fn exchange_token(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        user_id: Uuid,
        provider: &str,
    ) -> Result<ExchangedToken, NhiApiError> {
        let token = NhiVaultExternalToken::find_by_nhi_user_provider(
            pool, tenant_id, nhi_id, user_id, provider,
        )
        .await
        .map_err(NhiApiError::Database)?
        .ok_or(NhiApiError::NotFound)?;

        let now = Utc::now();
        let is_expired = token
            .access_token_expires_at
            .map(|exp| exp <= now)
            .unwrap_or(false);

        if is_expired {
            // Try auto-refresh
            if let (Some(ref enc_rt), Some(ref nonce_rt), Some(ref kid_rt), Some(ref endpoint)) = (
                &token.encrypted_refresh_token,
                &token.refresh_token_nonce,
                &token.refresh_token_key_id,
                &token.token_endpoint,
            ) {
                let mut refresh_token = self
                    .crypto
                    .decrypt(enc_rt, nonce_rt, kid_rt)
                    .map_err(crypto_err)?;

                match self
                    .refresh_from_provider(
                        endpoint,
                        &String::from_utf8_lossy(&refresh_token),
                        token.provider_client_id.as_deref(),
                    )
                    .await
                {
                    Ok(refreshed) => {
                        refresh_token.zeroize();

                        // Encrypt new tokens
                        let (enc_at, nonce_at, kid_at) = self
                            .crypto
                            .encrypt(refreshed.access_token.as_bytes())
                            .map_err(crypto_err)?;

                        let (enc_rt_new, nonce_rt_new, kid_rt_new) =
                            if let Some(ref new_rt) = refreshed.refresh_token {
                                let (e, n, k) =
                                    self.crypto.encrypt(new_rt.as_bytes()).map_err(crypto_err)?;
                                (Some(e), Some(n), Some(k))
                            } else {
                                (None, None, None)
                            };

                        // Persist refreshed tokens
                        NhiVaultExternalToken::update_after_refresh(
                            pool,
                            tenant_id,
                            token.id,
                            &enc_at,
                            &nonce_at,
                            &kid_at,
                            refreshed.expires_at,
                            enc_rt_new.as_deref(),
                            nonce_rt_new.as_deref(),
                            kid_rt_new.as_deref(),
                        )
                        .await
                        .map_err(NhiApiError::Database)?;

                        return Ok(ExchangedToken {
                            access_token: refreshed.access_token,
                            token_type: token.token_type,
                            expires_at: refreshed.expires_at,
                            provider: token.provider,
                            refreshed: true,
                        });
                    }
                    Err(e) => {
                        refresh_token.zeroize();
                        tracing::warn!(
                            provider = %token.provider,
                            nhi_id = %nhi_id,
                            user_id = %user_id,
                            error = %e,
                            "auto-refresh failed, returning expired token"
                        );
                        // Fall through to return the expired token
                    }
                }
            } else {
                tracing::warn!(
                    provider = %token.provider,
                    nhi_id = %nhi_id,
                    "token expired but no refresh token or endpoint available"
                );
            }
        }

        // Decrypt and return the (possibly expired) access token
        let mut decrypted = self
            .crypto
            .decrypt(
                &token.encrypted_access_token,
                &token.access_token_nonce,
                &token.access_token_key_id,
            )
            .map_err(crypto_err)?;

        let access_token = String::from_utf8_lossy(&decrypted).into_owned();
        decrypted.zeroize();

        Ok(ExchangedToken {
            access_token,
            token_type: token.token_type,
            expires_at: token.access_token_expires_at,
            provider: token.provider,
            refreshed: false,
        })
    }

    /// Call the provider's token endpoint to refresh an access token.
    async fn refresh_from_provider(
        &self,
        token_endpoint: &str,
        refresh_token: &str,
        client_id: Option<&str>,
    ) -> Result<RefreshedTokens, NhiApiError> {
        let mut form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];
        if let Some(cid) = client_id {
            form.push(("client_id", cid));
        }

        let resp = self
            .http_client
            .post(token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| NhiApiError::BadGateway(format!("token refresh request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(NhiApiError::BadGateway(format!(
                "token refresh returned {status}: {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| NhiApiError::BadGateway(format!("invalid token refresh response: {e}")))?;

        let access_token = body["access_token"]
            .as_str()
            .ok_or_else(|| {
                NhiApiError::BadGateway("missing access_token in refresh response".into())
            })?
            .to_string();

        let expires_at = body["expires_in"]
            .as_i64()
            .map(|secs| Utc::now() + chrono::Duration::seconds(secs));

        let refresh_token = body["refresh_token"].as_str().map(String::from);

        Ok(RefreshedTokens {
            access_token,
            refresh_token,
            expires_at,
        })
    }
}

struct RefreshedTokens {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<chrono::DateTime<Utc>>,
}

fn crypto_err(e: VaultCryptoError) -> NhiApiError {
    NhiApiError::Internal(format!("vault crypto error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchanged_token_fields() {
        let token = ExchangedToken {
            access_token: "test-token".into(),
            token_type: "bearer".into(),
            expires_at: Some(Utc::now()),
            provider: "salesforce".into(),
            refreshed: false,
        };
        assert_eq!(token.access_token, "test-token");
        assert!(!token.refreshed);
    }

    #[test]
    fn store_params_zeroize_pattern() {
        let mut params = StoreExternalTokenParams {
            nhi_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            provider: "google".into(),
            provider_client_id: None,
            access_token: b"secret-access-token".to_vec(),
            refresh_token: Some(b"secret-refresh-token".to_vec()),
            token_type: "bearer".into(),
            scopes: vec!["email".into()],
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            token_endpoint: None,
            created_by: None,
        };

        // Verify zeroize works on token fields
        params.access_token.zeroize();
        assert!(params.access_token.iter().all(|&b| b == 0));

        if let Some(ref mut rt) = params.refresh_token {
            rt.zeroize();
            assert!(rt.iter().all(|&b| b == 0));
        }
    }
}
