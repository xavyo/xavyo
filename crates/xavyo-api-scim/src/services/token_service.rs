//! SCIM token generation and validation service.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{ScimToken, ScimTokenCreated, ScimTokenInfo};

use crate::error::{ScimError, ScimResult};

/// Token prefix for SCIM tokens.
pub const TOKEN_PREFIX: &str = "xscim_";

/// Token service for generating and validating SCIM Bearer tokens.
pub struct TokenService {
    pool: PgPool,
}

impl TokenService {
    /// Create a new token service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Generate a new SCIM token.
    ///
    /// Returns the token details including the raw token (shown only once).
    ///
    /// SECURITY: Uses `OsRng` directly from the operating system's CSPRNG.
    pub async fn generate_token(
        &self,
        tenant_id: Uuid,
        name: &str,
        created_by: Uuid,
    ) -> ScimResult<ScimTokenCreated> {
        // Validate token name
        let name = name.trim();
        if name.is_empty() || name.len() > 255 {
            return Err(ScimError::Validation(
                "Token name must be between 1 and 255 characters".to_string(),
            ));
        }

        use rand::rngs::OsRng;
        // Generate 32 bytes of random data
        let mut random_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut random_bytes);

        // Encode as base64
        let token_body = URL_SAFE_NO_PAD.encode(random_bytes);
        let raw_token = format!("{TOKEN_PREFIX}{token_body}");

        // Hash the token for storage
        let token_hash = Self::hash_token(&raw_token);

        // Create display prefix (e.g., "xscim_...XXXX")
        let token_prefix = format!(
            "{}...{}",
            TOKEN_PREFIX,
            &token_body[token_body.len().saturating_sub(4)..]
        );

        // Store in database
        let token = ScimToken::create(
            &self.pool,
            tenant_id,
            name,
            &token_hash,
            &token_prefix,
            created_by,
        )
        .await?;

        Ok(ScimTokenCreated {
            id: token.id,
            name: token.name,
            token: raw_token,
            created_at: token.created_at,
            warning: "Store this token securely. It will not be shown again.".to_string(),
        })
    }

    /// Validate a Bearer token and return the associated token record.
    pub async fn validate_token(&self, bearer_token: &str) -> ScimResult<ScimToken> {
        // Check prefix
        if !bearer_token.starts_with(TOKEN_PREFIX) {
            return Err(ScimError::Unauthorized);
        }

        // Hash the provided token
        let token_hash = Self::hash_token(bearer_token);

        // Look up in database
        let token = ScimToken::find_by_hash(&self.pool, &token_hash)
            .await?
            .ok_or(ScimError::Unauthorized)?;

        // Check if revoked
        if !token.is_active() {
            return Err(ScimError::Unauthorized);
        }

        // Update last used timestamp. Persist errors must not look like
        // the token was unused for rotation/inactivity.
        scim_last_used_recorded(
            ScimToken::update_last_used(&self.pool, token.tenant_id, token.id).await,
        )?;

        Ok(token)
    }

    /// List all tokens for a tenant.
    pub async fn list_tokens(&self, tenant_id: Uuid) -> ScimResult<Vec<ScimTokenInfo>> {
        let tokens = ScimToken::list_by_tenant(&self.pool, tenant_id).await?;
        Ok(tokens.into_iter().map(ScimTokenInfo::from).collect())
    }

    /// Revoke a token.
    pub async fn revoke_token(&self, tenant_id: Uuid, token_id: Uuid) -> ScimResult<()> {
        let revoked = ScimToken::revoke(&self.pool, tenant_id, token_id).await?;

        if revoked.is_none() {
            return Err(ScimError::NotFound(
                "Token not found or already revoked".to_string(),
            ));
        }

        Ok(())
    }

    /// Hash a token using SHA-256.
    fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }
}

/// Persist last_used_at on SCIM token validation. Errors must not skip
/// inactivity/rotation tracking.
fn scim_last_used_recorded<T, E>(result: Result<T, E>) -> Result<T, E> {
    result
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_hash_consistency() {
        let token = "xscim_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk";
        let hash1 = TokenService::hash_token(token);
        let hash2 = TokenService::hash_token(token);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 produces 64 hex characters
    }

    #[test]
    fn test_different_tokens_different_hashes() {
        let token1 = "xscim_token1";
        let token2 = "xscim_token2";

        let hash1 = TokenService::hash_token(token1);
        let hash2 = TokenService::hash_token(token2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_token_prefix() {
        assert_eq!(TOKEN_PREFIX, "xscim_");
    }

    #[test]
    fn scim_last_used_recorded_propagates_errors() {
        assert!(scim_last_used_recorded(Ok::<(), &str>(())).is_ok());
        assert!(scim_last_used_recorded(Err::<(), _>("db")).is_err());
    }

    #[test]
    fn validate_token_does_not_swallow_last_used_persist() {
        let src = include_str!("token_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("scim_last_used_recorded(")
                && production.contains("ScimToken::update_last_used"),
            "last_used persist must fail closed"
        );
        assert!(
            !production.contains("tokio::spawn")
                && !production.contains("let _ = ScimToken::update_last_used"),
            "must not fire-and-forget last_used persist"
        );
    }
}
