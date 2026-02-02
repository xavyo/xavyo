//! JWT signing key lifecycle management (F082).
//!
//! Manages DB-backed signing keys with state machine:
//! - active: Used for signing new tokens + validation
//! - retiring: Used for validation only (rotated out)
//! - revoked: Removed from JWKS, tokens rejected
//!
//! Keys are loaded from DB at startup and cached in memory.
//! The cache is refreshed on rotation.

use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use xavyo_db::models::signing_key::{CreateSigningKey, SigningKey};

/// In-memory cache of signing keys per tenant.
type KeyCache = HashMap<Uuid, Vec<SigningKey>>;

/// Service for managing JWT signing key lifecycle.
#[derive(Clone)]
pub struct KeyService {
    pool: PgPool,
    /// In-memory cache: tenant_id → signing keys
    cache: Arc<RwLock<KeyCache>>,
}

impl KeyService {
    /// Create a new key service.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Load keys from DB for a tenant and populate cache.
    pub async fn load_keys(&self, tenant_id: Uuid) -> Result<Vec<SigningKey>, sqlx::Error> {
        let keys = SigningKey::find_non_revoked_by_tenant(&self.pool, tenant_id).await?;
        let mut cache = self.cache.write().await;
        cache.insert(tenant_id, keys.clone());
        Ok(keys)
    }

    /// Get the active signing key for a tenant (from cache or DB).
    pub async fn get_active_key(&self, tenant_id: Uuid) -> Result<Option<SigningKey>, sqlx::Error> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(keys) = cache.get(&tenant_id) {
                if let Some(active) = keys.iter().find(|k| k.state == "active") {
                    return Ok(Some(active.clone()));
                }
            }
        }

        // Cache miss — load from DB
        let keys = self.load_keys(tenant_id).await?;
        Ok(keys.into_iter().find(|k| k.state == "active"))
    }

    /// Get all non-revoked keys for a tenant (for JWKS).
    pub async fn get_non_revoked_keys(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<SigningKey>, sqlx::Error> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(keys) = cache.get(&tenant_id) {
                if !keys.is_empty() {
                    return Ok(keys.clone());
                }
            }
        }

        // Cache miss — load from DB
        self.load_keys(tenant_id).await
    }

    /// Rotate the signing key: generate new active key, retire current.
    ///
    /// Returns (new_key, old_key) on success.
    pub async fn rotate_key(
        &self,
        tenant_id: Uuid,
        created_by: Option<Uuid>,
    ) -> Result<(SigningKey, Option<SigningKey>), KeyServiceError> {
        // Generate a new RSA key pair
        let (private_pem, public_pem) =
            generate_rsa_key_pair().map_err(|e| KeyServiceError::KeyGeneration(e.to_string()))?;

        let kid = format!(
            "key-{}-{}",
            chrono::Utc::now().format("%Y%m%d%H%M%S"),
            &Uuid::new_v4().to_string()[..8]
        );

        // Retire current active key (if any)
        let old_key = SigningKey::find_active_by_tenant(&self.pool, tenant_id)
            .await
            .map_err(KeyServiceError::Database)?;

        if let Some(ref old) = old_key {
            SigningKey::update_state(&self.pool, &old.kid, tenant_id, "retiring")
                .await
                .map_err(KeyServiceError::Database)?;
        }

        // Insert new active key
        let new_key = SigningKey::insert(
            &self.pool,
            CreateSigningKey {
                tenant_id,
                kid,
                algorithm: "RS256".to_string(),
                private_key_pem: private_pem,
                public_key_pem: public_pem,
                created_by,
            },
        )
        .await
        .map_err(KeyServiceError::Database)?;

        // Refresh cache
        let _ = self.load_keys(tenant_id).await;

        Ok((new_key, old_key))
    }

    /// Revoke a key by kid (only retiring keys can be revoked; active must be rotated first).
    pub async fn revoke_key(&self, tenant_id: Uuid, kid: &str) -> Result<(), KeyServiceError> {
        let key = SigningKey::find_by_kid(&self.pool, kid)
            .await
            .map_err(KeyServiceError::Database)?
            .ok_or(KeyServiceError::NotFound)?;

        if key.tenant_id != tenant_id {
            return Err(KeyServiceError::NotFound);
        }

        if key.state == "active" {
            return Err(KeyServiceError::CannotRevokeActive);
        }

        if key.state == "revoked" {
            return Err(KeyServiceError::AlreadyRevoked);
        }

        SigningKey::update_state(&self.pool, kid, tenant_id, "revoked")
            .await
            .map_err(KeyServiceError::Database)?;

        // Refresh cache
        let _ = self.load_keys(tenant_id).await;

        Ok(())
    }

    /// List all keys for a tenant.
    pub async fn list_keys(&self, tenant_id: Uuid) -> Result<Vec<SigningKey>, sqlx::Error> {
        SigningKey::list_by_tenant(&self.pool, tenant_id).await
    }

    /// Build a kid → public_key_pem map for JwtPublicKeys extension.
    pub async fn build_public_key_map(
        &self,
        tenant_id: Uuid,
    ) -> Result<HashMap<String, String>, sqlx::Error> {
        let keys = self.get_non_revoked_keys(tenant_id).await?;
        Ok(keys
            .into_iter()
            .map(|k| (k.kid, k.public_key_pem))
            .collect())
    }
}

/// Generate an RSA 2048-bit key pair and return (private_pem, public_pem).
///
/// SECURITY: Uses OsRng directly from the operating system's CSPRNG.
fn generate_rsa_key_pair() -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    use rand::rngs::OsRng;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::RsaPrivateKey;

    let private_key = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let public_key = private_key.to_public_key();

    let private_pem = private_key.to_pkcs8_pem(LineEnding::LF)?.to_string();
    let public_pem = public_key.to_public_key_pem(LineEnding::LF)?;

    Ok((private_pem, public_pem))
}

/// Errors from the key service.
#[derive(Debug, thiserror::Error)]
pub enum KeyServiceError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Key not found")]
    NotFound,

    #[error("Cannot revoke active key — rotate first")]
    CannotRevokeActive,

    #[error("Key is already revoked")]
    AlreadyRevoked,
}
