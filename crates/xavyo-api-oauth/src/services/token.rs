//! Token service for `OAuth2` token operations.

use crate::error::OAuthError;
use crate::models::TokenResponse;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use xavyo_auth::{encode_token_with_kid, JwtClaims};

/// Database representation of a refresh token.
#[derive(Debug, FromRow)]
#[allow(dead_code)] // Fields used by SQLx query_as
struct DbRefreshToken {
    pub id: Uuid,
    pub token_hash: String,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub scope: String,
    pub family_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Access token expiration in seconds (15 minutes per spec).
const ACCESS_TOKEN_EXPIRY_SECS: i64 = 900; // 15 minutes

/// ID token expiration in seconds (1 hour per spec).
const ID_TOKEN_EXPIRY_SECS: i64 = 3600; // 1 hour

/// Refresh token expiration in seconds (7 days per spec).
const REFRESH_TOKEN_EXPIRY_SECS: i64 = 604800; // 7 days

/// Refresh token length in bytes (32 bytes = 256 bits).
const REFRESH_TOKEN_LENGTH: usize = 32;

/// OIDC ID Token claims structure.
///
/// Contains standard OIDC claims plus custom Xavyo claims.
/// See: <https://openid.net/specs/openid-connect-core-1_0.html#IDToken>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer identifier.
    pub iss: String,

    /// Subject identifier (user ID).
    pub sub: String,

    /// Audience (`client_id`).
    pub aud: String,

    /// Expiration time (Unix timestamp).
    pub exp: i64,

    /// Issued at time (Unix timestamp).
    pub iat: i64,

    /// Time when authentication occurred (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,

    /// Nonce value from authorization request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Tenant ID (custom claim).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tid: Option<Uuid>,

    /// Access token hash (for hybrid flows).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
}

impl IdTokenClaims {
    /// Create a new builder for ID token claims.
    #[must_use]
    pub fn builder() -> IdTokenClaimsBuilder {
        IdTokenClaimsBuilder::default()
    }
}

/// Builder for ID token claims.
#[derive(Debug, Default)]
pub struct IdTokenClaimsBuilder {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<String>,
    exp: Option<i64>,
    iat: Option<i64>,
    auth_time: Option<i64>,
    nonce: Option<String>,
    tid: Option<Uuid>,
    at_hash: Option<String>,
}

impl IdTokenClaimsBuilder {
    /// Set the issuer.
    #[must_use]
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    /// Set the subject (user ID).
    #[must_use]
    pub fn subject(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    /// Set the audience (`client_id`).
    #[must_use]
    pub fn audience(mut self, aud: impl Into<String>) -> Self {
        self.aud = Some(aud.into());
        self
    }

    /// Set expiration time as seconds from now.
    #[must_use]
    pub fn expires_in_secs(mut self, secs: i64) -> Self {
        self.exp = Some(Utc::now().timestamp() + secs);
        self
    }

    /// Set the authentication time.
    #[must_use]
    pub fn auth_time(mut self, auth_time: i64) -> Self {
        self.auth_time = Some(auth_time);
        self
    }

    /// Set the nonce.
    #[must_use]
    pub fn nonce(mut self, nonce: Option<&str>) -> Self {
        self.nonce = nonce.map(String::from);
        self
    }

    /// Set the tenant ID.
    #[must_use]
    pub fn tenant_id(mut self, tid: Uuid) -> Self {
        self.tid = Some(tid);
        self
    }

    /// Set the access token hash.
    #[must_use]
    pub fn at_hash(mut self, at_hash: impl Into<String>) -> Self {
        self.at_hash = Some(at_hash.into());
        self
    }

    /// Build the ID token claims.
    #[must_use]
    pub fn build(self) -> IdTokenClaims {
        let now = Utc::now().timestamp();

        IdTokenClaims {
            iss: self.iss.unwrap_or_default(),
            sub: self.sub.unwrap_or_default(),
            aud: self.aud.unwrap_or_default(),
            exp: self.exp.unwrap_or(now + ID_TOKEN_EXPIRY_SECS),
            iat: self.iat.unwrap_or(now),
            auth_time: self.auth_time,
            nonce: self.nonce,
            tid: self.tid,
            at_hash: self.at_hash,
        }
    }
}

/// Service for token generation and management.
#[derive(Debug, Clone)]
pub struct TokenService {
    pool: PgPool,
    issuer: String,
    private_key: Vec<u8>,
    key_id: String,
}

impl TokenService {
    /// Create a new token service.
    #[must_use]
    pub fn new(pool: PgPool, issuer: String, private_key: Vec<u8>, key_id: String) -> Self {
        Self {
            pool,
            issuer,
            private_key,
            key_id,
        }
    }

    /// Get the database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get the issuer.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Generate a cryptographically secure refresh token.
    ///
    /// SECURITY: Uses `OsRng` directly from the operating system's CSPRNG.
    fn generate_refresh_token_value() -> String {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut bytes = [0u8; REFRESH_TOKEN_LENGTH];
        OsRng.fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Hash a refresh token for storage.
    fn hash_refresh_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let hash = hasher.finalize();
        hex::encode(hash)
    }

    /// Generate an access token (JWT with RS256).
    ///
    /// # Arguments
    ///
    /// * `user_id` - Optional user ID (None for client credentials grant)
    /// * `client_id` - The `OAuth2` client ID
    /// * `tenant_id` - The tenant ID
    /// * `scope` - The granted scopes
    /// * `expires_in_secs` - Token expiration in seconds
    ///
    /// # Returns
    ///
    /// A signed JWT access token.
    pub fn generate_access_token(
        &self,
        user_id: Option<Uuid>,
        client_id: &str,
        tenant_id: Uuid,
        scope: &str,
        expires_in_secs: i64,
    ) -> Result<String, OAuthError> {
        // Build claims for access token
        let mut claims_builder = JwtClaims::builder()
            .issuer(&self.issuer)
            .audience(vec![client_id.to_string()])
            .tenant_uuid(tenant_id)
            .expires_in_secs(expires_in_secs);

        // Set subject based on user_id or client_id
        if let Some(uid) = user_id {
            claims_builder = claims_builder.subject(uid.to_string());
        } else {
            // For client credentials, subject is the client_id
            claims_builder = claims_builder.subject(client_id);
        }

        // Add scope as a custom claim by parsing roles from scope
        // Convert space-separated scopes to roles
        let scopes: Vec<String> = scope.split_whitespace().map(String::from).collect();
        claims_builder = claims_builder.roles(scopes);

        let claims = claims_builder.build();

        // Encode the token with key ID for JWKS support
        encode_token_with_kid(&claims, &self.private_key, &self.key_id).map_err(|e| {
            tracing::error!("Failed to encode access token: {}", e);
            OAuthError::Internal("Failed to generate access token".to_string())
        })
    }

    /// Generate an ID token (OIDC compliant JWT).
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID
    /// * `client_id` - The `OAuth2` client ID (used as audience)
    /// * `tenant_id` - The tenant ID
    /// * `nonce` - Optional nonce from authorization request
    /// * `auth_time` - Unix timestamp when user authentication occurred
    /// * `scope` - The granted scopes
    ///
    /// # Returns
    ///
    /// A signed JWT ID token.
    pub fn generate_id_token(
        &self,
        user_id: Uuid,
        client_id: &str,
        tenant_id: Uuid,
        nonce: Option<&str>,
        auth_time: i64,
        _scope: &str,
    ) -> Result<String, OAuthError> {
        // For OIDC ID tokens, we need additional claims beyond standard JWT
        // We'll use a specialized ID token claims structure
        let id_token_claims = IdTokenClaims::builder()
            .issuer(&self.issuer)
            .subject(user_id.to_string())
            .audience(client_id.to_string())
            .tenant_id(tenant_id)
            .auth_time(auth_time)
            .nonce(nonce)
            .expires_in_secs(ID_TOKEN_EXPIRY_SECS)
            .build();

        // Encode the token with key ID
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(&self.private_key).map_err(|e| {
            tracing::error!("Invalid private key: {}", e);
            OAuthError::Internal("Invalid signing key".to_string())
        })?;

        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(self.key_id.clone());

        jsonwebtoken::encode(&header, &id_token_claims, &key).map_err(|e| {
            tracing::error!("Failed to encode ID token: {}", e);
            OAuthError::Internal("Failed to generate ID token".to_string())
        })
    }

    /// Generate a refresh token and store it in the database.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID
    /// * `client_id` - The `OAuth2` client's internal UUID
    /// * `tenant_id` - The tenant ID
    /// * `scope` - The granted scopes (space-separated)
    /// * `family_id` - Optional existing family ID (for rotation)
    ///
    /// # Returns
    ///
    /// The opaque refresh token string.
    pub async fn generate_refresh_token(
        &self,
        user_id: Uuid,
        client_id: Uuid,
        tenant_id: Uuid,
        scope: &str,
        family_id: Option<Uuid>,
    ) -> Result<String, OAuthError> {
        let token = Self::generate_refresh_token_value();
        let token_hash = Self::hash_refresh_token(&token);
        let family = family_id.unwrap_or_else(Uuid::new_v4);
        let expires_at = Utc::now() + chrono::Duration::seconds(REFRESH_TOKEN_EXPIRY_SECS);

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                OAuthError::Internal("Failed to set tenant context".to_string())
            })?;

        sqlx::query(
            r"
            INSERT INTO oauth_refresh_tokens (
                token_hash, client_id, user_id, tenant_id,
                scope, family_id, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ",
        )
        .bind(&token_hash)
        .bind(client_id)
        .bind(user_id)
        .bind(tenant_id)
        .bind(scope)
        .bind(family)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create refresh token: {}", e);
            OAuthError::Internal("Failed to create refresh token".to_string())
        })?;

        Ok(token)
    }

    /// Validate and rotate a refresh token.
    ///
    /// This implements refresh token rotation as per OAuth 2.0 Security Best Practices.
    /// When a refresh token is used, it is immediately invalidated and a new one is issued.
    ///
    /// If a previously-rotated token is reused (token replay attack), the entire token
    /// family is revoked to protect against stolen tokens.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - The tenant ID for RLS
    /// * `refresh_token` - The opaque refresh token
    /// * `client_id` - The `OAuth2` client's internal UUID
    ///
    /// # Returns
    ///
    /// A tuple of (`user_id`, scope, `new_refresh_token`).
    pub async fn validate_and_rotate_refresh_token(
        &self,
        tenant_id: Uuid,
        refresh_token: &str,
        client_id: Uuid,
    ) -> Result<(Uuid, String, String), OAuthError> {
        let token_hash = Self::hash_refresh_token(refresh_token);

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                OAuthError::Internal("Failed to set tenant context".to_string())
            })?;

        // Look up the refresh token
        let db_token: Option<DbRefreshToken> = sqlx::query_as(
            r"
            SELECT id, token_hash, client_id, user_id, tenant_id, scope, family_id,
                   expires_at, revoked, revoked_at, created_at
            FROM oauth_refresh_tokens
            WHERE token_hash = $1 AND tenant_id = $2
            ",
        )
        .bind(&token_hash)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error looking up refresh token: {}", e);
            OAuthError::Internal("Database error".to_string())
        })?;

        let token = db_token
            .ok_or_else(|| OAuthError::InvalidGrant("Invalid refresh token".to_string()))?;

        // Check if the token is already revoked (potential replay attack)
        if token.revoked {
            tracing::warn!(
                "Refresh token replay detected for family {}. Revoking entire family.",
                token.family_id
            );
            // Revoke entire token family to protect against stolen tokens
            self.revoke_token_family(tenant_id, token.family_id).await?;
            return Err(OAuthError::InvalidGrant(
                "Refresh token has been revoked".to_string(),
            ));
        }

        // Check if the token has expired
        if token.expires_at < Utc::now() {
            return Err(OAuthError::InvalidGrant(
                "Refresh token has expired".to_string(),
            ));
        }

        // Verify the client matches
        if token.client_id != client_id {
            tracing::warn!(
                "Client mismatch for refresh token. Expected {}, got {}",
                token.client_id,
                client_id
            );
            return Err(OAuthError::InvalidGrant("Client mismatch".to_string()));
        }

        // Revoke the current token (rotate)
        sqlx::query(
            r"
            UPDATE oauth_refresh_tokens
            SET revoked = TRUE, revoked_at = now()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(token.id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke old refresh token: {}", e);
            OAuthError::Internal("Failed to rotate refresh token".to_string())
        })?;

        // Generate a new refresh token in the same family
        let new_token = self
            .generate_refresh_token(
                token.user_id,
                token.client_id,
                tenant_id,
                &token.scope,
                Some(token.family_id),
            )
            .await?;

        Ok((token.user_id, token.scope, new_token))
    }

    /// Revoke all tokens in a family.
    ///
    /// Used when a refresh token replay is detected (indicating potential token theft).
    pub async fn revoke_token_family(
        &self,
        tenant_id: Uuid,
        family_id: Uuid,
    ) -> Result<(), OAuthError> {
        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                OAuthError::Internal("Failed to set tenant context".to_string())
            })?;

        sqlx::query(
            r"
            UPDATE oauth_refresh_tokens
            SET revoked = TRUE, revoked_at = now()
            WHERE family_id = $1 AND tenant_id = $2 AND revoked = FALSE
            ",
        )
        .bind(family_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke token family: {}", e);
            OAuthError::Internal("Failed to revoke token family".to_string())
        })?;

        tracing::info!("Revoked all tokens in family {}", family_id);
        Ok(())
    }

    /// Revoke all refresh tokens for a user.
    ///
    /// Used for logout or security events (password change, account compromise).
    pub async fn revoke_user_tokens(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), OAuthError> {
        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                OAuthError::Internal("Failed to set tenant context".to_string())
            })?;

        let result = sqlx::query(
            r"
            UPDATE oauth_refresh_tokens
            SET revoked = TRUE, revoked_at = now()
            WHERE user_id = $1 AND tenant_id = $2 AND revoked = FALSE
            ",
        )
        .bind(user_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke user tokens: {}", e);
            OAuthError::Internal("Failed to revoke user tokens".to_string())
        })?;

        tracing::info!(
            "Revoked {} refresh tokens for user {}",
            result.rows_affected(),
            user_id
        );
        Ok(())
    }

    /// Issue tokens for authorization code grant.
    ///
    /// Generates access token, ID token (if openid scope), and refresh token
    /// (if `offline_access` scope).
    ///
    /// # Arguments
    ///
    /// * `user_id` - The authenticated user's ID
    /// * `client_id` - The `OAuth2` client ID (string identifier)
    /// * `client_internal_id` - The `OAuth2` client's internal UUID
    /// * `tenant_id` - The tenant ID
    /// * `scope` - The granted scopes (space-separated)
    /// * `nonce` - Optional nonce from authorization request
    ///
    /// # Returns
    ///
    /// A `TokenResponse` containing `access_token`, `id_token` (optional),
    /// `refresh_token` (optional), and metadata.
    pub async fn issue_authorization_code_tokens(
        &self,
        user_id: Uuid,
        client_id: &str,
        client_internal_id: Uuid,
        tenant_id: Uuid,
        scope: &str,
        nonce: Option<&str>,
    ) -> Result<TokenResponse, OAuthError> {
        let auth_time = Utc::now().timestamp();
        let scopes: Vec<&str> = scope.split_whitespace().collect();

        // Generate access token
        let access_token = self.generate_access_token(
            Some(user_id),
            client_id,
            tenant_id,
            scope,
            ACCESS_TOKEN_EXPIRY_SECS,
        )?;

        // Generate ID token if openid scope is present
        let id_token = if scopes.contains(&"openid") {
            Some(self.generate_id_token(user_id, client_id, tenant_id, nonce, auth_time, scope)?)
        } else {
            None
        };

        // Generate refresh token if offline_access scope is present
        let refresh_token = if scopes.contains(&"offline_access") {
            // Create a new token family
            let family_id = Uuid::new_v4();
            Some(
                self.create_refresh_token(user_id, client_internal_id, tenant_id, scope, family_id)
                    .await?,
            )
        } else {
            None
        };

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: ACCESS_TOKEN_EXPIRY_SECS,
            refresh_token,
            id_token,
            scope: Some(scope.to_string()),
        })
    }

    /// Create and store a refresh token.
    async fn create_refresh_token(
        &self,
        user_id: Uuid,
        client_id: Uuid,
        tenant_id: Uuid,
        scope: &str,
        family_id: Uuid,
    ) -> Result<String, OAuthError> {
        let token = Self::generate_refresh_token_value();
        let token_hash = Self::hash_refresh_token(&token);
        let expires_at = Utc::now() + chrono::Duration::seconds(REFRESH_TOKEN_EXPIRY_SECS);

        sqlx::query(
            r"
            INSERT INTO oauth_refresh_tokens (
                token_hash, client_id, user_id, tenant_id,
                scope, family_id, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ",
        )
        .bind(&token_hash)
        .bind(client_id)
        .bind(user_id)
        .bind(tenant_id)
        .bind(scope)
        .bind(family_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create refresh token: {}", e);
            OAuthError::Internal("Failed to create refresh token".to_string())
        })?;

        Ok(token)
    }

    /// Issue tokens for client credentials grant.
    ///
    /// Client credentials grant is for service-to-service authentication.
    /// No user is involved, so:
    /// - No ID token is issued (no openid scope)
    /// - No refresh token is issued (service can re-authenticate anytime)
    /// - Subject in the access token is the `client_id`
    ///
    /// # Arguments
    ///
    /// * `client_id` - The `OAuth2` client ID (string identifier)
    /// * `tenant_id` - The tenant ID
    /// * `scope` - The granted scopes (space-separated)
    ///
    /// # Returns
    ///
    /// A `TokenResponse` containing only an `access_token` (no `id_token` or `refresh_token`).
    pub async fn issue_client_credentials_tokens(
        &self,
        client_id: &str,
        tenant_id: Uuid,
        scope: &str,
    ) -> Result<TokenResponse, OAuthError> {
        // Generate access token with client_id as subject (no user)
        let access_token = self.generate_access_token(
            None, // No user_id for client credentials
            client_id,
            tenant_id,
            scope,
            ACCESS_TOKEN_EXPIRY_SECS,
        )?;

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: ACCESS_TOKEN_EXPIRY_SECS,
            refresh_token: None, // No refresh token for client credentials
            id_token: None,      // No ID token (no user authentication)
            scope: Some(scope.to_string()),
        })
    }

    /// Issue tokens for refresh token grant.
    ///
    /// Unlike authorization code grant:
    /// - No ID token is issued (only issued during initial authentication)
    /// - The new refresh token is already provided (from `validate_and_rotate`)
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID from the original refresh token
    /// * `client_id` - The `OAuth2` client ID (string identifier)
    /// * `client_internal_id` - The `OAuth2` client's internal UUID
    /// * `tenant_id` - The tenant ID
    /// * `scope` - The scope from the original refresh token
    /// * `new_refresh_token` - The new refresh token (already created by rotation)
    ///
    /// # Returns
    ///
    /// A `TokenResponse` containing `access_token` and `refresh_token`.
    pub async fn issue_refresh_tokens(
        &self,
        user_id: Uuid,
        client_id: &str,
        _client_internal_id: Uuid,
        tenant_id: Uuid,
        scope: &str,
        new_refresh_token: &str,
    ) -> Result<TokenResponse, OAuthError> {
        // Generate new access token
        let access_token = self.generate_access_token(
            Some(user_id),
            client_id,
            tenant_id,
            scope,
            ACCESS_TOKEN_EXPIRY_SECS,
        )?;

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: ACCESS_TOKEN_EXPIRY_SECS,
            refresh_token: Some(new_refresh_token.to_string()),
            id_token: None, // No ID token for refresh grant
            scope: Some(scope.to_string()),
        })
    }

    /// Issue tokens for RFC 8693 token exchange (delegation).
    ///
    /// Mints an access token with the `act` claim for the acting agent.
    /// The subject remains the principal being represented.
    ///
    /// Note: Scopes are stored in the `scope` claim, NOT as `roles`.
    /// Roles represent entitlements (e.g., `admin`, `nhi:read`) and are
    /// loaded from the authorization system. Scopes represent OAuth2
    /// permission boundaries (e.g., `read:tools`).
    pub async fn issue_token_exchange_tokens(
        &self,
        principal_id: Uuid,
        actor_nhi_id: Uuid,
        grant: &xavyo_db::models::NhiDelegationGrant,
        client_id: &str,
        tenant_id: Uuid,
        scope: &str,
        delegation_depth: i32,
        existing_actor: Option<&xavyo_auth::ActorClaim>,
    ) -> Result<TokenResponse, OAuthError> {
        use xavyo_auth::ActorClaim;

        // Build the actor claim, nesting any existing actor for chained delegation
        let actor_claim = ActorClaim {
            sub: actor_nhi_id.to_string(),
            nhi_type: Some("agent".to_string()),
            act: existing_actor.map(|a| Box::new(a.clone())),
        };

        // Build claims with delegation context
        // Scopes are NOT placed in roles — roles are authorization entitlements,
        // scopes are OAuth2 permission boundaries.
        let mut builder = JwtClaims::builder()
            .subject(principal_id.to_string())
            .issuer(&self.issuer)
            .audience(vec![client_id.to_string()])
            .tenant_uuid(tenant_id)
            .expires_in_secs(ACCESS_TOKEN_EXPIRY_SECS)
            .act(actor_claim)
            .delegation_id(grant.id)
            .delegation_depth(delegation_depth);

        // Include scopes in the JWT itself (RFC 9068) so resource servers
        // can enforce scopes without a DB round-trip.
        if !scope.is_empty() {
            builder = builder.scope(scope);
        }

        let claims = builder.build();

        let access_token = encode_token_with_kid(&claims, &self.private_key, &self.key_id)
            .map_err(|e| {
                tracing::error!("Failed to encode delegated access token: {}", e);
                OAuthError::Internal("Failed to generate delegated access token".to_string())
            })?;

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: ACCESS_TOKEN_EXPIRY_SECS,
            refresh_token: None,
            id_token: None,
            scope: if scope.is_empty() {
                None
            } else {
                Some(scope.to_string())
            },
        })
    }

    /// Issue tokens for device code grant (RFC 8628).
    ///
    /// Similar to authorization code grant but:
    /// - Device code has already been validated and consumed
    /// - User has already authenticated in browser
    ///
    /// Issues access token, ID token (if openid scope), and refresh token
    /// (if `offline_access` scope).
    ///
    /// # Arguments
    ///
    /// * `user_id` - The authenticated user's ID
    /// * `client_id` - The `OAuth2` client ID (string identifier)
    /// * `client_internal_id` - The `OAuth2` client's internal UUID
    /// * `tenant_id` - The tenant ID
    /// * `scope` - The granted scopes (space-separated)
    ///
    /// # Returns
    ///
    /// A `TokenResponse` containing `access_token`, `id_token` (optional),
    /// `refresh_token` (optional), and metadata.
    pub async fn issue_device_code_tokens(
        &self,
        user_id: Uuid,
        client_id: &str,
        client_internal_id: Uuid,
        tenant_id: Uuid,
        scope: &str,
    ) -> Result<TokenResponse, OAuthError> {
        let auth_time = Utc::now().timestamp();
        let scopes: Vec<&str> = scope.split_whitespace().collect();

        // Generate access token
        let access_token = self.generate_access_token(
            Some(user_id),
            client_id,
            tenant_id,
            scope,
            ACCESS_TOKEN_EXPIRY_SECS,
        )?;

        // Generate ID token if openid scope is present
        // For device code flow, no nonce is typically provided
        let id_token = if scopes.contains(&"openid") {
            Some(self.generate_id_token(user_id, client_id, tenant_id, None, auth_time, scope)?)
        } else {
            None
        };

        // Generate refresh token if offline_access scope is present
        let refresh_token = if scopes.contains(&"offline_access") {
            let family_id = Uuid::new_v4();
            Some(
                self.create_refresh_token(user_id, client_internal_id, tenant_id, scope, family_id)
                    .await?,
            )
        } else {
            None
        };

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: ACCESS_TOKEN_EXPIRY_SECS,
            refresh_token,
            id_token,
            scope: Some(scope.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test RSA key pair (2048-bit, for testing only).
    const TEST_PRIVATE_KEY: &[u8] = br"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCWvwXoegwG34YX
q+6MmsAfjZz2OZfBwbGVZSW0tiskb9UXZ2Rdz99ayewaKcLw1xwDcmI3BZWKcgfa
T2lnJbMeMv0SuewOAkZQ8ucZEScGHNcmBflGPUR/7ktUp55BJXFzkkqURqS3ORMp
Ds+4yx/GKez5HyOuK+gp0IxpoWhMMAGCA/7A3n3OLRbIkClK92u1sdCxtp5c9vEM
1oBK97p1qsPzRCUS3YLAnXAgbY8JOePbTdMrsqG2Y0/oXkjdGmcXH2KcMuRqnFql
qxegPR66n4k9LsBYk+dmKkDnAikOs0dpTWyaRI1POeLEOsjzfIL/xtZDOEK9QaaC
6S5ekP/dAgMBAAECggEACXmXvjk/nMX7aGz82TcX2NPemAZeMMZDKnP5Vv61PvzN
fMNZpmDctdjnv2w9DcTDhL7xh+pQsCtDLZhctGhE9iK3z+/CM842S7u8xVFT7dkt
t7zb4muS7OSWNQu1EXywQRaim+fFziNm/idpbIDN7jdv5uerZzToyooKbVBBHTq1
dbd+egtlLh6mGdAcpaw4CpURwH5+b5DwPwl2c8hYJKmGTEQj+FK8K9xSDVX0sov8
yseSTPo3Q1gp38lDJBZkNtxbzXORtjvTWldxI9FQtCLasedzX/HXqxh1c3qVbaVw
EZTqTSSmZX4VWD7YgweNSufxhyM5Nbd/vzaEhiFX6QKBgQDTycPQ7G0cImvnlCNX
RGMDYShHxXEe0iCoUDZoONNeVNqrs/MPVYlNiX3+Gy4VTmQpqGOAFr5afXVa3SSf
MDr+bhtJSK0MGNR/SmUsFvrCeDcDh2ZrbYFD69kEdALgM7VLs6YuBH1fJgmhhsjm
4X09bx1VpHEAh5+kSMwA6x2b1QKBgQC2NxiYQS1s005yZ2NcaO+gWk9gFpgQrvfL
C6nl/vt0wOy/P/0YApxAnQd+OQQfcfygQFj8/UZsAoI2HXj22x+ub5ZiJL/dZY6F
SarJQulNVODBsnrNHhUKLhH/mGxX3YB6pOPcX46/h6tJEM+xomBzMwXLkJPfUkkI
Gi9XRFH/6QKBgDqt1nFWcEyxRNBe/QO60OwoyS5JiDQP6Dh6MPjjdbzXKdcU/q0q
9+XhyGTVRwlkNOBN5XOh2Y/c3t0UFId+p3nDLBA78KY/YvD5vdpfa47iG+wAYeI1
7vDQscpIElvoN70Hw21QlSP9uAFnBNbjdv3EgY4vB5gr+5FbEhrXCdcZAoGAJ5Hf
bXD6BF/+8SkykqbXIuN5yUweycC1XwqxYpj00m3y+7VRqR0oAYAYWHjZRFrkmYhf
ytDVsi75R/cuha0gPClPZxDD+bhMMvXEeOBm+bws8uNnd5PIzeUjU3YuUQZxGDEm
qny16zHzKHLWJ6UzfNDfuU00T5L2+SN2lGTpycECgYEAmoV1LnfOnv7ytid8kHE8
tOmUhF0TRxS3K/I1d0EGkM0PcR4BVSxHYz0LU0ChL4SOYuo7yKzESChwdDRvm1MN
6vj1477kZXDY2XxVkiXZSD3kPRZ3RFTRIf4nObHi8sKMbGKkJUyDeN+n2SIvYST2
xxU7T7aU32bKZLygCDtwsN8=
-----END PRIVATE KEY-----";

    /// Helper to create test token service without database.
    /// Uses a wrapper struct that only contains what's needed for token generation.
    struct TestTokenGenerator {
        issuer: String,
        private_key: Vec<u8>,
        key_id: String,
    }

    impl TestTokenGenerator {
        fn new() -> Self {
            Self {
                issuer: "https://idp.test.xavyo.com".to_string(),
                private_key: TEST_PRIVATE_KEY.to_vec(),
                key_id: "test-key-1".to_string(),
            }
        }

        fn generate_access_token(
            &self,
            user_id: Option<Uuid>,
            client_id: &str,
            tenant_id: Uuid,
            scope: &str,
            expires_in_secs: i64,
        ) -> Result<String, OAuthError> {
            let mut claims_builder = JwtClaims::builder()
                .issuer(&self.issuer)
                .audience(vec![client_id.to_string()])
                .tenant_uuid(tenant_id)
                .expires_in_secs(expires_in_secs);

            if let Some(uid) = user_id {
                claims_builder = claims_builder.subject(uid.to_string());
            } else {
                claims_builder = claims_builder.subject(client_id);
            }

            let scopes: Vec<String> = scope.split_whitespace().map(String::from).collect();
            claims_builder = claims_builder.roles(scopes);

            let claims = claims_builder.build();

            encode_token_with_kid(&claims, &self.private_key, &self.key_id)
                .map_err(|e| OAuthError::Internal(format!("Failed to generate access token: {e}")))
        }

        fn generate_id_token(
            &self,
            user_id: Uuid,
            client_id: &str,
            tenant_id: Uuid,
            nonce: Option<&str>,
            auth_time: i64,
        ) -> Result<String, OAuthError> {
            let id_token_claims = IdTokenClaims::builder()
                .issuer(&self.issuer)
                .subject(user_id.to_string())
                .audience(client_id.to_string())
                .tenant_id(tenant_id)
                .auth_time(auth_time)
                .nonce(nonce)
                .expires_in_secs(ID_TOKEN_EXPIRY_SECS)
                .build();

            let key = jsonwebtoken::EncodingKey::from_rsa_pem(&self.private_key)
                .map_err(|e| OAuthError::Internal(format!("Invalid signing key: {e}")))?;

            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
            header.kid = Some(self.key_id.clone());

            jsonwebtoken::encode(&header, &id_token_claims, &key)
                .map_err(|e| OAuthError::Internal(format!("Failed to generate ID token: {e}")))
        }
    }

    #[test]
    fn test_generate_access_token_with_user() {
        let generator = TestTokenGenerator::new();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();

        let result = generator.generate_access_token(
            Some(user_id),
            "test-client",
            tenant_id,
            "openid profile",
            900,
        );

        assert!(result.is_ok());
        let token = result.unwrap();
        // Token should have 3 parts separated by dots
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn test_generate_access_token_for_client_credentials() {
        let generator = TestTokenGenerator::new();
        let tenant_id = Uuid::new_v4();

        let result = generator.generate_access_token(
            None,
            "service-client",
            tenant_id,
            "api:read api:write",
            900,
        );

        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn test_generate_id_token() {
        let generator = TestTokenGenerator::new();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let auth_time = Utc::now().timestamp();

        let result = generator.generate_id_token(
            user_id,
            "test-client",
            tenant_id,
            Some("random-nonce"),
            auth_time,
        );

        assert!(result.is_ok());
        let token = result.unwrap();
        // Token should have 3 parts separated by dots
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn test_generate_id_token_without_nonce() {
        let generator = TestTokenGenerator::new();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let auth_time = Utc::now().timestamp();

        let result =
            generator.generate_id_token(user_id, "test-client", tenant_id, None, auth_time);

        assert!(result.is_ok());
    }

    #[test]
    fn test_refresh_token_generation_is_unique() {
        let token1 = TokenService::generate_refresh_token_value();
        let token2 = TokenService::generate_refresh_token_value();
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_refresh_token_generation_length() {
        let token = TokenService::generate_refresh_token_value();
        // 32 bytes base64url encoded = 43 characters
        assert_eq!(token.len(), 43);
    }

    #[test]
    fn test_refresh_token_hashing_is_deterministic() {
        let token = "test-refresh-token";
        let hash1 = TokenService::hash_refresh_token(token);
        let hash2 = TokenService::hash_refresh_token(token);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_refresh_token_hashing_produces_hex() {
        let token = "test-refresh-token";
        let hash = TokenService::hash_refresh_token(token);
        // SHA-256 produces 64 hex characters
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_id_token_claims_builder() {
        let tid = Uuid::new_v4();
        let auth_time = Utc::now().timestamp();

        let claims = IdTokenClaims::builder()
            .issuer("https://idp.test.xavyo.com")
            .subject("user-123")
            .audience("test-client")
            .tenant_id(tid)
            .auth_time(auth_time)
            .nonce(Some("test-nonce"))
            .expires_in_secs(3600)
            .build();

        assert_eq!(claims.iss, "https://idp.test.xavyo.com");
        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.aud, "test-client");
        assert_eq!(claims.tid, Some(tid));
        assert_eq!(claims.auth_time, Some(auth_time));
        assert_eq!(claims.nonce, Some("test-nonce".to_string()));
    }

    #[test]
    fn test_id_token_claims_serialization() {
        let claims = IdTokenClaims::builder()
            .issuer("https://idp.test.xavyo.com")
            .subject("user-123")
            .audience("test-client")
            .build();

        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: IdTokenClaims = serde_json::from_str(&json).unwrap();

        assert_eq!(claims.iss, deserialized.iss);
        assert_eq!(claims.sub, deserialized.sub);
        assert_eq!(claims.aud, deserialized.aud);
    }

    #[test]
    fn test_id_token_claims_without_optional_fields() {
        let claims = IdTokenClaims::builder()
            .issuer("issuer")
            .subject("sub")
            .audience("aud")
            .build();

        let json = serde_json::to_string(&claims).unwrap();

        // Optional fields should not be present in JSON
        assert!(!json.contains("auth_time"));
        assert!(!json.contains("nonce"));
        assert!(!json.contains("tid"));
        assert!(!json.contains("at_hash"));
    }

    #[test]
    fn test_generate_access_token_for_client_credentials_has_client_id_as_subject() {
        let generator = TestTokenGenerator::new();
        let tenant_id = Uuid::new_v4();
        let client_id = "my-service-client";

        let result = generator.generate_access_token(
            None, // No user for client credentials
            client_id,
            tenant_id,
            "api:read api:write",
            900,
        );

        assert!(result.is_ok());
        let token = result.unwrap();

        // Decode the token to verify the subject
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Decode the payload (second part)
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("Failed to decode payload");
        let payload: serde_json::Value =
            serde_json::from_slice(&payload_bytes).expect("Failed to parse payload");

        // Verify subject is the client_id
        assert_eq!(payload["sub"].as_str().unwrap(), client_id);

        // Verify roles contain the scopes
        let roles = payload["roles"]
            .as_array()
            .expect("roles should be an array");
        assert!(roles.iter().any(|r| r.as_str() == Some("api:read")));
        assert!(roles.iter().any(|r| r.as_str() == Some("api:write")));
    }

    #[test]
    fn test_generate_access_token_for_user_has_user_id_as_subject() {
        let generator = TestTokenGenerator::new();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();

        let result = generator.generate_access_token(
            Some(user_id),
            "test-client",
            tenant_id,
            "openid profile",
            900,
        );

        assert!(result.is_ok());
        let token = result.unwrap();

        // Decode the token to verify the subject
        let parts: Vec<&str> = token.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("Failed to decode payload");
        let payload: serde_json::Value =
            serde_json::from_slice(&payload_bytes).expect("Failed to parse payload");

        // Verify subject is the user_id
        assert_eq!(payload["sub"].as_str().unwrap(), user_id.to_string());
    }
}
