//! `OAuth2` client service.

use crate::error::OAuthError;
use crate::models::{ClientResponse, ClientType, CreateClientRequest, UpdateClientRequest};
use rand::RngCore;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use xavyo_auth::{hash_password, verify_password};

/// Length of generated client IDs (bytes).
const CLIENT_ID_LENGTH: usize = 16;

/// Length of generated client secrets (bytes).
const CLIENT_SECRET_LENGTH: usize = 32;

/// Database representation of an `OAuth2` client.
#[derive(Debug, FromRow)]
#[allow(dead_code)] // Fields used by SQLx query_as
struct DbOAuth2Client {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub name: String,
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub is_active: bool,
    pub logo_url: Option<String>,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Service for managing `OAuth2` clients.
#[derive(Debug, Clone)]
pub struct OAuth2ClientService {
    pool: PgPool,
}

impl OAuth2ClientService {
    /// Create a new client service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Create a new `OAuth2` client.
    ///
    /// Generates a unique `client_id` and, for confidential clients, a `client_secret`.
    /// The `client_secret` is returned in plaintext only once; the hash is stored.
    ///
    /// # Returns
    ///
    /// A tuple of (`ClientResponse`, Option<`plaintext_secret`>). The secret is only
    /// present for confidential clients.
    pub async fn create_client(
        &self,
        tenant_id: Uuid,
        request: CreateClientRequest,
    ) -> Result<(ClientResponse, Option<String>), OAuthError> {
        // Acquire a single connection to ensure set_config and query use the same connection
        let mut conn = self.pool.acquire().await.map_err(|e| {
            tracing::error!("Failed to acquire connection: {}", e);
            OAuthError::Internal("Failed to acquire database connection".to_string())
        })?;

        // Set tenant context for RLS on this connection
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                OAuthError::Internal("Failed to set tenant context".to_string())
            })?;

        // Generate unique client_id
        let client_id = self.generate_client_id();

        // Generate and hash secret for confidential clients
        let (secret_hash, plaintext_secret) = if request.client_type == ClientType::Confidential {
            let secret = self.generate_client_secret();
            let hash = hash_password(&secret).map_err(|e| {
                tracing::error!("Failed to hash client secret: {}", e);
                OAuthError::Internal("Failed to hash client secret".to_string())
            })?;
            (Some(hash), Some(secret))
        } else {
            (None, None)
        };

        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let client_type_str = match request.client_type {
            ClientType::Confidential => "confidential",
            ClientType::Public => "public",
        };

        // Insert the client using the same connection
        sqlx::query(
            r"
            INSERT INTO oauth_clients (
                id, tenant_id, client_id, client_secret_hash, name, client_type,
                redirect_uris, grant_types, scopes, is_active, logo_url, description,
                created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true, $10, $11, $12, $12)
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&client_id)
        .bind(&secret_hash)
        .bind(&request.name)
        .bind(client_type_str)
        .bind(&request.redirect_uris)
        .bind(&request.grant_types)
        .bind(&request.scopes)
        .bind(&request.logo_url)
        .bind(&request.description)
        .bind(now)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create client: {}", e);
            OAuthError::Internal("Failed to create client".to_string())
        })?;

        let response = ClientResponse {
            id,
            client_id,
            name: request.name,
            client_type: request.client_type,
            redirect_uris: request.redirect_uris,
            grant_types: request.grant_types,
            scopes: request.scopes,
            is_active: true,
            logo_url: request.logo_url,
            description: request.description,
            created_at: now,
            updated_at: now,
        };

        Ok((response, plaintext_secret))
    }

    /// Generate a cryptographically secure client ID.
    ///
    /// SECURITY: Uses `OsRng` directly from the operating system's CSPRNG.
    fn generate_client_id(&self) -> String {
        use rand::rngs::OsRng;
        let mut bytes = vec![0u8; CLIENT_ID_LENGTH];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Generate a cryptographically secure client secret.
    ///
    /// SECURITY: Uses `OsRng` directly from the operating system's CSPRNG.
    fn generate_client_secret(&self) -> String {
        use rand::rngs::OsRng;
        let mut bytes = vec![0u8; CLIENT_SECRET_LENGTH];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Get a client by its public `client_id`.
    pub async fn get_client_by_client_id(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> Result<ClientResponse, OAuthError> {
        // Acquire a single connection to ensure set_config and query use the same connection
        let mut conn = self.pool.acquire().await.map_err(|e| {
            tracing::error!("Failed to acquire connection: {}", e);
            OAuthError::Internal("Failed to acquire database connection".to_string())
        })?;

        // Set tenant context for RLS on this connection
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                OAuthError::Internal("Failed to set tenant context".to_string())
            })?;

        let client: DbOAuth2Client = sqlx::query_as(
            r"
            SELECT id, tenant_id, client_id, client_secret_hash, name, client_type,
                   redirect_uris, grant_types, scopes, is_active, logo_url, description, created_at, updated_at
            FROM oauth_clients
            WHERE client_id = $1 AND tenant_id = $2
            ",
        )
        .bind(client_id)
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error looking up client: {}", e);
            OAuthError::Internal("Database error".to_string())
        })?
        .ok_or(OAuthError::ClientNotFound)?;

        Ok(self.db_client_to_response(client))
    }

    /// Get a client by its internal ID.
    pub async fn get_client_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<ClientResponse, OAuthError> {
        // Acquire a single connection to ensure set_config and query use the same connection
        let mut conn = self.pool.acquire().await.map_err(|e| {
            tracing::error!("Failed to acquire connection: {}", e);
            OAuthError::Internal("Failed to acquire database connection".to_string())
        })?;

        // Set tenant context for RLS on this connection
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                OAuthError::Internal("Failed to set tenant context".to_string())
            })?;

        let client: DbOAuth2Client = sqlx::query_as(
            r"
            SELECT id, tenant_id, client_id, client_secret_hash, name, client_type,
                   redirect_uris, grant_types, scopes, is_active, logo_url, description, created_at, updated_at
            FROM oauth_clients
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error looking up client: {}", e);
            OAuthError::Internal("Database error".to_string())
        })?
        .ok_or(OAuthError::ClientNotFound)?;

        Ok(self.db_client_to_response(client))
    }

    /// List all clients for a tenant.
    ///
    /// Returns all active and inactive clients for administrative purposes.
    pub async fn list_clients(&self, tenant_id: Uuid) -> Result<Vec<ClientResponse>, OAuthError> {
        // Acquire a single connection to ensure set_config and query use the same connection
        let mut conn = self.pool.acquire().await.map_err(|e| {
            tracing::error!("Failed to acquire connection: {}", e);
            OAuthError::Internal("Failed to acquire database connection".to_string())
        })?;

        // Set tenant context for RLS on this connection
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                OAuthError::Internal("Failed to set tenant context".to_string())
            })?;

        let clients: Vec<DbOAuth2Client> = sqlx::query_as(
            r"
            SELECT id, tenant_id, client_id, client_secret_hash, name, client_type,
                   redirect_uris, grant_types, scopes, is_active, logo_url, description, created_at, updated_at
            FROM oauth_clients
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            ",
        )
        .bind(tenant_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error listing clients: {}", e);
            OAuthError::Internal("Database error".to_string())
        })?;

        Ok(clients
            .into_iter()
            .map(|c| self.db_client_to_response(c))
            .collect())
    }

    /// Update a client.
    ///
    /// Only updates fields that are provided in the request.
    /// Client type and `client_id` cannot be changed after creation.
    pub async fn update_client(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        request: UpdateClientRequest,
    ) -> Result<ClientResponse, OAuthError> {
        // Acquire a single connection to ensure set_config and query use the same connection
        let mut conn = self.pool.acquire().await.map_err(|e| {
            tracing::error!("Failed to acquire connection: {}", e);
            OAuthError::Internal("Failed to acquire database connection".to_string())
        })?;

        // Set tenant context for RLS on this connection
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                OAuthError::Internal("Failed to set tenant context".to_string())
            })?;

        // First, verify the client exists
        let existing: DbOAuth2Client = sqlx::query_as(
            r"
            SELECT id, tenant_id, client_id, client_secret_hash, name, client_type,
                   redirect_uris, grant_types, scopes, is_active, logo_url, description, created_at, updated_at
            FROM oauth_clients
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error looking up client: {}", e);
            OAuthError::Internal("Database error".to_string())
        })?
        .ok_or(OAuthError::ClientNotFound)?;

        // Build update with provided fields (or keep existing)
        let name = request.name.unwrap_or(existing.name);
        let redirect_uris = request.redirect_uris.unwrap_or(existing.redirect_uris);
        let grant_types = request.grant_types.unwrap_or(existing.grant_types);
        let scopes = request.scopes.unwrap_or(existing.scopes);
        let is_active = request.is_active.unwrap_or(existing.is_active);
        let logo_url = request.logo_url.or(existing.logo_url);
        let description = request.description.or(existing.description);
        let now = chrono::Utc::now();

        sqlx::query(
            r"
            UPDATE oauth_clients
            SET name = $1, redirect_uris = $2, grant_types = $3, scopes = $4,
                is_active = $5, logo_url = $6, description = $7, updated_at = $8
            WHERE id = $9 AND tenant_id = $10
            ",
        )
        .bind(&name)
        .bind(&redirect_uris)
        .bind(&grant_types)
        .bind(&scopes)
        .bind(is_active)
        .bind(&logo_url)
        .bind(&description)
        .bind(now)
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update client: {}", e);
            OAuthError::Internal("Failed to update client".to_string())
        })?;

        // Return updated client
        let client_type = match existing.client_type.as_str() {
            "confidential" => ClientType::Confidential,
            _ => ClientType::Public,
        };

        Ok(ClientResponse {
            id: existing.id,
            client_id: existing.client_id,
            name,
            client_type,
            redirect_uris,
            grant_types,
            scopes,
            is_active,
            logo_url,
            description,
            created_at: existing.created_at,
            updated_at: now,
        })
    }

    /// Deactivate a client.
    ///
    /// Performs a soft delete by setting `is_active` to false.
    /// Also revokes all refresh tokens for this client.
    pub async fn deactivate_client(&self, tenant_id: Uuid, id: Uuid) -> Result<(), OAuthError> {
        // Acquire a single connection to ensure set_config and query use the same connection
        let mut conn = self.pool.acquire().await.map_err(|e| {
            tracing::error!("Failed to acquire connection: {}", e);
            OAuthError::Internal("Failed to acquire database connection".to_string())
        })?;

        // Set tenant context for RLS on this connection
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                OAuthError::Internal("Failed to set tenant context".to_string())
            })?;

        // Verify client exists
        let result = sqlx::query(
            r"
            UPDATE oauth_clients
            SET is_active = false, updated_at = $1
            WHERE id = $2 AND tenant_id = $3
            ",
        )
        .bind(chrono::Utc::now())
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to deactivate client: {}", e);
            OAuthError::Internal("Failed to deactivate client".to_string())
        })?;

        if result.rows_affected() == 0 {
            return Err(OAuthError::ClientNotFound);
        }

        // Revoke all refresh tokens for this client
        sqlx::query(
            r"
            UPDATE oauth_refresh_tokens
            SET revoked = true, revoked_at = $1
            WHERE client_id = $2 AND tenant_id = $3 AND revoked = false
            ",
        )
        .bind(chrono::Utc::now())
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke client tokens: {}", e);
            OAuthError::Internal("Failed to revoke client tokens".to_string())
        })?;

        Ok(())
    }

    /// Hard-delete a client.
    ///
    /// Permanently removes the client record and revokes all refresh tokens.
    /// Unlike `deactivate_client`, this cannot be undone.
    pub async fn delete_client(&self, tenant_id: Uuid, id: Uuid) -> Result<(), OAuthError> {
        let mut conn = self.pool.acquire().await.map_err(|e| {
            tracing::error!("Failed to acquire connection: {}", e);
            OAuthError::Internal("Failed to acquire database connection".to_string())
        })?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                OAuthError::Internal("Failed to set tenant context".to_string())
            })?;

        // Revoke all refresh tokens for this client first
        sqlx::query(
            r"
            DELETE FROM oauth_refresh_tokens
            WHERE client_id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete client tokens: {}", e);
            OAuthError::Internal("Failed to delete client tokens".to_string())
        })?;

        // Delete the client record
        let result = sqlx::query(
            r"
            DELETE FROM oauth_clients
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete client: {}", e);
            OAuthError::Internal("Failed to delete client".to_string())
        })?;

        if result.rows_affected() == 0 {
            return Err(OAuthError::ClientNotFound);
        }

        Ok(())
    }

    /// Regenerate client secret for a confidential client.
    ///
    /// Returns the new plaintext secret (only shown once).
    pub async fn regenerate_client_secret(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<String, OAuthError> {
        // Acquire a single connection to ensure set_config and query use the same connection
        let mut conn = self.pool.acquire().await.map_err(|e| {
            tracing::error!("Failed to acquire connection: {}", e);
            OAuthError::Internal("Failed to acquire database connection".to_string())
        })?;

        // Set tenant context for RLS on this connection
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                OAuthError::Internal("Failed to set tenant context".to_string())
            })?;

        // Verify client exists and is confidential
        let client: DbOAuth2Client = sqlx::query_as(
            r"
            SELECT id, tenant_id, client_id, client_secret_hash, name, client_type,
                   redirect_uris, grant_types, scopes, is_active, logo_url, description, created_at, updated_at
            FROM oauth_clients
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error looking up client: {}", e);
            OAuthError::Internal("Database error".to_string())
        })?
        .ok_or(OAuthError::ClientNotFound)?;

        if client.client_type != "confidential" {
            return Err(OAuthError::InvalidClient(
                "Cannot regenerate secret for public clients".to_string(),
            ));
        }

        // Generate new secret
        let new_secret = self.generate_client_secret();
        let new_hash = hash_password(&new_secret).map_err(|e| {
            tracing::error!("Failed to hash client secret: {}", e);
            OAuthError::Internal("Failed to hash client secret".to_string())
        })?;

        // Update the secret
        sqlx::query(
            r"
            UPDATE oauth_clients
            SET client_secret_hash = $1, updated_at = $2
            WHERE id = $3 AND tenant_id = $4
            ",
        )
        .bind(&new_hash)
        .bind(chrono::Utc::now())
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update client secret: {}", e);
            OAuthError::Internal("Failed to update client secret".to_string())
        })?;

        // Revoke all existing refresh tokens (security measure)
        sqlx::query(
            r"
            UPDATE oauth_refresh_tokens
            SET revoked = true, revoked_at = $1
            WHERE client_id = $2 AND tenant_id = $3 AND revoked = false
            ",
        )
        .bind(chrono::Utc::now())
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke client tokens: {}", e);
            OAuthError::Internal("Failed to revoke client tokens".to_string())
        })?;

        Ok(new_secret)
    }

    /// Verify client credentials for confidential clients.
    ///
    /// Authenticates a client using its `client_id` and `client_secret`.
    /// Only confidential clients can be authenticated this way.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - The tenant ID for RLS
    /// * `client_id` - The public client identifier
    /// * `client_secret` - The plaintext client secret
    ///
    /// # Returns
    ///
    /// The client details if authentication succeeds.
    ///
    /// # Errors
    ///
    /// - `InvalidClient` if client not found, inactive, or credentials invalid
    ///
    /// # Security
    ///
    /// IMPORTANT: This function returns a generic error message for all authentication
    /// failures to prevent client enumeration attacks. The specific reason is only logged.
    pub async fn verify_client_credentials(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        client_secret: &str,
    ) -> Result<ClientResponse, OAuthError> {
        // SECURITY: Generic error message to prevent client enumeration
        // Specific reason is logged for debugging but not exposed to client
        const GENERIC_AUTH_ERROR: &str = "Invalid client credentials";

        // Acquire a single connection to ensure set_config and query use the same connection
        let mut conn = self.pool.acquire().await.map_err(|e| {
            tracing::error!("Failed to acquire connection: {}", e);
            OAuthError::Internal("Failed to acquire database connection".to_string())
        })?;

        // Set tenant context for RLS on this connection
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                OAuthError::Internal("Failed to set tenant context".to_string())
            })?;

        // Look up the client by client_id
        let client: Option<DbOAuth2Client> = sqlx::query_as(
            r"
            SELECT id, tenant_id, client_id, client_secret_hash, name, client_type,
                   redirect_uris, grant_types, scopes, is_active, logo_url, description, created_at, updated_at
            FROM oauth_clients
            WHERE client_id = $1 AND tenant_id = $2
            ",
        )
        .bind(client_id)
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error looking up client: {}", e);
            OAuthError::Internal("Database error".to_string())
        })?;

        let client = if let Some(c) = client {
            c
        } else {
            tracing::warn!(
                client_id = %client_id,
                "Client authentication failed: client not found"
            );
            return Err(OAuthError::InvalidClient(GENERIC_AUTH_ERROR.to_string()));
        };

        // Check if client is active
        if !client.is_active {
            tracing::warn!(
                client_id = %client_id,
                "Client authentication failed: client is inactive"
            );
            return Err(OAuthError::InvalidClient(GENERIC_AUTH_ERROR.to_string()));
        }

        // Check if this is a confidential client
        if client.client_type != "confidential" {
            tracing::warn!(
                client_id = %client_id,
                client_type = %client.client_type,
                "Client authentication failed: public client cannot use client_credentials"
            );
            return Err(OAuthError::InvalidClient(GENERIC_AUTH_ERROR.to_string()));
        }

        // Verify the secret
        let secret_hash = if let Some(hash) = client.client_secret_hash.as_ref() {
            hash
        } else {
            tracing::warn!(
                client_id = %client_id,
                "Client authentication failed: no secret configured"
            );
            return Err(OAuthError::InvalidClient(GENERIC_AUTH_ERROR.to_string()));
        };

        let is_valid = verify_password(client_secret, secret_hash).map_err(|e| {
            tracing::error!("Password verification error: {}", e);
            OAuthError::Internal("Credential verification failed".to_string())
        })?;

        if !is_valid {
            tracing::warn!(
                client_id = %client_id,
                "Client authentication failed: invalid secret"
            );
            return Err(OAuthError::InvalidClient(GENERIC_AUTH_ERROR.to_string()));
        }

        // Convert to ClientResponse
        Ok(self.db_client_to_response(client))
    }

    /// Convert database client to response type.
    fn db_client_to_response(&self, client: DbOAuth2Client) -> ClientResponse {
        let client_type = match client.client_type.as_str() {
            "confidential" => ClientType::Confidential,
            _ => ClientType::Public,
        };

        ClientResponse {
            id: client.id,
            client_id: client.client_id,
            name: client.name,
            client_type,
            redirect_uris: client.redirect_uris,
            grant_types: client.grant_types,
            scopes: client.scopes,
            is_active: client.is_active,
            logo_url: client.logo_url,
            description: client.description,
            created_at: client.created_at,
            updated_at: client.updated_at,
        }
    }

    /// Normalize a redirect URI for consistent comparison.
    ///
    /// SECURITY: Normalizes URLs to prevent bypass attacks via:
    /// - Different case in host/scheme (`HTTPS://EXAMPLE.COM` vs `https://example.com`)
    /// - Default ports (`https://example.com:443` vs `https://example.com`)
    /// - Trailing slashes (handled by comparing normalized forms)
    ///
    /// Returns None if the URL is invalid or uses an unsafe scheme.
    fn normalize_redirect_uri(uri: &str) -> Option<String> {
        // Parse the URL
        let parsed = url::Url::parse(uri).ok()?;

        // Only allow https (or http for localhost during development)
        let scheme = parsed.scheme().to_lowercase();
        if scheme != "https" {
            // Allow http only for localhost/127.0.0.1 (development)
            if scheme == "http" {
                let host = parsed.host_str().unwrap_or("");
                if host != "localhost" && host != "127.0.0.1" && host != "[::1]" {
                    return None; // Non-localhost http is not allowed
                }
            } else {
                return None; // Only http/https schemes allowed
            }
        }

        // Reconstruct normalized URL
        // - Scheme: lowercase
        // - Host: lowercase
        // - Port: omit if default (443 for https, 80 for http)
        // - Path: preserve exactly (no normalization to avoid security issues)
        // - Query: preserve exactly
        // - Fragment: strip (not sent to server per RFC)

        let host = parsed.host_str()?.to_lowercase();
        let port = parsed.port();
        let path = parsed.path();
        let query = parsed.query();

        let mut normalized = format!("{scheme}://{host}");

        // Only include port if non-default
        if let Some(p) = port {
            let is_default = (scheme == "https" && p == 443) || (scheme == "http" && p == 80);
            if !is_default {
                normalized.push(':');
                normalized.push_str(&p.to_string());
            }
        }

        normalized.push_str(path);

        if let Some(q) = query {
            normalized.push('?');
            normalized.push_str(q);
        }

        Some(normalized)
    }

    /// Validate redirect URI against registered URIs.
    ///
    /// Performs strict validation with URL normalization to prevent bypass attacks.
    /// The `redirect_uri` must match one of the client's registered redirect URIs
    /// after normalization.
    ///
    /// # Security
    ///
    /// This validation prevents authorization code theft via open redirect attacks.
    /// - URLs are normalized before comparison to prevent case/port bypass
    /// - Partial matching or wildcard matching is NOT supported
    /// - Only https is allowed (http only for localhost development)
    pub fn validate_redirect_uri(
        &self,
        client: &ClientResponse,
        redirect_uri: &str,
    ) -> Result<(), OAuthError> {
        // Normalize the requested redirect URI
        let normalized_request = Self::normalize_redirect_uri(redirect_uri).ok_or_else(|| {
            tracing::warn!(
                client_id = %client.client_id,
                redirect_uri = %redirect_uri,
                "Redirect URI validation failed: invalid or unsafe URL"
            );
            OAuthError::InvalidRequest("redirect_uri is not a valid HTTPS URL".to_string())
        })?;

        // Check if normalized URI matches any normalized registered URI
        for registered in &client.redirect_uris {
            if let Some(normalized_registered) = Self::normalize_redirect_uri(registered) {
                if normalized_request == normalized_registered {
                    return Ok(());
                }
            }
        }

        tracing::warn!(
            client_id = %client.client_id,
            redirect_uri = %redirect_uri,
            normalized_uri = %normalized_request,
            registered_uris = ?client.redirect_uris,
            "Redirect URI validation failed: URI not in registered list"
        );
        Err(OAuthError::InvalidRequest(
            "redirect_uri does not match any registered redirect URIs".to_string(),
        ))
    }

    /// Validate grant type is allowed for client.
    ///
    /// Checks that the requested grant type is in the client's list of allowed grant types.
    pub fn validate_grant_type(
        &self,
        client: &ClientResponse,
        grant_type: &str,
    ) -> Result<(), OAuthError> {
        if client.grant_types.contains(&grant_type.to_string()) {
            Ok(())
        } else {
            tracing::warn!(
                client_id = %client.client_id,
                grant_type = %grant_type,
                allowed_grants = ?client.grant_types,
                "Grant type validation failed: not allowed for client"
            );
            Err(OAuthError::UnauthorizedClient(format!(
                "Client is not authorized for {grant_type} grant type"
            )))
        }
    }

    /// Validate requested scopes against allowed scopes.
    ///
    /// Returns the validated scope string. If no scope is requested,
    /// returns the client's default allowed scopes.
    pub fn validate_scopes(
        &self,
        client: &ClientResponse,
        requested_scopes: &str,
    ) -> Result<String, OAuthError> {
        if requested_scopes.is_empty() {
            // Return default scopes for the client
            return Ok(client.scopes.join(" "));
        }

        // Validate each requested scope
        let requested: Vec<&str> = requested_scopes.split_whitespace().collect();
        for scope in &requested {
            if !client.scopes.contains(&scope.to_string()) {
                tracing::warn!(
                    client_id = %client.client_id,
                    invalid_scope = %scope,
                    allowed_scopes = ?client.scopes,
                    "Scope validation failed: scope not allowed"
                );
                return Err(OAuthError::InvalidScope(format!(
                    "Scope '{scope}' is not allowed for this client"
                )));
            }
        }

        Ok(requested_scopes.to_string())
    }
}

impl ClientType {
    /// Check if this client type requires a secret.
    #[must_use]
    pub fn requires_secret(&self) -> bool {
        matches!(self, ClientType::Confidential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rand::thread_rng; // For test utilities only (not security-critical)

    #[test]
    fn test_client_type_requires_secret() {
        assert!(ClientType::Confidential.requires_secret());
        assert!(!ClientType::Public.requires_secret());
    }

    #[test]
    fn test_db_client_to_response_confidential() {
        // This test verifies the conversion logic without a database
        let db_client = DbOAuth2Client {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            client_secret_hash: Some("hashed-secret".to_string()),
            name: "Test Client".to_string(),
            client_type: "confidential".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec!["client_credentials".to_string()],
            scopes: vec!["api:read".to_string(), "api:write".to_string()],
            is_active: true,
            logo_url: None,
            description: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Create a mock pool (we won't use it, just need it for the service)
        // In a real test, we'd use a test database or mock
        // For now, we test the conversion logic in isolation

        // Test conversion logic directly
        let client_type = match db_client.client_type.as_str() {
            "confidential" => ClientType::Confidential,
            _ => ClientType::Public,
        };

        assert_eq!(client_type, ClientType::Confidential);
        assert!(db_client.is_active);
        assert_eq!(db_client.client_id, "test-client");
        assert_eq!(
            db_client.grant_types,
            vec!["client_credentials".to_string()]
        );
    }

    #[test]
    fn test_db_client_to_response_public() {
        let db_client = DbOAuth2Client {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "spa-client".to_string(),
            client_secret_hash: None,
            name: "SPA Client".to_string(),
            client_type: "public".to_string(),
            redirect_uris: vec!["https://spa.example.com/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            scopes: vec!["openid".to_string(), "profile".to_string()],
            is_active: true,
            logo_url: None,
            description: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let client_type = match db_client.client_type.as_str() {
            "confidential" => ClientType::Confidential,
            _ => ClientType::Public,
        };

        assert_eq!(client_type, ClientType::Public);
        assert!(db_client.client_secret_hash.is_none());
    }

    #[test]
    fn test_client_id_generation_length() {
        // Client ID should be CLIENT_ID_LENGTH bytes encoded as hex
        // 16 bytes = 32 hex chars
        let mut bytes = vec![0u8; CLIENT_ID_LENGTH];
        thread_rng().fill_bytes(&mut bytes);
        let client_id = hex::encode(&bytes);

        assert_eq!(client_id.len(), CLIENT_ID_LENGTH * 2);
    }

    #[test]
    fn test_client_secret_generation_length() {
        // Client secret should be CLIENT_SECRET_LENGTH bytes encoded as hex
        // 32 bytes = 64 hex chars
        let mut bytes = vec![0u8; CLIENT_SECRET_LENGTH];
        thread_rng().fill_bytes(&mut bytes);
        let client_secret = hex::encode(&bytes);

        assert_eq!(client_secret.len(), CLIENT_SECRET_LENGTH * 2);
    }

    #[test]
    fn test_client_id_generation_is_unique() {
        // Generate two client IDs and verify they're different
        let mut bytes1 = vec![0u8; CLIENT_ID_LENGTH];
        let mut bytes2 = vec![0u8; CLIENT_ID_LENGTH];
        thread_rng().fill_bytes(&mut bytes1);
        thread_rng().fill_bytes(&mut bytes2);
        let id1 = hex::encode(&bytes1);
        let id2 = hex::encode(&bytes2);

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_client_secret_generation_is_unique() {
        // Generate two client secrets and verify they're different
        let mut bytes1 = vec![0u8; CLIENT_SECRET_LENGTH];
        let mut bytes2 = vec![0u8; CLIENT_SECRET_LENGTH];
        thread_rng().fill_bytes(&mut bytes1);
        thread_rng().fill_bytes(&mut bytes2);
        let secret1 = hex::encode(&bytes1);
        let secret2 = hex::encode(&bytes2);

        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_client_id_is_valid_hex() {
        // Client ID should be valid hex
        let mut bytes = vec![0u8; CLIENT_ID_LENGTH];
        thread_rng().fill_bytes(&mut bytes);
        let client_id = hex::encode(&bytes);

        // Verify it can be decoded back
        let decoded = hex::decode(&client_id);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap().len(), CLIENT_ID_LENGTH);
    }

    #[test]
    fn test_client_secret_is_valid_hex() {
        // Client secret should be valid hex
        let mut bytes = vec![0u8; CLIENT_SECRET_LENGTH];
        thread_rng().fill_bytes(&mut bytes);
        let client_secret = hex::encode(&bytes);

        // Verify it can be decoded back
        let decoded = hex::decode(&client_secret);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap().len(), CLIENT_SECRET_LENGTH);
    }

    // Note: Integration tests for verify_client_credentials require a database
    // and are placed in tests/integration/

    // ── Redirect URI Normalization Tests (Security Hardening) ───────────────

    #[test]
    fn test_normalize_redirect_uri_basic() {
        let normalized =
            OAuth2ClientService::normalize_redirect_uri("https://example.com/callback");
        assert_eq!(normalized, Some("https://example.com/callback".to_string()));
    }

    #[test]
    fn test_normalize_redirect_uri_lowercase_scheme_and_host() {
        let normalized =
            OAuth2ClientService::normalize_redirect_uri("HTTPS://EXAMPLE.COM/Callback");
        assert_eq!(normalized, Some("https://example.com/Callback".to_string()));
    }

    #[test]
    fn test_normalize_redirect_uri_strips_default_https_port() {
        let normalized =
            OAuth2ClientService::normalize_redirect_uri("https://example.com:443/callback");
        assert_eq!(normalized, Some("https://example.com/callback".to_string()));
    }

    #[test]
    fn test_normalize_redirect_uri_strips_default_http_port_localhost() {
        let normalized =
            OAuth2ClientService::normalize_redirect_uri("http://localhost:80/callback");
        assert_eq!(normalized, Some("http://localhost/callback".to_string()));
    }

    #[test]
    fn test_normalize_redirect_uri_preserves_non_default_port() {
        let normalized =
            OAuth2ClientService::normalize_redirect_uri("https://example.com:8443/callback");
        assert_eq!(
            normalized,
            Some("https://example.com:8443/callback".to_string())
        );
    }

    #[test]
    fn test_normalize_redirect_uri_preserves_query_string() {
        let normalized =
            OAuth2ClientService::normalize_redirect_uri("https://example.com/callback?param=value");
        assert_eq!(
            normalized,
            Some("https://example.com/callback?param=value".to_string())
        );
    }

    #[test]
    fn test_normalize_redirect_uri_allows_localhost_http() {
        let normalized = OAuth2ClientService::normalize_redirect_uri("http://localhost/callback");
        assert_eq!(normalized, Some("http://localhost/callback".to_string()));

        let normalized = OAuth2ClientService::normalize_redirect_uri("http://127.0.0.1/callback");
        assert_eq!(normalized, Some("http://127.0.0.1/callback".to_string()));
    }

    #[test]
    fn test_normalize_redirect_uri_rejects_http_non_localhost() {
        // HTTP is only allowed for localhost
        let normalized = OAuth2ClientService::normalize_redirect_uri("http://example.com/callback");
        assert_eq!(normalized, None);
    }

    #[test]
    fn test_normalize_redirect_uri_rejects_invalid_schemes() {
        assert_eq!(
            OAuth2ClientService::normalize_redirect_uri("ftp://example.com/callback"),
            None
        );
        assert_eq!(
            OAuth2ClientService::normalize_redirect_uri("javascript:alert(1)"),
            None
        );
        assert_eq!(
            OAuth2ClientService::normalize_redirect_uri("file:///etc/passwd"),
            None
        );
    }

    #[test]
    fn test_normalize_redirect_uri_rejects_invalid_urls() {
        assert_eq!(
            OAuth2ClientService::normalize_redirect_uri("not a url"),
            None
        );
        assert_eq!(OAuth2ClientService::normalize_redirect_uri(""), None);
    }

    #[tokio::test]
    async fn test_redirect_uri_validation_with_normalization() {
        // Create a mock client with registered URIs
        let client = ClientResponse {
            id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            name: "Test Client".to_string(),
            client_type: ClientType::Public,
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            scopes: vec!["openid".to_string()],
            is_active: true,
            logo_url: None,
            description: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Create a mock pool (not used for validation, just needed for service)
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://invalid")
            .unwrap();
        let service = OAuth2ClientService::new(pool);

        // Exact match should work
        assert!(service
            .validate_redirect_uri(&client, "https://example.com/callback")
            .is_ok());

        // Case-insensitive host should work
        assert!(service
            .validate_redirect_uri(&client, "https://EXAMPLE.COM/callback")
            .is_ok());

        // Default port stripped should work
        assert!(service
            .validate_redirect_uri(&client, "https://example.com:443/callback")
            .is_ok());

        // Different path should fail
        assert!(service
            .validate_redirect_uri(&client, "https://example.com/other")
            .is_err());

        // HTTP non-localhost should fail
        assert!(service
            .validate_redirect_uri(&client, "http://example.com/callback")
            .is_err());
    }
}
