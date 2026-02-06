//! Authorization service for `OAuth2` authorization code flow.

use crate::error::OAuthError;
use crate::models::AuthorizationRequest;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Authorization code record from the database.
#[derive(Debug, FromRow)]
struct AuthCodeRecord {
    id: Uuid,
    client_id: Uuid,
    user_id: Uuid,
    redirect_uri: String,
    scope: String,
    code_challenge: String,
    nonce: Option<String>,
    expires_at: DateTime<Utc>,
    used: bool,
}

/// Authorization code length in bytes (32 bytes = 256 bits).
const AUTH_CODE_LENGTH: usize = 32;

/// Authorization code expiration in minutes.
const AUTH_CODE_EXPIRY_MINUTES: i64 = 10;

/// Service for handling authorization code flow.
#[derive(Debug, Clone)]
pub struct AuthorizationService {
    pool: PgPool,
}

impl AuthorizationService {
    /// Create a new authorization service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Generate a cryptographically secure authorization code.
    ///
    /// SECURITY: Uses `OsRng` directly from the operating system's CSPRNG for maximum security.
    fn generate_code() -> String {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut bytes = [0u8; AUTH_CODE_LENGTH];
        OsRng.fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Hash an authorization code for storage.
    fn hash_code(code: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        let hash = hasher.finalize();
        hex::encode(hash)
    }

    /// Generate a PKCE code challenge from a verifier using S256.
    #[must_use]
    pub fn generate_code_challenge(code_verifier: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let hash = hasher.finalize();
        URL_SAFE_NO_PAD.encode(hash)
    }

    /// Verify a PKCE code verifier against a code challenge.
    #[must_use]
    pub fn verify_code_verifier(code_verifier: &str, code_challenge: &str) -> bool {
        let computed_challenge = Self::generate_code_challenge(code_verifier);
        // Use constant-time comparison to prevent timing attacks
        subtle::ConstantTimeEq::ct_eq(computed_challenge.as_bytes(), code_challenge.as_bytes())
            .into()
    }

    /// Validate the authorization request parameters.
    pub fn validate_authorization_request(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<(), OAuthError> {
        // Validate response_type
        if request.response_type != "code" {
            return Err(OAuthError::UnsupportedResponseType(
                request.response_type.clone(),
            ));
        }

        // Validate code_challenge_method
        if request.code_challenge_method != "S256" {
            return Err(OAuthError::InvalidRequest(
                "Only S256 code_challenge_method is supported".to_string(),
            ));
        }

        // Validate code_challenge length (43-128 characters for base64url-encoded SHA256)
        if request.code_challenge.len() < 43 || request.code_challenge.len() > 128 {
            return Err(OAuthError::InvalidRequest(
                "code_challenge must be between 43 and 128 characters".to_string(),
            ));
        }

        // SECURITY: Validate state parameter (RFC 6749 CSRF protection)
        // - Minimum 16 characters (128-bit entropy recommended for CSRF tokens)
        // - Maximum 256 characters (prevent DoS from oversized state)
        // - Must be URL-safe characters only (alphanumeric, hyphen, underscore, period, tilde)
        if request.state.len() < 16 {
            return Err(OAuthError::InvalidRequest(
                "state must be at least 16 characters for CSRF protection".to_string(),
            ));
        }

        if request.state.len() > 256 {
            return Err(OAuthError::InvalidRequest(
                "state must be at most 256 characters".to_string(),
            ));
        }

        // Validate state contains only URL-safe characters (RFC 3986 unreserved + base64url)
        // This prevents injection attacks and ensures state can be safely round-tripped
        if !request
            .state
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~')
        {
            return Err(OAuthError::InvalidRequest(
                "state must contain only URL-safe characters (alphanumeric, -, _, ., ~)"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Create a new authorization code.
    ///
    /// Returns the plaintext authorization code (to be sent to client).
    /// The code is stored hashed in the database.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_authorization_code(
        &self,
        tenant_id: Uuid,
        client_id: Uuid,
        user_id: Uuid,
        redirect_uri: &str,
        scope: &str,
        code_challenge: &str,
        code_challenge_method: &str,
        nonce: Option<&str>,
    ) -> Result<String, OAuthError> {
        // Generate a cryptographically secure code
        let code = Self::generate_code();
        let code_hash = Self::hash_code(&code);
        let expires_at = Utc::now() + Duration::minutes(AUTH_CODE_EXPIRY_MINUTES);

        // Store the hashed code in the database
        sqlx::query(
            r"
            INSERT INTO authorization_codes (
                code_hash, client_id, user_id, tenant_id,
                redirect_uri, scope, code_challenge, code_challenge_method,
                nonce, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ",
        )
        .bind(&code_hash)
        .bind(client_id)
        .bind(user_id)
        .bind(tenant_id)
        .bind(redirect_uri)
        .bind(scope)
        .bind(code_challenge)
        .bind(code_challenge_method)
        .bind(nonce)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create authorization code: {}", e);
            OAuthError::Internal("Failed to create authorization code".to_string())
        })?;

        Ok(code)
    }

    /// Validate and consume an authorization code.
    ///
    /// This performs the following validations:
    /// 1. Code exists and is not expired
    /// 2. Code has not been used before
    /// 3. Client ID matches
    /// 4. Redirect URI matches
    /// 5. PKCE code verifier matches the stored challenge
    ///
    /// Returns (`user_id`, scope, nonce) if valid.
    pub async fn validate_and_consume_code(
        &self,
        tenant_id: Uuid,
        code: &str,
        client_id: Uuid,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<(Uuid, String, Option<String>), OAuthError> {
        let code_hash = Self::hash_code(code);

        // Start a transaction to ensure atomicity
        let mut tx = self.pool.begin().await.map_err(|e| {
            tracing::error!("Failed to start transaction: {}", e);
            OAuthError::Internal("Database error".to_string())
        })?;

        // Set tenant context for RLS using parameterized query (prevents SQL injection)
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                OAuthError::Internal("Database error".to_string())
            })?;

        // Fetch the authorization code record
        let record: Option<AuthCodeRecord> = sqlx::query_as(
            r"
            SELECT id, client_id, user_id, redirect_uri, scope,
                   code_challenge, nonce, expires_at, used
            FROM authorization_codes
            WHERE code_hash = $1 AND tenant_id = $2
            FOR UPDATE
            ",
        )
        .bind(&code_hash)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch authorization code: {}", e);
            OAuthError::Internal("Database error".to_string())
        })?;

        let record = match record {
            Some(r) => r,
            None => {
                return Err(OAuthError::InvalidGrant(
                    "Authorization code not found or invalid".to_string(),
                ));
            }
        };

        // Check if already used
        if record.used {
            // Potential token replay attack - revoke all tokens for this family
            tracing::warn!(
                "Authorization code reuse detected for code_id={}, user_id={}",
                record.id,
                record.user_id
            );
            return Err(OAuthError::InvalidGrant(
                "Authorization code has already been used".to_string(),
            ));
        }

        // Check expiration
        if Utc::now() >= record.expires_at {
            return Err(OAuthError::InvalidGrant(
                "Authorization code has expired".to_string(),
            ));
        }

        // Validate client_id
        if record.client_id != client_id {
            return Err(OAuthError::InvalidGrant("Client ID mismatch".to_string()));
        }

        // Validate redirect_uri (exact match required)
        if record.redirect_uri != redirect_uri {
            return Err(OAuthError::InvalidGrant(
                "Redirect URI mismatch".to_string(),
            ));
        }

        // Verify PKCE code verifier
        if !Self::verify_code_verifier(code_verifier, &record.code_challenge) {
            return Err(OAuthError::InvalidGrant(
                "Invalid code verifier".to_string(),
            ));
        }

        // Mark the code as used
        sqlx::query(
            r"
            UPDATE authorization_codes
            SET used = TRUE
            WHERE id = $1
            ",
        )
        .bind(record.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("Failed to mark authorization code as used: {}", e);
            OAuthError::Internal("Database error".to_string())
        })?;

        // Commit the transaction
        tx.commit().await.map_err(|e| {
            tracing::error!("Failed to commit transaction: {}", e);
            OAuthError::Internal("Database error".to_string())
        })?;

        Ok((record.user_id, record.scope, record.nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_code_challenge_generation() {
        // Test vector from RFC 7636 Appendix B
        // Note: The RFC uses a specific code_verifier that produces a known challenge
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let challenge = AuthorizationService::generate_code_challenge(code_verifier);
        assert_eq!(challenge, expected_challenge);
    }

    #[test]
    fn test_pkce_code_verifier_validation() {
        let code_verifier = "test-verifier-that-is-at-least-43-characters-long";
        let challenge = AuthorizationService::generate_code_challenge(code_verifier);

        assert!(AuthorizationService::verify_code_verifier(
            code_verifier,
            &challenge
        ));
        assert!(!AuthorizationService::verify_code_verifier(
            "wrong-verifier",
            &challenge
        ));
    }

    #[test]
    fn test_challenge_is_deterministic() {
        let verifier = "my-secure-verifier-string-that-is-long-enough";
        let c1 = AuthorizationService::generate_code_challenge(verifier);
        let c2 = AuthorizationService::generate_code_challenge(verifier);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_code_generation_is_unique() {
        let code1 = AuthorizationService::generate_code();
        let code2 = AuthorizationService::generate_code();
        assert_ne!(code1, code2);
    }

    #[test]
    fn test_code_generation_length() {
        let code = AuthorizationService::generate_code();
        // 32 bytes base64url encoded = 43 characters
        assert_eq!(code.len(), 43);
    }

    #[test]
    fn test_code_hash_is_deterministic() {
        let code = "test-authorization-code";
        let hash1 = AuthorizationService::hash_code(code);
        let hash2 = AuthorizationService::hash_code(code);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_code_hash_is_hex() {
        let code = "test-authorization-code";
        let hash = AuthorizationService::hash_code(code);
        // SHA-256 produces 64 hex characters
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── State Parameter Validation Tests (F082 Security Hardening) ───────────

    fn mock_auth_request(state: &str) -> crate::models::AuthorizationRequest {
        crate::models::AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "test-client-id".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: "openid".to_string(),
            state: state.to_string(),
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
            code_challenge_method: "S256".to_string(),
            nonce: None,
        }
    }

    #[tokio::test]
    async fn test_state_validation_accepts_valid_state() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://invalid")
            .unwrap();
        let service = AuthorizationService::new(pool);

        // Valid: 16+ alphanumeric characters
        let request = mock_auth_request("abcdefghij123456");
        assert!(service.validate_authorization_request(&request).is_ok());

        // Valid: with URL-safe special characters
        let request = mock_auth_request("abc-def_ghi.jkl~mnop");
        assert!(service.validate_authorization_request(&request).is_ok());

        // Valid: base64url-like state
        let request = mock_auth_request("dGVzdF9zdGF0ZV92YWx1ZQ");
        assert!(service.validate_authorization_request(&request).is_ok());
    }

    #[tokio::test]
    async fn test_state_validation_rejects_short_state() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://invalid")
            .unwrap();
        let service = AuthorizationService::new(pool);

        // Too short: 8 characters (was previously accepted, now rejected)
        let request = mock_auth_request("abcd1234");
        let err = service
            .validate_authorization_request(&request)
            .unwrap_err();
        assert!(err.to_string().contains("at least 16 characters"));

        // Too short: 15 characters
        let request = mock_auth_request("abcdefghij12345");
        let err = service
            .validate_authorization_request(&request)
            .unwrap_err();
        assert!(err.to_string().contains("at least 16 characters"));
    }

    #[tokio::test]
    async fn test_state_validation_rejects_too_long_state() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://invalid")
            .unwrap();
        let service = AuthorizationService::new(pool);

        // Too long: 257 characters
        let long_state = "a".repeat(257);
        let request = mock_auth_request(&long_state);
        let err = service
            .validate_authorization_request(&request)
            .unwrap_err();
        assert!(err.to_string().contains("at most 256 characters"));
    }

    #[tokio::test]
    async fn test_state_validation_rejects_invalid_characters() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://invalid")
            .unwrap();
        let service = AuthorizationService::new(pool);

        // Invalid: contains space
        let request = mock_auth_request("valid state with space");
        let err = service
            .validate_authorization_request(&request)
            .unwrap_err();
        assert!(err.to_string().contains("URL-safe characters"));

        // Invalid: contains special characters
        let request = mock_auth_request("state<script>evil</script>");
        let err = service
            .validate_authorization_request(&request)
            .unwrap_err();
        assert!(err.to_string().contains("URL-safe characters"));

        // Invalid: contains URL-encoded characters
        let request = mock_auth_request("state%20with%20encoding");
        let err = service
            .validate_authorization_request(&request)
            .unwrap_err();
        assert!(err.to_string().contains("URL-safe characters"));

        // Invalid: contains slash
        let request = mock_auth_request("state/with/slashes");
        let err = service
            .validate_authorization_request(&request)
            .unwrap_err();
        assert!(err.to_string().contains("URL-safe characters"));
    }

    #[tokio::test]
    async fn test_state_validation_boundary_cases() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://invalid")
            .unwrap();
        let service = AuthorizationService::new(pool);

        // Exactly 16 characters (minimum valid)
        let request = mock_auth_request("abcdefghij123456");
        assert!(service.validate_authorization_request(&request).is_ok());

        // Exactly 256 characters (maximum valid)
        let max_state = "a".repeat(256);
        let request = mock_auth_request(&max_state);
        assert!(service.validate_authorization_request(&request).is_ok());
    }
}
