//! Authorization flow service for federated authentication.
//!
//! Handles the OAuth2/OIDC authorization code flow with PKCE.

use crate::error::{FederationError, FederationResult};
use crate::services::{DiscoveryService, EncryptionService, TokenVerifierService};
use chrono::{Duration, Utc};
use openidconnect::{CsrfToken, Nonce, PkceCodeChallenge};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;
use xavyo_db::models::{CreateFederatedAuthSession, FederatedAuthSession, TenantIdentityProvider};

/// Authorization flow service.
#[derive(Clone)]
pub struct AuthFlowService {
    pool: PgPool,
    discovery: DiscoveryService,
    encryption: EncryptionService,
    token_verifier: TokenVerifierService,
    /// Base URL for callbacks.
    callback_base_url: String,
}

/// Authorization URL result.
#[derive(Debug, Clone)]
pub struct AuthorizationUrl {
    /// The URL to redirect the user to.
    pub url: String,
    /// The state token for CSRF protection.
    pub state: String,
    /// The session ID for tracking.
    pub session_id: Uuid,
}

/// Authorization initiation input.
#[derive(Debug, Clone)]
pub struct InitiateAuthInput {
    pub tenant_id: Uuid,
    pub idp_id: Uuid,
    pub redirect_uri: Option<String>,
    pub email: Option<String>,
}

/// Token exchange result.
#[derive(Debug, Clone)]
pub struct TokenExchangeResult {
    /// Access token from the `IdP`.
    pub access_token: String,
    /// ID token (JWT) from the `IdP`.
    pub id_token: String,
    /// Optional refresh token.
    pub refresh_token: Option<String>,
    /// Token expiry in seconds.
    pub expires_in: Option<i64>,
    /// The session used for this exchange.
    pub session: FederatedAuthSession,
    /// Verified ID token claims (signature, expiry, nonce, and audience validated).
    pub claims: IdTokenClaims,
}

/// Decoded ID token claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Subject (user ID at `IdP`).
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Audience.
    pub aud: serde_json::Value,
    /// Expiration time.
    pub exp: i64,
    /// Issued at.
    pub iat: i64,
    /// Nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Email verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Given name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// Family name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// Picture URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// Additional claims.
    #[serde(flatten)]
    pub additional: std::collections::HashMap<String, serde_json::Value>,
}

impl AuthFlowService {
    /// Create a new authorization flow service.
    #[must_use]
    pub fn new(pool: PgPool, encryption: EncryptionService, callback_base_url: String) -> Self {
        Self {
            pool,
            discovery: DiscoveryService::new(),
            encryption,
            token_verifier: TokenVerifierService::default(),
            callback_base_url,
        }
    }

    /// Initiate authorization flow.
    #[instrument(skip(self))]
    pub async fn initiate(&self, input: InitiateAuthInput) -> FederationResult<AuthorizationUrl> {
        // Get the identity provider
        let idp = TenantIdentityProvider::find_by_id_and_tenant(
            &self.pool,
            input.idp_id,
            input.tenant_id,
        )
        .await?
        .ok_or(FederationError::IdpNotFound(input.idp_id))?;

        // Check if IdP is enabled
        if !idp.is_enabled {
            return Err(FederationError::IdpDisabled(input.idp_id));
        }

        // Discover OIDC endpoints
        let endpoints = self.discovery.discover(&idp.issuer_url).await?;

        // Generate PKCE challenge
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Generate state and nonce
        let state = CsrfToken::new_random();
        let nonce = Nonce::new_random();

        // Build callback URL
        let callback_url = format!("{}/auth/federation/callback", self.callback_base_url);

        // Validate redirect URI to prevent open redirects (H2)
        if let Some(ref uri) = input.redirect_uri {
            Self::validate_redirect_uri(uri, &self.callback_base_url)?;
        }

        // Determine final redirect URI
        let final_redirect = input
            .redirect_uri
            .unwrap_or_else(|| format!("{}/", self.callback_base_url));

        // Encrypt PKCE verifier and nonce before storing at rest
        let encrypted_verifier = self
            .encryption
            .encrypt(input.tenant_id, pkce_verifier.secret())?;
        let encrypted_nonce = self.encryption.encrypt(input.tenant_id, nonce.secret())?;

        // Create session record
        let session = FederatedAuthSession::create(
            &self.pool,
            CreateFederatedAuthSession {
                tenant_id: input.tenant_id,
                identity_provider_id: input.idp_id,
                state: state.secret().clone(),
                nonce: encrypted_nonce,
                pkce_verifier: encrypted_verifier,
                redirect_uri: final_redirect,
            },
        )
        .await?;

        // Parse scopes from IdP config
        let scopes: Vec<&str> = idp.scopes.split_whitespace().collect();

        // Build authorization URL
        let mut auth_url = url::Url::parse(&endpoints.authorization_endpoint)
            .map_err(|e| FederationError::InvalidConfiguration(e.to_string()))?;

        {
            let mut query = auth_url.query_pairs_mut();
            query.append_pair("response_type", "code");
            query.append_pair("client_id", &idp.client_id);
            query.append_pair("redirect_uri", &callback_url);
            query.append_pair("state", state.secret());
            query.append_pair("nonce", nonce.secret());
            query.append_pair("code_challenge", pkce_challenge.as_str());
            query.append_pair("code_challenge_method", "S256");

            // Add scopes
            let scope_str = scopes.join(" ");
            query.append_pair("scope", &scope_str);

            // Add login hint if email provided
            if let Some(email) = &input.email {
                query.append_pair("login_hint", email);
            }
        }

        tracing::info!(
            tenant_id = %input.tenant_id,
            idp_id = %input.idp_id,
            session_id = %session.id,
            "Initiated federated authentication"
        );

        Ok(AuthorizationUrl {
            url: auth_url.to_string(),
            state: state.secret().clone(),
            session_id: session.id,
        })
    }

    /// Handle authorization callback.
    #[instrument(skip(self, code))]
    pub async fn callback(&self, state: &str, code: &str) -> FederationResult<TokenExchangeResult> {
        // Atomically consume session by state (prevents TOCTOU race conditions and replay attacks)
        let session = FederatedAuthSession::consume_by_state(&self.pool, state)
            .await?
            .ok_or(FederationError::SessionNotFound)?;

        // Session is already marked as used by consume_by_state, so we don't need the is_used check

        // Check session expiry (10 minutes) - defensive check, consume_by_state already filters expired
        let now = Utc::now();
        if now.signed_duration_since(session.created_at) > Duration::minutes(10) {
            // Delete expired session
            FederatedAuthSession::delete(&self.pool, session.tenant_id, session.id).await?;
            return Err(FederationError::SessionExpired);
        }

        // Get the identity provider
        let idp = TenantIdentityProvider::find_by_id_and_tenant(
            &self.pool,
            session.identity_provider_id,
            session.tenant_id,
        )
        .await?
        .ok_or(FederationError::IdpNotFound(session.identity_provider_id))?;

        // Discover OIDC endpoints
        let endpoints = self.discovery.discover(&idp.issuer_url).await?;

        // Decrypt client secret
        let client_secret = self
            .encryption
            .decrypt(session.tenant_id, &idp.client_secret_encrypted)?;

        // Decrypt PKCE verifier and nonce from encrypted at-rest storage
        let pkce_verifier = self
            .encryption
            .decrypt(session.tenant_id, &session.pkce_verifier)?;
        let nonce_value = self.encryption.decrypt(session.tenant_id, &session.nonce)?;

        // Build callback URL (must match what was used in initiate)
        let callback_url = format!("{}/auth/federation/callback", self.callback_base_url);

        // Exchange code for tokens
        let token_response = self
            .exchange_code(
                &endpoints.token_endpoint,
                code,
                &idp.client_id,
                &client_secret,
                &callback_url,
                &pkce_verifier,
            )
            .await?;

        // C1: Verify ID token signature and expiry using IdP's JWKS
        self.token_verifier
            .verify_token_with_issuer(
                &token_response.id_token,
                &endpoints.jwks_uri,
                &endpoints.issuer,
            )
            .await?;

        // Decode full claims after signature verification
        let claims = self.decode_id_token_payload(&token_response.id_token)?;

        // C2: Validate nonce to prevent replay attacks
        if claims.nonce.as_deref() != Some(nonce_value.as_str()) {
            tracing::warn!(
                session_id = %session.id,
                "Nonce mismatch in ID token — possible replay attack"
            );
            return Err(FederationError::InvalidIdToken(
                "Nonce mismatch: possible replay attack".to_string(),
            ));
        }

        // H3: Validate audience contains our client_id
        Self::validate_audience(&claims, &idp.client_id)?;

        // Session already marked as used by consume_by_state (no need to call mark_used separately)

        tracing::info!(
            tenant_id = %session.tenant_id,
            idp_id = %session.identity_provider_id,
            session_id = %session.id,
            "Token exchange and verification successful"
        );

        Ok(TokenExchangeResult {
            access_token: token_response.access_token,
            id_token: token_response.id_token,
            refresh_token: token_response.refresh_token,
            expires_in: token_response.expires_in,
            session,
            claims,
        })
    }

    /// Exchange authorization code for tokens.
    async fn exchange_code(
        &self,
        token_endpoint: &str,
        code: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        pkce_verifier: &str,
    ) -> FederationResult<TokenResponse> {
        // M-4: SSRF protection — validate token endpoint URL from discovered metadata
        super::discovery::validate_url_not_internal(token_endpoint)
            .map_err(|e| FederationError::InvalidConfiguration(format!("SSRF protection: {e}")))?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
            ("code_verifier", pkce_verifier),
        ];

        let response = client
            .post(token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| FederationError::TokenExchangeFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            // SECURITY: Truncate IdP error response in logs to prevent log injection/bloat.
            // R9: Use char boundary-safe truncation to prevent panic on multi-byte UTF-8.
            let truncated = if error_text.len() > 500 {
                let safe_end = error_text
                    .char_indices()
                    .take_while(|(i, _)| *i < 500)
                    .last()
                    .map_or(0, |(i, c)| i + c.len_utf8());
                format!("{}... (truncated)", &error_text[..safe_end])
            } else {
                error_text
            };
            tracing::error!(
                token_endpoint = %token_endpoint,
                status = %status,
                error = %truncated,
                "Token exchange failed"
            );
            // Never pass raw IdP response to caller — use generic message
            return Err(FederationError::TokenExchangeFailed(format!(
                "Token endpoint returned HTTP {status}"
            )));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| FederationError::TokenExchangeFailed(e.to_string()))?;

        Ok(token_response)
    }

    /// Get the callback base URL.
    #[must_use]
    pub fn callback_base_url(&self) -> &str {
        &self.callback_base_url
    }

    /// Decode the ID token payload into claims.
    ///
    /// This must only be called after signature verification via `TokenVerifierService`.
    fn decode_id_token_payload(&self, id_token: &str) -> FederationResult<IdTokenClaims> {
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(FederationError::InvalidIdToken(
                "Invalid JWT format".to_string(),
            ));
        }

        // SECURITY (H2): Guard against oversized payloads before base64 decode.
        // Base64-encoded 64KB payload is ~87KB. Cap the encoded part to 128KB.
        if parts[1].len() > 128 * 1024 {
            return Err(FederationError::InvalidIdToken(
                "ID token payload exceeds maximum size (128KB encoded)".to_string(),
            ));
        }

        let payload =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
                .map_err(|e| FederationError::InvalidIdToken(e.to_string()))?;

        // Defense-in-depth: cap decoded payload size at 64KB
        if payload.len() > 64 * 1024 {
            return Err(FederationError::InvalidIdToken(
                "ID token payload exceeds maximum size (64KB decoded)".to_string(),
            ));
        }

        let claims: IdTokenClaims = serde_json::from_slice(&payload)
            .map_err(|e| FederationError::InvalidIdToken(e.to_string()))?;

        // SECURITY: Guard against unbounded additional claims from malicious IdPs.
        if claims.additional.len() > 50 {
            return Err(FederationError::InvalidIdToken(
                "Too many additional claims".to_string(),
            ));
        }

        Ok(claims)
    }

    /// Validate that the ID token audience contains our client_id.
    fn validate_audience(claims: &IdTokenClaims, client_id: &str) -> FederationResult<()> {
        let valid = match &claims.aud {
            serde_json::Value::String(s) => s == client_id,
            serde_json::Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(client_id)),
            _ => false,
        };
        if !valid {
            return Err(FederationError::InvalidIdToken(format!(
                "Audience does not contain expected client_id: {client_id}"
            )));
        }
        Ok(())
    }

    /// Validate redirect URI to prevent open redirects.
    fn validate_redirect_uri(redirect_uri: &str, callback_base_url: &str) -> FederationResult<()> {
        let trimmed = redirect_uri.trim();
        // Allow relative paths starting with / (but not // or /\)
        if trimmed.starts_with('/')
            && !trimmed.starts_with("//")
            && !trimmed.starts_with("/\\")
            && !trimmed.contains("://")
        {
            // SECURITY: Block encoded path traversal patterns that could bypass the above checks
            // after browser URL normalization (e.g., %2f → /, %5c → \, %0a → newline).
            let lower = trimmed.to_lowercase();
            if lower.contains("%2f")
                || lower.contains("%5c")
                || lower.contains("%0a")
                || lower.contains("%0d")
                || lower.contains("\\")
            {
                return Err(FederationError::InvalidCallback(
                    "redirect_uri contains invalid encoded characters".to_string(),
                ));
            }
            return Ok(());
        }
        // For absolute URLs: parse both and compare scheme + host + port
        if let (Ok(redirect), Ok(base)) =
            (url::Url::parse(trimmed), url::Url::parse(callback_base_url))
        {
            if redirect.scheme() == base.scheme()
                && redirect.host_str() == base.host_str()
                && redirect.port() == base.port()
            {
                return Ok(());
            }
        }
        Err(FederationError::InvalidCallback(
            "redirect_uri must be a relative path or under the configured base URL".to_string(),
        ))
    }

    /// Get session by ID with tenant isolation.
    pub async fn get_session(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
    ) -> FederationResult<Option<FederatedAuthSession>> {
        Ok(FederatedAuthSession::find_by_id(&self.pool, tenant_id, session_id).await?)
    }

    /// Delete a session with tenant isolation.
    pub async fn delete_session(&self, tenant_id: Uuid, session_id: Uuid) -> FederationResult<()> {
        FederatedAuthSession::delete(&self.pool, tenant_id, session_id).await?;
        Ok(())
    }

    /// Clean up expired sessions (all tenants — use for system maintenance only).
    pub async fn cleanup_expired_sessions(&self) -> FederationResult<u64> {
        let count = FederatedAuthSession::delete_expired(&self.pool).await?;
        if count > 0 {
            tracing::info!(count = count, "Cleaned up expired federation sessions");
        }
        Ok(count)
    }

    /// R9: Clean up expired sessions for a specific tenant (respects data sovereignty).
    pub async fn cleanup_expired_sessions_for_tenant(
        &self,
        tenant_id: Uuid,
    ) -> FederationResult<u64> {
        let count = FederatedAuthSession::cleanup_expired_for_tenant(&self.pool, tenant_id).await?;
        if count > 0 {
            tracing::info!(
                tenant_id = %tenant_id,
                count = count,
                "Cleaned up expired federation sessions for tenant"
            );
        }
        Ok(count)
    }
}

/// Token response from `IdP`.
#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    access_token: String,
    id_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[allow(dead_code)]
    token_type: Option<String>,
}
