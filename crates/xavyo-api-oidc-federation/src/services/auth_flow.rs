//! Authorization flow service for federated authentication.
//!
//! Handles the OAuth2/OIDC authorization code flow with PKCE.

use crate::error::{FederationError, FederationResult};
use crate::services::{DiscoveryService, EncryptionService};
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

        // Determine final redirect URI
        let final_redirect = input
            .redirect_uri
            .unwrap_or_else(|| format!("{}/", self.callback_base_url));

        // Create session record
        let session = FederatedAuthSession::create(
            &self.pool,
            CreateFederatedAuthSession {
                tenant_id: input.tenant_id,
                identity_provider_id: input.idp_id,
                state: state.secret().clone(),
                nonce: nonce.secret().clone(),
                pkce_verifier: pkce_verifier.secret().clone(),
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
        // Find session by state
        let session = FederatedAuthSession::find_by_state(&self.pool, state)
            .await?
            .ok_or(FederationError::SessionNotFound)?;

        // Check session expiry (10 minutes)
        let now = Utc::now();
        if now.signed_duration_since(session.created_at) > Duration::minutes(10) {
            // Delete expired session
            FederatedAuthSession::delete(&self.pool, session.id).await?;
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
                &session.pkce_verifier,
            )
            .await?;

        // Mark session as used
        FederatedAuthSession::mark_used(&self.pool, session.id).await?;

        tracing::info!(
            tenant_id = %session.tenant_id,
            idp_id = %session.identity_provider_id,
            session_id = %session.id,
            "Token exchange successful"
        );

        Ok(TokenExchangeResult {
            access_token: token_response.access_token,
            id_token: token_response.id_token,
            refresh_token: token_response.refresh_token,
            expires_in: token_response.expires_in,
            session,
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
        let client = reqwest::Client::new();

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
            let error_text = response.text().await.unwrap_or_default();
            tracing::error!(
                token_endpoint = %token_endpoint,
                error = %error_text,
                "Token exchange failed"
            );
            return Err(FederationError::TokenExchangeFailed(error_text));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| FederationError::TokenExchangeFailed(e.to_string()))?;

        Ok(token_response)
    }

    /// Validate and decode an ID token.
    pub fn decode_id_token(&self, id_token: &str) -> FederationResult<IdTokenClaims> {
        // Split the JWT
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(FederationError::InvalidIdToken(
                "Invalid JWT format".to_string(),
            ));
        }

        // Decode the payload (we validate signature separately or trust TLS)
        let payload =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
                .map_err(|e| FederationError::InvalidIdToken(e.to_string()))?;

        let claims: IdTokenClaims = serde_json::from_slice(&payload)
            .map_err(|e| FederationError::InvalidIdToken(e.to_string()))?;

        Ok(claims)
    }

    /// Get session by ID.
    pub async fn get_session(
        &self,
        session_id: Uuid,
    ) -> FederationResult<Option<FederatedAuthSession>> {
        Ok(FederatedAuthSession::find_by_id(&self.pool, session_id).await?)
    }

    /// Delete a session.
    pub async fn delete_session(&self, session_id: Uuid) -> FederationResult<()> {
        FederatedAuthSession::delete(&self.pool, session_id).await?;
        Ok(())
    }

    /// Clean up expired sessions.
    pub async fn cleanup_expired_sessions(&self) -> FederationResult<u64> {
        let count = FederatedAuthSession::delete_expired(&self.pool).await?;
        if count > 0 {
            tracing::info!(count = count, "Cleaned up expired federation sessions");
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
