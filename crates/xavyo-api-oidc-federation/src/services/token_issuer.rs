//! Token issuer service for issuing Xavyo JWTs after successful federation.

use crate::error::{FederationError, FederationResult};
use tracing::instrument;
use uuid::Uuid;

/// Token issuer service.
///
/// This is a bridge to the main xavyo-auth library for issuing JWTs.
#[derive(Clone)]
pub struct TokenIssuerService {
    /// JWT configuration (would come from xavyo-auth in production).
    access_token_ttl: i64,
    refresh_token_ttl: i64,
}

/// Issued tokens response.
#[derive(Debug, Clone)]
pub struct IssuedTokens {
    /// Access token (JWT).
    pub access_token: String,
    /// Token expiry in seconds.
    pub expires_in: i64,
    /// Optional refresh token.
    pub refresh_token: Option<String>,
}

impl TokenIssuerService {
    /// Create a new token issuer service.
    pub fn new() -> Self {
        Self {
            access_token_ttl: 900,     // 15 minutes
            refresh_token_ttl: 604800, // 7 days
        }
    }

    /// Create with custom TTLs.
    pub fn with_ttl(access_token_ttl: i64, refresh_token_ttl: i64) -> Self {
        Self {
            access_token_ttl,
            refresh_token_ttl,
        }
    }

    /// Issue tokens for a user.
    ///
    /// In production, this should integrate with xavyo-auth to generate
    /// proper JWTs with RS256 signatures.
    #[instrument(skip(self))]
    pub async fn issue_tokens(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> FederationResult<IssuedTokens> {
        // TODO: Integrate with xavyo-auth JwtService
        // For now, generate a placeholder token that can be replaced
        // when integrating with the main auth system.

        let now = chrono::Utc::now().timestamp();
        let exp = now + self.access_token_ttl;

        // Build a simple claims structure (would be proper JWT in production)
        let claims = serde_json::json!({
            "sub": user_id.to_string(),
            "tid": tenant_id.to_string(),
            "iat": now,
            "exp": exp,
            "type": "access"
        });

        // Encode as base64 (placeholder - real implementation uses RS256)
        let claims_json = serde_json::to_string(&claims)
            .map_err(|e| FederationError::TokenIssueFailed(e.to_string()))?;
        let encoded_claims = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            claims_json,
        );

        // Build a placeholder JWT (header.payload.signature)
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            r#"{"alg":"RS256","typ":"JWT"}"#,
        );
        let access_token = format!("{}.{}.placeholder_signature", header, encoded_claims);

        // Generate refresh token
        let refresh_claims = serde_json::json!({
            "sub": user_id.to_string(),
            "tid": tenant_id.to_string(),
            "iat": now,
            "exp": now + self.refresh_token_ttl,
            "type": "refresh"
        });
        let refresh_json = serde_json::to_string(&refresh_claims)
            .map_err(|e| FederationError::TokenIssueFailed(e.to_string()))?;
        let refresh_encoded = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            refresh_json,
        );
        let refresh_token = format!("{}.{}.placeholder_signature", header, refresh_encoded);

        tracing::info!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            expires_in = %self.access_token_ttl,
            "Issued federation tokens"
        );

        Ok(IssuedTokens {
            access_token,
            expires_in: self.access_token_ttl,
            refresh_token: Some(refresh_token),
        })
    }
}

impl Default for TokenIssuerService {
    fn default() -> Self {
        Self::new()
    }
}
