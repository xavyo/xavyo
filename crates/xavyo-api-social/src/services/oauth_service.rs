//! OAuth service for state management and PKCE.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{ProviderType, SocialError, SocialResult};

/// State lifetime in minutes.
const STATE_LIFETIME_MINUTES: i64 = 10;

/// PKCE code verifier length in bytes (before base64 encoding).
const PKCE_VERIFIER_LENGTH: usize = 32;

/// OAuth state claims stored in a signed JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthStateClaims {
    /// Random nonce for uniqueness.
    pub nonce: String,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Provider type.
    pub provider: String,
    /// PKCE code verifier.
    pub pkce_verifier: String,
    /// Where to redirect after login.
    pub redirect_after: Option<String>,
    /// User ID for account linking (if linking existing account).
    pub user_id: Option<Uuid>,
    /// Expiration timestamp.
    pub exp: i64,
    /// Issued at timestamp.
    pub iat: i64,
}

/// PKCE challenge and verifier pair.
#[derive(Debug, Clone)]
pub struct PkceChallenge {
    /// Code verifier (secret, stored in state).
    pub verifier: String,
    /// Code challenge (SHA256 hash, sent to provider).
    pub challenge: String,
}

/// OAuth service for managing state and PKCE.
#[derive(Clone)]
pub struct OAuthService {
    /// Secret key for signing state JWTs.
    state_secret: Vec<u8>,
}

impl OAuthService {
    /// Create a new OAuth service.
    #[must_use]
    pub fn new(state_secret: &str) -> Self {
        Self {
            state_secret: state_secret.as_bytes().to_vec(),
        }
    }

    /// Generate a new PKCE challenge pair.
    #[must_use]
    pub fn generate_pkce() -> PkceChallenge {
        // Generate random verifier
        let mut verifier_bytes = [0u8; PKCE_VERIFIER_LENGTH];
        rand::rngs::OsRng.fill_bytes(&mut verifier_bytes);
        let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

        // Create S256 challenge
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let challenge_bytes = hasher.finalize();
        let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

        PkceChallenge {
            verifier,
            challenge,
        }
    }

    /// Verify a PKCE verifier against a challenge.
    #[must_use]
    pub fn verify_pkce(verifier: &str, challenge: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let computed_bytes = hasher.finalize();
        let computed_challenge = URL_SAFE_NO_PAD.encode(computed_bytes);

        computed_challenge == challenge
    }

    /// Create a signed state parameter for an OAuth flow.
    pub fn create_state(
        &self,
        tenant_id: Uuid,
        provider: ProviderType,
        pkce_verifier: &str,
        redirect_after: Option<String>,
        user_id: Option<Uuid>,
    ) -> SocialResult<String> {
        let now = Utc::now();
        let exp = now + Duration::minutes(STATE_LIFETIME_MINUTES);

        let claims = OAuthStateClaims {
            nonce: Uuid::new_v4().to_string(),
            tenant_id,
            provider: provider.to_string(),
            pkce_verifier: pkce_verifier.to_string(),
            redirect_after,
            user_id,
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(&self.state_secret),
        )?;

        Ok(token)
    }

    /// Validate and decode a state parameter.
    pub fn validate_state(&self, state: &str) -> SocialResult<OAuthStateClaims> {
        let mut validation = Validation::default();
        validation.validate_exp = true;
        validation.required_spec_claims.clear();

        let token_data = decode::<OAuthStateClaims>(
            state,
            &DecodingKey::from_secret(&self.state_secret),
            &validation,
        )
        .map_err(|e| SocialError::InvalidState {
            reason: e.to_string(),
        })?;

        // Check expiration
        let now = Utc::now().timestamp();
        if token_data.claims.exp < now {
            return Err(SocialError::InvalidState {
                reason: "state has expired".to_string(),
            });
        }

        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service() -> OAuthService {
        OAuthService::new("test-secret-key-for-signing-state")
    }

    #[test]
    fn test_generate_pkce() {
        let pkce = OAuthService::generate_pkce();

        // Verifier should be base64url encoded
        assert!(!pkce.verifier.is_empty());
        assert!(!pkce.verifier.contains('+'));
        assert!(!pkce.verifier.contains('/'));

        // Challenge should be different from verifier
        assert_ne!(pkce.verifier, pkce.challenge);

        // Verification should work
        assert!(OAuthService::verify_pkce(&pkce.verifier, &pkce.challenge));
    }

    #[test]
    fn test_pkce_verification_fails_with_wrong_verifier() {
        let pkce = OAuthService::generate_pkce();
        let wrong_verifier = "wrong-verifier";

        assert!(!OAuthService::verify_pkce(wrong_verifier, &pkce.challenge));
    }

    #[test]
    fn test_create_and_validate_state() {
        let service = test_service();
        let tenant_id = Uuid::new_v4();
        let pkce = OAuthService::generate_pkce();

        let state = service
            .create_state(
                tenant_id,
                ProviderType::Google,
                &pkce.verifier,
                Some("/dashboard".to_string()),
                None,
            )
            .unwrap();

        // State should be a valid JWT
        assert!(state.contains('.'));

        // Should validate successfully
        let claims = service.validate_state(&state).unwrap();
        assert_eq!(claims.tenant_id, tenant_id);
        assert_eq!(claims.provider, "google");
        assert_eq!(claims.pkce_verifier, pkce.verifier);
        assert_eq!(claims.redirect_after, Some("/dashboard".to_string()));
        assert!(claims.user_id.is_none());
    }

    #[test]
    fn test_state_with_user_id_for_linking() {
        let service = test_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let pkce = OAuthService::generate_pkce();

        let state = service
            .create_state(
                tenant_id,
                ProviderType::Microsoft,
                &pkce.verifier,
                None,
                Some(user_id),
            )
            .unwrap();

        let claims = service.validate_state(&state).unwrap();
        assert_eq!(claims.user_id, Some(user_id));
    }

    #[test]
    fn test_invalid_state_signature() {
        let service = test_service();
        let other_service = OAuthService::new("different-secret");
        let tenant_id = Uuid::new_v4();
        let pkce = OAuthService::generate_pkce();

        // Create state with one service
        let state = service
            .create_state(tenant_id, ProviderType::Apple, &pkce.verifier, None, None)
            .unwrap();

        // Try to validate with different service
        let result = other_service.validate_state(&state);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_state() {
        let service = test_service();

        // Tampered JWT
        let result = service.validate_state("invalid.state.token");
        assert!(result.is_err());
    }
}
