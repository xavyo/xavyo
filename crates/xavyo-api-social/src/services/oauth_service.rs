//! OAuth service for state management and PKCE.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use moka::sync::Cache;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{ProviderType, SocialError, SocialResult};

/// State lifetime in minutes.
const STATE_LIFETIME_MINUTES: i64 = 10;

/// Sanitize `redirect_after` to prevent open redirects at state creation time.
/// Only allows relative paths starting with `/` (rejects `//`, `://`, `\`).
/// Returns `None` for invalid or empty values.
fn sanitize_redirect_after(redirect: &str) -> Option<String> {
    let trimmed = redirect.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Must start with /
    if !trimmed.starts_with('/') {
        return None;
    }
    // Reject protocol-relative URLs (//evil.com) and backslash tricks
    if trimmed.starts_with("//") || trimmed.starts_with("/\\") || trimmed.contains("://") {
        return None;
    }
    Some(trimmed.to_string())
}

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
    /// OIDC nonce sent in the authorization URL, validated against the ID token.
    /// `None` for non-OIDC providers (GitHub) or in-flight tokens from before this field existed.
    #[serde(default)]
    pub oidc_nonce: Option<String>,
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
///
/// # Distributed deployment caveat
///
/// The replay-prevention nonce cache (`used_nonces`) is in-memory.
/// In a multi-instance deployment, the same state token could be
/// replayed against a different instance. Mitigations:
/// - State JWTs have short lifetimes (`STATE_LIFETIME_MINUTES`).
/// - PKCE ties the token exchange to the original verifier.
/// - For stronger guarantees, replace with a shared store (Redis/DB).
#[derive(Clone)]
pub struct OAuthService {
    /// Secret key for signing state JWTs.
    state_secret: Vec<u8>,
    /// Cache of used state nonces to prevent replay attacks.
    /// Entries expire after STATE_LIFETIME_MINUTES to bound memory usage.
    used_nonces: Cache<String, ()>,
}

impl OAuthService {
    /// Create a new OAuth service.
    ///
    /// # Panics
    ///
    /// Panics at startup if `state_secret` is shorter than 32 bytes.
    /// This is intentional — a weak secret allows state token forgery.
    #[must_use]
    pub fn new(state_secret: &str) -> Self {
        assert!(
            state_secret.len() >= 32,
            "SOCIAL_STATE_SECRET must be at least 32 bytes (got {}). A weak secret allows OAuth state forgery.",
            state_secret.len()
        );

        let used_nonces = Cache::builder()
            .max_capacity(100_000)
            .time_to_live(std::time::Duration::from_secs(
                (STATE_LIFETIME_MINUTES * 60) as u64,
            ))
            .build();

        Self {
            state_secret: state_secret.as_bytes().to_vec(),
            used_nonces,
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

    /// Generate an OIDC nonce for providers that support it.
    ///
    /// Returns `Some` for Google, Microsoft, and Apple (OIDC providers),
    /// `None` for GitHub (not OIDC, no ID token).
    #[must_use]
    pub fn generate_oidc_nonce(provider: ProviderType) -> Option<String> {
        match provider {
            ProviderType::Google | ProviderType::Microsoft | ProviderType::Apple => {
                Some(Uuid::new_v4().to_string())
            }
            ProviderType::Github => None,
        }
    }

    /// Create a signed state parameter for an OAuth flow.
    ///
    /// The `redirect_after` value is sanitized before embedding to prevent
    /// open redirects. Invalid values are silently dropped (treated as `None`).
    pub fn create_state(
        &self,
        tenant_id: Uuid,
        provider: ProviderType,
        pkce_verifier: &str,
        redirect_after: Option<String>,
        user_id: Option<Uuid>,
        oidc_nonce: Option<String>,
    ) -> SocialResult<String> {
        let now = Utc::now();
        let exp = now + Duration::minutes(STATE_LIFETIME_MINUTES);

        // Validate redirect_after before embedding in state to prevent open redirects
        let safe_redirect = redirect_after.as_deref().and_then(sanitize_redirect_after);

        let claims = OAuthStateClaims {
            nonce: Uuid::new_v4().to_string(),
            tenant_id,
            provider: provider.to_string(),
            pkce_verifier: pkce_verifier.to_string(),
            redirect_after: safe_redirect,
            user_id,
            oidc_nonce,
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
    ///
    /// Each state token can only be used once (replay protection).
    /// The nonce is tracked in an in-memory cache with TTL matching the state lifetime.
    pub fn validate_state(&self, state: &str) -> SocialResult<OAuthStateClaims> {
        let mut validation = Validation::default();
        // SECURITY: Explicitly pin HS256 to prevent algorithm confusion if defaults change.
        validation.algorithms = vec![Algorithm::HS256];
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

        // SECURITY: Enforce single-use via moka's entry API for atomic check-and-insert.
        // `entry().or_insert()` is atomic within moka — prevents TOCTOU race where
        // two concurrent requests both see "not present" with separate get()+insert().
        let nonce = token_data.claims.nonce.clone();
        let entry = self.used_nonces.entry(nonce).or_insert(());
        if !entry.is_fresh() {
            // Nonce was already present — replay attack
            return Err(SocialError::InvalidState {
                reason: "state token has already been used".to_string(),
            });
        }

        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service() -> OAuthService {
        OAuthService::new("test-secret-key-for-signing-state-min32bytes")
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
        assert!(claims.oidc_nonce.is_none());
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
                None,
            )
            .unwrap();

        let claims = service.validate_state(&state).unwrap();
        assert_eq!(claims.user_id, Some(user_id));
    }

    #[test]
    fn test_state_with_oidc_nonce() {
        let service = test_service();
        let tenant_id = Uuid::new_v4();
        let pkce = OAuthService::generate_pkce();
        let nonce = Uuid::new_v4().to_string();

        let state = service
            .create_state(
                tenant_id,
                ProviderType::Google,
                &pkce.verifier,
                None,
                None,
                Some(nonce.clone()),
            )
            .unwrap();

        let claims = service.validate_state(&state).unwrap();
        assert_eq!(claims.oidc_nonce, Some(nonce));
    }

    #[test]
    fn test_generate_oidc_nonce_oidc_providers() {
        assert!(OAuthService::generate_oidc_nonce(ProviderType::Google).is_some());
        assert!(OAuthService::generate_oidc_nonce(ProviderType::Microsoft).is_some());
        assert!(OAuthService::generate_oidc_nonce(ProviderType::Apple).is_some());
    }

    #[test]
    fn test_generate_oidc_nonce_github_none() {
        assert!(OAuthService::generate_oidc_nonce(ProviderType::Github).is_none());
    }

    #[test]
    fn test_invalid_state_signature() {
        let service = test_service();
        let other_service = OAuthService::new("different-secret-key-at-least-32-bytes-long");
        let tenant_id = Uuid::new_v4();
        let pkce = OAuthService::generate_pkce();

        // Create state with one service
        let state = service
            .create_state(
                tenant_id,
                ProviderType::Apple,
                &pkce.verifier,
                None,
                None,
                None,
            )
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

    #[test]
    fn test_state_single_use_rejects_replay() {
        let service = test_service();
        let tenant_id = Uuid::new_v4();
        let pkce = OAuthService::generate_pkce();

        let state = service
            .create_state(
                tenant_id,
                ProviderType::Google,
                &pkce.verifier,
                None,
                None,
                None,
            )
            .unwrap();

        // First use should succeed
        let result = service.validate_state(&state);
        assert!(result.is_ok());

        // Second use of the same state should fail (replay attack)
        let result = service.validate_state(&state);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("already been used"),
            "Expected 'already been used' error, got: {err}"
        );
    }

    #[test]
    fn test_different_states_are_independent() {
        let service = test_service();
        let tenant_id = Uuid::new_v4();

        let pkce1 = OAuthService::generate_pkce();
        let state1 = service
            .create_state(
                tenant_id,
                ProviderType::Google,
                &pkce1.verifier,
                None,
                None,
                None,
            )
            .unwrap();

        let pkce2 = OAuthService::generate_pkce();
        let state2 = service
            .create_state(
                tenant_id,
                ProviderType::Google,
                &pkce2.verifier,
                None,
                None,
                None,
            )
            .unwrap();

        // Using state1 should not affect state2
        assert!(service.validate_state(&state1).is_ok());
        assert!(service.validate_state(&state2).is_ok());

        // But replaying either should fail
        assert!(service.validate_state(&state1).is_err());
        assert!(service.validate_state(&state2).is_err());
    }
}
