//! Error types for authentication operations.
//!
//! Provides explicit error variants for all authentication failures.

use thiserror::Error;

/// Authentication error types.
///
/// This enum provides explicit error variants for precise error handling.
/// Each variant maps to a specific failure mode in authentication operations.
#[derive(Debug, Clone, Error)]
pub enum AuthError {
    // JWT errors
    /// Token has expired (exp claim is in the past).
    #[error("Token has expired")]
    TokenExpired,

    /// Token signature is invalid.
    #[error("Invalid token signature")]
    InvalidSignature,

    /// Token format is malformed or invalid.
    #[error("Invalid token: {0}")]
    InvalidToken(String),

    /// Token uses an unsupported algorithm (only RS256 is allowed).
    #[error("Unsupported algorithm: only RS256 is allowed")]
    InvalidAlgorithm,

    /// Required claim is missing from token.
    #[error("Missing required claim: {0}")]
    MissingClaim(String),

    // Password errors
    /// Password hashing operation failed.
    #[error("Password hashing failed: {0}")]
    HashingFailed(String),

    /// Password hash format is invalid.
    #[error("Invalid password hash format")]
    InvalidHashFormat,

    /// Password verification failed (internal error, not wrong password).
    #[error("Password verification failed")]
    VerificationFailed,

    // JWKS errors
    /// Failed to fetch JWKS from endpoint.
    #[error("JWKS fetch failed: {0}")]
    JwksFetchFailed(String),

    /// Key with specified kid not found in JWKS.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    // Key errors
    /// RSA key is invalid or malformed.
    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

impl AuthError {
    /// Check if this error indicates an expired token.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        matches!(self, AuthError::TokenExpired)
    }

    /// Check if this error indicates an invalid signature.
    #[must_use]
    pub fn is_invalid_signature(&self) -> bool {
        matches!(self, AuthError::InvalidSignature)
    }

    /// Check if this error is related to JWT validation.
    #[must_use]
    pub fn is_jwt_error(&self) -> bool {
        matches!(
            self,
            AuthError::TokenExpired
                | AuthError::InvalidSignature
                | AuthError::InvalidToken(_)
                | AuthError::InvalidAlgorithm
                | AuthError::MissingClaim(_)
        )
    }

    /// Check if this error is related to password operations.
    #[must_use]
    pub fn is_password_error(&self) -> bool {
        matches!(
            self,
            AuthError::HashingFailed(_)
                | AuthError::InvalidHashFormat
                | AuthError::VerificationFailed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = AuthError::TokenExpired;
        assert_eq!(err.to_string(), "Token has expired");

        let err = AuthError::InvalidSignature;
        assert_eq!(err.to_string(), "Invalid token signature");

        let err = AuthError::InvalidToken("malformed base64".to_string());
        assert_eq!(err.to_string(), "Invalid token: malformed base64");

        let err = AuthError::MissingClaim("sub".to_string());
        assert_eq!(err.to_string(), "Missing required claim: sub");
    }

    #[test]
    fn test_is_expired() {
        assert!(AuthError::TokenExpired.is_expired());
        assert!(!AuthError::InvalidSignature.is_expired());
    }

    #[test]
    fn test_is_invalid_signature() {
        assert!(AuthError::InvalidSignature.is_invalid_signature());
        assert!(!AuthError::TokenExpired.is_invalid_signature());
    }

    #[test]
    fn test_is_jwt_error() {
        assert!(AuthError::TokenExpired.is_jwt_error());
        assert!(AuthError::InvalidSignature.is_jwt_error());
        assert!(AuthError::InvalidToken("test".to_string()).is_jwt_error());
        assert!(AuthError::InvalidAlgorithm.is_jwt_error());
        assert!(AuthError::MissingClaim("sub".to_string()).is_jwt_error());

        assert!(!AuthError::HashingFailed("test".to_string()).is_jwt_error());
        assert!(!AuthError::JwksFetchFailed("test".to_string()).is_jwt_error());
    }

    #[test]
    fn test_is_password_error() {
        assert!(AuthError::HashingFailed("test".to_string()).is_password_error());
        assert!(AuthError::InvalidHashFormat.is_password_error());
        assert!(AuthError::VerificationFailed.is_password_error());

        assert!(!AuthError::TokenExpired.is_password_error());
        assert!(!AuthError::JwksFetchFailed("test".to_string()).is_password_error());
    }
}
