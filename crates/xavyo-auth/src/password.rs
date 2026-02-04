//! Password hashing with Argon2id.
//!
//! Provides secure password hashing and verification using Argon2id
//! with OWASP-recommended parameters.

use crate::error::AuthError;
use argon2::{
    password_hash::{
        rand_core::OsRng, PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString,
    },
    Algorithm, Argon2, Params, Version,
};

/// Password hasher configuration.
///
/// Uses OWASP 2024 recommended parameters for Argon2id:
/// - Memory: 19456 KiB (19 MiB)
/// - Iterations: 2
/// - Parallelism: 1
#[derive(Debug, Clone)]
pub struct PasswordHasher {
    params: Params,
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordHasher {
    /// Create a new password hasher with OWASP-recommended parameters.
    ///
    /// Parameters:
    /// - Memory: 19456 KiB (~19 MiB)
    /// - Iterations: 2
    /// - Parallelism: 1
    #[must_use]
    pub fn new() -> Self {
        // OWASP 2024 recommended parameters
        // m=19456 (19 MiB), t=2, p=1
        // These are hardcoded constants that are always valid - the expect() is acceptable
        // since failure indicates a bug in the Argon2 library, not a runtime condition.
        let params = Params::new(
            19456, // m_cost: memory in KiB
            2,     // t_cost: iterations
            1,     // p_cost: parallelism
            None,  // output_len: default (32 bytes)
        )
        .expect("OWASP 2024 Argon2 parameters are valid constants");

        Self { params }
    }

    /// Create a password hasher with custom parameters.
    ///
    /// # Arguments
    ///
    /// * `memory_kib` - Memory cost in KiB
    /// * `iterations` - Number of iterations
    /// * `parallelism` - Degree of parallelism
    ///
    /// # Errors
    ///
    /// Returns error if parameters are invalid.
    pub fn with_params(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<Self, AuthError> {
        let params = Params::new(memory_kib, iterations, parallelism, None)
            .map_err(|e| AuthError::HashingFailed(format!("Invalid parameters: {e}")))?;

        Ok(Self { params })
    }

    /// Hash a password using Argon2id.
    ///
    /// # Arguments
    ///
    /// * `password` - The plaintext password to hash
    ///
    /// # Returns
    ///
    /// A PHC-formatted hash string.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::HashingFailed` if hashing fails.
    pub fn hash(&self, password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone());

        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::HashingFailed(format!("Hashing failed: {e}")))?;

        Ok(hash.to_string())
    }

    /// Verify a password against a hash.
    ///
    /// # Arguments
    ///
    /// * `password` - The plaintext password to verify
    /// * `hash` - The PHC-formatted hash to verify against
    ///
    /// # Returns
    ///
    /// `Ok(true)` if password matches, `Ok(false)` if not.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::InvalidHashFormat` if the hash format is invalid.
    pub fn verify(&self, password: &str, hash: &str) -> Result<bool, AuthError> {
        let parsed_hash = PasswordHash::new(hash).map_err(|_| AuthError::InvalidHashFormat)?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone());

        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(_) => Ok(false), // Other errors also treated as non-match
        }
    }
}

/// Hash a password using Argon2id with OWASP-recommended parameters.
///
/// This is a convenience function using the default `PasswordHasher`.
///
/// # Arguments
///
/// * `password` - The plaintext password to hash
///
/// # Returns
///
/// A PHC-formatted hash string.
///
/// # Example
///
/// ```rust
/// use xavyo_auth::hash_password;
///
/// let hash = hash_password("my-secure-password").unwrap();
/// assert!(hash.starts_with("$argon2id$"));
/// ```
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    PasswordHasher::new().hash(password)
}

/// Verify a password against an Argon2id hash.
///
/// This is a convenience function using the default `PasswordHasher`.
///
/// # Arguments
///
/// * `password` - The plaintext password to verify
/// * `hash` - The PHC-formatted hash to verify against
///
/// # Returns
///
/// `Ok(true)` if password matches, `Ok(false)` if not.
///
/// # Example
///
/// ```rust
/// use xavyo_auth::{hash_password, verify_password};
///
/// let hash = hash_password("my-password").unwrap();
/// assert!(verify_password("my-password", &hash).unwrap());
/// assert!(!verify_password("wrong-password", &hash).unwrap());
/// ```
pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthError> {
    PasswordHasher::new().verify(password, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_password_returns_argon2id() {
        let hash = hash_password("test-password").unwrap();

        // Hash should be in PHC format starting with $argon2id$
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn test_verify_password_correct() {
        let password = "correct-password";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash).unwrap());
    }

    #[test]
    fn test_verify_password_incorrect() {
        let hash = hash_password("correct-password").unwrap();

        assert!(!verify_password("wrong-password", &hash).unwrap());
    }

    #[test]
    fn test_verify_password_invalid_hash_format() {
        let result = verify_password("password", "not-a-valid-hash");

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::InvalidHashFormat));
    }

    #[test]
    fn test_hash_is_unique() {
        let password = "same-password";
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();

        // Same password should produce different hashes (different salts)
        assert_ne!(hash1, hash2);

        // But both should verify correctly
        assert!(verify_password(password, &hash1).unwrap());
        assert!(verify_password(password, &hash2).unwrap());
    }

    #[test]
    fn test_password_hasher_custom_params() {
        // Use smaller params for faster testing
        let hasher = PasswordHasher::with_params(4096, 1, 1).unwrap();

        let hash = hasher.hash("test-password").unwrap();
        assert!(hasher.verify("test-password", &hash).unwrap());
    }

    #[test]
    fn test_empty_password() {
        let hash = hash_password("").unwrap();
        assert!(verify_password("", &hash).unwrap());
        assert!(!verify_password("non-empty", &hash).unwrap());
    }

    #[test]
    fn test_unicode_password() {
        let password = "пароль日本語🔐";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong", &hash).unwrap());
    }

    #[test]
    fn test_long_password() {
        let password = "a".repeat(1000);
        let hash = hash_password(&password).unwrap();

        assert!(verify_password(&password, &hash).unwrap());
    }

    #[test]
    fn test_hash_format_contains_params() {
        let hash = hash_password("test").unwrap();

        // PHC format includes algorithm and parameters
        // Example: $argon2id$v=19$m=19456,t=2,p=1$...
        assert!(hash.contains("v=19")); // Version
        assert!(hash.contains("m=19456")); // Memory
        assert!(hash.contains("t=2")); // Iterations
        assert!(hash.contains("p=1")); // Parallelism
    }
}
