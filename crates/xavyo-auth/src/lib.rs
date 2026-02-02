//! JWT authentication and password hashing library for xavyo.
//!
//! This crate provides:
//! - JWT RS256 encoding and decoding with standard and custom claims
//! - JWKS endpoint fetching for key rotation support
//! - Argon2id password hashing with OWASP-recommended parameters
//!
//! # Example
//!
//! ```rust,ignore
//! use xavyo_auth::{encode_token, decode_token, JwtClaims, hash_password, verify_password};
//! use xavyo_core::TenantId;
//!
//! // Create JWT claims
//! let claims = JwtClaims::builder()
//!     .subject("user-123")
//!     .issuer("xavyo")
//!     .audience(vec!["xavyo-api"])
//!     .tenant_id(TenantId::new())
//!     .roles(vec!["admin"])
//!     .expires_in_secs(3600)
//!     .build();
//!
//! // Encode token
//! let token = encode_token(&claims, private_key_pem)?;
//!
//! // Decode token
//! let decoded = decode_token(&token, public_key_pem)?;
//!
//! // Hash password
//! let hash = hash_password("my-secure-password")?;
//!
//! // Verify password
//! let is_valid = verify_password("my-secure-password", &hash)?;
//! ```

mod claims;
mod error;
mod jwks;
mod jwt;
mod password;

// Re-export public API
pub use claims::{JwtClaims, JwtClaimsBuilder};
pub use error::AuthError;
pub use jwks::{JwkSet, JwksClient};
pub use jwt::{
    decode_token, decode_token_with_config, encode_token, encode_token_with_kid, extract_kid,
    ValidationConfig,
};
pub use password::{hash_password, verify_password, PasswordHasher};
