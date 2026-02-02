//! Cryptographic utilities for MFA.
//!
//! This module provides encryption for sensitive MFA data like TOTP secrets.

mod totp_encryption;

pub use totp_encryption::{TotpEncryption, TotpEncryptionError};
