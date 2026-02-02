//! Middleware for AI Agent Security (F127).
//!
//! This module provides Tower middleware for:
//! - **mTLS Validation**: Validate agent certificates for mTLS authentication
//! - **Certificate Identity Extraction**: Extract agent identity from certificates

pub mod mtls;

pub use mtls::{MtlsConfig, MtlsError, MtlsIdentity, MtlsLayer, MtlsMiddleware};
