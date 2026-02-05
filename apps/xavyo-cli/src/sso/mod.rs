//! SSO/SAML Authentication module for xavyo-cli
//!
//! This module provides SSO authentication support including:
//! - Browser-based SSO flow with IdP redirection
//! - IdP discovery based on email domain
//! - Manual IdP URL/entity ID specification
//! - SAML assertion handling via backend delegation
//!
//! The SSO flow follows the same browser handoff pattern as WebAuthn:
//! 1. CLI initiates SSO session with backend
//! 2. Backend creates session and provides verification URL
//! 3. CLI opens browser to IdP login page
//! 4. CLI polls for completion
//! 5. Backend handles SAML assertion and returns OAuth tokens

pub mod config;
pub mod flow;
pub mod session;

pub use config::{SSOConfig, SSOConfigError};
pub use flow::{display_sso_url, SSOResult, DEFAULT_POLL_INTERVAL_SECS};
pub use session::{IdPInfo, SSOProtocol, SSOSession, SSOSessionStatus, SSOState};
