//! WebAuthn/Passkey authentication module for xavyo-cli
//!
//! This module provides passkey authentication support including:
//! - Hardware security key (YubiKey) authentication via CTAP2
//! - Browser handoff for platform authenticators (Touch ID, Windows Hello)
//! - Environment detection for headless/interactive modes
//! - Fallback to TOTP when passkey is unavailable

pub mod detection;
pub mod handoff;
pub mod hardware;

use crate::api;
use crate::config::Config;
use crate::error::CliResult;
use crate::models::webauthn::{PasskeyChallenge, PasskeyVerifyRequest};

/// Result of passkey authentication attempt
#[derive(Debug)]
#[allow(dead_code)]
pub enum PasskeyResult {
    /// Authentication succeeded with tokens
    Success {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: u64,
        device_token: Option<String>,
    },
    /// Passkey not available, should fall back to TOTP
    FallbackToTotp(String),
    /// User cancelled the operation
    Cancelled,
}

/// Handle a passkey MFA challenge
///
/// This function orchestrates the passkey authentication flow:
/// 1. Detect environment capabilities
/// 2. If hardware key available, attempt direct CTAP2 authentication
/// 3. If no hardware key but browser available, attempt browser handoff
/// 4. Return FallbackToTotp if passkey not possible
#[allow(dead_code)]
pub async fn handle_passkey_challenge(
    client: &reqwest::Client,
    config: &Config,
    challenge: &PasskeyChallenge,
    remember_device: bool,
) -> CliResult<PasskeyResult> {
    // Detect environment capabilities
    let capabilities = detection::detect_capabilities();

    // If headless, immediately fall back to TOTP
    if capabilities.headless {
        return Ok(PasskeyResult::FallbackToTotp(
            "Headless environment detected - passkey unavailable".to_string(),
        ));
    }

    // Try hardware key first if available
    if capabilities.hardware_key_available {
        match authenticate_with_hardware(client, config, challenge, remember_device).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                // Log error but continue to try other methods
                eprintln!("Hardware key authentication failed: {}", e);
            }
        }
    }

    // Try browser handoff if display available
    if capabilities.browser_handoff_possible {
        match handoff::authenticate_via_browser(client, config, challenge, remember_device).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                // Log error but continue to fallback
                eprintln!("Browser handoff failed: {}", e);
            }
        }
    }

    // Fall back to TOTP
    Ok(PasskeyResult::FallbackToTotp(
        "No passkey authentication method available".to_string(),
    ))
}

/// Authenticate using hardware security key
async fn authenticate_with_hardware(
    client: &reqwest::Client,
    config: &Config,
    challenge: &PasskeyChallenge,
    remember_device: bool,
) -> CliResult<PasskeyResult> {
    // Attempt hardware key authentication
    let assertion = hardware::authenticate_with_hardware_key(challenge)?;

    // Submit assertion to server
    let request = PasskeyVerifyRequest {
        challenge_id: challenge.challenge_id.clone(),
        credential_id: assertion.credential_id.clone(),
        authenticator_data: assertion.authenticator_data.clone(),
        client_data_json: assertion.client_data_json.clone(),
        signature: assertion.signature.clone(),
        user_handle: assertion.user_handle.clone(),
        remember_device,
    };

    let response = api::webauthn::verify_passkey(client, config, &request).await?;

    Ok(PasskeyResult::Success {
        access_token: response.access_token,
        refresh_token: response.refresh_token,
        expires_in: response.expires_in,
        device_token: response.device_token,
    })
}

/// Check if passkey authentication should be attempted
///
/// Returns false if:
/// - Environment is headless
/// - No hardware key and no browser available
/// - User explicitly requested TOTP
#[allow(dead_code)]
pub fn should_attempt_passkey(force_totp: bool) -> bool {
    if force_totp {
        return false;
    }

    let capabilities = detection::detect_capabilities();

    // Don't attempt if headless
    if capabilities.headless {
        return false;
    }

    // Need either hardware key or browser handoff capability
    capabilities.hardware_key_available || capabilities.browser_handoff_possible
}

/// Determine the reason passkey was skipped (for user messaging)
#[allow(dead_code)]
pub fn passkey_skip_reason(force_totp: bool) -> Option<String> {
    if force_totp {
        return Some("TOTP mode requested".to_string());
    }

    let capabilities = detection::detect_capabilities();

    if capabilities.headless {
        return Some("Headless environment detected".to_string());
    }

    if !capabilities.hardware_key_available && !capabilities.browser_handoff_possible {
        return Some("No passkey authentication method available".to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_attempt_passkey_force_totp() {
        assert!(!should_attempt_passkey(true));
    }

    #[test]
    fn test_passkey_skip_reason_force_totp() {
        let reason = passkey_skip_reason(true);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("TOTP"));
    }
}
