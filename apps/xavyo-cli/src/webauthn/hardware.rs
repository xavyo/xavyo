//! Hardware security key authentication via CTAP2
//!
//! Provides direct authentication with hardware keys like YubiKey.
//! Requires the `hardware-keys` feature to be enabled.

use crate::error::{CliError, CliResult};
use crate::models::webauthn::{PasskeyAssertion, PasskeyChallenge};

#[cfg(feature = "hardware-keys")]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

#[cfg(feature = "hardware-keys")]
use ctap_hid_fido2::{get_assertion::GetAssertionArgsBuilder, FidoKeyHidFactory};

/// Authenticate using a hardware security key
///
/// This function:
/// 1. Connects to the first available FIDO2 device
/// 2. Sends the challenge to the device
/// 3. Waits for user to touch/verify
/// 4. Returns the assertion for server verification
///
/// # Arguments
/// * `challenge` - The passkey challenge from the server
///
/// # Returns
/// * `Ok(PasskeyAssertion)` - The signed assertion
/// * `Err(CliError)` - If authentication fails
#[cfg(feature = "hardware-keys")]
pub fn authenticate_with_hardware_key(challenge: &PasskeyChallenge) -> CliResult<PasskeyAssertion> {
    println!("Touch your security key to authenticate...");

    // Initialize CTAP library
    let cfg = ctap_hid_fido2::LibCfg::init();

    // Connect to first available device
    let device = FidoKeyHidFactory::create(&cfg).map_err(|e| {
        CliError::PasskeyHardwareError(format!("Failed to connect to security key: {}", e))
    })?;

    // Decode challenge from base64url
    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(&challenge.challenge)
        .map_err(|e| CliError::PasskeyError(format!("Invalid challenge encoding: {}", e)))?;

    // Get credential IDs from allowed credentials
    let credential_ids: Vec<Vec<u8>> = challenge
        .allowed_credentials
        .iter()
        .filter_map(|cred| URL_SAFE_NO_PAD.decode(&cred.id).ok())
        .collect();

    // Build GetAssertion arguments
    let mut args_builder = GetAssertionArgsBuilder::new(&challenge.rp_id, &challenge_bytes);

    // Add allowed credentials if provided
    if !credential_ids.is_empty() {
        for cred_id in &credential_ids {
            args_builder = args_builder.add_credential_id(cred_id);
        }
    }

    let args = args_builder.build();

    // Request assertion from device (user must touch)
    let assertions = device
        .get_assertion_with_args(&args)
        .map_err(|e| classify_hardware_error(e))?;

    // Should get at least one assertion
    if assertions.is_empty() {
        return Err(CliError::PasskeyError(
            "No assertion returned from device".to_string(),
        ));
    }

    let assertion = &assertions[0];

    // Build client data JSON (what the browser would normally create)
    let client_data = serde_json::json!({
        "type": "webauthn.get",
        "challenge": challenge.challenge,
        "origin": format!("https://{}", challenge.rp_id),
        "crossOrigin": false
    });
    let client_data_json = serde_json::to_string(&client_data)
        .map_err(|e| CliError::PasskeyError(format!("Failed to create client data: {}", e)))?;

    // Convert assertion to our format
    Ok(PasskeyAssertion {
        credential_id: URL_SAFE_NO_PAD.encode(&assertion.credential_id),
        authenticator_data: URL_SAFE_NO_PAD.encode(&assertion.authenticator_data),
        client_data_json,
        signature: URL_SAFE_NO_PAD.encode(&assertion.signature),
        user_handle: assertion
            .user
            .as_ref()
            .map(|u| URL_SAFE_NO_PAD.encode(&u.id)),
    })
}

/// Stub implementation when hardware-keys feature is not enabled
#[cfg(not(feature = "hardware-keys"))]
pub fn authenticate_with_hardware_key(
    _challenge: &PasskeyChallenge,
) -> CliResult<PasskeyAssertion> {
    Err(CliError::PasskeyHardwareError(
        "Hardware key support not compiled in. Rebuild with --features hardware-keys".to_string(),
    ))
}

/// Classify hardware errors into appropriate CLI errors
#[cfg(feature = "hardware-keys")]
fn classify_hardware_error(e: impl std::fmt::Display) -> CliError {
    let error_string = e.to_string().to_lowercase();

    if error_string.contains("timeout") || error_string.contains("timed out") {
        CliError::PasskeyTimeout
    } else if error_string.contains("cancel") || error_string.contains("denied") {
        CliError::PasskeyCancelled
    } else if error_string.contains("not found") || error_string.contains("no device") {
        CliError::PasskeyHardwareError(
            "No security key found. Please connect your key and try again.".to_string(),
        )
    } else if error_string.contains("pin") {
        CliError::PasskeyHardwareError(
            "PIN required. Please enter your security key PIN.".to_string(),
        )
    } else {
        CliError::PasskeyHardwareError(format!("Security key error: {}", e))
    }
}

/// Check if a hardware key is available
#[allow(dead_code)]
pub fn is_hardware_key_available() -> bool {
    #[cfg(feature = "hardware-keys")]
    {
        let cfg = ctap_hid_fido2::LibCfg::init();
        FidoKeyHidFactory::get_device_paths(&cfg)
            .map(|paths| !paths.is_empty())
            .unwrap_or(false)
    }

    #[cfg(not(feature = "hardware-keys"))]
    {
        false
    }
}

/// Get the name of the first available hardware key
#[allow(dead_code)]
pub fn get_hardware_key_name() -> Option<String> {
    #[cfg(feature = "hardware-keys")]
    {
        let cfg = ctap_hid_fido2::LibCfg::init();
        FidoKeyHidFactory::get_device_paths(&cfg)
            .ok()
            .and_then(|paths| paths.into_iter().next())
    }

    #[cfg(not(feature = "hardware-keys"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::webauthn::{AllowedCredential, UserVerification};

    #[cfg(feature = "hardware-keys")]
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    fn create_test_challenge() -> PasskeyChallenge {
        #[cfg(feature = "hardware-keys")]
        let challenge = URL_SAFE_NO_PAD.encode(b"test-challenge-bytes");

        #[cfg(not(feature = "hardware-keys"))]
        let challenge = "dGVzdC1jaGFsbGVuZ2UtYnl0ZXM".to_string(); // base64url of "test-challenge-bytes"

        PasskeyChallenge {
            challenge_id: "test-challenge-123".to_string(),
            challenge,
            rp_id: "xavyo.io".to_string(),
            allowed_credentials: vec![AllowedCredential {
                id: "Y3JlZGVudGlhbC1pZC0xMjM".to_string(), // base64url of "credential-id-123"
                type_: "public-key".to_string(),
                transports: Some(vec!["usb".to_string()]),
            }],
            user_verification: UserVerification::Preferred,
            timeout: 60000,
        }
    }

    #[test]
    #[cfg(feature = "hardware-keys")]
    fn test_classify_hardware_error_timeout() {
        let error = classify_hardware_error("Operation timed out");
        assert!(matches!(error, CliError::PasskeyTimeout));
    }

    #[test]
    #[cfg(feature = "hardware-keys")]
    fn test_classify_hardware_error_cancelled() {
        let error = classify_hardware_error("User cancelled the operation");
        assert!(matches!(error, CliError::PasskeyCancelled));
    }

    #[test]
    #[cfg(feature = "hardware-keys")]
    fn test_classify_hardware_error_no_device() {
        let error = classify_hardware_error("No device found");
        assert!(matches!(error, CliError::PasskeyHardwareError(_)));
    }

    #[test]
    #[cfg(feature = "hardware-keys")]
    fn test_classify_hardware_error_generic() {
        let error = classify_hardware_error("Unknown error");
        assert!(matches!(error, CliError::PasskeyHardwareError(_)));
    }

    #[test]
    #[ignore] // Requires physical hardware key
    fn test_authenticate_with_hardware_key() {
        let challenge = create_test_challenge();
        // This test would require a physical YubiKey
        let _result = authenticate_with_hardware_key(&challenge);
    }

    #[test]
    fn test_is_hardware_key_available() {
        // Just test that the function runs without panic
        let _available = is_hardware_key_available();
    }

    #[test]
    fn test_get_hardware_key_name() {
        // Just test that the function runs without panic
        let _name = get_hardware_key_name();
    }
}
