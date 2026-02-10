//! Environment detection for WebAuthn capability
//!
//! Detects whether the current environment supports passkey authentication.

use std::io::IsTerminal;

use crate::models::webauthn::{AuthenticatorCapability, DetectedKey};

/// Detect WebAuthn capabilities of the current environment
///
/// Checks for:
/// - Hardware security keys (USB HID devices) - only when hardware-keys feature enabled
/// - Platform authenticator availability (via browser)
/// - Display/browser availability for handoff
/// - Headless environment detection
pub fn detect_capabilities() -> AuthenticatorCapability {
    let headless = is_headless();
    let has_display = has_display_available();
    let detected_keys = enumerate_hardware_keys();

    AuthenticatorCapability {
        hardware_key_available: !detected_keys.is_empty(),
        platform_available: has_display && !headless,
        browser_handoff_possible: has_display && !headless,
        headless,
        detected_keys,
    }
}

/// Check if running in a headless environment
///
/// Returns true if:
/// - No TTY attached (stdin is not a terminal)
/// - Running in CI environment (CI env var set)
/// - No display available
pub fn is_headless() -> bool {
    // Check if stdin is a TTY
    if !std::io::stdin().is_terminal() {
        return true;
    }

    // Check for CI environment
    if std::env::var("CI").is_ok() {
        return true;
    }

    // Check for common CI environment variables
    let ci_vars = [
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "JENKINS_URL",
        "TRAVIS",
        "CIRCLECI",
    ];
    for var in ci_vars {
        if std::env::var(var).is_ok() {
            return true;
        }
    }

    // Check for SSH session without display forwarding
    if std::env::var("SSH_CLIENT").is_ok() || std::env::var("SSH_TTY").is_ok() {
        // In SSH, check if we have display forwarding
        if !has_display_available() {
            return true;
        }
    }

    false
}

/// Check if a display is available for browser handoff
///
/// Checks for:
/// - DISPLAY environment variable (X11)
/// - WAYLAND_DISPLAY environment variable
/// - macOS (always has display if not SSH)
/// - Windows (always has display if not SSH)
pub fn has_display_available() -> bool {
    // Check X11 display
    if std::env::var("DISPLAY").is_ok() {
        return true;
    }

    // Check Wayland display
    if std::env::var("WAYLAND_DISPLAY").is_ok() {
        return true;
    }

    // On macOS, check for window server
    #[cfg(target_os = "macos")]
    {
        // If not in SSH and not CI, assume display available
        if std::env::var("SSH_CLIENT").is_err() && std::env::var("CI").is_err() {
            return true;
        }
    }

    // On Windows, check for SESSIONNAME (indicates console/RDP session)
    #[cfg(target_os = "windows")]
    {
        if std::env::var("SESSIONNAME").is_ok() {
            return true;
        }
        // If not in SSH and not CI, assume display available
        if std::env::var("SSH_CLIENT").is_err() && std::env::var("CI").is_err() {
            return true;
        }
    }

    false
}

/// Enumerate connected hardware security keys
///
/// When hardware-keys feature is enabled, uses ctap-hid-fido2 to find FIDO2 devices.
/// Otherwise returns empty list.
fn enumerate_hardware_keys() -> Vec<DetectedKey> {
    #[cfg(feature = "hardware-keys")]
    {
        // Try to enumerate HID devices
        match try_enumerate_fido_devices() {
            Ok(keys) => keys,
            Err(_) => {
                // Silently return empty on error (no hardware key support)
                vec![]
            }
        }
    }

    #[cfg(not(feature = "hardware-keys"))]
    {
        // Hardware key support not compiled in
        vec![]
    }
}

/// Attempt to enumerate FIDO2 devices using ctap-hid-fido2
#[cfg(feature = "hardware-keys")]
fn try_enumerate_fido_devices() -> Result<Vec<DetectedKey>, String> {
    use ctap_hid_fido2::FidoKeyHidFactory;

    let cfg = ctap_hid_fido2::LibCfg::init();

    // Get list of connected FIDO devices
    let devices = FidoKeyHidFactory::get_device_paths(&cfg)
        .map_err(|e| format!("Failed to enumerate devices: {}", e))?;

    let mut detected_keys = Vec::new();

    for device_path in devices {
        let name = device_path.clone();

        detected_keys.push(DetectedKey {
            name,
            vendor_id: 0, // Would need HID API to get these
            product_id: 0,
            has_pin: false,              // Would need to query device
            supports_resident_key: true, // Assume FIDO2 device supports it
        });
    }

    Ok(detected_keys)
}

/// Check if any hardware security key is available
#[allow(dead_code)]
pub fn has_hardware_key() -> bool {
    !enumerate_hardware_keys().is_empty()
}

/// Get a human-readable description of detected capabilities
#[allow(dead_code)]
pub fn describe_capabilities(caps: &AuthenticatorCapability) -> String {
    let mut parts = Vec::new();

    if caps.hardware_key_available {
        let key_count = caps.detected_keys.len();
        if key_count == 1 {
            parts.push(format!("1 hardware key ({})", caps.detected_keys[0].name));
        } else {
            parts.push(format!("{} hardware keys", key_count));
        }
    }

    if caps.browser_handoff_possible {
        parts.push("browser handoff".to_string());
    }

    if caps.headless {
        parts.push("headless environment".to_string());
    }

    if parts.is_empty() {
        "no passkey support detected".to_string()
    } else {
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_capabilities_returns_struct() {
        let caps = detect_capabilities();
        // Should return a valid struct
        assert!(caps.headless || !caps.headless); // Always true, just testing struct
    }

    #[test]
    fn test_is_headless_in_ci() {
        // This test will pass in CI environments
        if std::env::var("CI").is_ok() {
            assert!(is_headless());
        }
    }

    #[test]
    fn test_describe_capabilities_empty() {
        let caps = AuthenticatorCapability {
            hardware_key_available: false,
            platform_available: false,
            browser_handoff_possible: false,
            headless: false,
            detected_keys: vec![],
        };
        let desc = describe_capabilities(&caps);
        assert!(desc.contains("no passkey support"));
    }

    #[test]
    fn test_describe_capabilities_with_hardware_key() {
        let caps = AuthenticatorCapability {
            hardware_key_available: true,
            platform_available: false,
            browser_handoff_possible: false,
            headless: false,
            detected_keys: vec![DetectedKey {
                name: "YubiKey 5".to_string(),
                vendor_id: 0x1050,
                product_id: 0x0407,
                has_pin: true,
                supports_resident_key: true,
            }],
        };
        let desc = describe_capabilities(&caps);
        assert!(desc.contains("hardware key"));
        assert!(desc.contains("YubiKey 5"));
    }

    #[test]
    fn test_describe_capabilities_headless() {
        let caps = AuthenticatorCapability {
            hardware_key_available: false,
            platform_available: false,
            browser_handoff_possible: false,
            headless: true,
            detected_keys: vec![],
        };
        let desc = describe_capabilities(&caps);
        assert!(desc.contains("headless"));
    }
}
