//! CLI error types and exit codes

use thiserror::Error;

/// Exit codes for the CLI
/// - 0: Success
/// - 1: General error
/// - 2: Authentication required
/// - 3: Network error
/// - 4: Validation error
/// - 5: Server error
pub type CliResult<T> = Result<T, CliError>;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("Not logged in. Run 'xavyo login' first.")]
    NotAuthenticated,

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Token expired. Please run 'xavyo login' again.")]
    TokenExpired,

    #[error("Network error: {0}")]
    Network(String),

    #[error("Connection failed: {0}\n\nTroubleshooting:\n  - Check your internet connection\n  - Verify the API endpoint is correct\n  - Try again in a few moments")]
    ConnectionFailed(String),

    #[error("Invalid input: {0}")]
    Validation(String),

    #[error("Server error: {0}")]
    Server(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Credential storage error: {0}")]
    CredentialStorage(String),

    #[error("Device code expired. Please run 'xavyo login' again.")]
    DeviceCodeExpired,

    #[error("Authentication was denied.")]
    AuthorizationDenied,

    #[error("Tenant already exists with slug: {0}")]
    TenantExists(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("API error (status {status}): {message}")]
    Api { status: u16, message: String },

    #[error("I/O error: {0}")]
    Io(String),

    #[error("Checksum verification failed: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("Permission denied: {0}\n\nOptions:\n  - Run with sudo: sudo xavyo upgrade\n  - Install to user directory: Move binary to ~/.local/bin/")]
    PermissionDenied(String),

    #[error("Unsupported platform: {os}-{arch}")]
    UnsupportedPlatform { os: String, arch: String },

    #[error("No release asset found for platform: {0}")]
    NoAssetFound(String),

    #[error("Invalid version format: {0}")]
    InvalidVersion(String),

    #[error("Upgrade aborted by user")]
    UpgradeAborted,

    #[error("Input error: {0}")]
    InputError(String),

    // MFA-specific errors
    #[error("MFA verification required")]
    MfaRequired,

    #[error("Invalid MFA code. Please check your authenticator app and try again.")]
    MfaInvalidCode,

    #[error("MFA session timed out. Please run 'xavyo login' again.")]
    MfaTimeout,

    #[error("Too many incorrect MFA codes. Please wait and try again.")]
    MfaRetriesExceeded,

    #[error("MFA is not configured for this account.\n\nTo set up MFA, visit your account settings in the web interface.")]
    MfaNotConfigured,

    #[error("MFA verification failed: {0}\n\nIf this persists, check that your device's clock is synchronized.")]
    MfaClockSkew(String),

    #[allow(dead_code)]
    #[error("MFA verification cancelled")]
    MfaCancelled,

    // WebAuthn/Passkey errors
    #[allow(dead_code)]
    #[error("Passkey authentication timed out. Please try again.")]
    PasskeyTimeout,

    #[allow(dead_code)]
    #[error("No passkeys configured for this account.\n\nTo set up passkeys, visit your account settings in the web interface.")]
    PasskeyNotConfigured,

    #[allow(dead_code)]
    #[error("Passkey authentication was cancelled.")]
    PasskeyCancelled,

    #[allow(dead_code)]
    #[error("Hardware security key error: {0}")]
    PasskeyHardwareError(String),

    #[allow(dead_code)]
    #[error("Passkey authentication failed: {0}")]
    PasskeyError(String),

    // Cache/Offline mode errors
    #[error("Cache error: {0}")]
    Cache(String),

    #[error(
        "No cached data available for {0}.\nRun this command while online to populate the cache."
    )]
    NoCacheAvailable(String),

    #[error("Cannot {0} while offline.\nWrite operations require network connectivity.")]
    OfflineWriteRejected(String),

    #[allow(dead_code)]
    #[error("Offline mode: {0}")]
    OfflineMode(String),
}

impl CliError {
    /// Get the exit code for this error
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::NotAuthenticated | CliError::TokenExpired => 2,
            CliError::Network(_) | CliError::ConnectionFailed(_) => 3,
            CliError::Validation(_) => 4,
            CliError::Server(_) => 5,
            CliError::AuthenticationFailed(_)
            | CliError::DeviceCodeExpired
            | CliError::AuthorizationDenied
            | CliError::MfaRequired
            | CliError::MfaInvalidCode
            | CliError::MfaTimeout
            | CliError::MfaRetriesExceeded
            | CliError::MfaNotConfigured
            | CliError::MfaClockSkew(_)
            | CliError::MfaCancelled
            | CliError::PasskeyTimeout
            | CliError::PasskeyNotConfigured
            | CliError::PasskeyCancelled
            | CliError::PasskeyHardwareError(_)
            | CliError::PasskeyError(_) => 2,
            CliError::TenantExists(_) | CliError::Conflict(_) => 4,
            CliError::NotFound(_) => 4,
            CliError::Api { status, .. } => {
                if *status >= 500 {
                    5
                } else if *status == 401 || *status == 403 {
                    2
                } else {
                    4
                }
            }
            CliError::Io(_) => 1,
            CliError::Config(_) => 1,
            CliError::Cache(_) => 1,
            CliError::NoCacheAvailable(_) => 1,
            CliError::OfflineWriteRejected(_) => 1,
            CliError::OfflineMode(_) => 1,
            CliError::CredentialStorage(_) => 1,
            CliError::ChecksumMismatch { .. } => 1,
            CliError::PermissionDenied(_) => 1,
            CliError::UnsupportedPlatform { .. } => 4,
            CliError::NoAssetFound(_) => 4,
            CliError::InvalidVersion(_) => 4,
            CliError::UpgradeAborted => 0, // User chose to abort, not an error
            CliError::InputError(_) => 1,
        }
    }

    /// Print the error to stderr with appropriate formatting
    pub fn print(&self) {
        let use_color = std::env::var("NO_COLOR").is_err();

        if use_color {
            eprintln!("\x1b[31mError:\x1b[0m {}", self);
        } else {
            eprintln!("Error: {}", self);
        }

        // Print suggested action if available
        if let Some(suggestion) = self.suggestion() {
            if use_color {
                eprintln!("\n\x1b[33mSuggestion:\x1b[0m {}", suggestion);
            } else {
                eprintln!("\nSuggestion: {}", suggestion);
            }
        }
    }

    /// Get a suggested action for this error
    fn suggestion(&self) -> Option<&'static str> {
        match self {
            CliError::NotAuthenticated => Some("Run 'xavyo login' to authenticate."),
            CliError::TokenExpired => Some("Run 'xavyo login' to re-authenticate."),
            CliError::DeviceCodeExpired => {
                Some("Run 'xavyo login' to start a new authentication flow.")
            }
            CliError::ConnectionFailed(_) => Some("Check your network connection and try again."),
            CliError::AuthorizationDenied => {
                Some("Make sure you complete the authentication in the browser.")
            }
            _ => None,
        }
    }
}

impl From<reqwest::Error> for CliError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_connect() {
            CliError::ConnectionFailed(e.to_string())
        } else if e.is_timeout() {
            CliError::Network("Request timed out".to_string())
        } else {
            CliError::Network(e.to_string())
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Config(format!("I/O error: {}", e))
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        CliError::Config(format!("JSON error: {}", e))
    }
}

impl From<keyring::Error> for CliError {
    fn from(e: keyring::Error) -> Self {
        CliError::CredentialStorage(e.to_string())
    }
}

impl From<serde_yaml::Error> for CliError {
    fn from(e: serde_yaml::Error) -> Self {
        CliError::Config(format!("YAML error: {}", e))
    }
}

impl From<dialoguer::Error> for CliError {
    fn from(e: dialoguer::Error) -> Self {
        CliError::InputError(format!("Dialog error: {}", e))
    }
}

impl From<rustyline::error::ReadlineError> for CliError {
    fn from(e: rustyline::error::ReadlineError) -> Self {
        CliError::InputError(format!("Readline error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_code_not_authenticated() {
        assert_eq!(CliError::NotAuthenticated.exit_code(), 2);
    }

    #[test]
    fn test_exit_code_token_expired() {
        assert_eq!(CliError::TokenExpired.exit_code(), 2);
    }

    #[test]
    fn test_exit_code_network_error() {
        assert_eq!(CliError::Network("test".to_string()).exit_code(), 3);
    }

    #[test]
    fn test_exit_code_connection_failed() {
        assert_eq!(
            CliError::ConnectionFailed("test".to_string()).exit_code(),
            3
        );
    }

    #[test]
    fn test_exit_code_validation_error() {
        assert_eq!(CliError::Validation("test".to_string()).exit_code(), 4);
    }

    #[test]
    fn test_exit_code_server_error() {
        assert_eq!(CliError::Server("test".to_string()).exit_code(), 5);
    }

    #[test]
    fn test_exit_code_api_error_5xx() {
        assert_eq!(
            CliError::Api {
                status: 500,
                message: "test".to_string()
            }
            .exit_code(),
            5
        );
    }

    #[test]
    fn test_exit_code_api_error_401() {
        assert_eq!(
            CliError::Api {
                status: 401,
                message: "test".to_string()
            }
            .exit_code(),
            2
        );
    }

    #[test]
    fn test_exit_code_upgrade_aborted() {
        assert_eq!(CliError::UpgradeAborted.exit_code(), 0);
    }

    #[test]
    fn test_error_display_not_authenticated() {
        let error = CliError::NotAuthenticated;
        assert!(error.to_string().contains("Not logged in"));
    }
}
