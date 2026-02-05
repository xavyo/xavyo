//! Browser handoff for platform authenticator authentication
//!
//! When hardware keys are not available, this module provides browser-based
//! authentication using platform authenticators (Touch ID, Windows Hello).

use crate::api;
use crate::config::Config;
use crate::error::{CliError, CliResult};
use crate::models::webauthn::{HandoffState, PasskeyChallenge};
use crate::webauthn::PasskeyResult;
use std::time::{Duration, Instant};

/// Default poll interval for browser handoff status
const DEFAULT_POLL_INTERVAL_SECS: u64 = 2;

/// Maximum wait time for browser handoff (5 minutes)
const MAX_HANDOFF_WAIT_SECS: u64 = 300;

/// Authenticate via browser handoff
///
/// This function:
/// 1. Creates a browser handoff session
/// 2. Opens the verification URL in the user's browser
/// 3. Polls for completion
/// 4. Returns the authentication result
///
/// # Arguments
/// * `client` - HTTP client
/// * `config` - CLI configuration
/// * `challenge` - The passkey challenge from the server
/// * `remember_device` - Whether to trust this device for future logins
pub async fn authenticate_via_browser(
    client: &reqwest::Client,
    config: &Config,
    challenge: &PasskeyChallenge,
    _remember_device: bool,
) -> CliResult<PasskeyResult> {
    // Create browser handoff session
    let session =
        api::webauthn::create_browser_handoff(client, config, &challenge.challenge_id).await?;

    // Display URL to user
    println!("\nOpen this URL in your browser to authenticate with passkey:");
    println!("  {}", session.verification_url);

    if let Some(code) = &session.user_code {
        println!("\nVerification code: {}", code);
    }

    // Try to open browser automatically
    if open::that(&session.verification_url).is_ok() {
        println!("\nBrowser opened automatically.");
    }

    println!("\nWaiting for browser authentication...");

    // Poll for completion
    let poll_interval = Duration::from_secs(session.poll_interval.max(DEFAULT_POLL_INTERVAL_SECS));
    let start = Instant::now();
    let max_wait = Duration::from_secs(MAX_HANDOFF_WAIT_SECS);

    loop {
        // Check timeout
        if start.elapsed() > max_wait {
            return Err(CliError::PasskeyTimeout);
        }

        // Wait before polling
        tokio::time::sleep(poll_interval).await;

        // Poll status
        let status =
            api::webauthn::poll_handoff_status(client, config, &session.session_id).await?;

        match status.state {
            HandoffState::Completed => {
                // Authentication succeeded
                if let Some(access_token) = status.access_token {
                    return Ok(PasskeyResult::Success {
                        access_token,
                        refresh_token: status.refresh_token,
                        expires_in: status.expires_in.unwrap_or(3600),
                        device_token: status.device_token,
                    });
                } else {
                    return Err(CliError::PasskeyError(
                        "Authentication completed but no token received".to_string(),
                    ));
                }
            }
            HandoffState::Failed => {
                let error_msg = status
                    .error_description
                    .or(status.error)
                    .unwrap_or_else(|| "Browser authentication failed".to_string());
                return Ok(PasskeyResult::FallbackToTotp(error_msg));
            }
            HandoffState::Expired => {
                return Err(CliError::PasskeyTimeout);
            }
            HandoffState::Pending => {
                // Continue polling
                print!(".");
                use std::io::Write;
                std::io::stdout().flush().ok();
            }
        }
    }
}

/// Display browser handoff instructions without opening browser
#[allow(dead_code)]
pub fn display_handoff_url(url: &str, user_code: Option<&str>) {
    println!("\nOpen this URL in your browser to authenticate:");
    println!("  {}", url);

    if let Some(code) = user_code {
        println!("\nVerification code: {}", code);
    }

    println!("\nAfter authentication, return here to continue.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_poll_interval() {
        assert!(DEFAULT_POLL_INTERVAL_SECS > 0);
    }

    #[test]
    fn test_max_handoff_wait() {
        assert!(MAX_HANDOFF_WAIT_SECS >= 60);
    }
}
