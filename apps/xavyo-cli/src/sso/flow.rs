//! SSO Authentication flow
//!
//! Browser-based SSO authentication following the handoff pattern.
//! This module coordinates the SSO flow:
//! 1. IdP discovery (if needed)
//! 2. Session creation
//! 3. Browser handoff
//! 4. Polling for completion
//!
//! Note: The actual API calls are made through the api::sso module in
//! the main binary. This module is exposed through lib.rs for testing
//! and provides the flow coordination types.

/// Default poll interval for SSO status
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 2;

/// SSO authentication result
#[derive(Debug)]
pub enum SSOResult {
    /// Authentication succeeded with tokens
    Success {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: u64,
        device_token: Option<String>,
    },
    /// SSO authentication cancelled
    Cancelled,
}

/// Display SSO URL for manual browser navigation
pub fn display_sso_url(url: &str) {
    println!("\nPlease open this URL in your browser:");
    println!("  {}", url);
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
    fn test_sso_result_success() {
        let result = SSOResult::Success {
            access_token: "token".to_string(),
            refresh_token: Some("refresh".to_string()),
            expires_in: 3600,
            device_token: None,
        };
        matches!(result, SSOResult::Success { .. });
    }

    #[test]
    fn test_sso_result_cancelled() {
        let result = SSOResult::Cancelled;
        matches!(result, SSOResult::Cancelled);
    }
}
