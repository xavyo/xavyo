//! Logout command - Clear stored credentials

use crate::config::ConfigPaths;
use crate::credentials::get_credential_store;
use crate::error::CliResult;
use crate::models::Session;
use crate::output::{print_info, print_success};
use clap::Args;

/// Arguments for the logout command
#[derive(Args)]
pub struct LogoutArgs {}

/// Execute the logout command
pub async fn execute(_args: LogoutArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;

    // Check if logged in
    let store = get_credential_store(&paths);
    let was_logged_in = store.exists();

    if !was_logged_in && !paths.session_file.exists() {
        print_info("You are not logged in.");
        return Ok(());
    }

    // Delete credentials
    if was_logged_in {
        store.delete()?;
    }

    // Delete session
    Session::delete(&paths)?;

    print_success("Credentials cleared. Logged out successfully.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_logout_not_logged_in() {
        // Set up temp config dir
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("XAVYO_CONFIG_DIR", temp_dir.path().to_str().unwrap());

        let args = LogoutArgs {};
        let result = execute(args).await;

        // Should succeed even if not logged in
        assert!(result.is_ok());

        std::env::remove_var("XAVYO_CONFIG_DIR");
    }
}
