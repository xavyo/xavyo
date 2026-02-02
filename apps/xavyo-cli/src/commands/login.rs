//! Login command - Device code OAuth authentication

use crate::api::{poll_device_token, request_device_code};
use crate::config::{Config, ConfigPaths};
use crate::credentials::get_credential_store;
use crate::error::{CliError, CliResult};
use crate::models::{Credentials, Session};
use crate::output::{print_info, print_success};
use clap::Args;
use reqwest::Client;
use std::time::Duration;
use tokio::time::sleep;

/// Arguments for the login command
#[derive(Args)]
pub struct LoginArgs {
    /// Don't automatically open the browser
    #[arg(long)]
    pub no_browser: bool,
}

/// Execute the login command
pub async fn execute(args: LoginArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;

    // Check if already logged in
    let store = get_credential_store(&paths);
    if let Some(creds) = store.load()? {
        if !creds.is_expired() {
            print_info("You are already logged in. Run 'xavyo logout' first to log out.");
            return Ok(());
        }
    }

    // Create HTTP client
    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .build()
        .map_err(|e| CliError::Network(format!("Failed to create HTTP client: {}", e)))?;

    // Request device code
    print_info("Requesting device code...");
    let device_code = request_device_code(&client, &config).await?;

    // Display instructions
    println!();
    println!("To authenticate, visit:");
    println!("  {}", device_code.verification_uri);
    println!();
    println!("And enter this code: {}", device_code.user_code);
    println!();

    // Try to open browser
    if !args.no_browser {
        let url = device_code.display_url();
        if open::that(url).is_ok() {
            print_info("Browser opened. Complete authentication there.");
        } else {
            print_info("Could not open browser. Please visit the URL above manually.");
        }
    }

    // Poll for token
    println!();
    print!("Waiting for authentication");

    let poll_interval = Duration::from_secs(device_code.interval.max(5));
    let deadline = std::time::Instant::now() + Duration::from_secs(device_code.expires_in);

    loop {
        // Check if we've exceeded the deadline
        if std::time::Instant::now() > deadline {
            println!();
            return Err(CliError::DeviceCodeExpired);
        }

        // Wait before polling
        sleep(poll_interval).await;
        print!(".");

        // Poll for token
        match poll_device_token(&client, &config, &device_code.device_code).await {
            Ok(Some(token_response)) => {
                println!();

                // Create credentials
                let credentials = Credentials::from_token_response(token_response);

                // Create session from JWT
                let session = Session::from_jwt_claims(&credentials.access_token)?;

                // Store credentials
                let store = get_credential_store(&paths);
                store.store(&credentials)?;

                // Save session
                session.save(&paths)?;

                // Save config if not exists
                if !paths.config_file.exists() {
                    config.save(&paths)?;
                }

                println!();
                print_success(&format!("Successfully authenticated as {}", session.email));

                if session.has_tenant() {
                    print_info(&format!(
                        "Current tenant: {} ({})",
                        session.tenant_name.as_deref().unwrap_or("Unknown"),
                        session.tenant_slug.as_deref().unwrap_or("unknown")
                    ));
                } else {
                    print_info("No tenant context. Run 'xavyo init <name>' to create one.");
                }

                return Ok(());
            }
            Ok(None) => {
                // Still pending, continue polling
                continue;
            }
            Err(e) => {
                println!();
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_args_default() {
        let args = LoginArgs { no_browser: false };
        assert!(!args.no_browser);
    }
}
