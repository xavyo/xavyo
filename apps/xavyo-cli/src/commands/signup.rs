//! Signup command - Create a new account in the system tenant

use crate::api::signup;
use crate::commands::login;
use crate::config::{Config, ConfigPaths};
use crate::credentials::get_credential_store;
use crate::error::{CliError, CliResult};
use crate::models::{Credentials, Session};
use crate::output::{print_info, print_success};
use clap::Args;
use dialoguer::{Input, Password};
use reqwest::Client;
use std::time::Duration;

/// Arguments for the signup command
#[derive(Args)]
pub struct SignupArgs {
    /// Automatically login after signup
    #[arg(long)]
    pub login: bool,

    /// Skip confirmation prompts
    #[arg(long, short = 'y')]
    pub yes: bool,
}

/// Execute the signup command
pub async fn execute(args: SignupArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;

    // Check if already logged in
    let store = get_credential_store(&paths);
    if let Some(creds) = store.load()? {
        if !creds.is_expired() {
            print_info(
                "You are already logged in. Run 'xavyo logout' first to create a new account.",
            );
            return Ok(());
        }
    }

    println!();
    println!("Create a new xavyo account");
    println!("===========================");
    println!();

    // Prompt for email
    let email: String = Input::new()
        .with_prompt("Email")
        .validate_with(|input: &String| {
            if input.contains('@') && input.contains('.') {
                Ok(())
            } else {
                Err("Please enter a valid email address")
            }
        })
        .interact_text()
        .map_err(|e| CliError::InputError(format!("Failed to read email: {e}")))?;

    // Prompt for password
    let password = Password::new()
        .with_prompt("Password (min 8 characters)")
        .validate_with(|input: &String| {
            if input.len() >= 8 {
                Ok(())
            } else {
                Err("Password must be at least 8 characters")
            }
        })
        .interact()
        .map_err(|e| CliError::InputError(format!("Failed to read password: {e}")))?;

    // Confirm password
    let password_confirm = Password::new()
        .with_prompt("Confirm password")
        .interact()
        .map_err(|e| CliError::InputError(format!("Failed to read password: {e}")))?;

    if password != password_confirm {
        return Err(CliError::InputError("Passwords do not match".to_string()));
    }

    // Optional display name
    let display_name: String = Input::new()
        .with_prompt("Display name (optional, press Enter to skip)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| CliError::InputError(format!("Failed to read display name: {e}")))?;

    let display_name = if display_name.is_empty() {
        None
    } else {
        Some(display_name)
    };

    // Create HTTP client
    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .build()
        .map_err(|e| CliError::Network(format!("Failed to create HTTP client: {e}")))?;

    // Call signup API
    println!();
    print_info("Creating account...");

    let response = signup(&client, &config, &email, &password, display_name.as_deref()).await?;

    // Create credentials from response
    let credentials = Credentials::new(
        response.access_token.clone(),
        None, // No refresh token from signup
        response.expires_in,
    );

    // Store credentials
    store.store(&credentials)?;

    // Create and save session
    let session = Session::from_jwt_claims(&response.access_token)?;
    session.save(&paths)?;

    println!();
    print_success(&format!(
        "Account created successfully for {}",
        response.email
    ));
    println!();

    if !response.email_verified {
        print_info("Please check your email to verify your account.");
        println!();
    }

    // Auto-login if requested
    if args.login {
        print_info("Starting login flow...");
        println!();
        let login_args = login::LoginArgs { no_browser: false };
        return login::execute(login_args).await;
    }

    print_info("Run 'xavyo login' to authenticate with the device code flow.");
    print_info("Run 'xavyo init <name>' to create a new tenant.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signup_args_default() {
        let args = SignupArgs {
            login: false,
            yes: false,
        };
        assert!(!args.login);
        assert!(!args.yes);
    }

    #[test]
    fn test_signup_args_with_login() {
        let args = SignupArgs {
            login: true,
            yes: false,
        };
        assert!(args.login);
    }
}
