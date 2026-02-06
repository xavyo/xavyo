//! Setup wizard - Interactive onboarding for new users
//!
//! Guides users through the complete setup process:
//! 1. Authentication (signup or login)
//! 2. Email verification
//! 3. Tenant creation

use crate::api::{get_profile, ApiClient};
use crate::commands::{init, login, signup};
use crate::config::ConfigPaths;
use crate::credentials::get_credential_store;
use crate::error::{CliError, CliResult};
use crate::models::Session;
use crate::output::{print_info, print_success, print_warning};
use clap::Args;
use dialoguer::{Confirm, Select};

/// Arguments for the setup command
#[derive(Args)]
pub struct SetupArgs {
    /// Check setup status without interactive prompts
    #[arg(long)]
    pub check: bool,
}

/// Authentication state
#[derive(Debug, Clone, PartialEq)]
enum AuthState {
    NotLoggedIn,
    LoggedIn { email: String },
}

/// Tenant state
#[derive(Debug, Clone, PartialEq)]
enum TenantState {
    NoTenant,
    HasTenant { name: String, slug: String },
}

/// Check authentication state
fn check_auth_state(paths: &ConfigPaths) -> CliResult<AuthState> {
    let store = get_credential_store(paths);

    match store.load()? {
        Some(creds) if !creds.is_expired() => {
            // Try to load session for email
            match Session::load(paths)? {
                Some(session) => Ok(AuthState::LoggedIn {
                    email: session.email,
                }),
                None => Ok(AuthState::LoggedIn {
                    email: "unknown".to_string(),
                }),
            }
        }
        _ => Ok(AuthState::NotLoggedIn),
    }
}

/// Check tenant state
fn check_tenant_state(paths: &ConfigPaths) -> CliResult<TenantState> {
    match Session::load(paths)? {
        Some(session) if session.has_tenant() => Ok(TenantState::HasTenant {
            name: session.tenant_name.unwrap_or_else(|| "Unknown".to_string()),
            slug: session.tenant_slug.unwrap_or_else(|| "unknown".to_string()),
        }),
        _ => Ok(TenantState::NoTenant),
    }
}

/// Check if current user's email is verified via the profile API.
/// Returns Ok(true) if verified, Ok(false) if not, Err if we can't check.
async fn check_email_verified(api_client: &ApiClient) -> CliResult<bool> {
    let profile = get_profile(api_client).await?;
    Ok(profile.email_verified)
}

/// Execute the setup command
pub async fn execute(args: SetupArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    // Check current state
    let auth_state = check_auth_state(&paths)?;
    let tenant_state = check_tenant_state(&paths)?;

    // Non-interactive check mode
    if args.check {
        let api_client = if auth_state.is_logged_in() {
            Some(ApiClient::from_defaults()?)
        } else {
            None
        };
        return execute_check_mode(&auth_state, &tenant_state, api_client.as_ref()).await;
    }

    println!();
    println!("xavyo Setup Wizard");
    println!("==================");
    println!();

    // Step 1: Authentication
    println!("Step 1: Authentication");
    match &auth_state {
        AuthState::NotLoggedIn => {
            println!("  Status: Not logged in");
            println!();

            let options = vec![
                "Create a new account (signup)",
                "Login with existing account",
            ];
            let selection = Select::new()
                .with_prompt("What would you like to do?")
                .items(&options)
                .default(0)
                .interact()
                .map_err(|e| CliError::InputError(format!("Selection failed: {e}")))?;

            println!();

            match selection {
                0 => {
                    // Signup
                    let signup_args = signup::SignupArgs {
                        login: false,
                        yes: false,
                    };
                    signup::execute(signup_args).await?;
                }
                1 => {
                    // Login
                    let login_args = login::LoginArgs { no_browser: false };
                    login::execute(login_args).await?;
                }
                _ => unreachable!(),
            }

            println!();
        }
        AuthState::LoggedIn { email } => {
            print_success(&format!("Logged in as {email}"));
            println!();
        }
    }

    // Step 2: Email verification check (only if logged in after step 1)
    let auth_after_step1 = check_auth_state(&paths)?;
    if auth_after_step1.is_logged_in() {
        let api_client = ApiClient::from_defaults()?;
        println!("Step 2: Email Verification");
        match check_email_verified(&api_client).await {
            Ok(true) => {
                print_success("Email is verified");
                println!();
            }
            Ok(false) => {
                print_warning("Email is not yet verified.");
                print_info("Please check your inbox for the verification link.");
                print_info("You can resend it with: xavyo verify resend");
                print_info("Check status with: xavyo verify status");
                println!();

                let proceed = Confirm::new()
                    .with_prompt("Continue setup without email verification?")
                    .default(false)
                    .interact()
                    .map_err(|e| CliError::InputError(format!("Confirmation failed: {e}")))?;

                if !proceed {
                    println!();
                    print_info("Run 'xavyo setup' again after verifying your email.");
                    return Ok(());
                }
                println!();
            }
            Err(_) => {
                // Could not check verification (e.g. token issue), continue
                print_info("Could not check email verification status. Continuing...");
                println!();
            }
        }
    }

    // Reload state after potential auth change
    let tenant_state = check_tenant_state(&paths)?;

    // Step 3: Tenant
    println!("Step 3: Tenant");
    match &tenant_state {
        TenantState::NoTenant => {
            println!("  Status: No tenant configured");
            println!();

            let create_tenant = Confirm::new()
                .with_prompt("Would you like to create a new tenant?")
                .default(true)
                .interact()
                .map_err(|e| CliError::InputError(format!("Confirmation failed: {e}")))?;

            if create_tenant {
                println!();
                let org_name: String = dialoguer::Input::new()
                    .with_prompt("Organization name")
                    .interact_text()
                    .map_err(|e| CliError::InputError(format!("Input failed: {e}")))?;

                println!();

                let init_args = init::InitArgs {
                    name: org_name,
                    json: false,
                };
                init::execute(init_args).await?;
            } else {
                print_info("Skipping tenant creation. You can run 'xavyo init <name>' later.");
            }

            println!();
        }
        TenantState::HasTenant { name, slug } => {
            print_success(&format!("Tenant: {name} ({slug})"));
            println!();
        }
    }

    // Final summary
    let final_auth = check_auth_state(&paths)?;
    let final_tenant = check_tenant_state(&paths)?;

    println!();
    println!("Setup Summary");
    println!("=============");

    match &final_auth {
        AuthState::LoggedIn { email } => {
            print_success(&format!("Authenticated as: {email}"));
        }
        AuthState::NotLoggedIn => {
            print_info("Not authenticated");
        }
    }

    let email_verified = if final_auth.is_logged_in() {
        let api_client = ApiClient::from_defaults()?;
        match check_email_verified(&api_client).await {
            Ok(true) => {
                print_success("Email: Verified");
                true
            }
            Ok(false) => {
                print_warning("Email: Not verified");
                false
            }
            Err(_) => {
                print_warning("Email: Could not check");
                false
            }
        }
    } else {
        false
    };

    match &final_tenant {
        TenantState::HasTenant { name, slug } => {
            print_success(&format!("Tenant: {name} ({slug})"));
        }
        TenantState::NoTenant => {
            print_info("No tenant configured");
        }
    }

    // Check if fully set up (auth + email verified + tenant)
    if matches!(final_auth, AuthState::LoggedIn { .. })
        && email_verified
        && matches!(final_tenant, TenantState::HasTenant { .. })
    {
        println!();
        print_success("You're all set! Run 'xavyo --help' to see available commands.");
    }

    Ok(())
}

/// Execute check mode (non-interactive)
async fn execute_check_mode(
    auth_state: &AuthState,
    tenant_state: &TenantState,
    api_client: Option<&ApiClient>,
) -> CliResult<()> {
    println!("Setup Status");
    println!("============");

    let auth_ok = match auth_state {
        AuthState::LoggedIn { email } => {
            print_success(&format!("Authentication: Logged in as {email}"));
            true
        }
        AuthState::NotLoggedIn => {
            println!("  Authentication: Not logged in");
            false
        }
    };

    // Check email verification if authenticated
    let email_ok = if let Some(client) = api_client {
        match check_email_verified(client).await {
            Ok(true) => {
                print_success("Email: Verified");
                true
            }
            Ok(false) => {
                print_warning("Email: Not verified");
                false
            }
            Err(_) => {
                print_warning("Email: Could not check verification status");
                false
            }
        }
    } else {
        false
    };

    let tenant_ok = match tenant_state {
        TenantState::HasTenant { name, slug } => {
            print_success(&format!("Tenant: {name} ({slug})"));
            true
        }
        TenantState::NoTenant => {
            println!("  Tenant: Not configured");
            false
        }
    };

    if auth_ok && email_ok && tenant_ok {
        println!();
        print_success("Setup complete!");
        Ok(())
    } else {
        println!();
        print_info("Run 'xavyo setup' to complete setup.");
        // Return error to indicate incomplete setup (exit code 1)
        Err(CliError::Validation("Setup incomplete".to_string()))
    }
}

impl AuthState {
    fn is_logged_in(&self) -> bool {
        matches!(self, AuthState::LoggedIn { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_args_default() {
        let args = SetupArgs { check: false };
        assert!(!args.check);
    }

    #[test]
    fn test_setup_args_check() {
        let args = SetupArgs { check: true };
        assert!(args.check);
    }

    #[test]
    fn test_auth_state_variants() {
        let not_logged = AuthState::NotLoggedIn;
        let logged = AuthState::LoggedIn {
            email: "test@example.com".to_string(),
        };

        assert_eq!(not_logged, AuthState::NotLoggedIn);
        assert!(matches!(logged, AuthState::LoggedIn { .. }));
    }

    #[test]
    fn test_auth_state_is_logged_in() {
        assert!(!AuthState::NotLoggedIn.is_logged_in());
        assert!(AuthState::LoggedIn {
            email: "a@b.com".to_string()
        }
        .is_logged_in());
    }

    #[test]
    fn test_tenant_state_variants() {
        let no_tenant = TenantState::NoTenant;
        let has_tenant = TenantState::HasTenant {
            name: "Test Org".to_string(),
            slug: "test-org".to_string(),
        };

        assert_eq!(no_tenant, TenantState::NoTenant);
        assert!(matches!(has_tenant, TenantState::HasTenant { .. }));
    }
}
