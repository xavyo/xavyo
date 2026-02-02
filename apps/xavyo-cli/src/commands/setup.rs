//! Setup wizard - Interactive onboarding for new users
//!
//! Guides users through the complete setup process:
//! 1. Authentication (signup or login)
//! 2. Tenant creation

use crate::commands::{init, login, signup};
use crate::config::{Config, ConfigPaths};
use crate::credentials::get_credential_store;
use crate::error::{CliError, CliResult};
use crate::models::Session;
use crate::output::{print_info, print_success};
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

/// Execute the setup command
pub async fn execute(args: SetupArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    let _config = Config::load(&paths)?;

    // Check current state
    let auth_state = check_auth_state(&paths)?;
    let tenant_state = check_tenant_state(&paths)?;

    // Non-interactive check mode
    if args.check {
        return execute_check_mode(&auth_state, &tenant_state);
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
                .map_err(|e| CliError::InputError(format!("Selection failed: {}", e)))?;

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
            print_success(&format!("Logged in as {}", email));
            println!();
        }
    }

    // Reload state after potential auth change
    let tenant_state = check_tenant_state(&paths)?;

    // Step 2: Tenant
    println!("Step 2: Tenant");
    match &tenant_state {
        TenantState::NoTenant => {
            println!("  Status: No tenant configured");
            println!();

            let create_tenant = Confirm::new()
                .with_prompt("Would you like to create a new tenant?")
                .default(true)
                .interact()
                .map_err(|e| CliError::InputError(format!("Confirmation failed: {}", e)))?;

            if create_tenant {
                println!();
                let org_name: String = dialoguer::Input::new()
                    .with_prompt("Organization name")
                    .interact_text()
                    .map_err(|e| CliError::InputError(format!("Input failed: {}", e)))?;

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
            print_success(&format!("Tenant: {} ({})", name, slug));
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
            print_success(&format!("Authenticated as: {}", email));
        }
        AuthState::NotLoggedIn => {
            print_info("Not authenticated");
        }
    }

    match &final_tenant {
        TenantState::HasTenant { name, slug } => {
            print_success(&format!("Tenant: {} ({})", name, slug));
        }
        TenantState::NoTenant => {
            print_info("No tenant configured");
        }
    }

    // Check if fully set up
    if matches!(final_auth, AuthState::LoggedIn { .. })
        && matches!(final_tenant, TenantState::HasTenant { .. })
    {
        println!();
        print_success("You're all set! Run 'xavyo --help' to see available commands.");
    }

    Ok(())
}

/// Execute check mode (non-interactive)
fn execute_check_mode(auth_state: &AuthState, tenant_state: &TenantState) -> CliResult<()> {
    println!("Setup Status");
    println!("============");

    let auth_ok = match auth_state {
        AuthState::LoggedIn { email } => {
            print_success(&format!("Authentication: Logged in as {}", email));
            true
        }
        AuthState::NotLoggedIn => {
            println!("  Authentication: Not logged in");
            false
        }
    };

    let tenant_ok = match tenant_state {
        TenantState::HasTenant { name, slug } => {
            print_success(&format!("Tenant: {} ({})", name, slug));
            true
        }
        TenantState::NoTenant => {
            println!("  Tenant: Not configured");
            false
        }
    };

    if auth_ok && tenant_ok {
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
