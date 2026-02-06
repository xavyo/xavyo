//! Doctor command - Diagnose connection and configuration issues

use crate::api::{check_health_display, ApiClient};
use crate::config::{Config, ConfigPaths};
use crate::credentials::get_credential_store;
use crate::error::{CliError, CliResult};
use crate::models::doctor::{DiagnosticCheck, DiagnosticReport, DiagnosticStatus};
use crate::models::Session;
use clap::Args;

const RESET: &str = "\x1b[0m";

/// Arguments for the doctor command
#[derive(Args, Debug)]
#[command(about = "Diagnose connection and configuration issues")]
pub struct DoctorArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Check if configuration file exists and is valid
fn check_configuration(paths: &ConfigPaths) -> DiagnosticCheck {
    if !paths.config_file.exists() {
        // Config file not existing is OK - we use defaults
        return DiagnosticCheck::pass(
            "configuration",
            "Configuration",
            "Using default configuration",
        );
    }

    // Try to load the config
    match Config::load(paths) {
        Ok(_) => DiagnosticCheck::pass(
            "configuration",
            "Configuration",
            &format!("{} found and valid", paths.config_file.display()),
        ),
        Err(e) => DiagnosticCheck::fail(
            "configuration",
            "Configuration",
            &format!("Config file invalid: {e}"),
            "Delete the config file or fix its format",
        ),
    }
}

/// Check if credentials exist and can be loaded
fn check_credentials(paths: &ConfigPaths) -> DiagnosticCheck {
    let store = get_credential_store(paths);

    if !store.exists() {
        return DiagnosticCheck::fail(
            "credentials",
            "Credentials",
            "No credentials found",
            "Run `xavyo login` to authenticate",
        );
    }

    match store.load() {
        Ok(_) => DiagnosticCheck::pass(
            "credentials",
            "Credentials",
            "Credentials loaded successfully",
        ),
        Err(e) => DiagnosticCheck::fail(
            "credentials",
            "Credentials",
            &format!("Failed to load credentials: {e}"),
            "Run `xavyo login` to re-authenticate",
        ),
    }
}

/// Check API connectivity
async fn check_api_connectivity(client: &ApiClient, config: &Config) -> DiagnosticCheck {
    let url = config.health_url();
    let (status, version) = check_health_display(client, &url).await;

    match status {
        crate::models::HealthStatus::Healthy => {
            let version_info = version.map(|v| format!(" (v{v})")).unwrap_or_default();
            DiagnosticCheck::pass(
                "api_connectivity",
                "API Connectivity",
                &format!("Connected to {}{}", config.api_url, version_info),
            )
        }
        crate::models::HealthStatus::Degraded => DiagnosticCheck::warn(
            "api_connectivity",
            "API Connectivity",
            &format!("{} is degraded", config.api_url),
            Some("Some features may not work correctly"),
        ),
        crate::models::HealthStatus::Unhealthy => DiagnosticCheck::fail(
            "api_connectivity",
            "API Connectivity",
            &format!("Cannot connect to {}", config.api_url),
            "Check your network connection and firewall settings",
        ),
    }
}

/// Check Auth service connectivity
async fn check_auth_service(client: &ApiClient, config: &Config) -> DiagnosticCheck {
    let url = config.auth_health_url();
    let (status, version) = check_health_display(client, &url).await;

    match status {
        crate::models::HealthStatus::Healthy => {
            let version_info = version.map(|v| format!(" (v{v})")).unwrap_or_default();
            DiagnosticCheck::pass(
                "auth_service",
                "Auth Service",
                &format!("Connected to {}{}", config.auth_url, version_info),
            )
        }
        crate::models::HealthStatus::Degraded => DiagnosticCheck::warn(
            "auth_service",
            "Auth Service",
            &format!("{} is degraded", config.auth_url),
            Some("Authentication may be slow or unreliable"),
        ),
        crate::models::HealthStatus::Unhealthy => DiagnosticCheck::fail(
            "auth_service",
            "Auth Service",
            &format!("Cannot connect to {}", config.auth_url),
            "Check your network connection and firewall settings",
        ),
    }
}

/// Check token validity
fn check_token_validity(paths: &ConfigPaths) -> DiagnosticCheck {
    let store = get_credential_store(paths);

    match store.load() {
        Ok(Some(creds)) => {
            if creds.access_token.is_empty() {
                return DiagnosticCheck::fail(
                    "token_validity",
                    "Token Validity",
                    "No access token found",
                    "Run `xavyo login` to authenticate",
                );
            }

            // Check expiration
            let now = chrono::Utc::now();
            if creds.expires_at <= now {
                return DiagnosticCheck::fail(
                    "token_validity",
                    "Token Validity",
                    "Access token has expired",
                    "Run `xavyo login` to re-authenticate",
                );
            }

            let duration: chrono::TimeDelta = creds.expires_at - now;
            let hours = duration.num_hours();
            let minutes = duration.num_minutes() % 60;

            if hours < 1 {
                DiagnosticCheck::warn(
                    "token_validity",
                    "Token Validity",
                    &format!("Token expires in {minutes}m"),
                    Some("Consider running `xavyo login` soon to refresh"),
                )
            } else {
                DiagnosticCheck::pass(
                    "token_validity",
                    "Token Validity",
                    &format!("Token valid, expires in {hours}h {minutes}m"),
                )
            }
        }
        Ok(None) => DiagnosticCheck::skip(
            "token_validity",
            "Token Validity",
            "Skipped - no credentials stored",
        ),
        Err(_) => DiagnosticCheck::skip(
            "token_validity",
            "Token Validity",
            "Skipped - credentials not available",
        ),
    }
}

/// Check tenant health
fn check_tenant_health(paths: &ConfigPaths) -> DiagnosticCheck {
    match Session::load(paths) {
        Ok(Some(session)) => {
            if session.has_tenant() {
                let name = session.tenant_name.unwrap_or_else(|| "unknown".to_string());
                DiagnosticCheck::pass(
                    "tenant_health",
                    "Tenant Health",
                    &format!("Tenant active ({name})"),
                )
            } else {
                DiagnosticCheck::warn(
                    "tenant_health",
                    "Tenant Health",
                    "No tenant configured",
                    Some("Run `xavyo init <name>` to create a tenant"),
                )
            }
        }
        Ok(None) => DiagnosticCheck::skip(
            "tenant_health",
            "Tenant Health",
            "Skipped - not authenticated",
        ),
        Err(_) => DiagnosticCheck::skip(
            "tenant_health",
            "Tenant Health",
            "Skipped - session not available",
        ),
    }
}

/// Run all diagnostic checks
async fn run_all_checks(paths: &ConfigPaths, config: &Config) -> DiagnosticReport {
    let mut checks = Vec::new();

    // Check 1: Configuration
    let config_check = check_configuration(paths);
    let config_ok = config_check.status.is_ok();
    checks.push(config_check);

    // Check 2: Credentials
    let creds_check = if config_ok {
        check_credentials(paths)
    } else {
        DiagnosticCheck::skip(
            "credentials",
            "Credentials",
            "Skipped - configuration failed",
        )
    };
    let creds_ok = creds_check.status.is_ok();
    checks.push(creds_check);

    // Check 3 & 4: Network connectivity (can run even without credentials)
    if config_ok {
        // Create unauthenticated client for health checks
        if let Ok(client) = ApiClient::new(config.clone(), paths.clone()) {
            checks.push(check_api_connectivity(&client, config).await);
            checks.push(check_auth_service(&client, config).await);
        } else {
            checks.push(DiagnosticCheck::fail(
                "api_connectivity",
                "API Connectivity",
                "Failed to create HTTP client",
                "Check system configuration",
            ));
            checks.push(DiagnosticCheck::skip(
                "auth_service",
                "Auth Service",
                "Skipped - HTTP client unavailable",
            ));
        }
    } else {
        checks.push(DiagnosticCheck::skip(
            "api_connectivity",
            "API Connectivity",
            "Skipped - configuration failed",
        ));
        checks.push(DiagnosticCheck::skip(
            "auth_service",
            "Auth Service",
            "Skipped - configuration failed",
        ));
    }

    // Check 5: Token validity (requires credentials)
    if creds_ok {
        checks.push(check_token_validity(paths));
    } else {
        checks.push(DiagnosticCheck::skip(
            "token_validity",
            "Token Validity",
            "Skipped - credentials not available",
        ));
    }

    // Check 6: Tenant health (requires authentication)
    if creds_ok {
        checks.push(check_tenant_health(paths));
    } else {
        checks.push(DiagnosticCheck::skip(
            "tenant_health",
            "Tenant Health",
            "Skipped - not authenticated",
        ));
    }

    DiagnosticReport::new(checks)
}

/// Print human-readable output
fn print_report(report: &DiagnosticReport) {
    let use_color = std::env::var("NO_COLOR").is_err();

    println!();
    println!("xavyo doctor");
    println!("═══════════════════════════════════════════════════════");
    println!();

    for check in &report.checks {
        let status_display = if use_color {
            format!(
                "{}{} {}{}",
                check.status.color(),
                check.status.symbol(),
                check.status.display(),
                RESET
            )
        } else {
            format!("{} {}", check.status.symbol(), check.status.display())
        };

        // Align columns: display_name (20 chars), status (10 chars), message
        println!(
            "  {:<20} {:>10}    {}",
            check.display_name, status_display, check.message
        );

        // Show suggestion if present
        if let Some(ref suggestion) = check.suggestion {
            if use_color {
                println!("                              └─ \x1b[90m{suggestion}{RESET}");
            } else {
                println!("                              └─ {suggestion}");
            }
        }
    }

    println!();
    println!("═══════════════════════════════════════════════════════");

    // Overall status
    let overall_display = if use_color {
        format!(
            "{}{} {}{}",
            report.overall_status.color(),
            report.overall_status.symbol(),
            match report.overall_status {
                DiagnosticStatus::Pass => "All checks passed",
                DiagnosticStatus::Fail => {
                    let count = report.fail_count();
                    if count == 1 {
                        "1 check failed"
                    } else {
                        "checks failed"
                    }
                }
                DiagnosticStatus::Warn => "Warnings detected",
                DiagnosticStatus::Skip => "Checks skipped",
            },
            RESET
        )
    } else {
        format!(
            "{} {}",
            report.overall_status.symbol(),
            match report.overall_status {
                DiagnosticStatus::Pass => "All checks passed".to_string(),
                DiagnosticStatus::Fail => format!("{} check(s) failed", report.fail_count()),
                DiagnosticStatus::Warn => "Warnings detected".to_string(),
                DiagnosticStatus::Skip => "Checks skipped".to_string(),
            }
        )
    };

    println!("  Overall Status: {overall_display}");
    println!();
    println!("  CLI Version: {}", report.cli_version);
    println!("  Checked at: {}", report.timestamp);
    println!();
}

/// Execute the doctor command
pub async fn execute(args: DoctorArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;

    let report = run_all_checks(&paths, &config).await;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
    }

    // Return error if any check failed (for scripting exit codes)
    if !report.all_passed() && report.overall_status == DiagnosticStatus::Fail {
        return Err(CliError::Validation(
            "One or more diagnostic checks failed".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doctor_args() {
        let args = DoctorArgs { json: true };
        assert!(args.json);

        let args = DoctorArgs { json: false };
        assert!(!args.json);
    }

    #[test]
    fn test_diagnostic_check_pass_creation() {
        let check = DiagnosticCheck::pass("test", "Test Check", "Everything is fine");
        assert_eq!(check.name, "test");
        assert_eq!(check.display_name, "Test Check");
        assert_eq!(check.status, DiagnosticStatus::Pass);
        assert_eq!(check.message, "Everything is fine");
        assert!(check.suggestion.is_none());
    }

    #[test]
    fn test_diagnostic_check_fail_creation() {
        let check = DiagnosticCheck::fail("test", "Test Check", "Something failed", "Fix it");
        assert_eq!(check.status, DiagnosticStatus::Fail);
        assert_eq!(check.suggestion, Some("Fix it".to_string()));
    }

    #[test]
    fn test_diagnostic_check_skip_creation() {
        let check = DiagnosticCheck::skip("test", "Test Check", "Skipped");
        assert_eq!(check.status, DiagnosticStatus::Skip);
        assert!(check.suggestion.is_none());
    }

    #[test]
    fn test_diagnostic_report_creation() {
        let checks = vec![
            DiagnosticCheck::pass("config", "Configuration", "Found"),
            DiagnosticCheck::pass("creds", "Credentials", "Loaded"),
        ];
        let report = DiagnosticReport::new(checks);
        assert_eq!(report.overall_status, DiagnosticStatus::Pass);
        assert_eq!(report.checks.len(), 2);
        assert!(report.all_passed());
    }

    #[test]
    fn test_diagnostic_report_with_failure() {
        let checks = vec![
            DiagnosticCheck::pass("config", "Configuration", "Found"),
            DiagnosticCheck::fail("creds", "Credentials", "Not found", "Run login"),
        ];
        let report = DiagnosticReport::new(checks);
        assert_eq!(report.overall_status, DiagnosticStatus::Fail);
        assert!(!report.all_passed());
        assert_eq!(report.fail_count(), 1);
    }

    #[test]
    fn test_diagnostic_report_json_serialization() {
        let checks = vec![DiagnosticCheck::pass("config", "Configuration", "Found")];
        let report = DiagnosticReport::new(checks);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"overall_status\":\"pass\""));
        assert!(json.contains("\"cli_version\""));
        assert!(json.contains("\"timestamp\""));
    }
}
