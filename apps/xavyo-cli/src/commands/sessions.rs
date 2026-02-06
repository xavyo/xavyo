//! Session management CLI commands

use crate::api::ApiClient;
use crate::config::{Config, ConfigPaths};
use crate::error::{CliError, CliResult};
use crate::models::api_session::{ApiSession, DeviceType};
use chrono::{DateTime, Utc};
use clap::{Args, Subcommand};
use dialoguer::Confirm;
use uuid::Uuid;

/// Session management commands
#[derive(Args, Debug)]
pub struct SessionsArgs {
    #[command(subcommand)]
    pub command: SessionsCommands,
}

#[derive(Subcommand, Debug)]
pub enum SessionsCommands {
    /// List all active sessions
    List(ListArgs),
    /// Get details of a specific session
    Get(GetArgs),
    /// Revoke one or more sessions
    Revoke(RevokeArgs),
}

/// Arguments for the list command
#[derive(Args, Debug)]
pub struct ListArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Maximum number of sessions to return
    #[arg(long, default_value = "50")]
    pub limit: u32,

    /// Pagination cursor from previous response
    #[arg(long)]
    pub after: Option<String>,
}

/// Arguments for the get command
#[derive(Args, Debug)]
pub struct GetArgs {
    /// Session ID (UUID)
    pub id: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for the revoke command
#[derive(Args, Debug)]
pub struct RevokeArgs {
    /// Session ID to revoke (optional if --all is used)
    pub id: Option<String>,

    /// Revoke all sessions except the current one
    #[arg(long)]
    pub all: bool,

    /// Skip confirmation prompt
    #[arg(long, short = 'y')]
    pub yes: bool,
}

/// Execute session commands
pub async fn execute(args: SessionsArgs) -> CliResult<()> {
    match args.command {
        SessionsCommands::List(list_args) => execute_list(list_args).await,
        SessionsCommands::Get(get_args) => execute_get(get_args).await,
        SessionsCommands::Revoke(revoke_args) => execute_revoke(revoke_args).await,
    }
}

/// Execute list command
async fn execute_list(args: ListArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let response = client
        .list_sessions(Some(args.limit), args.after.as_deref())
        .await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.sessions.is_empty() {
        println!("No active sessions found.");
    } else {
        print_session_table(&response.sessions);
        println!();
        println!(
            "Showing {} of {} session(s)",
            response.sessions.len(),
            response.total
        );

        if response.has_more {
            if let Some(cursor) = &response.next_cursor {
                println!();
                println!(
                    "More sessions available. Use --after {} to see more.",
                    cursor
                );
            }
        }
    }

    Ok(())
}

/// Execute get command
async fn execute_get(args: GetArgs) -> CliResult<()> {
    let session_id = parse_session_id(&args.id)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let session = client.get_session(session_id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&session)?);
    } else {
        print_session_details(&session);
    }

    Ok(())
}

/// Execute revoke command
async fn execute_revoke(args: RevokeArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    if args.all {
        // Revoke all sessions except current
        execute_revoke_all(&client, args.yes).await
    } else if let Some(id) = &args.id {
        // Revoke specific session
        let session_id = parse_session_id(id)?;
        execute_revoke_single(&client, session_id, args.yes).await
    } else {
        Err(CliError::Validation(
            "Either provide a session ID or use --all to revoke all other sessions.".to_string(),
        ))
    }
}

/// Revoke a single session
async fn execute_revoke_single(
    client: &ApiClient,
    session_id: Uuid,
    skip_confirm: bool,
) -> CliResult<()> {
    // Check if this is the current session
    let session = client.get_session(session_id).await?;

    if session.is_current {
        // Warn about revoking current session
        if !skip_confirm {
            if !atty::is(atty::Stream::Stdin) {
                return Err(CliError::Validation(
                    "Cannot revoke current session in non-interactive mode. Use 'xavyo logout' instead.".to_string(),
                ));
            }

            println!("Warning: You are about to revoke your current session.");
            println!("This will log you out of this CLI. Use 'xavyo logout' instead.");
            println!();

            let confirm = Confirm::new()
                .with_prompt("Are you sure you want to revoke your current session?")
                .default(false)
                .interact()
                .map_err(|e| CliError::Io(e.to_string()))?;

            if !confirm {
                println!("Cancelled.");
                return Ok(());
            }
        }
    } else if !skip_confirm {
        // Confirm revocation for non-current session
        if atty::is(atty::Stream::Stdin) {
            let device_info = format!("{} ({})", session.device_name, session.device_type);
            let confirm = Confirm::new()
                .with_prompt(format!("Revoke session '{}'?", device_info))
                .default(true)
                .interact()
                .map_err(|e| CliError::Io(e.to_string()))?;

            if !confirm {
                println!("Cancelled.");
                return Ok(());
            }
        }
    }

    // Revoke the session
    let response = client.revoke_session(session_id).await?;

    println!("Session revoked successfully.");
    if response.revoked_count > 0 {
        println!("Revoked {} session(s).", response.revoked_count);
    }

    Ok(())
}

/// Revoke all sessions except current
async fn execute_revoke_all(client: &ApiClient, skip_confirm: bool) -> CliResult<()> {
    // First, count how many sessions will be revoked
    let response = client.list_sessions(Some(100), None).await?;
    let other_sessions: Vec<_> = response.sessions.iter().filter(|s| !s.is_current).collect();

    if other_sessions.is_empty() {
        println!("No other sessions to revoke.");
        return Ok(());
    }

    // Confirm revocation
    if !skip_confirm {
        if !atty::is(atty::Stream::Stdin) {
            return Err(CliError::Validation(
                "Cannot confirm revocation in non-interactive mode. Use --yes to skip confirmation.".to_string(),
            ));
        }

        println!("The following sessions will be revoked:");
        println!();
        for session in &other_sessions {
            let location = session
                .location
                .as_ref()
                .map(|l| l.display())
                .unwrap_or_else(|| "Unknown".to_string());
            println!(
                "  - {} ({}) - {}",
                session.device_name, session.device_type, location
            );
        }
        println!();

        let confirm = Confirm::new()
            .with_prompt(format!("Revoke {} other session(s)?", other_sessions.len()))
            .default(false)
            .interact()
            .map_err(|e| CliError::Io(e.to_string()))?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Revoke all sessions
    let response = client.revoke_all_sessions().await?;

    println!(
        "{} session(s) revoked successfully.",
        response.revoked_count
    );

    Ok(())
}

/// Parse session ID from string
fn parse_session_id(id_str: &str) -> CliResult<Uuid> {
    Uuid::parse_str(id_str).map_err(|_| {
        CliError::Validation(format!(
            "Invalid session ID '{}'. Must be a valid UUID.",
            id_str
        ))
    })
}

/// Format relative time for display
fn format_relative_time(dt: &DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(*dt);

    if duration.num_seconds() < 60 {
        "Just now".to_string()
    } else if duration.num_minutes() < 60 {
        let mins = duration.num_minutes();
        if mins == 1 {
            "1 minute ago".to_string()
        } else {
            format!("{} minutes ago", mins)
        }
    } else if duration.num_hours() < 24 {
        let hours = duration.num_hours();
        if hours == 1 {
            "1 hour ago".to_string()
        } else {
            format!("{} hours ago", hours)
        }
    } else if duration.num_days() < 7 {
        let days = duration.num_days();
        if days == 1 {
            "1 day ago".to_string()
        } else {
            format!("{} days ago", days)
        }
    } else if duration.num_weeks() < 4 {
        let weeks = duration.num_weeks();
        if weeks == 1 {
            "1 week ago".to_string()
        } else {
            format!("{} weeks ago", weeks)
        }
    } else {
        dt.format("%Y-%m-%d").to_string()
    }
}

/// Get device type icon/indicator
fn device_type_indicator(dt: &DeviceType) -> &'static str {
    match dt {
        DeviceType::Desktop => "desktop",
        DeviceType::Mobile => "mobile",
        DeviceType::Cli => "cli",
        DeviceType::Browser => "browser",
        DeviceType::Unknown => "unknown",
    }
}

/// Print sessions as a table
fn print_session_table(sessions: &[ApiSession]) {
    // Print header
    println!(
        "{:<38} {:<18} {:<8} {:<16} {:<16} CURRENT",
        "ID", "DEVICE", "TYPE", "LOCATION", "LAST ACTIVITY"
    );
    println!("{}", "-".repeat(110));

    // Print each session
    for session in sessions {
        let truncated_name = if session.device_name.len() > 16 {
            format!("{}...", &session.device_name[..13])
        } else {
            session.device_name.clone()
        };

        let location = session
            .location
            .as_ref()
            .map(|l| {
                let display = l.display();
                if display.len() > 14 {
                    format!("{}...", &display[..11])
                } else {
                    display
                }
            })
            .unwrap_or_else(|| "Unknown".to_string());

        let last_activity = format_relative_time(&session.last_activity_at);
        let current_marker = if session.is_current { "*" } else { "" };

        println!(
            "{:<38} {:<18} {:<8} {:<16} {:<16} {}",
            session.id,
            truncated_name,
            device_type_indicator(&session.device_type),
            location,
            last_activity,
            current_marker
        );
    }
}

/// Print detailed session information
fn print_session_details(session: &ApiSession) {
    println!("Session Details");
    println!("{}", "━".repeat(50));
    println!("ID:            {}", session.id);
    println!("Device:        {}", session.device_name);
    println!("Type:          {}", session.device_type);

    if let Some(ref os) = session.os {
        println!("OS:            {}", os);
    }

    if let Some(ref client) = session.client {
        println!("Client:        {}", client);
    }

    println!("IP Address:    {}", session.ip_address);

    if let Some(ref location) = session.location {
        println!("Location:      {}", location.display());
    }

    println!(
        "Created:       {}",
        session.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "Last Activity: {} ({})",
        session.last_activity_at.format("%Y-%m-%d %H:%M:%S UTC"),
        format_relative_time(&session.last_activity_at)
    );

    if session.is_current {
        println!();
        println!("* This is the current session");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_session_id_valid() {
        let valid_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let result = parse_session_id(valid_uuid);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_session_id_invalid() {
        let invalid_uuid = "not-a-uuid";
        let result = parse_session_id(invalid_uuid);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_relative_time_just_now() {
        let now = Utc::now();
        let result = format_relative_time(&now);
        assert_eq!(result, "Just now");
    }

    #[test]
    fn test_format_relative_time_minutes() {
        let time = Utc::now() - chrono::Duration::minutes(5);
        let result = format_relative_time(&time);
        assert_eq!(result, "5 minutes ago");
    }

    #[test]
    fn test_format_relative_time_one_minute() {
        let time = Utc::now() - chrono::Duration::minutes(1);
        let result = format_relative_time(&time);
        assert_eq!(result, "1 minute ago");
    }

    #[test]
    fn test_format_relative_time_hours() {
        let time = Utc::now() - chrono::Duration::hours(3);
        let result = format_relative_time(&time);
        assert_eq!(result, "3 hours ago");
    }

    #[test]
    fn test_format_relative_time_one_hour() {
        let time = Utc::now() - chrono::Duration::hours(1);
        let result = format_relative_time(&time);
        assert_eq!(result, "1 hour ago");
    }

    #[test]
    fn test_format_relative_time_days() {
        let time = Utc::now() - chrono::Duration::days(2);
        let result = format_relative_time(&time);
        assert_eq!(result, "2 days ago");
    }

    #[test]
    fn test_format_relative_time_one_day() {
        let time = Utc::now() - chrono::Duration::days(1);
        let result = format_relative_time(&time);
        assert_eq!(result, "1 day ago");
    }

    #[test]
    fn test_format_relative_time_weeks() {
        let time = Utc::now() - chrono::Duration::weeks(2);
        let result = format_relative_time(&time);
        assert_eq!(result, "2 weeks ago");
    }

    #[test]
    fn test_device_type_indicator() {
        assert_eq!(device_type_indicator(&DeviceType::Desktop), "desktop");
        assert_eq!(device_type_indicator(&DeviceType::Mobile), "mobile");
        assert_eq!(device_type_indicator(&DeviceType::Cli), "cli");
        assert_eq!(device_type_indicator(&DeviceType::Browser), "browser");
        assert_eq!(device_type_indicator(&DeviceType::Unknown), "unknown");
    }
}
