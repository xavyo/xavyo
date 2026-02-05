//! Audit log command implementations
//!
//! This module implements the `xavyo audit` command for viewing and
//! streaming audit logs with filtering, pagination, and export support.

use crate::api::ApiClient;
use crate::config::{Config, ConfigPaths};
use crate::error::{CliError, CliResult};
use crate::models::audit::{AuditEntry, AuditFilter, AuditListResponse};
use crate::verbose;
use chrono::{DateTime, NaiveDate, Utc};
use clap::{Args, Subcommand, ValueEnum};
use csv::Writer as CsvWriter;
use futures_util::StreamExt;
use reqwest_eventsource::{Event, EventSource};
use std::io::Write;
use std::time::Instant;

// ============================================================================
// Command Arguments
// ============================================================================

/// Audit log management commands
#[derive(Args, Debug)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommands,
}

/// Available audit subcommands
#[derive(Subcommand, Debug)]
pub enum AuditCommands {
    /// List audit log entries with optional filtering
    ///
    /// Examples:
    ///   xavyo audit list
    ///   xavyo audit list --limit 100
    ///   xavyo audit list --user alice@example.com
    ///   xavyo audit list --since 2026-02-01 --until 2026-02-04
    ///   xavyo audit list --action login
    ///   xavyo audit list --output json
    List(ListArgs),

    /// Stream audit log events in real-time
    ///
    /// Press Ctrl+C to stop streaming.
    ///
    /// Examples:
    ///   xavyo audit tail
    ///   xavyo audit tail --action login
    Tail(TailArgs),
}

/// Arguments for the list command
#[derive(Args, Debug)]
pub struct ListArgs {
    /// Maximum number of entries to return (1-1000)
    #[arg(long, short = 'l', default_value = "50")]
    pub limit: i32,

    /// Offset for pagination
    #[arg(long, short = 'o', default_value = "0")]
    pub offset: i32,

    /// Filter by user email or UUID
    #[arg(long, short = 'u')]
    pub user: Option<String>,

    /// Filter by start date (YYYY-MM-DD or ISO 8601)
    #[arg(long)]
    pub since: Option<String>,

    /// Filter by end date (YYYY-MM-DD or ISO 8601)
    #[arg(long)]
    pub until: Option<String>,

    /// Filter by action type (login, logout, create, read, update, delete, etc.)
    #[arg(long, short = 'a')]
    pub action: Option<String>,

    /// Output format: table (default), json, or csv
    #[arg(long, value_enum, default_value = "table")]
    pub output: OutputFormat,
}

/// Arguments for the tail command
#[derive(Args, Debug)]
pub struct TailArgs {
    /// Filter by action type (login, logout, create, read, update, delete, etc.)
    #[arg(long, short = 'a')]
    pub action: Option<String>,
}

/// Output format options
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum OutputFormat {
    /// Display as formatted table (default)
    #[default]
    Table,
    /// Output as JSON array
    Json,
    /// Output as CSV
    Csv,
}

// ============================================================================
// Command Execution
// ============================================================================

/// Execute audit commands
pub async fn execute(args: AuditArgs) -> CliResult<()> {
    match args.command {
        AuditCommands::List(list_args) => execute_list(list_args).await,
        AuditCommands::Tail(tail_args) => execute_tail(tail_args).await,
    }
}

/// Execute the list command
async fn execute_list(args: ListArgs) -> CliResult<()> {
    verbose!("Loading configuration...");
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;

    // Validate limit
    if args.limit < 1 || args.limit > 1000 {
        return Err(CliError::Validation(
            "Limit must be between 1 and 1000".to_string(),
        ));
    }

    // Parse and validate date range
    let since = args.since.as_ref().map(|s| parse_date(s)).transpose()?;
    let until = args.until.as_ref().map(|s| parse_date(s)).transpose()?;

    // Validate date range
    if let (Some(s), Some(u)) = (&since, &until) {
        if s > u {
            return Err(CliError::InvalidDateRange);
        }
    }

    // Build filter
    let mut filter = AuditFilter::new()
        .with_limit(args.limit)
        .with_offset(args.offset);

    if let Some(ref user) = args.user {
        filter = filter.with_user(user.clone());
    }
    if let Some(s) = since {
        filter = filter.with_since(s);
    }
    if let Some(u) = until {
        filter = filter.with_until(u);
    }
    if let Some(ref action) = args.action {
        filter = filter.with_action(action.clone());
    }

    verbose!("Authenticating with API...");
    let client = ApiClient::new(config, paths)?;

    verbose!("Fetching audit logs...");
    let start = Instant::now();
    let response = client.list_audit_logs(&filter).await?;
    let elapsed = start.elapsed();

    verbose!(
        "Retrieved {} entries in {:.2}s",
        response.entries.len(),
        elapsed.as_secs_f64()
    );

    // Output based on format
    match args.output {
        OutputFormat::Table => format_table(&response, &args),
        OutputFormat::Json => format_json(&response)?,
        OutputFormat::Csv => format_csv(&response)?,
    }

    Ok(())
}

/// Execute the tail command (real-time streaming)
async fn execute_tail(args: TailArgs) -> CliResult<()> {
    verbose!("Loading configuration...");
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;

    verbose!("Authenticating with API...");
    let client = ApiClient::new(config, paths)?;

    // Build the stream URL
    let mut url = format!("{}/audit/stream", client.config().api_url);
    if let Some(ref action) = args.action {
        url = format!("{}?action={}", url, action);
    }

    verbose!("Connecting to audit stream...");
    let token = client.get_access_token().await?;

    // Create SSE event source
    let req_client = reqwest::Client::new();
    let request = req_client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Accept", "text/event-stream");

    let mut es = EventSource::new(request).map_err(|e| CliError::Network(e.to_string()))?;

    println!("Streaming audit events (press Ctrl+C to stop)...");
    if let Some(ref action) = args.action {
        println!("Filter: action={}", action);
    }
    println!();

    // Set up Ctrl+C handler
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

    // Spawn the signal handler
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = shutdown_tx_clone.send(()).await;
        }
    });

    let start_time = Instant::now();
    let mut event_count: u64 = 0;

    // Main event loop
    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                // Ctrl+C received
                break;
            }
            event = es.next() => {
                match event {
                    Some(Ok(Event::Open)) => {
                        verbose!("Connected to stream");
                    }
                    Some(Ok(Event::Message(msg))) => {
                        // Parse and display the audit entry
                        match serde_json::from_str::<AuditEntry>(&msg.data) {
                            Ok(entry) => {
                                event_count += 1;
                                print_stream_entry(&entry);
                            }
                            Err(e) => {
                                verbose!("Failed to parse event: {}", e);
                            }
                        }
                    }
                    Some(Err(e)) => {
                        // Handle stream errors
                        let error_msg = format!("{}", e);
                        if error_msg.contains("401") || error_msg.contains("403") {
                            return Err(CliError::NotAuthenticated);
                        }
                        return Err(CliError::Network(error_msg));
                    }
                    None => {
                        // Stream ended
                        println!();
                        println!("Stream ended.");
                        break;
                    }
                }
            }
        }
    }

    // Print summary
    let elapsed = start_time.elapsed();
    println!();
    println!(
        "Received {} events in {:.0} seconds. Exiting.",
        event_count,
        elapsed.as_secs_f64()
    );

    Ok(())
}

// ============================================================================
// Date Parsing
// ============================================================================

/// Parse a date string into a DateTime<Utc>
///
/// Supports:
/// - YYYY-MM-DD (assumes start of day UTC)
/// - Full ISO 8601 datetime
fn parse_date(s: &str) -> CliResult<DateTime<Utc>> {
    // Try parsing as full ISO 8601 datetime
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }

    // Try parsing as YYYY-MM-DD
    if let Ok(date) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let dt = date
            .and_hms_opt(0, 0, 0)
            .ok_or_else(|| CliError::Validation(format!("Invalid date: {}", s)))?;
        return Ok(DateTime::from_naive_utc_and_offset(dt, Utc));
    }

    Err(CliError::Validation(format!(
        "Invalid date format '{}'. Use YYYY-MM-DD or ISO 8601 format.",
        s
    )))
}

// ============================================================================
// Output Formatting
// ============================================================================

/// Format and print audit entries as a table
fn format_table(response: &AuditListResponse, args: &ListArgs) {
    if response.entries.is_empty() {
        println!("No audit log entries found.");
        return;
    }

    // Print header
    println!(
        "{:<22} {:<26} {:<18} {:<20}",
        "TIMESTAMP", "USER", "ACTION", "RESOURCE"
    );
    println!("{}", "-".repeat(90));

    // Print each entry
    for entry in &response.entries {
        let timestamp = entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
        let user = truncate_string(&entry.user.email, 24);
        let action = entry.action.to_string();
        let resource = format_resource(entry);

        println!(
            "{:<22} {:<26} {:<18} {:<20}",
            timestamp, user, action, resource
        );
    }

    // Print pagination info
    println!();
    println!(
        "Showing {} of {} total entries.",
        response.entries.len(),
        response.total
    );

    if response.has_more {
        let next_offset = args.offset + args.limit;
        println!("Use --offset {} to see more.", next_offset);
    }
}

/// Format and print audit entries as JSON
fn format_json(response: &AuditListResponse) -> CliResult<()> {
    let json = serde_json::to_string_pretty(&response.entries)?;
    println!("{}", json);
    Ok(())
}

/// Format and print audit entries as CSV
fn format_csv(response: &AuditListResponse) -> CliResult<()> {
    let mut wtr = CsvWriter::from_writer(std::io::stdout());

    // Write header
    wtr.write_record([
        "id",
        "timestamp",
        "user_email",
        "action",
        "resource_type",
        "resource_id",
        "ip_address",
    ])
    .map_err(|e| CliError::Io(e.to_string()))?;

    // Write data rows
    for entry in &response.entries {
        wtr.write_record([
            &entry.id.to_string(),
            &entry.timestamp.to_rfc3339(),
            &entry.user.email,
            &entry.action.to_string(),
            &entry.resource_type,
            &entry
                .resource_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            entry.ip_address.as_deref().unwrap_or(""),
        ])
        .map_err(|e| CliError::Io(e.to_string()))?;
    }

    wtr.flush().map_err(|e| CliError::Io(e.to_string()))?;
    Ok(())
}

/// Print a streaming entry in real-time
fn print_stream_entry(entry: &AuditEntry) {
    let timestamp = entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
    let user = truncate_string(&entry.user.email, 24);
    let action = entry.action.to_string();
    let resource = format_resource(entry);

    println!("[{}] {} {} {}", timestamp, user, action, resource);
    std::io::stdout().flush().ok();
}

/// Format resource information for display
fn format_resource(entry: &AuditEntry) -> String {
    match &entry.resource_id {
        Some(id) => format!("{}/{}", entry.resource_type, truncate_uuid(id)),
        None => entry.resource_type.clone(),
    }
}

/// Truncate a string to fit in a column
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Truncate a UUID for display (first 8 chars)
fn truncate_uuid(id: &uuid::Uuid) -> String {
    id.to_string()[..8].to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_date_iso8601() {
        let result = parse_date("2026-02-04T10:30:00Z");
        assert!(result.is_ok());
        let dt = result.unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2026-02-04");
    }

    #[test]
    fn test_parse_date_simple() {
        let result = parse_date("2026-02-04");
        assert!(result.is_ok());
        let dt = result.unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2026-02-04");
        assert_eq!(dt.format("%H:%M:%S").to_string(), "00:00:00");
    }

    #[test]
    fn test_parse_date_invalid() {
        let result = parse_date("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("short", 10), "short");
        assert_eq!(truncate_string("verylongstring", 10), "verylon...");
        assert_eq!(truncate_string("exactly10!", 10), "exactly10!");
    }

    #[test]
    fn test_truncate_uuid() {
        let id = uuid::Uuid::parse_str("a1b2c3d4-e5f6-7890-abcd-ef1234567890").unwrap();
        assert_eq!(truncate_uuid(&id), "a1b2c3d4");
    }

    #[test]
    fn test_output_format_default() {
        let format = OutputFormat::default();
        assert!(matches!(format, OutputFormat::Table));
    }

    #[test]
    fn test_format_resource_with_id() {
        let entry = AuditEntry {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            user: crate::models::audit::AuditUser {
                id: uuid::Uuid::new_v4(),
                email: "test@example.com".to_string(),
                display_name: None,
            },
            action: crate::models::audit::AuditAction::Create,
            resource_type: "agent".to_string(),
            resource_id: Some(
                uuid::Uuid::parse_str("a1b2c3d4-e5f6-7890-abcd-ef1234567890").unwrap(),
            ),
            resource_name: None,
            ip_address: None,
            user_agent: None,
            metadata: None,
        };

        let result = format_resource(&entry);
        assert!(result.starts_with("agent/a1b2c3d4"));
    }

    #[test]
    fn test_format_resource_without_id() {
        let entry = AuditEntry {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            user: crate::models::audit::AuditUser {
                id: uuid::Uuid::new_v4(),
                email: "test@example.com".to_string(),
                display_name: None,
            },
            action: crate::models::audit::AuditAction::Login,
            resource_type: "session".to_string(),
            resource_id: None,
            resource_name: None,
            ip_address: None,
            user_agent: None,
            metadata: None,
        };

        let result = format_resource(&entry);
        assert_eq!(result, "session");
    }

    #[test]
    fn test_date_range_validation() {
        // This is tested implicitly through execute_list
        // but we can test the parse_date function
        let since = parse_date("2026-02-01").unwrap();
        let until = parse_date("2026-02-04").unwrap();
        assert!(since < until);

        // Reversed should fail in execute_list
        let since2 = parse_date("2026-02-05").unwrap();
        let until2 = parse_date("2026-02-01").unwrap();
        assert!(since2 > until2); // This would trigger InvalidDateRange
    }
}
