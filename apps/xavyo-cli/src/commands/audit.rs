//! Audit log command implementations
//!
//! This module implements the `xavyo audit` command for viewing login history.

use crate::api::ApiClient;
use crate::config::{Config, ConfigPaths};
use crate::error::{CliError, CliResult};
use crate::models::audit::{AuditFilter, AuditListResponse};
use crate::verbose;
use chrono::{DateTime, NaiveDate, Utc};
use clap::{Args, Subcommand, ValueEnum};
use csv::Writer as CsvWriter;
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
    /// List login history entries with optional filtering
    ///
    /// Examples:
    ///   xavyo audit list
    ///   xavyo audit list --limit 100
    ///   xavyo audit list --user alice@example.com
    ///   xavyo audit list --since 2026-02-01 --until 2026-02-04
    ///   xavyo audit list --output json
    List(ListArgs),
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

    /// Output format: table (default), json, or csv
    #[arg(long, value_enum, default_value = "table")]
    pub output: OutputFormat,
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

    verbose!("Authenticating with API...");
    let client = ApiClient::new(config, paths)?;

    verbose!("Fetching login history...");
    let start = Instant::now();
    let response = client.list_audit_logs(&filter).await?;
    let elapsed = start.elapsed();

    verbose!(
        "Retrieved {} entries in {:.2}s",
        response.items.len(),
        elapsed.as_secs_f64()
    );

    // Output based on format
    match args.output {
        OutputFormat::Table => format_table(&response),
        OutputFormat::Json => format_json(&response)?,
        OutputFormat::Csv => format_csv(&response)?,
    }

    Ok(())
}

// ============================================================================
// Date Parsing
// ============================================================================

/// Parse a date string into a DateTime<Utc>
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

/// Format and print login history entries as a table
fn format_table(response: &AuditListResponse) {
    if response.items.is_empty() {
        println!("No login history entries found.");
        return;
    }

    // Print header
    println!(
        "{:<22} {:<28} {:<10} {:<12} {:<16}",
        "TIMESTAMP", "EMAIL", "SUCCESS", "METHOD", "IP ADDRESS"
    );
    println!("{}", "-".repeat(90));

    // Print each entry
    for entry in &response.items {
        let timestamp = entry.created_at.format("%Y-%m-%d %H:%M:%S").to_string();
        let email = truncate_string(entry.email.as_deref().unwrap_or("-"), 26);
        let success = if entry.success { "yes" } else { "no" };
        let method = entry.auth_method.as_deref().unwrap_or("-");
        let ip = entry.ip_address.as_deref().unwrap_or("-");

        println!(
            "{:<22} {:<28} {:<10} {:<12} {:<16}",
            timestamp, email, success, method, ip
        );
    }

    // Print pagination info
    println!();
    println!(
        "Showing {} of {} total entries.",
        response.items.len(),
        response.total
    );

    if response.next_cursor.is_some() {
        println!("More entries available.");
    }
}

/// Format and print entries as JSON
fn format_json(response: &AuditListResponse) -> CliResult<()> {
    let json = serde_json::to_string_pretty(&response.items)?;
    println!("{}", json);
    Ok(())
}

/// Format and print entries as CSV
fn format_csv(response: &AuditListResponse) -> CliResult<()> {
    let mut wtr = CsvWriter::from_writer(std::io::stdout());

    // Write header
    wtr.write_record([
        "id",
        "timestamp",
        "email",
        "success",
        "auth_method",
        "ip_address",
        "is_new_device",
        "is_new_location",
    ])
    .map_err(|e| CliError::Io(e.to_string()))?;

    // Write data rows
    for entry in &response.items {
        wtr.write_record([
            &entry.id.to_string(),
            &entry.created_at.to_rfc3339(),
            entry.email.as_deref().unwrap_or(""),
            &entry.success.to_string(),
            entry.auth_method.as_deref().unwrap_or(""),
            entry.ip_address.as_deref().unwrap_or(""),
            &entry.is_new_device.to_string(),
            &entry.is_new_location.to_string(),
        ])
        .map_err(|e| CliError::Io(e.to_string()))?;
    }

    wtr.flush().map_err(|e| CliError::Io(e.to_string()))?;
    Ok(())
}

/// Truncate a string to fit in a column
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
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
    fn test_output_format_default() {
        let format = OutputFormat::default();
        assert!(matches!(format, OutputFormat::Table));
    }
}
