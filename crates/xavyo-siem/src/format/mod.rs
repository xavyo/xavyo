//! Event format converters for SIEM export.
//!
//! Supported formats:
//! - CEF v0 (Common Event Format)
//! - RFC 5424 syslog with structured data
//! - JSON structured output
//! - CSV (batch export)

pub mod cef;
pub mod csv;
pub mod json;
pub mod syslog;

use crate::models::{ExportFormat, SiemEvent};
use thiserror::Error;

/// Errors from event formatting.
#[derive(Debug, Error)]
pub enum FormatError {
    #[error("Format error: {0}")]
    FormatFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Trait for formatting SIEM events into a specific output format.
pub trait EventFormatter: Send + Sync {
    /// Format a single SIEM event into a string representation.
    fn format(&self, event: &SiemEvent) -> Result<String, FormatError>;
}

/// Select and format an event using the appropriate formatter.
pub fn format_event(event: &SiemEvent, format: ExportFormat) -> Result<String, FormatError> {
    match format {
        ExportFormat::Cef => cef::CefFormatter::new().format(event),
        ExportFormat::SyslogRfc5424 => syslog::SyslogFormatter::new(10, None).format(event),
        ExportFormat::Json => json::JsonFormatter::new().format(event),
        ExportFormat::Csv => csv::CsvFormatter::new().format(event),
    }
}
