//! Output writers for CLI logging
//!
//! This module provides terminal and file output writers for log messages.

use chrono::{DateTime, Local};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

use super::level::LogLevel;
use super::redaction::Redactor;

/// A trait for log output destinations
#[allow(dead_code)]
pub trait LogOutput: Send + Sync {
    /// Write a log entry
    fn write(&self, entry: &LogEntry) -> io::Result<()>;

    /// Flush any buffered output
    fn flush(&self) -> io::Result<()>;
}

/// A log entry to be output
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// When the entry was created
    pub timestamp: DateTime<Local>,
    /// Verbosity level of this entry
    pub level: LogLevel,
    /// The log message content
    pub message: String,
    /// Additional context (e.g., operation name)
    pub context: Option<String>,
}

impl LogEntry {
    /// Create a new log entry at the current time
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            timestamp: Local::now(),
            level,
            message: message.into(),
            context: None,
        }
    }

    /// Add context to the entry
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }
}

/// HTTP log entry for request/response logging
#[derive(Debug, Clone)]
pub struct HttpLogEntry {
    /// Whether this is a request or response
    pub direction: HttpDirection,
    /// HTTP method (for requests)
    pub method: Option<String>,
    /// Request URL (for requests)
    pub url: Option<String>,
    /// HTTP status code (for responses)
    pub status: Option<u16>,
    /// Status text (for responses)
    pub status_text: Option<String>,
    /// Time taken in milliseconds (for responses)
    pub timing_ms: Option<u64>,
    /// Headers (for trace mode)
    pub headers: Option<HashMap<String, String>>,
    /// Body content (for trace mode)
    pub body: Option<String>,
}

/// HTTP log direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpDirection {
    /// Outgoing request
    Request,
    /// Incoming response
    Response,
}

impl HttpLogEntry {
    /// Create a new HTTP request entry
    pub fn request(method: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            direction: HttpDirection::Request,
            method: Some(method.into()),
            url: Some(url.into()),
            status: None,
            status_text: None,
            timing_ms: None,
            headers: None,
            body: None,
        }
    }

    /// Create a new HTTP response entry
    pub fn response(status: u16, status_text: impl Into<String>, timing_ms: u64) -> Self {
        Self {
            direction: HttpDirection::Response,
            method: None,
            url: None,
            status: Some(status),
            status_text: Some(status_text.into()),
            timing_ms: Some(timing_ms),
            headers: None,
            body: None,
        }
    }

    /// Add headers to the entry
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = Some(headers);
        self
    }

    /// Add body to the entry
    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Format for debug output (method, URL, status, timing)
    pub fn format_debug(&self) -> String {
        match self.direction {
            HttpDirection::Request => {
                format!(
                    "→ {} {}",
                    self.method.as_deref().unwrap_or("?"),
                    self.url.as_deref().unwrap_or("?")
                )
            }
            HttpDirection::Response => {
                format!(
                    "← {} {} ({}ms)",
                    self.status.unwrap_or(0),
                    self.status_text.as_deref().unwrap_or("?"),
                    self.timing_ms.unwrap_or(0)
                )
            }
        }
    }

    /// Format for trace output (includes headers and body)
    pub fn format_trace(&self, redactor: &Redactor) -> String {
        let mut output = self.format_debug();

        if let Some(ref headers) = self.headers {
            output.push_str("\n  Headers:");
            for (key, value) in headers {
                let redacted_value = redactor.redact(value);
                output.push_str(&format!("\n    {}: {}", key, redacted_value));
            }
        }

        if let Some(ref body) = self.body {
            let redacted_body = redactor.redact(body);
            if redacted_body.is_empty() {
                output.push_str("\n  Body: (empty)");
            } else {
                output.push_str(&format!("\n  Body:\n    {}", redacted_body));
            }
        }

        output
    }
}

/// Terminal output writer
pub struct TerminalWriter {
    /// Whether to use color output
    color: bool,
}

impl TerminalWriter {
    /// Create a new terminal writer
    pub fn new(color: bool) -> Self {
        Self { color }
    }

    /// Format a log entry for terminal output
    fn format_entry(&self, entry: &LogEntry) -> String {
        let context = entry.context.as_deref().unwrap_or("verbose");

        if self.color {
            format!("\x1b[36m[{}]\x1b[0m {}", context, entry.message)
        } else {
            format!("[{}] {}", context, entry.message)
        }
    }

    /// Format HTTP entry for debug level
    pub fn format_http_debug(&self, entry: &HttpLogEntry) -> String {
        let text = entry.format_debug();
        if self.color {
            match entry.direction {
                HttpDirection::Request => format!("\x1b[33m{}\x1b[0m", text),
                HttpDirection::Response => {
                    let status = entry.status.unwrap_or(0);
                    if (200..300).contains(&status) {
                        format!("\x1b[32m{}\x1b[0m", text) // Green for success
                    } else if status >= 400 {
                        format!("\x1b[31m{}\x1b[0m", text) // Red for errors
                    } else {
                        format!("\x1b[33m{}\x1b[0m", text) // Yellow for others
                    }
                }
            }
        } else {
            text
        }
    }

    /// Format HTTP entry for trace level
    pub fn format_http_trace(&self, entry: &HttpLogEntry, redactor: &Redactor) -> String {
        let text = entry.format_trace(redactor);
        if self.color {
            match entry.direction {
                HttpDirection::Request => format!("\x1b[33m{}\x1b[0m", text),
                HttpDirection::Response => format!("\x1b[32m{}\x1b[0m", text),
            }
        } else {
            text
        }
    }

    /// Format trace warning message
    pub fn format_trace_warning(&self) -> String {
        if self.color {
            "\x1b[33m⚠️  TRACE MODE: Output may contain sensitive information\x1b[0m".to_string()
        } else {
            "WARNING: TRACE MODE - Output may contain sensitive information".to_string()
        }
    }
}

impl LogOutput for TerminalWriter {
    fn write(&self, entry: &LogEntry) -> io::Result<()> {
        let formatted = self.format_entry(entry);
        eprintln!("{}", formatted);
        Ok(())
    }

    fn flush(&self) -> io::Result<()> {
        io::stderr().flush()
    }
}

/// File output writer with append mode
pub struct FileWriter {
    file: Mutex<File>,
}

impl FileWriter {
    /// Create a new file writer, creating or appending to the file
    pub fn new(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;

        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Format a log entry for file output (with timestamp)
    fn format_entry(&self, entry: &LogEntry) -> String {
        let timestamp = entry.timestamp.format("%Y-%m-%dT%H:%M:%S");
        let context = entry
            .context
            .as_deref()
            .map(|c| format!(" [{}]", c))
            .unwrap_or_default();

        format!(
            "[{}] [{}]{} {}",
            timestamp, entry.level, context, entry.message
        )
    }

    /// Write HTTP entry to file
    pub fn write_http(&self, entry: &HttpLogEntry, redactor: &Redactor) -> io::Result<()> {
        let timestamp = Local::now().format("%Y-%m-%dT%H:%M:%S");
        let formatted = entry.format_trace(redactor);

        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("Failed to lock file"))?;

        writeln!(file, "[{}] [HTTP] {}", timestamp, formatted)?;
        file.flush()
    }
}

impl LogOutput for FileWriter {
    fn write(&self, entry: &LogEntry) -> io::Result<()> {
        let formatted = self.format_entry(entry);

        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("Failed to lock file"))?;

        writeln!(file, "{}", formatted)?;
        file.flush()
    }

    fn flush(&self) -> io::Result<()> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("Failed to lock file"))?;
        file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::NamedTempFile;

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry::new(LogLevel::Verbose, "Test message");
        assert_eq!(entry.level, LogLevel::Verbose);
        assert_eq!(entry.message, "Test message");
        assert!(entry.context.is_none());
    }

    #[test]
    fn test_log_entry_with_context() {
        let entry = LogEntry::new(LogLevel::Verbose, "Test message").with_context("my-context");
        assert_eq!(entry.context, Some("my-context".to_string()));
    }

    #[test]
    fn test_http_request_entry() {
        let entry = HttpLogEntry::request("GET", "https://api.example.com/v1/users");
        assert_eq!(entry.direction, HttpDirection::Request);
        assert_eq!(entry.method, Some("GET".to_string()));
        assert_eq!(
            entry.url,
            Some("https://api.example.com/v1/users".to_string())
        );
    }

    #[test]
    fn test_http_response_entry() {
        let entry = HttpLogEntry::response(200, "OK", 143);
        assert_eq!(entry.direction, HttpDirection::Response);
        assert_eq!(entry.status, Some(200));
        assert_eq!(entry.status_text, Some("OK".to_string()));
        assert_eq!(entry.timing_ms, Some(143));
    }

    #[test]
    fn test_http_entry_format_debug() {
        let request = HttpLogEntry::request("GET", "https://api.example.com/v1/users");
        assert_eq!(
            request.format_debug(),
            "→ GET https://api.example.com/v1/users"
        );

        let response = HttpLogEntry::response(200, "OK", 143);
        assert_eq!(response.format_debug(), "← 200 OK (143ms)");
    }

    #[test]
    fn test_http_entry_format_trace() {
        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            "Bearer secret-token".to_string(),
        );
        headers.insert("Accept".to_string(), "application/json".to_string());

        let entry = HttpLogEntry::request("GET", "https://api.example.com")
            .with_headers(headers)
            .with_body(r#"{"test": "data"}"#);

        let redactor = Redactor::new();
        let formatted = entry.format_trace(&redactor);

        assert!(formatted.contains("→ GET https://api.example.com"));
        assert!(formatted.contains("Headers:"));
        assert!(formatted.contains("Accept: application/json"));
        assert!(formatted.contains("Body:"));
    }

    #[test]
    fn test_terminal_writer_format() {
        let writer = TerminalWriter::new(false);
        let entry = LogEntry::new(LogLevel::Verbose, "Loading config...").with_context("verbose");

        let formatted = writer.format_entry(&entry);
        assert_eq!(formatted, "[verbose] Loading config...");
    }

    #[test]
    fn test_terminal_writer_color_format() {
        let writer = TerminalWriter::new(true);
        let entry = LogEntry::new(LogLevel::Verbose, "Loading config...").with_context("verbose");

        let formatted = writer.format_entry(&entry);
        assert!(formatted.contains("\x1b[36m")); // Cyan
        assert!(formatted.contains("\x1b[0m")); // Reset
    }

    #[test]
    fn test_file_writer_creates_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let writer = FileWriter::new(temp_file.path()).unwrap();

        let entry = LogEntry::new(LogLevel::Verbose, "Test message").with_context("test");

        writer.write(&entry).unwrap();
        writer.flush().unwrap();

        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(content.contains("[VERBOSE]"));
        assert!(content.contains("[test]"));
        assert!(content.contains("Test message"));
    }

    #[test]
    fn test_file_writer_appends() {
        let temp_file = NamedTempFile::new().unwrap();
        let writer = FileWriter::new(temp_file.path()).unwrap();

        writer
            .write(&LogEntry::new(LogLevel::Verbose, "First message"))
            .unwrap();
        writer
            .write(&LogEntry::new(LogLevel::Debug, "Second message"))
            .unwrap();
        writer.flush().unwrap();

        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_terminal_writer_http_debug() {
        let writer = TerminalWriter::new(false);
        let entry = HttpLogEntry::request("POST", "https://api.example.com/v1/create");
        let formatted = writer.format_http_debug(&entry);
        assert_eq!(formatted, "→ POST https://api.example.com/v1/create");
    }

    #[test]
    fn test_trace_warning_format() {
        let writer = TerminalWriter::new(false);
        let warning = writer.format_trace_warning();
        assert!(warning.contains("TRACE MODE"));
        assert!(warning.contains("sensitive information"));
    }
}
