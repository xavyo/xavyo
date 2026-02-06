//! CLI Verbose/Debug Logging Module
//!
//! This module provides configurable logging for the xavyo CLI with:
//! - Multiple verbosity levels (Normal, Verbose, Debug, Trace)
//! - Environment variable support (XAVYO_VERBOSE, XAVYO_DEBUG, XAVYO_TRACE)
//! - File output with timestamps
//! - Automatic sensitive data redaction
//!
//! # Usage
//!
//! ```rust,ignore
//! use xavyo_cli::logging::{Logger, LogConfig, LogLevel};
//!
//! // Create config from CLI args
//! let config = LogConfig::from_args_and_env(verbose, debug, trace, quiet, log_file);
//!
//! // Create logger
//! let logger = Logger::new(config)?;
//!
//! // Log messages
//! logger.verbose("Loading configuration...");
//! logger.debug_http_request("GET", "https://api.example.com/v1/users");
//! ```

pub mod config;
pub mod level;
pub mod output;
pub mod redaction;

pub use config::LogConfig;
pub use level::LogLevel;
#[allow(unused_imports)]
pub use output::{FileWriter, HttpDirection, HttpLogEntry, LogEntry, LogOutput, TerminalWriter};
#[allow(unused_imports)]
pub use redaction::{Redactor, REDACTED};

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Main logger for CLI verbose/debug output
///
/// Thread-safe logger that manages output to terminal and optionally to a file.
/// Handles verbosity levels, sensitive data redaction, and trace mode warnings.
pub struct Logger {
    config: LogConfig,
    terminal: TerminalWriter,
    file: Option<FileWriter>,
    redactor: Redactor,
    trace_warned: Arc<AtomicBool>,
}

#[allow(dead_code)]
impl Logger {
    /// Create a new logger with the given configuration
    pub fn new(config: LogConfig) -> io::Result<Self> {
        let terminal = TerminalWriter::new(config.color);
        let file = config
            .log_file
            .as_ref()
            .map(|path| FileWriter::new(path))
            .transpose()?;

        Ok(Self {
            config,
            terminal,
            file,
            redactor: Redactor::new(),
            trace_warned: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Get the current log configuration
    pub fn config(&self) -> &LogConfig {
        &self.config
    }

    /// Check if verbose output is enabled
    pub fn is_verbose(&self) -> bool {
        self.config.is_verbose()
    }

    /// Check if debug output is enabled
    pub fn is_debug(&self) -> bool {
        self.config.is_debug()
    }

    /// Check if trace output is enabled
    pub fn is_trace(&self) -> bool {
        self.config.is_trace()
    }

    /// Show trace warning if not already shown
    fn maybe_show_trace_warning(&self) {
        if self.config.is_trace() && !self.trace_warned.swap(true, Ordering::SeqCst) {
            let warning = self.terminal.format_trace_warning();
            eprintln!("{}", warning);
        }
    }

    /// Log a verbose message
    pub fn verbose(&self, message: impl Into<String>) {
        if !self.config.is_verbose() {
            return;
        }

        let entry = LogEntry::new(LogLevel::Verbose, message).with_context("verbose");
        let _ = self.terminal.write(&entry);

        if let Some(ref file) = self.file {
            let _ = file.write(&entry);
        }
    }

    /// Log a verbose message with custom context
    pub fn verbose_with_context(&self, context: impl Into<String>, message: impl Into<String>) {
        if !self.config.is_verbose() {
            return;
        }

        let entry = LogEntry::new(LogLevel::Verbose, message).with_context(context);
        let _ = self.terminal.write(&entry);

        if let Some(ref file) = self.file {
            let _ = file.write(&entry);
        }
    }

    /// Log an HTTP request at debug level
    pub fn debug_request(&self, method: impl Into<String>, url: impl Into<String>) {
        if !self.config.is_debug() {
            return;
        }

        let entry = HttpLogEntry::request(method, url);
        let formatted = self.terminal.format_http_debug(&entry);
        eprintln!("{}", formatted);

        if let Some(ref file) = self.file {
            let _ = file.write_http(&entry, &self.redactor);
        }
    }

    /// Log an HTTP response at debug level
    pub fn debug_response(&self, status: u16, status_text: impl Into<String>, timing_ms: u64) {
        if !self.config.is_debug() {
            return;
        }

        let entry = HttpLogEntry::response(status, status_text, timing_ms);
        let formatted = self.terminal.format_http_debug(&entry);
        eprintln!("{}", formatted);

        if let Some(ref file) = self.file {
            let _ = file.write_http(&entry, &self.redactor);
        }
    }

    /// Log an HTTP request body at trace level
    pub fn trace_request_body(
        &self,
        method: impl Into<String>,
        url: impl Into<String>,
        headers: std::collections::HashMap<String, String>,
        body: Option<impl Into<String>>,
    ) {
        if !self.config.is_trace() {
            return;
        }

        self.maybe_show_trace_warning();

        let mut entry = HttpLogEntry::request(method, url).with_headers(headers);
        if let Some(b) = body {
            entry = entry.with_body(b);
        }

        let formatted = self.terminal.format_http_trace(&entry, &self.redactor);
        eprintln!("{}", formatted);

        if let Some(ref file) = self.file {
            let _ = file.write_http(&entry, &self.redactor);
        }
    }

    /// Log an HTTP response body at trace level
    pub fn trace_response_body(
        &self,
        status: u16,
        status_text: impl Into<String>,
        timing_ms: u64,
        headers: std::collections::HashMap<String, String>,
        body: Option<impl Into<String>>,
    ) {
        if !self.config.is_trace() {
            return;
        }

        self.maybe_show_trace_warning();

        let mut entry =
            HttpLogEntry::response(status, status_text, timing_ms).with_headers(headers);
        if let Some(b) = body {
            entry = entry.with_body(b);
        }

        let formatted = self.terminal.format_http_trace(&entry, &self.redactor);
        eprintln!("{}", formatted);

        if let Some(ref file) = self.file {
            let _ = file.write_http(&entry, &self.redactor);
        }
    }
}

/// Global logger instance for use throughout the CLI
static GLOBAL_LOGGER: std::sync::OnceLock<Logger> = std::sync::OnceLock::new();

/// Initialize the global logger
///
/// This should be called once at the start of the CLI with the parsed config.
/// Returns an error if the logger has already been initialized or if file
/// creation fails.
pub fn init_global_logger(config: LogConfig) -> io::Result<()> {
    let logger = Logger::new(config)?;
    GLOBAL_LOGGER
        .set(logger)
        .map_err(|_| io::Error::other("Global logger already initialized"))
}

/// Get a reference to the global logger
///
/// Returns None if the global logger hasn't been initialized.
pub fn global_logger() -> Option<&'static Logger> {
    GLOBAL_LOGGER.get()
}

/// Log a verbose message using the global logger
#[macro_export]
macro_rules! verbose {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::logging::global_logger() {
            logger.verbose(format!($($arg)*));
        }
    };
}

/// Log a verbose message with context using the global logger
#[macro_export]
macro_rules! verbose_ctx {
    ($ctx:expr, $($arg:tt)*) => {
        if let Some(logger) = $crate::logging::global_logger() {
            logger.verbose_with_context($ctx, format!($($arg)*));
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::NamedTempFile;

    #[test]
    fn test_logger_creation_without_file() {
        let config = LogConfig::default();
        let logger = Logger::new(config).unwrap();
        assert!(!logger.is_verbose());
        assert!(!logger.is_debug());
        assert!(!logger.is_trace());
    }

    #[test]
    fn test_logger_creation_with_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let config = LogConfig {
            level: LogLevel::Verbose,
            quiet: false,
            log_file: Some(temp_file.path().to_path_buf()),
            color: false,
        };

        let logger = Logger::new(config).unwrap();
        assert!(logger.is_verbose());
        assert!(logger.file.is_some());
    }

    #[test]
    fn test_logger_verbose_level() {
        let config = LogConfig {
            level: LogLevel::Verbose,
            quiet: false,
            log_file: None,
            color: false,
        };

        let logger = Logger::new(config).unwrap();
        assert!(logger.is_verbose());
        assert!(!logger.is_debug());
        assert!(!logger.is_trace());
    }

    #[test]
    fn test_logger_debug_level() {
        let config = LogConfig {
            level: LogLevel::Debug,
            quiet: false,
            log_file: None,
            color: false,
        };

        let logger = Logger::new(config).unwrap();
        assert!(logger.is_verbose()); // Debug includes verbose
        assert!(logger.is_debug());
        assert!(!logger.is_trace());
    }

    #[test]
    fn test_logger_trace_level() {
        let config = LogConfig {
            level: LogLevel::Trace,
            quiet: false,
            log_file: None,
            color: false,
        };

        let logger = Logger::new(config).unwrap();
        assert!(logger.is_verbose()); // Trace includes verbose
        assert!(logger.is_debug()); // Trace includes debug
        assert!(logger.is_trace());
    }

    #[test]
    fn test_logger_quiet_mode() {
        let config = LogConfig {
            level: LogLevel::Trace,
            quiet: true,
            log_file: None,
            color: false,
        };

        let logger = Logger::new(config).unwrap();
        assert!(!logger.is_verbose()); // Quiet overrides everything
        assert!(!logger.is_debug());
        assert!(!logger.is_trace());
    }

    #[test]
    fn test_trace_warning_shown_once() {
        let config = LogConfig {
            level: LogLevel::Trace,
            quiet: false,
            log_file: None,
            color: false,
        };

        let logger = Logger::new(config).unwrap();

        // First call should show warning
        logger.maybe_show_trace_warning();
        assert!(logger.trace_warned.load(Ordering::SeqCst));

        // Second call should not show warning again (already shown)
        logger.maybe_show_trace_warning();
        // Warning flag should still be true
        assert!(logger.trace_warned.load(Ordering::SeqCst));
    }

    #[test]
    fn test_logger_writes_to_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let config = LogConfig {
            level: LogLevel::Verbose,
            quiet: false,
            log_file: Some(temp_file.path().to_path_buf()),
            color: false,
        };

        let logger = Logger::new(config).unwrap();
        logger.verbose("Test message");

        // Read file content
        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(content.contains("Test message"));
        assert!(content.contains("[VERBOSE]"));
    }

    #[test]
    fn test_debug_request_response() {
        let config = LogConfig {
            level: LogLevel::Debug,
            quiet: false,
            log_file: None,
            color: false,
        };

        let logger = Logger::new(config).unwrap();
        // These won't panic if debug is enabled
        logger.debug_request("GET", "https://api.example.com/v1/users");
        logger.debug_response(200, "OK", 143);
    }

    #[test]
    fn test_trace_request_body() {
        let config = LogConfig {
            level: LogLevel::Trace,
            quiet: false,
            log_file: None,
            color: false,
        };

        let logger = Logger::new(config).unwrap();
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        logger.trace_request_body(
            "POST",
            "https://api.example.com/v1/create",
            headers,
            Some(r#"{"name": "test"}"#),
        );
    }

    #[test]
    fn test_trace_response_body() {
        let config = LogConfig {
            level: LogLevel::Trace,
            quiet: false,
            log_file: None,
            color: false,
        };

        let logger = Logger::new(config).unwrap();
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        logger.trace_response_body(
            200,
            "OK",
            143,
            headers,
            Some(r#"{"id": "123", "name": "test"}"#),
        );
    }

    #[test]
    fn test_verbose_disabled() {
        let config = LogConfig::default(); // Normal level
        let logger = Logger::new(config).unwrap();

        // Should not panic, just do nothing
        logger.verbose("This should not appear");
    }

    #[test]
    fn test_debug_disabled() {
        let config = LogConfig {
            level: LogLevel::Verbose, // Only verbose, not debug
            quiet: false,
            log_file: None,
            color: false,
        };

        let logger = Logger::new(config).unwrap();

        // Should not panic, just do nothing
        logger.debug_request("GET", "https://api.example.com");
        logger.debug_response(200, "OK", 100);
    }

    #[test]
    fn test_trace_disabled() {
        let config = LogConfig {
            level: LogLevel::Debug, // Only debug, not trace
            quiet: false,
            log_file: None,
            color: false,
        };

        let logger = Logger::new(config).unwrap();

        // Should not panic, just do nothing
        logger.trace_request_body(
            "POST",
            "https://api.example.com",
            HashMap::new(),
            None::<String>,
        );
        logger.trace_response_body(200, "OK", 100, HashMap::new(), None::<String>);
    }
}
