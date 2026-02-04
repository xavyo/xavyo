//! Integration tests for CLI verbose/debug output
//!
//! These tests verify the logging functionality works correctly when
//! integrated with the CLI commands.

use std::path::PathBuf;
use tempfile::NamedTempFile;
use xavyo_cli::logging::{LogConfig, LogLevel, Logger};

// Note: Integration tests that run the actual CLI binary would require
// setting up a mock server. These tests focus on the logging module itself.

#[test]
fn test_verbose_flag_creates_verbose_config() {
    let config = LogConfig::from_args_and_env(true, false, false, false, None);
    assert_eq!(config.level, LogLevel::Verbose);
    assert!(config.is_verbose());
    assert!(!config.is_debug());
    assert!(!config.is_trace());
}

#[test]
fn test_debug_flag_creates_debug_config() {
    let config = LogConfig::from_args_and_env(false, true, false, false, None);
    assert_eq!(config.level, LogLevel::Debug);
    assert!(config.is_verbose()); // Debug includes verbose
    assert!(config.is_debug());
    assert!(!config.is_trace());
}

#[test]
fn test_trace_flag_creates_trace_config() {
    let config = LogConfig::from_args_and_env(false, false, true, false, None);
    assert_eq!(config.level, LogLevel::Trace);
    assert!(config.is_verbose()); // Trace includes verbose
    assert!(config.is_debug()); // Trace includes debug
    assert!(config.is_trace());
}

#[test]
fn test_quiet_overrides_verbose() {
    let config = LogConfig::from_args_and_env(true, false, false, true, None);
    assert!(config.quiet);
    assert!(!config.is_verbose()); // Quiet overrides everything
}

#[test]
fn test_quiet_overrides_debug() {
    let config = LogConfig::from_args_and_env(false, true, false, true, None);
    assert!(config.quiet);
    assert!(!config.is_debug()); // Quiet overrides everything
}

#[test]
fn test_quiet_overrides_trace() {
    let config = LogConfig::from_args_and_env(false, false, true, true, None);
    assert!(config.quiet);
    assert!(!config.is_trace()); // Quiet overrides everything
}

#[test]
fn test_log_file_option() {
    let path = PathBuf::from("/tmp/test-debug.log");
    let config = LogConfig::from_args_and_env(true, false, false, false, Some(path.clone()));
    assert_eq!(config.log_file, Some(path));
}

#[test]
fn test_logger_with_file_output() {
    let temp_file = NamedTempFile::new().unwrap();
    let config = LogConfig {
        level: LogLevel::Verbose,
        quiet: false,
        log_file: Some(temp_file.path().to_path_buf()),
        color: false,
    };

    let logger = Logger::new(config).unwrap();
    logger.verbose("Test verbose message");

    // Read the file and verify content
    let content = std::fs::read_to_string(temp_file.path()).unwrap();
    assert!(content.contains("[VERBOSE]"));
    assert!(content.contains("Test verbose message"));
}

#[test]
fn test_logger_file_append_mode() {
    let temp_file = NamedTempFile::new().unwrap();

    // First write
    {
        let config = LogConfig {
            level: LogLevel::Verbose,
            quiet: false,
            log_file: Some(temp_file.path().to_path_buf()),
            color: false,
        };
        let logger = Logger::new(config).unwrap();
        logger.verbose("First message");
    }

    // Second write (new logger, same file)
    {
        let config = LogConfig {
            level: LogLevel::Verbose,
            quiet: false,
            log_file: Some(temp_file.path().to_path_buf()),
            color: false,
        };
        let logger = Logger::new(config).unwrap();
        logger.verbose("Second message");
    }

    // Both messages should be in the file
    let content = std::fs::read_to_string(temp_file.path()).unwrap();
    assert!(content.contains("First message"));
    assert!(content.contains("Second message"));
    assert_eq!(content.lines().count(), 2);
}

#[test]
fn test_log_level_ordering() {
    assert!(LogLevel::Normal < LogLevel::Verbose);
    assert!(LogLevel::Verbose < LogLevel::Debug);
    assert!(LogLevel::Debug < LogLevel::Trace);
}

#[test]
fn test_cumulative_levels() {
    // Debug implies verbose
    let debug_config = LogConfig::from_args_and_env(false, true, false, false, None);
    assert!(debug_config.is_verbose());
    assert!(debug_config.is_debug());

    // Trace implies debug and verbose
    let trace_config = LogConfig::from_args_and_env(false, false, true, false, None);
    assert!(trace_config.is_verbose());
    assert!(trace_config.is_debug());
    assert!(trace_config.is_trace());
}

#[test]
fn test_log_level_from_flags_precedence() {
    // Trace takes precedence over all
    assert_eq!(LogLevel::from_flags(true, true, true), LogLevel::Trace);

    // Debug takes precedence over verbose
    assert_eq!(LogLevel::from_flags(true, true, false), LogLevel::Debug);

    // Only verbose
    assert_eq!(LogLevel::from_flags(true, false, false), LogLevel::Verbose);

    // No flags
    assert_eq!(LogLevel::from_flags(false, false, false), LogLevel::Normal);
}

#[test]
fn test_should_log_at_correct_levels() {
    let verbose_config = LogConfig {
        level: LogLevel::Verbose,
        quiet: false,
        log_file: None,
        color: true,
    };

    assert!(verbose_config.should_log(LogLevel::Normal));
    assert!(verbose_config.should_log(LogLevel::Verbose));
    assert!(!verbose_config.should_log(LogLevel::Debug));
    assert!(!verbose_config.should_log(LogLevel::Trace));
}

#[test]
fn test_quiet_prevents_all_logging() {
    let quiet_config = LogConfig {
        level: LogLevel::Trace, // Even at max level
        quiet: true,
        log_file: None,
        color: true,
    };

    assert!(!quiet_config.should_log(LogLevel::Verbose));
    assert!(!quiet_config.should_log(LogLevel::Debug));
    assert!(!quiet_config.should_log(LogLevel::Trace));
}
