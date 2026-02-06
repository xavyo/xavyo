//! Log level definitions for CLI verbose/debug output
//!
//! This module provides the `LogLevel` enum for controlling CLI output verbosity.
//! Levels are cumulative: Debug includes Verbose, Trace includes Debug.

use std::fmt;

/// Verbosity level for CLI output
///
/// Levels are ordered: Normal < Verbose < Debug < Trace
/// Higher levels include all output from lower levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum LogLevel {
    /// Standard CLI output only (default)
    #[default]
    Normal = 0,
    /// Progress messages for each operation
    Verbose = 1,
    /// HTTP method, URL, status code, timing
    Debug = 2,
    /// Full request/response headers and bodies
    Trace = 3,
}

impl LogLevel {
    /// Create LogLevel from CLI flags
    ///
    /// Returns the highest level specified by flags.
    /// Order of precedence: trace > debug > verbose > normal
    pub fn from_flags(verbose: bool, debug: bool, trace: bool) -> Self {
        if trace {
            Self::Trace
        } else if debug {
            Self::Debug
        } else if verbose {
            Self::Verbose
        } else {
            Self::Normal
        }
    }

    /// Check if this level enables verbose output
    pub fn is_verbose(&self) -> bool {
        *self >= Self::Verbose
    }

    /// Check if this level enables debug output
    pub fn is_debug(&self) -> bool {
        *self >= Self::Debug
    }

    /// Check if this level enables trace output
    pub fn is_trace(&self) -> bool {
        *self >= Self::Trace
    }

    /// Get the display name for this level
    pub fn name(&self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Verbose => "VERBOSE",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Normal < LogLevel::Verbose);
        assert!(LogLevel::Verbose < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Trace);
    }

    #[test]
    fn test_log_level_from_flags_normal() {
        let level = LogLevel::from_flags(false, false, false);
        assert_eq!(level, LogLevel::Normal);
    }

    #[test]
    fn test_log_level_from_flags_verbose() {
        let level = LogLevel::from_flags(true, false, false);
        assert_eq!(level, LogLevel::Verbose);
    }

    #[test]
    fn test_log_level_from_flags_debug() {
        let level = LogLevel::from_flags(false, true, false);
        assert_eq!(level, LogLevel::Debug);
    }

    #[test]
    fn test_log_level_from_flags_trace() {
        let level = LogLevel::from_flags(false, false, true);
        assert_eq!(level, LogLevel::Trace);
    }

    #[test]
    fn test_log_level_from_flags_trace_takes_precedence() {
        let level = LogLevel::from_flags(true, true, true);
        assert_eq!(level, LogLevel::Trace);
    }

    #[test]
    fn test_log_level_from_flags_debug_over_verbose() {
        let level = LogLevel::from_flags(true, true, false);
        assert_eq!(level, LogLevel::Debug);
    }

    #[test]
    fn test_is_verbose() {
        assert!(!LogLevel::Normal.is_verbose());
        assert!(LogLevel::Verbose.is_verbose());
        assert!(LogLevel::Debug.is_verbose());
        assert!(LogLevel::Trace.is_verbose());
    }

    #[test]
    fn test_is_debug() {
        assert!(!LogLevel::Normal.is_debug());
        assert!(!LogLevel::Verbose.is_debug());
        assert!(LogLevel::Debug.is_debug());
        assert!(LogLevel::Trace.is_debug());
    }

    #[test]
    fn test_is_trace() {
        assert!(!LogLevel::Normal.is_trace());
        assert!(!LogLevel::Verbose.is_trace());
        assert!(!LogLevel::Debug.is_trace());
        assert!(LogLevel::Trace.is_trace());
    }

    #[test]
    fn test_log_level_display() {
        assert_eq!(format!("{}", LogLevel::Normal), "NORMAL");
        assert_eq!(format!("{}", LogLevel::Verbose), "VERBOSE");
        assert_eq!(format!("{}", LogLevel::Debug), "DEBUG");
        assert_eq!(format!("{}", LogLevel::Trace), "TRACE");
    }

    #[test]
    fn test_log_level_default() {
        let level: LogLevel = Default::default();
        assert_eq!(level, LogLevel::Normal);
    }
}
