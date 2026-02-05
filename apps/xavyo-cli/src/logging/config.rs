//! Logging configuration for CLI verbose/debug output
//!
//! This module provides `LogConfig` for managing logging behavior,
//! including level, quiet mode, log file, and color settings.

use std::path::PathBuf;

use super::level::LogLevel;

/// Environment variable names for logging configuration
pub mod env_vars {
    /// Enable verbose mode (XAVYO_VERBOSE=1)
    pub const VERBOSE: &str = "XAVYO_VERBOSE";
    /// Enable debug mode (XAVYO_DEBUG=1)
    pub const DEBUG: &str = "XAVYO_DEBUG";
    /// Enable trace mode (XAVYO_TRACE=1)
    pub const TRACE: &str = "XAVYO_TRACE";
    /// Path to log file (XAVYO_LOG_FILE=/path/to/file.log)
    pub const LOG_FILE: &str = "XAVYO_LOG_FILE";
    /// Disable color output (NO_COLOR=1)
    pub const NO_COLOR: &str = "NO_COLOR";
}

/// Configuration for logging behavior
///
/// Parsed from CLI flags and environment variables.
/// CLI flags take precedence over environment variables.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Current verbosity level
    pub level: LogLevel,
    /// Suppress all output except errors
    pub quiet: bool,
    /// Path to log file for output (if specified)
    pub log_file: Option<PathBuf>,
    /// Whether to use ANSI colors in output
    pub color: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Normal,
            quiet: false,
            log_file: None,
            color: true,
        }
    }
}

#[allow(dead_code)]
impl LogConfig {
    /// Create LogConfig from CLI arguments and environment variables
    ///
    /// # Arguments
    /// * `verbose` - --verbose/-v flag
    /// * `debug` - --debug flag
    /// * `trace` - --trace flag
    /// * `quiet` - --quiet/-q flag
    /// * `log_file` - --log-file <path> option
    ///
    /// # Precedence
    /// 1. --quiet overrides all verbosity flags
    /// 2. CLI flags override environment variables
    /// 3. Trace > Debug > Verbose > Normal
    pub fn from_args_and_env(
        verbose: bool,
        debug: bool,
        trace: bool,
        quiet: bool,
        log_file: Option<PathBuf>,
    ) -> Self {
        // Check environment variables for level (if no CLI flag)
        let env_trace = std::env::var(env_vars::TRACE).is_ok();
        let env_debug = std::env::var(env_vars::DEBUG).is_ok();
        let env_verbose = std::env::var(env_vars::VERBOSE).is_ok();

        // CLI flags take precedence over env vars
        // If any CLI flag is set, ignore env vars
        let any_cli_flag = verbose || debug || trace;

        let effective_trace = trace || (!any_cli_flag && env_trace);
        let effective_debug = debug || (!any_cli_flag && env_debug);
        let effective_verbose = verbose || (!any_cli_flag && env_verbose);

        let level = LogLevel::from_flags(effective_verbose, effective_debug, effective_trace);

        // Check for log file from env if not specified in CLI
        let effective_log_file =
            log_file.or_else(|| std::env::var(env_vars::LOG_FILE).ok().map(PathBuf::from));

        // Check NO_COLOR environment variable
        let color = std::env::var(env_vars::NO_COLOR).is_err();

        Self {
            level,
            quiet,
            log_file: effective_log_file,
            color,
        }
    }

    /// Check if output should be shown at the given level
    ///
    /// Returns false if quiet mode is enabled.
    pub fn should_log(&self, entry_level: LogLevel) -> bool {
        if self.quiet {
            return false;
        }
        self.level >= entry_level
    }

    /// Check if verbose output is enabled
    pub fn is_verbose(&self) -> bool {
        !self.quiet && self.level.is_verbose()
    }

    /// Check if debug output is enabled
    pub fn is_debug(&self) -> bool {
        !self.quiet && self.level.is_debug()
    }

    /// Check if trace output is enabled
    pub fn is_trace(&self) -> bool {
        !self.quiet && self.level.is_trace()
    }

    /// Get the effective log level (Normal if quiet)
    pub fn effective_level(&self) -> LogLevel {
        if self.quiet {
            LogLevel::Normal
        } else {
            self.level
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    // Global mutex to serialize tests that modify environment variables
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    // Helper to temporarily set environment variables
    struct EnvGuard {
        vars: Vec<(String, Option<String>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn new() -> Self {
            let lock = ENV_MUTEX.lock().unwrap();
            Self {
                vars: Vec::new(),
                _lock: lock,
            }
        }

        fn set(&mut self, key: &str, value: &str) {
            let old = env::var(key).ok();
            self.vars.push((key.to_string(), old));
            env::set_var(key, value);
        }

        fn remove(&mut self, key: &str) {
            let old = env::var(key).ok();
            self.vars.push((key.to_string(), old));
            env::remove_var(key);
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.vars {
                match value {
                    Some(v) => env::set_var(key, v),
                    None => env::remove_var(key),
                }
            }
        }
    }

    #[test]
    fn test_config_default() {
        let config = LogConfig::default();
        assert_eq!(config.level, LogLevel::Normal);
        assert!(!config.quiet);
        assert!(config.log_file.is_none());
        assert!(config.color);
    }

    #[test]
    fn test_config_from_args_verbose() {
        let mut guard = EnvGuard::new();
        guard.remove(env_vars::VERBOSE);
        guard.remove(env_vars::DEBUG);
        guard.remove(env_vars::TRACE);
        guard.remove(env_vars::NO_COLOR);

        let config = LogConfig::from_args_and_env(true, false, false, false, None);
        assert_eq!(config.level, LogLevel::Verbose);
    }

    #[test]
    fn test_config_from_args_debug() {
        let mut guard = EnvGuard::new();
        guard.remove(env_vars::VERBOSE);
        guard.remove(env_vars::DEBUG);
        guard.remove(env_vars::TRACE);
        guard.remove(env_vars::NO_COLOR);

        let config = LogConfig::from_args_and_env(false, true, false, false, None);
        assert_eq!(config.level, LogLevel::Debug);
    }

    #[test]
    fn test_config_from_args_trace() {
        let mut guard = EnvGuard::new();
        guard.remove(env_vars::VERBOSE);
        guard.remove(env_vars::DEBUG);
        guard.remove(env_vars::TRACE);
        guard.remove(env_vars::NO_COLOR);

        let config = LogConfig::from_args_and_env(false, false, true, false, None);
        assert_eq!(config.level, LogLevel::Trace);
    }

    #[test]
    fn test_config_from_env_verbose() {
        let mut guard = EnvGuard::new();
        guard.set(env_vars::VERBOSE, "1");
        guard.remove(env_vars::DEBUG);
        guard.remove(env_vars::TRACE);
        guard.remove(env_vars::NO_COLOR);

        let config = LogConfig::from_args_and_env(false, false, false, false, None);
        assert_eq!(config.level, LogLevel::Verbose);
    }

    #[test]
    fn test_config_from_env_debug() {
        let mut guard = EnvGuard::new();
        guard.remove(env_vars::VERBOSE);
        guard.set(env_vars::DEBUG, "1");
        guard.remove(env_vars::TRACE);
        guard.remove(env_vars::NO_COLOR);

        let config = LogConfig::from_args_and_env(false, false, false, false, None);
        assert_eq!(config.level, LogLevel::Debug);
    }

    #[test]
    fn test_config_from_env_trace() {
        let mut guard = EnvGuard::new();
        guard.remove(env_vars::VERBOSE);
        guard.remove(env_vars::DEBUG);
        guard.set(env_vars::TRACE, "1");
        guard.remove(env_vars::NO_COLOR);

        let config = LogConfig::from_args_and_env(false, false, false, false, None);
        assert_eq!(config.level, LogLevel::Trace);
    }

    #[test]
    fn test_config_cli_overrides_env() {
        let mut guard = EnvGuard::new();
        guard.set(env_vars::VERBOSE, "1");
        guard.remove(env_vars::DEBUG);
        guard.remove(env_vars::TRACE);
        guard.remove(env_vars::NO_COLOR);

        // CLI debug should override env verbose
        let config = LogConfig::from_args_and_env(false, true, false, false, None);
        assert_eq!(config.level, LogLevel::Debug);
    }

    #[test]
    fn test_config_quiet_mode() {
        let mut guard = EnvGuard::new();
        guard.remove(env_vars::VERBOSE);
        guard.remove(env_vars::DEBUG);
        guard.remove(env_vars::TRACE);
        guard.remove(env_vars::NO_COLOR);

        let config = LogConfig::from_args_and_env(true, false, false, true, None);
        assert!(config.quiet);
        assert!(!config.is_verbose());
    }

    #[test]
    fn test_config_log_file_from_args() {
        let mut guard = EnvGuard::new();
        guard.remove(env_vars::VERBOSE);
        guard.remove(env_vars::DEBUG);
        guard.remove(env_vars::TRACE);
        guard.remove(env_vars::NO_COLOR);
        guard.remove(env_vars::LOG_FILE);

        let path = PathBuf::from("/tmp/test.log");
        let config = LogConfig::from_args_and_env(false, false, false, false, Some(path.clone()));
        assert_eq!(config.log_file, Some(path));
    }

    #[test]
    fn test_config_log_file_from_env() {
        let mut guard = EnvGuard::new();
        guard.remove(env_vars::VERBOSE);
        guard.remove(env_vars::DEBUG);
        guard.remove(env_vars::TRACE);
        guard.remove(env_vars::NO_COLOR);
        guard.set(env_vars::LOG_FILE, "/tmp/env-test.log");

        let config = LogConfig::from_args_and_env(false, false, false, false, None);
        assert_eq!(config.log_file, Some(PathBuf::from("/tmp/env-test.log")));
    }

    #[test]
    fn test_config_no_color() {
        let mut guard = EnvGuard::new();
        guard.remove(env_vars::VERBOSE);
        guard.remove(env_vars::DEBUG);
        guard.remove(env_vars::TRACE);
        guard.set(env_vars::NO_COLOR, "1");

        let config = LogConfig::from_args_and_env(false, false, false, false, None);
        assert!(!config.color);
    }

    #[test]
    fn test_should_log() {
        let mut guard = EnvGuard::new();
        guard.remove(env_vars::VERBOSE);
        guard.remove(env_vars::DEBUG);
        guard.remove(env_vars::TRACE);
        guard.remove(env_vars::NO_COLOR);

        let config = LogConfig::from_args_and_env(false, true, false, false, None);

        assert!(config.should_log(LogLevel::Normal));
        assert!(config.should_log(LogLevel::Verbose));
        assert!(config.should_log(LogLevel::Debug));
        assert!(!config.should_log(LogLevel::Trace));
    }

    #[test]
    fn test_should_log_quiet() {
        let mut guard = EnvGuard::new();
        guard.remove(env_vars::VERBOSE);
        guard.remove(env_vars::DEBUG);
        guard.remove(env_vars::TRACE);
        guard.remove(env_vars::NO_COLOR);

        let config = LogConfig::from_args_and_env(true, false, false, true, None);

        assert!(!config.should_log(LogLevel::Verbose));
    }

    #[test]
    fn test_effective_level() {
        let mut guard = EnvGuard::new();
        guard.remove(env_vars::VERBOSE);
        guard.remove(env_vars::DEBUG);
        guard.remove(env_vars::TRACE);
        guard.remove(env_vars::NO_COLOR);

        let config = LogConfig::from_args_and_env(true, false, false, false, None);
        assert_eq!(config.effective_level(), LogLevel::Verbose);

        let quiet_config = LogConfig::from_args_and_env(true, false, false, true, None);
        assert_eq!(quiet_config.effective_level(), LogLevel::Normal);
    }
}
