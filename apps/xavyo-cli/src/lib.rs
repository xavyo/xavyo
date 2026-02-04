//! xavyo CLI library
//!
//! This library exposes internal modules for integration testing.
//! The main CLI binary is still in main.rs.

// Re-export error types for testing
pub mod error;

// Re-export config module for testing
pub mod config;

/// REPL exports for testing
/// These are standalone types that don't require the full module tree
pub mod repl {
    use clap::Command;

    /// Result of executing a command in the shell
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum ExecuteResult {
        /// Command executed successfully, continue REPL
        Continue,
        /// User requested exit
        Exit,
        /// Empty input, just show new prompt
        Empty,
    }

    /// Command executor for the interactive shell
    pub struct CommandExecutor {
        #[allow(dead_code)]
        cli_command: Command,
    }

    impl CommandExecutor {
        /// Create a new command executor
        pub fn new(cli_command: Command) -> Self {
            Self { cli_command }
        }

        /// Check if the input is an exit command
        pub fn is_exit_command(&self, line: &str) -> bool {
            let cmd = line.trim().to_lowercase();
            matches!(cmd.as_str(), "exit" | "quit" | "q")
        }

        /// Check if the input is a help command
        pub fn is_help_command(&self, line: &str) -> bool {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                return false;
            }
            matches!(parts[0].to_lowercase().as_str(), "help" | "?")
        }
    }

    /// Shell session for integration tests
    pub struct ShellSession {
        /// Current tenant name from credentials
        pub tenant_name: Option<String>,
        /// Current user email from credentials
        pub user_email: Option<String>,
        /// Whether user has valid credentials
        pub is_authenticated: bool,
        /// Whether shell is in offline mode
        pub is_offline: bool,
    }

    impl ShellSession {
        /// Create a new unauthenticated shell session for testing
        pub fn new(paths: crate::config::ConfigPaths) -> Result<Self, crate::error::CliError> {
            let _ = paths; // Paths not used in test-only implementation
            Ok(Self {
                tenant_name: None,
                user_email: None,
                is_authenticated: false,
                is_offline: false,
            })
        }

        /// Check if the user has valid authentication
        pub fn is_authenticated(&self) -> bool {
            self.is_authenticated
        }

        /// Get the display name for the prompt
        pub fn prompt_context(&self) -> String {
            if let Some(ref tenant) = self.tenant_name {
                tenant.clone()
            } else if self.is_authenticated {
                "(no tenant)".to_string()
            } else {
                "(not logged in)".to_string()
            }
        }
    }

    /// Prompt generator for testing
    pub struct Prompt;

    impl Prompt {
        /// Generate the prompt string
        pub fn generate(session: &ShellSession) -> String {
            let context = session.prompt_context();
            let offline_suffix = if session.is_offline { " (offline)" } else { "" };
            format!("xavyo [{}]{offline_suffix}> ", context)
        }
    }

    /// Tab completion for testing
    pub struct Completer {
        _private: (),
    }

    impl Completer {
        /// Create a new completer from a clap Command
        pub fn new(_command: Command) -> Self {
            Self { _private: () }
        }
    }
}

// Re-export batch result types for testing (no internal dependencies)
#[path = "batch/result.rs"]
pub mod batch_result;

// Re-export batch types at a convenient namespace
pub mod batch {
    pub use super::batch_result::*;
}

// Re-export selected model types for testing
// We can't expose the full models module because some models have internal dependencies
#[path = "models"]
pub mod models {
    pub mod agent;
    pub mod api_session;

    // Re-export types at models level for convenience
    pub use agent::{
        DryRunRotationPreview, NhiCredentialListResponse, NhiCredentialResponse,
        PlannedRotationChanges,
    };
    pub use api_session::{ApiSession, DeviceType, Location, RevokeResponse, SessionListResponse};
}
