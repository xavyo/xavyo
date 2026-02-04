//! xavyo CLI library
//!
//! This library exposes internal modules for integration testing.
//! The main CLI binary is still in main.rs.

// Re-export error types for testing
pub mod error;

// Re-export config module for testing
pub mod config;

// Re-export logging module for testing
pub mod logging;

// Re-export format types for testing
pub mod formats {
    use clap::ValueEnum;

    /// Export format for the export command
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
    pub enum ExportFormat {
        /// YAML format (default)
        #[default]
        Yaml,
        /// JSON format
        Json,
        /// CSV format (requires --resource)
        Csv,
    }

    /// Import format for the apply command
    #[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
    pub enum ImportFormat {
        /// YAML configuration file
        Yaml,
        /// JSON configuration file
        Json,
        /// CSV file (requires --resource)
        Csv,
    }

    /// Resource type for CSV operations
    #[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
    pub enum ResourceType {
        /// Agent configurations
        Agents,
        /// Tool configurations
        Tools,
    }

    /// Detect import format based on file extension
    pub fn detect_format(path: &std::path::Path) -> Result<ImportFormat, String> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("json") => Ok(ImportFormat::Json),
            Some("csv") => Ok(ImportFormat::Csv),
            Some("yaml") | Some("yml") => Ok(ImportFormat::Yaml),
            Some(ext) => Err(format!(
                "Unknown file format '.{}' for '{}'. Use --format to specify.",
                ext,
                path.display()
            )),
            None => Err(format!(
                "Cannot determine format for '{}' (no file extension). Use --format to specify.",
                path.display()
            )),
        }
    }
}

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
    pub mod audit;
    pub mod session;
    pub mod tenant;

    // Re-export types at models level for convenience
    pub use agent::{
        DryRunRotationPreview, NhiCredentialListResponse, NhiCredentialResponse,
        PlannedRotationChanges,
    };
    pub use api_session::{ApiSession, DeviceType, Location, RevokeResponse, SessionListResponse};
    pub use audit::{AuditAction, AuditEntry, AuditFilter, AuditListResponse, AuditUser};
    pub use session::Session;
    pub use tenant::{
        TenantCurrentOutput, TenantInfo, TenantListResponse, TenantRole, TenantSwitchOutput,
        TenantSwitchRequest, TenantSwitchResponse,
    };
}

// Re-export command argument types for testing
// Note: We define a simplified version to avoid internal dependencies
pub mod commands {
    pub mod audit {
        use clap::ValueEnum;

        /// Output format options (matching the internal definition)
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
    }
    pub use audit::OutputFormat;
}

// Re-export diff module types for testing
pub mod diff {
    pub use serde::{Deserialize, Serialize};

    /// Type of resource being compared
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum ResourceType {
        /// AI agent configuration
        Agent,
        /// Tool configuration
        Tool,
    }

    /// Type of change detected
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum ChangeType {
        /// Resource exists in target but not in source
        Added,
        /// Resource exists in both with differences
        Modified,
        /// Resource exists in source but not in target
        Removed,
    }

    /// Represents a single field-level change within a resource
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FieldChange {
        /// Dot-notation path to field
        pub path: String,
        /// Previous value (None if field was added)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub old_value: Option<serde_json::Value>,
        /// New value (None if field was removed)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub new_value: Option<serde_json::Value>,
    }

    /// Represents a single resource difference
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DiffItem {
        /// Type of resource (Agent, Tool)
        pub resource_type: ResourceType,
        /// Resource name/identifier
        pub name: String,
        /// Type of change (Added, Modified, Removed)
        pub change_type: ChangeType,
        /// For modifications, list of changed fields
        #[serde(skip_serializing_if = "Option::is_none")]
        pub field_changes: Option<Vec<FieldChange>>,
    }

    /// Represents the complete result of a configuration comparison
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DiffResult {
        /// Resources present in target but not in source
        pub added: Vec<DiffItem>,
        /// Resources present in both with different values
        pub modified: Vec<DiffItem>,
        /// Resources present in source but not in target
        pub removed: Vec<DiffItem>,
        /// Count of resources that are identical
        #[serde(skip_serializing_if = "is_zero")]
        pub unchanged_count: usize,
        /// Label for source (e.g., "local", "config.yaml")
        pub source_label: String,
        /// Label for target (e.g., "remote", "server")
        pub target_label: String,
    }

    fn is_zero(value: &usize) -> bool {
        *value == 0
    }

    impl DiffResult {
        /// Returns true if any additions, modifications, or removals exist
        pub fn has_changes(&self) -> bool {
            !self.added.is_empty() || !self.modified.is_empty() || !self.removed.is_empty()
        }

        /// Returns count of all changes (added + modified + removed)
        pub fn total_changes(&self) -> usize {
            self.added.len() + self.modified.len() + self.removed.len()
        }
    }

    /// Summary of diff result
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DiffSummary {
        /// Number of added resources
        pub added: usize,
        /// Number of modified resources
        pub modified: usize,
        /// Number of removed resources
        pub removed: usize,
    }

    /// Output format for diff results
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub enum OutputFormat {
        /// Colored table format (default, human-readable)
        #[default]
        Table,
        /// JSON format (machine-readable)
        Json,
        /// YAML format (for config-as-code workflows)
        Yaml,
    }

    /// Exit codes for diff command
    pub const EXIT_NO_CHANGES: i32 = 0;
    pub const EXIT_CHANGES_FOUND: i32 = 1;
    pub const EXIT_ERROR: i32 = 2;
}

// Re-export plugin module for testing
pub mod plugin;

// Re-export proxy module for testing
pub mod proxy;

// Re-export SSO module for testing
pub mod sso;

// Re-export history types for testing
pub mod history {
    pub use chrono::{DateTime, Utc};
    pub use serde::{Deserialize, Serialize};

    /// Summary metadata for quick display without loading full config
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct VersionSummary {
        /// Number of agents in this version
        pub agent_count: usize,
        /// Number of tools in this version
        pub tool_count: usize,
        /// Optional description (e.g., source file name)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
    }

    /// A saved configuration version (simplified for testing)
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConfigVersion {
        /// Sequential version number (1, 2, 3, ...)
        pub version: u32,
        /// When this version was saved (UTC)
        pub timestamp: DateTime<Utc>,
        /// Summary metadata for display
        pub summary: VersionSummary,
    }
}
