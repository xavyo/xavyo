//! Shared prompt helpers for interactive CLI commands.
//!
//! This module provides reusable utilities for TTY detection and
//! interactive prompts using dialoguer.

use std::io::IsTerminal;

use dialoguer::{Confirm, Input, Select};

use crate::error::{CliError, CliResult};

/// Checks if both stdin and stdout are connected to a terminal.
///
/// Returns `true` if running in an interactive TTY environment,
/// `false` if running in a pipe or CI environment.
pub fn is_interactive_terminal() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Requires an interactive terminal, returning an error if not available.
///
/// Use this at the start of interactive command handlers to fail early
/// with a helpful error message suggesting explicit flags for scripting.
pub fn require_interactive() -> CliResult<()> {
    if !is_interactive_terminal() {
        return Err(CliError::Validation(
            "Interactive mode requires a terminal.\n\
             Use explicit flags for scripting.\n\
             Run with --help for all options."
                .into(),
        ));
    }
    Ok(())
}

/// Prompts for text input with validation.
///
/// Loops until valid input is provided or the user cancels.
///
/// # Arguments
/// * `prompt` - The prompt message to display
/// * `validator` - A function that returns `Ok(())` if valid, `Err(message)` if invalid
pub fn prompt_text<F>(prompt: &str, validator: F) -> CliResult<String>
where
    F: Fn(&str) -> Result<(), String> + Clone,
{
    loop {
        let input: String = Input::new()
            .with_prompt(prompt)
            .interact_text()
            .map_err(|e| CliError::Io(e.to_string()))?;

        match validator(&input) {
            Ok(()) => return Ok(input),
            Err(msg) => {
                eprintln!("Error: {}", msg);
                // Loop continues for retry
            }
        }
    }
}

/// Prompts for optional text input.
///
/// Returns `None` if the user provides empty input.
pub fn prompt_text_optional(prompt: &str) -> CliResult<Option<String>> {
    let input: String = Input::new()
        .with_prompt(prompt)
        .allow_empty(true)
        .interact_text()
        .map_err(|e| CliError::Io(e.to_string()))?;

    if input.trim().is_empty() {
        Ok(None)
    } else {
        Ok(Some(input))
    }
}

/// Prompts for single selection from a list of options.
///
/// # Arguments
/// * `prompt` - The prompt message to display
/// * `options` - Slice of display strings for the options
/// * `default` - Default selection index (0-based)
///
/// # Returns
/// The index of the selected option.
pub fn prompt_select(prompt: &str, options: &[String], default: usize) -> CliResult<usize> {
    Select::new()
        .with_prompt(prompt)
        .items(options)
        .default(default)
        .interact()
        .map_err(|e| CliError::Io(e.to_string()))
}

/// Prompts for multi-selection with checkboxes.
///
/// # Arguments
/// * `prompt` - The prompt message to display
/// * `options` - Slice of display strings for the options
///
/// # Returns
/// A vector of indices for selected options.
pub fn prompt_multiselect(prompt: &str, options: &[String]) -> CliResult<Vec<usize>> {
    dialoguer::MultiSelect::new()
        .with_prompt(prompt)
        .items(options)
        .interact()
        .map_err(|e| CliError::Io(e.to_string()))
}

/// Prompts for yes/no confirmation.
///
/// # Arguments
/// * `prompt` - The prompt message to display
/// * `default` - Default value (true for yes, false for no)
///
/// # Returns
/// `true` if confirmed, `false` if declined.
pub fn prompt_confirm(prompt: &str, default: bool) -> CliResult<bool> {
    Confirm::new()
        .with_prompt(prompt)
        .default(default)
        .interact()
        .map_err(|e| CliError::Io(e.to_string()))
}

/// Agent type option with description for interactive selection.
#[derive(Debug, Clone)]
pub struct AgentTypeOption {
    pub value: &'static str,
    pub description: &'static str,
}

impl std::fmt::Display for AgentTypeOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:<12} - {}", self.value, self.description)
    }
}

/// Available agent type options for interactive creation.
pub const AGENT_TYPE_OPTIONS: &[AgentTypeOption] = &[
    AgentTypeOption {
        value: "copilot",
        description: "AI assistant that works alongside users",
    },
    AgentTypeOption {
        value: "autonomous",
        description: "Self-directed agent for automated tasks",
    },
    AgentTypeOption {
        value: "workflow",
        description: "Agent that orchestrates multi-step processes",
    },
    AgentTypeOption {
        value: "orchestrator",
        description: "Agent that coordinates other agents",
    },
];

/// Risk level option with description for interactive selection.
#[derive(Debug, Clone)]
pub struct RiskLevelOption {
    pub value: &'static str,
    pub description: &'static str,
}

impl std::fmt::Display for RiskLevelOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:<8} - {}", self.value, self.description)
    }
}

/// Available risk level options for interactive creation.
pub const RISK_LEVEL_OPTIONS: &[RiskLevelOption] = &[
    RiskLevelOption {
        value: "low",
        description: "Read-only access, minimal impact",
    },
    RiskLevelOption {
        value: "medium",
        description: "Limited write access, moderate impact",
    },
    RiskLevelOption {
        value: "high",
        description: "Broad access, significant impact potential",
    },
    RiskLevelOption {
        value: "critical",
        description: "Full access, critical system impact",
    },
];

/// Grace period option with description for credential rotation.
#[derive(Debug, Clone)]
pub struct GracePeriodOption {
    pub hours: i32,
    pub label: &'static str,
    pub description: &'static str,
}

impl std::fmt::Display for GracePeriodOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:<10} - {}", self.label, self.description)
    }
}

/// Available grace period options for credential rotation.
pub const GRACE_PERIOD_OPTIONS: &[GracePeriodOption] = &[
    GracePeriodOption {
        hours: 0,
        label: "Immediate",
        description: "Old credential invalidated instantly",
    },
    GracePeriodOption {
        hours: 1,
        label: "1 hour",
        description: "Brief window for key rotation",
    },
    GracePeriodOption {
        hours: 24,
        label: "24 hours",
        description: "Standard rotation window (default)",
    },
    GracePeriodOption {
        hours: 72,
        label: "3 days",
        description: "Extended window for large deployments",
    },
    GracePeriodOption {
        hours: 168,
        label: "1 week",
        description: "Maximum allowed grace period",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_interactive_terminal_returns_bool() {
        // This test verifies the function compiles and returns a boolean.
        // In test environment, it's typically not a TTY, so we just verify the return type.
        let result = is_interactive_terminal();
        // Result should be false in test environment (not a real TTY)
        let _: bool = result; // Verifies bool type
    }

    #[test]
    fn test_require_interactive_fails_in_test_environment() {
        // Tests typically run without a TTY, so this should fail
        let result = require_interactive();
        // In CI/test environment, this should return an error
        // but we can't guarantee the test environment, so we just verify it doesn't panic
        match result {
            Ok(()) => {
                // Running in a real terminal (rare in tests)
            }
            Err(CliError::Validation(msg)) => {
                assert!(msg.contains("Interactive mode requires a terminal"));
            }
            Err(_) => panic!("Unexpected error type"),
        }
    }

    #[test]
    fn test_agent_type_options_display() {
        let option = &AGENT_TYPE_OPTIONS[0];
        let display = format!("{}", option);
        assert!(display.contains("copilot"));
        assert!(display.contains("AI assistant"));
    }

    #[test]
    fn test_risk_level_options_display() {
        let option = &RISK_LEVEL_OPTIONS[1];
        let display = format!("{}", option);
        assert!(display.contains("medium"));
        assert!(display.contains("Limited write access"));
    }

    #[test]
    fn test_grace_period_options_have_descriptions() {
        for option in GRACE_PERIOD_OPTIONS {
            assert!(!option.description.is_empty());
            assert!(!option.label.is_empty());
            let display = format!("{}", option);
            assert!(display.contains(option.label));
            assert!(display.contains(option.description));
        }
    }

    #[test]
    fn test_agent_type_options_count() {
        assert_eq!(AGENT_TYPE_OPTIONS.len(), 4);
    }

    #[test]
    fn test_risk_level_options_count() {
        assert_eq!(RISK_LEVEL_OPTIONS.len(), 4);
    }

    #[test]
    fn test_grace_period_options_count() {
        assert_eq!(GRACE_PERIOD_OPTIONS.len(), 5);
    }
}
