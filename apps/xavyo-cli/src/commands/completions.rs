//! Generate shell completions for the xavyo CLI
//!
//! This module provides shell completion script generation for bash, zsh, and fish shells.
//! Users can install completions by adding the output to their shell configuration.
//!
//! # Examples
//!
//! ## Bash
//! ```bash
//! # Add to ~/.bashrc for persistent completions
//! eval "$(xavyo completions bash)"
//!
//! # Or save to a file
//! xavyo completions bash > ~/.local/share/bash-completion/completions/xavyo
//! ```
//!
//! ## Zsh
//! ```bash
//! # Add to ~/.zshrc for persistent completions
//! eval "$(xavyo completions zsh)"
//!
//! # Or save to completions directory (add to fpath first)
//! xavyo completions zsh > ~/.zsh/completions/_xavyo
//! ```
//!
//! ## Fish
//! ```fish
//! # Source directly
//! xavyo completions fish | source
//!
//! # Or save permanently
//! xavyo completions fish > ~/.config/fish/completions/xavyo.fish
//! ```

use clap::{Args, CommandFactory, ValueEnum};
use clap_complete::{generate, Shell as ClapShell};
use std::io;

/// Supported shell types for completion generation
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Shell {
    /// Generate completions for Bash
    Bash,
    /// Generate completions for Zsh
    Zsh,
    /// Generate completions for Fish
    Fish,
}

impl Shell {
    /// Convert to `clap_complete` Shell type
    fn to_clap_shell(self) -> ClapShell {
        match self {
            Shell::Bash => ClapShell::Bash,
            Shell::Zsh => ClapShell::Zsh,
            Shell::Fish => ClapShell::Fish,
        }
    }
}

/// Generate shell completion scripts
///
/// Outputs a completion script for the specified shell to stdout.
/// The script can be sourced in your shell configuration to enable
/// tab completion for all xavyo commands, subcommands, and flags.
///
/// # Installation
///
/// ## Bash
///
/// Add to ~/.bashrc:
///   eval "$(xavyo completions bash)"
///
/// Or save to completions directory:
///   xavyo completions bash > ~/.local/share/bash-completion/completions/xavyo
///
/// ## Zsh
///
/// Add to ~/.zshrc:
///   eval "$(xavyo completions zsh)"
///
/// Or save to completions directory (ensure it's in fpath):
///   mkdir -p ~/.zsh/completions
///   xavyo completions zsh > ~/.zsh/completions/_xavyo
///   # Add to .zshrc: fpath=(~/.zsh/completions $fpath)
///
/// ## Fish
///
/// Source directly:
///   xavyo completions fish | source
///
/// Or save permanently:
///   xavyo completions fish > ~/.config/fish/completions/xavyo.fish
#[derive(Args, Debug)]
pub struct CompletionsArgs {
    /// The shell to generate completions for
    #[arg(value_enum)]
    pub shell: Shell,
}

/// Execute the completions command
pub fn execute(args: CompletionsArgs) -> crate::error::CliResult<()> {
    print_completions(args.shell);
    Ok(())
}

/// Generate and print completion script to stdout
fn print_completions(shell: Shell) {
    let mut cmd = crate::Cli::command();
    let bin_name = cmd.get_name().to_string();
    generate(shell.to_clap_shell(), &mut cmd, bin_name, &mut io::stdout());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_enum_from_str() {
        // Test that Shell enum can be parsed from strings (used by clap)
        assert!(matches!(Shell::from_str("bash", true), Ok(Shell::Bash)));
        assert!(matches!(Shell::from_str("zsh", true), Ok(Shell::Zsh)));
        assert!(matches!(Shell::from_str("fish", true), Ok(Shell::Fish)));
    }

    #[test]
    fn test_shell_enum_case_insensitive() {
        // Test case-insensitive parsing
        assert!(matches!(Shell::from_str("BASH", true), Ok(Shell::Bash)));
        assert!(matches!(Shell::from_str("Zsh", true), Ok(Shell::Zsh)));
        assert!(matches!(Shell::from_str("FISH", true), Ok(Shell::Fish)));
    }

    #[test]
    fn test_shell_to_clap_shell() {
        // Test conversion to clap_complete Shell type
        assert!(matches!(Shell::Bash.to_clap_shell(), ClapShell::Bash));
        assert!(matches!(Shell::Zsh.to_clap_shell(), ClapShell::Zsh));
        assert!(matches!(Shell::Fish.to_clap_shell(), ClapShell::Fish));
    }

    #[test]
    fn test_invalid_shell_rejected() {
        // Test that invalid shell names are rejected
        assert!(Shell::from_str("powershell", true).is_err());
        assert!(Shell::from_str("cmd", true).is_err());
        assert!(Shell::from_str("invalid", true).is_err());
    }

    #[test]
    fn test_completion_generation_bash() {
        // Test that bash completions can be generated (non-empty output)
        let mut output = Vec::new();
        let mut cmd = crate::Cli::command();
        generate(ClapShell::Bash, &mut cmd, "xavyo", &mut output);

        let script = String::from_utf8(output).expect("valid UTF-8");
        assert!(
            !script.is_empty(),
            "Bash completion script should not be empty"
        );
        assert!(
            script.contains("xavyo"),
            "Script should contain binary name"
        );
        assert!(
            script.contains("complete"),
            "Bash script should use complete builtin"
        );
    }

    #[test]
    fn test_completion_generation_zsh() {
        // Test that zsh completions can be generated (non-empty output)
        let mut output = Vec::new();
        let mut cmd = crate::Cli::command();
        generate(ClapShell::Zsh, &mut cmd, "xavyo", &mut output);

        let script = String::from_utf8(output).expect("valid UTF-8");
        assert!(
            !script.is_empty(),
            "Zsh completion script should not be empty"
        );
        assert!(
            script.contains("xavyo"),
            "Script should contain binary name"
        );
        assert!(
            script.contains("#compdef"),
            "Zsh script should have #compdef directive"
        );
    }

    #[test]
    fn test_completion_generation_fish() {
        // Test that fish completions can be generated (non-empty output)
        let mut output = Vec::new();
        let mut cmd = crate::Cli::command();
        generate(ClapShell::Fish, &mut cmd, "xavyo", &mut output);

        let script = String::from_utf8(output).expect("valid UTF-8");
        assert!(
            !script.is_empty(),
            "Fish completion script should not be empty"
        );
        assert!(
            script.contains("xavyo"),
            "Script should contain binary name"
        );
        assert!(
            script.contains("complete"),
            "Fish script should use complete command"
        );
    }

    #[test]
    fn test_completions_include_all_commands() {
        // Test that completions include expected commands
        let mut output = Vec::new();
        let mut cmd = crate::Cli::command();
        generate(ClapShell::Bash, &mut cmd, "xavyo", &mut output);

        let script = String::from_utf8(output).expect("valid UTF-8");

        // Check for main commands
        let expected_commands = [
            "login",
            "logout",
            "whoami",
            "init",
            "status",
            "agents",
            "tools",
            "authorize",
            "doctor",
            "apply",
            "export",
            "completions",
        ];

        for cmd_name in expected_commands {
            assert!(
                script.contains(cmd_name),
                "Completion script should include '{cmd_name}' command"
            );
        }
    }
}
