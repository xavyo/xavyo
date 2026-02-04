//! Command execution for the interactive shell
//!
//! Handles parsing and executing commands entered in the REPL,
//! including shell-specific commands like exit, quit, and help.

use crate::error::{CliError, CliResult};
use crate::repl::ShellSession;
use clap::Command;
use std::process::Stdio;

/// Result of executing a command in the shell
#[derive(Debug, PartialEq, Eq)]
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
    /// The clap Command for introspection and help
    cli_command: Command,
}

impl CommandExecutor {
    /// Create a new command executor
    pub fn new(cli_command: Command) -> Self {
        Self { cli_command }
    }

    /// Execute a command line entered by the user
    pub async fn execute(
        &self,
        line: &str,
        session: &mut ShellSession,
    ) -> CliResult<ExecuteResult> {
        let line = line.trim();

        // Handle empty input
        if line.is_empty() {
            return Ok(ExecuteResult::Empty);
        }

        // Handle shell-specific commands
        if self.is_exit_command(line) {
            return Ok(ExecuteResult::Exit);
        }

        if self.is_help_command(line) {
            self.show_help(line)?;
            return Ok(ExecuteResult::Continue);
        }

        // Execute the command through the CLI
        self.execute_cli_command(line, session).await?;

        Ok(ExecuteResult::Continue)
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

    /// Show help for the shell or a specific command
    fn show_help(&self, line: &str) -> CliResult<()> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() <= 1 {
            // General help
            self.show_general_help();
        } else {
            // Command-specific help
            let cmd_name = parts[1];
            self.show_command_help(cmd_name)?;
        }

        Ok(())
    }

    /// Show general help listing all available commands
    fn show_general_help(&self) {
        println!("Available commands:");
        println!();

        // List subcommands from clap
        for subcommand in self.cli_command.get_subcommands() {
            let name = subcommand.get_name();
            let about = subcommand
                .get_about()
                .map(|s| s.to_string())
                .unwrap_or_default();
            println!("  {:<14} {}", name, about);
        }

        println!();
        println!("Shell commands:");
        println!("  help <cmd>    Show help for a command");
        println!("  ?             Alias for help");
        println!("  exit/quit     Exit the shell");
        println!();
        println!("Type 'help <command>' for detailed help on a specific command.");
    }

    /// Show help for a specific command
    fn show_command_help(&self, cmd_name: &str) -> CliResult<()> {
        // Find the subcommand
        let subcommand = self
            .cli_command
            .get_subcommands()
            .find(|c| c.get_name() == cmd_name);

        match subcommand {
            Some(cmd) => {
                let name = cmd.get_name();
                let about = cmd
                    .get_about()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "No description available".to_string());

                println!("{} - {}", name, about);
                println!();

                // Show subcommands if any
                let subcommands: Vec<_> = cmd.get_subcommands().collect();
                if !subcommands.is_empty() {
                    println!("Subcommands:");
                    for subcmd in subcommands {
                        let subcmd_name = subcmd.get_name();
                        let subcmd_about = subcmd
                            .get_about()
                            .map(|s| s.to_string())
                            .unwrap_or_default();
                        println!("  {:<12} {}", subcmd_name, subcmd_about);
                    }
                    println!();
                }

                // Show common flags
                println!("Use '{} --help' for detailed usage information.", name);

                Ok(())
            }
            None => {
                println!("Unknown command: '{}'", cmd_name);
                println!("Type 'help' to see available commands.");
                Ok(())
            }
        }
    }

    /// Execute a CLI command by spawning a subprocess
    async fn execute_cli_command(&self, line: &str, session: &mut ShellSession) -> CliResult<()> {
        // Parse the command line into arguments
        let args = self.parse_args(line)?;

        if args.is_empty() {
            return Ok(());
        }

        // Get the current executable path
        let exe_path = std::env::current_exe()
            .map_err(|e| CliError::Config(format!("Could not determine executable path: {}", e)))?;

        // Execute the command as a subprocess
        let mut child = std::process::Command::new(&exe_path)
            .args(&args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| CliError::Io(format!("Failed to execute command: {}", e)))?;

        let status = child
            .wait()
            .map_err(|e| CliError::Io(format!("Failed to wait for command: {}", e)))?;

        if !status.success() {
            // Command failed, but don't exit the shell
            // The error message was already printed by the subprocess
        }

        // Check if the command might have changed auth state
        let first_arg = args.first().map(|s| s.as_str()).unwrap_or("");
        if matches!(first_arg, "login" | "logout") {
            // Reload auth state after login/logout
            session.reload_auth_state()?;
        }

        Ok(())
    }

    /// Parse a command line into arguments, respecting quotes
    fn parse_args(&self, line: &str) -> CliResult<Vec<String>> {
        let mut args = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut quote_char = '"';
        let mut escape_next = false;

        for c in line.chars() {
            if escape_next {
                current.push(c);
                escape_next = false;
                continue;
            }

            if c == '\\' {
                escape_next = true;
                continue;
            }

            if c == '"' || c == '\'' {
                if in_quotes && c == quote_char {
                    in_quotes = false;
                } else if !in_quotes {
                    in_quotes = true;
                    quote_char = c;
                } else {
                    current.push(c);
                }
                continue;
            }

            if c.is_whitespace() && !in_quotes {
                if !current.is_empty() {
                    args.push(current);
                    current = String::new();
                }
                continue;
            }

            current.push(c);
        }

        if !current.is_empty() {
            args.push(current);
        }

        if in_quotes {
            return Err(CliError::Validation(
                "Unclosed quote in command".to_string(),
            ));
        }

        Ok(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_executor() -> CommandExecutor {
        let cmd = Command::new("xavyo")
            .subcommand(Command::new("agents").about("Manage AI agents"))
            .subcommand(Command::new("tools").about("Manage tools"))
            .subcommand(Command::new("login").about("Authenticate"))
            .subcommand(Command::new("logout").about("Clear credentials"))
            .subcommand(Command::new("whoami").about("Show current identity"));
        CommandExecutor::new(cmd)
    }

    #[test]
    fn test_is_exit_command() {
        let executor = create_test_executor();

        assert!(executor.is_exit_command("exit"));
        assert!(executor.is_exit_command("EXIT"));
        assert!(executor.is_exit_command("  exit  "));
        assert!(executor.is_exit_command("quit"));
        assert!(executor.is_exit_command("QUIT"));
        assert!(executor.is_exit_command("q"));

        assert!(!executor.is_exit_command("exit now"));
        assert!(!executor.is_exit_command("agents"));
        assert!(!executor.is_exit_command(""));
    }

    #[test]
    fn test_is_help_command() {
        let executor = create_test_executor();

        assert!(executor.is_help_command("help"));
        assert!(executor.is_help_command("HELP"));
        assert!(executor.is_help_command("?"));
        assert!(executor.is_help_command("help agents"));
        assert!(executor.is_help_command("? agents"));

        assert!(!executor.is_help_command("agents help"));
        assert!(!executor.is_help_command("agents"));
        assert!(!executor.is_help_command(""));
    }

    #[test]
    fn test_parse_args_simple() {
        let executor = create_test_executor();

        let args = executor.parse_args("agents list").unwrap();
        assert_eq!(args, vec!["agents", "list"]);
    }

    #[test]
    fn test_parse_args_with_quotes() {
        let executor = create_test_executor();

        let args = executor
            .parse_args(r#"agents create --name "My Agent""#)
            .unwrap();
        assert_eq!(args, vec!["agents", "create", "--name", "My Agent"]);
    }

    #[test]
    fn test_parse_args_with_single_quotes() {
        let executor = create_test_executor();

        let args = executor
            .parse_args("agents create --name 'My Agent'")
            .unwrap();
        assert_eq!(args, vec!["agents", "create", "--name", "My Agent"]);
    }

    #[test]
    fn test_parse_args_empty() {
        let executor = create_test_executor();

        let args = executor.parse_args("").unwrap();
        assert!(args.is_empty());

        let args = executor.parse_args("   ").unwrap();
        assert!(args.is_empty());
    }

    #[test]
    fn test_parse_args_unclosed_quote() {
        let executor = create_test_executor();

        let result = executor.parse_args(r#"agents create --name "My Agent"#);
        assert!(result.is_err());
    }
}
