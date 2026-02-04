//! Interactive shell command
//!
//! Provides a REPL (Read-Eval-Print-Loop) interface for executing
//! multiple xavyo commands in sequence with tab completion and history.

use crate::config::ConfigPaths;
use crate::error::{CliError, CliResult};
use crate::repl::{CommandExecutor, ExecuteResult, Prompt, ShellSession};
use clap::{Args, Command, CommandFactory};
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::history::FileHistory;
use rustyline::Editor;

/// Arguments for the shell command
#[derive(Args, Debug)]
pub struct ShellArgs {
    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,
}

/// Execute the shell command
pub async fn execute(args: ShellArgs) -> CliResult<()> {
    // Check if running in a TTY
    if !atty::is(atty::Stream::Stdin) {
        return Err(CliError::Validation(
            "Interactive shell requires a terminal.\nUse standard commands for scripted operations.".to_string(),
        ));
    }

    // Initialize configuration paths
    let paths = ConfigPaths::new()?;
    paths.ensure_dir_exists()?;

    // Create shell session
    let mut session = ShellSession::new(paths.clone())?;

    // Show welcome message
    show_welcome(&session);

    // Get the CLI command structure for completion and help
    let cli_command = get_cli_command();

    // Create command executor
    let executor = CommandExecutor::new(cli_command.clone());

    // Create completer
    let completer = crate::repl::Completer::new(cli_command);

    // Create readline editor with history
    let mut rl: Editor<crate::repl::Completer, FileHistory> =
        Editor::with_history(rustyline::Config::default(), FileHistory::new())?;

    // Configure readline
    rl.set_helper(Some(completer));
    rl.set_max_history_size(1000)?;
    rl.set_auto_add_history(true);

    // Load history from file
    if paths.history_file.exists() {
        let _ = rl.load_history(&paths.history_file);
    }

    // Main REPL loop
    loop {
        // Generate prompt
        let prompt = if args.no_color || std::env::var("NO_COLOR").is_ok() {
            Prompt::generate(&session)
        } else {
            Prompt::generate_auto(&session)
        };

        // Read line
        match rl.readline(&prompt) {
            Ok(line) => {
                // Execute command
                match executor.execute(&line, &mut session).await {
                    Ok(ExecuteResult::Exit) => {
                        // Save history before exit
                        let _ = rl.save_history(&paths.history_file);
                        show_goodbye();
                        break;
                    }
                    Ok(ExecuteResult::Continue) => {
                        // Command executed, continue
                    }
                    Ok(ExecuteResult::Empty) => {
                        // Empty input, just show new prompt
                    }
                    Err(e) => {
                        // Print error but continue shell
                        e.print();
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl+C - cancel current line, don't exit
                println!("^C");
            }
            Err(ReadlineError::Eof) => {
                // Ctrl+D on empty line - exit
                let _ = rl.save_history(&paths.history_file);
                show_goodbye();
                break;
            }
            Err(err) => {
                // Other readline error
                eprintln!("Error reading input: {}", err);
                break;
            }
        }
    }

    Ok(())
}

/// Show welcome message when entering the shell
fn show_welcome(session: &ShellSession) {
    println!("Welcome to xavyo interactive shell. Type 'help' for commands, 'exit' to quit.");

    if !session.is_authenticated() {
        println!("\x1b[33mWarning:\x1b[0m Not logged in. Run 'login' to authenticate.");
    } else if session.credentials_expiring_soon() {
        println!("\x1b[33mWarning:\x1b[0m Credentials expiring soon. Consider re-authenticating.");
    }

    println!();
}

/// Show goodbye message when exiting the shell
fn show_goodbye() {
    println!("Goodbye!");
}

/// Get the CLI command structure for introspection
fn get_cli_command() -> Command {
    // We need to build the CLI command structure manually here
    // This mirrors the structure in main.rs
    crate::Cli::command()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_args_default() {
        let args = ShellArgs { no_color: false };
        assert!(!args.no_color);
    }

    #[test]
    fn test_shell_args_no_color() {
        let args = ShellArgs { no_color: true };
        assert!(args.no_color);
    }
}
