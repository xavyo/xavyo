//! Integration tests for the interactive shell feature

mod common;

use std::process::{Command, Stdio};
use tempfile::TempDir;

/// Test that shell command exists and has proper help
#[test]
#[ignore = "shell command not yet registered in CLI"]
fn test_shell_command_exists() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["shell", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("interactive shell") || stdout.contains("Shell"),
        "Shell help should mention interactive shell: {}",
        stdout
    );
}

/// Test that shell rejects non-TTY input (piped stdin)
#[test]
#[ignore = "shell command not yet registered in CLI"]
fn test_shell_non_tty_rejection() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["shell"])
        .stdin(Stdio::piped())
        .output()
        .expect("Failed to execute command");

    // Should exit with error
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("terminal") || stderr.contains("TTY") || stderr.contains("interactive"),
        "Should indicate terminal requirement: {}",
        stderr
    );
}

/// Test that shell can be invoked with --no-color flag
#[test]
#[ignore = "shell command not yet registered in CLI"]
fn test_shell_no_color_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["shell", "--no-color", "--help"])
        .output()
        .expect("Failed to execute command");

    // Help should work regardless of --no-color
    assert!(output.status.success() || !output.stdout.is_empty());
}

/// Test shell history file path configuration
#[test]
fn test_shell_history_path() {
    use xavyo_cli::config::ConfigPaths;

    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("XAVYO_CONFIG_DIR", temp_dir.path().to_str().unwrap());

    let paths = ConfigPaths::new().unwrap();

    assert!(paths.history_file.ends_with("shell_history"));
    assert!(paths.history_file.starts_with(temp_dir.path()));

    std::env::remove_var("XAVYO_CONFIG_DIR");
}

/// Test that exit command is recognized
#[test]
fn test_executor_exit_command() {
    use clap::Command;
    use xavyo_cli::repl::CommandExecutor;

    let cmd = Command::new("xavyo");
    let executor = CommandExecutor::new(cmd);

    assert!(executor.is_exit_command("exit"));
    assert!(executor.is_exit_command("quit"));
    assert!(executor.is_exit_command("q"));
    assert!(executor.is_exit_command("EXIT"));
    assert!(executor.is_exit_command("  exit  "));

    assert!(!executor.is_exit_command("agents"));
    assert!(!executor.is_exit_command(""));
    assert!(!executor.is_exit_command("exiting"));
}

/// Test that help command is recognized
#[test]
fn test_executor_help_command() {
    use clap::Command;
    use xavyo_cli::repl::CommandExecutor;

    let cmd = Command::new("xavyo");
    let executor = CommandExecutor::new(cmd);

    assert!(executor.is_help_command("help"));
    assert!(executor.is_help_command("?"));
    assert!(executor.is_help_command("help agents"));
    assert!(executor.is_help_command("HELP"));

    assert!(!executor.is_help_command("agents"));
    assert!(!executor.is_help_command(""));
    assert!(!executor.is_help_command("agents --help"));
}

/// Test ShellSession initialization
#[test]
fn test_shell_session_unauthenticated() {
    use xavyo_cli::config::ConfigPaths;
    use xavyo_cli::repl::ShellSession;

    let temp_dir = TempDir::new().unwrap();
    let paths = ConfigPaths {
        config_dir: temp_dir.path().to_path_buf(),
        config_file: temp_dir.path().join("config.json"),
        session_file: temp_dir.path().join("session.json"),
        credentials_file: temp_dir.path().join("credentials.enc"),
        cache_dir: temp_dir.path().join("cache"),
        history_file: temp_dir.path().join("shell_history"),
        version_history_dir: temp_dir.path().join("history"),
    };

    let session = ShellSession::new(paths).unwrap();

    assert!(!session.is_authenticated());
    assert_eq!(session.prompt_context(), "(not logged in)");
}

/// Test Prompt generation
#[test]
fn test_prompt_generation() {
    use xavyo_cli::config::ConfigPaths;
    use xavyo_cli::repl::{Prompt, ShellSession};

    let temp_dir = TempDir::new().unwrap();
    let paths = ConfigPaths {
        config_dir: temp_dir.path().to_path_buf(),
        config_file: temp_dir.path().join("config.json"),
        session_file: temp_dir.path().join("session.json"),
        credentials_file: temp_dir.path().join("credentials.enc"),
        cache_dir: temp_dir.path().join("cache"),
        history_file: temp_dir.path().join("shell_history"),
        version_history_dir: temp_dir.path().join("history"),
    };

    let session = ShellSession::new(paths).unwrap();
    let prompt = Prompt::generate(&session);

    assert!(prompt.contains("xavyo"));
    assert!(prompt.contains("not logged in"));
    assert!(prompt.ends_with("> "));
}

/// Test Completer completion tree building
#[test]
fn test_completer_tree_building() {
    use clap::Command;
    use xavyo_cli::repl::Completer;

    let cmd = Command::new("xavyo")
        .subcommand(Command::new("agents").about("Manage agents"))
        .subcommand(Command::new("tools").about("Manage tools"));

    // Should not panic when creating completer
    let _completer = Completer::new(cmd);
}

/// Test that shell module is exported from lib
#[test]
fn test_repl_module_exports() {
    // These should compile if exports are correct
    use xavyo_cli::repl::{CommandExecutor, Completer, ExecuteResult, Prompt, ShellSession};

    // Basic sanity check - just verify the types exist and can be used
    // Some types may be zero-sized, that's fine
    let _: fn() -> usize = || std::mem::size_of::<CommandExecutor>();
    let _: fn() -> usize = || std::mem::size_of::<Completer>();
    let _: fn() -> usize = || std::mem::size_of::<ExecuteResult>();
    let _: fn() -> usize = || std::mem::size_of::<Prompt>();
    let _: fn() -> usize = || std::mem::size_of::<ShellSession>();
}

/// Test ExecuteResult variants
#[test]
fn test_execute_result_variants() {
    use xavyo_cli::repl::ExecuteResult;

    let continue_result = ExecuteResult::Continue;
    let exit_result = ExecuteResult::Exit;
    let empty_result = ExecuteResult::Empty;

    assert_eq!(continue_result, ExecuteResult::Continue);
    assert_eq!(exit_result, ExecuteResult::Exit);
    assert_eq!(empty_result, ExecuteResult::Empty);
    assert_ne!(continue_result, exit_result);
}

/// Test session prompt context with different states
#[test]
fn test_shell_session_prompt_contexts() {
    use xavyo_cli::config::ConfigPaths;
    use xavyo_cli::repl::ShellSession;

    let temp_dir = TempDir::new().unwrap();
    let paths = ConfigPaths {
        config_dir: temp_dir.path().to_path_buf(),
        config_file: temp_dir.path().join("config.json"),
        session_file: temp_dir.path().join("session.json"),
        credentials_file: temp_dir.path().join("credentials.enc"),
        cache_dir: temp_dir.path().join("cache"),
        history_file: temp_dir.path().join("shell_history"),
        version_history_dir: temp_dir.path().join("history"),
    };

    let mut session = ShellSession::new(paths).unwrap();

    // Unauthenticated
    assert_eq!(session.prompt_context(), "(not logged in)");

    // Authenticated without tenant
    session.is_authenticated = true;
    assert_eq!(session.prompt_context(), "(no tenant)");

    // Authenticated with tenant
    session.tenant_name = Some("test-tenant".to_string());
    assert_eq!(session.prompt_context(), "test-tenant");
}
