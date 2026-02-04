//! Integration tests for shell completions command
//!
//! Tests cover:
//! - Bash completions generation
//! - Zsh completions generation
//! - Fish completions generation
//! - Invalid shell handling

use std::process::Command;

/// Test that completions command generates bash completions
#[test]
fn test_completions_bash() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["completions", "bash"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Command should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Bash completions typically contain these patterns
    assert!(
        stdout.contains("complete") || stdout.contains("_xavyo"),
        "Should generate bash completion script"
    );
}

/// Test that completions command generates zsh completions
#[test]
fn test_completions_zsh() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["completions", "zsh"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Command should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Zsh completions typically contain compdef or _arguments
    assert!(
        stdout.contains("#compdef") || stdout.contains("_xavyo") || stdout.contains("_arguments"),
        "Should generate zsh completion script"
    );
}

/// Test that completions command generates fish completions
#[test]
fn test_completions_fish() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["completions", "fish"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Command should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Fish completions typically contain these patterns
    assert!(
        stdout.contains("complete -c xavyo") || stdout.contains("function"),
        "Should generate fish completion script"
    );
}

/// Test that completions help shows available shells
#[test]
fn test_completions_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["completions", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bash"), "Help should mention bash");
    assert!(stdout.contains("zsh"), "Help should mention zsh");
    assert!(stdout.contains("fish"), "Help should mention fish");
}

/// Test that completions with invalid shell shows error
#[test]
fn test_completions_invalid_shell() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["completions", "invalid"])
        .output()
        .expect("Failed to execute command");

    assert!(
        !output.status.success(),
        "Should fail for invalid shell"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid") || stderr.contains("error") || stderr.contains("not"),
        "Should indicate invalid shell: {}",
        stderr
    );
}

/// Test that completions without argument shows error
#[test]
fn test_completions_missing_argument() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["completions"])
        .output()
        .expect("Failed to execute command");

    assert!(
        !output.status.success(),
        "Should fail without shell argument"
    );
}
