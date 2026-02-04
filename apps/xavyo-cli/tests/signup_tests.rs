//! Integration tests for signup command
//!
//! Tests cover:
//! - Signup command help
//! - Signup command flags

use std::process::Command;

/// Test that signup help shows options
#[test]
fn test_signup_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["signup", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Help should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Create") || stdout.contains("account"),
        "Help should describe account creation"
    );
    assert!(
        stdout.contains("--login"),
        "Help should mention --login flag"
    );
    assert!(
        stdout.contains("--yes") || stdout.contains("-y"),
        "Help should mention --yes flag"
    );
}

/// Test that signup mentions confirmation skip
#[test]
fn test_signup_yes_flag_documented() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["signup", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("confirmation") || stdout.contains("prompt"),
        "Help should explain confirmation: {}",
        stdout
    );
}

/// Test that signup mentions auto-login option
#[test]
fn test_signup_login_flag_documented() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["signup", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("login") || stdout.contains("Login"),
        "Help should explain auto-login option: {}",
        stdout
    );
}
