//! Integration tests for templates command
//!
//! Tests cover:
//! - Templates list subcommand
//! - Templates show subcommand
//! - Templates use subcommand
//! - Help documentation

use std::process::Command;

/// Test that templates command shows help with subcommands
#[test]
fn test_templates_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["templates", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Help should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("list"), "Help should mention list subcommand");
    assert!(stdout.contains("show"), "Help should mention show subcommand");
    assert!(stdout.contains("use"), "Help should mention use subcommand");
}

/// Test that templates list help is available
#[test]
fn test_templates_list_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["templates", "list", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Help should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("available") || stdout.contains("List") || stdout.contains("template"),
        "Help should describe listing templates"
    );
}

/// Test that templates show help is available
#[test]
fn test_templates_show_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["templates", "show", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Help should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("details") || stdout.contains("Show") || stdout.contains("template"),
        "Help should describe showing template details"
    );
}

/// Test that templates use help is available
#[test]
fn test_templates_use_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["templates", "use", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Help should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Apply") || stdout.contains("apply") || stdout.contains("template"),
        "Help should describe applying template"
    );
}

/// Test that templates list runs (may show empty list without auth)
#[test]
fn test_templates_list_runs() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["templates", "list"])
        .output()
        .expect("Failed to execute command");

    // May fail without auth, but should produce output
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should produce some output (success or error)
    assert!(
        !stdout.is_empty() || !stderr.is_empty(),
        "Should produce some output"
    );
}

/// Test that templates show requires template name
#[test]
fn test_templates_show_requires_name() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["templates", "show"])
        .output()
        .expect("Failed to execute command");

    // Should fail or prompt for required argument
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success() || stderr.contains("required"),
        "Should require template name"
    );
}

/// Test that templates use requires template name
#[test]
fn test_templates_use_requires_name() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["templates", "use"])
        .output()
        .expect("Failed to execute command");

    // Should fail or prompt for required argument
    assert!(
        !output.status.success(),
        "Should require template name"
    );
}
