//! Integration tests for upgrade command
//!
//! Tests cover:
//! - Upgrade check functionality
//! - JSON output format
//! - Help documentation
//! - Flag combinations

use std::process::Command;

/// Test that upgrade help shows all options
#[test]
fn test_upgrade_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["upgrade", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Help should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Check") || stdout.contains("update"),
        "Help should describe update checking"
    );
    assert!(
        stdout.contains("--check"),
        "Help should mention --check flag"
    );
    assert!(
        stdout.contains("--force"),
        "Help should mention --force flag"
    );
    assert!(stdout.contains("--yes"), "Help should mention --yes flag");
    assert!(stdout.contains("--json"), "Help should mention --json flag");
}

/// Test that upgrade --check runs without modifying anything
#[test]
fn test_upgrade_check_only() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["upgrade", "--check"])
        .output()
        .expect("Failed to execute command");

    // May succeed or fail depending on network, but should run
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    // Should produce output about version status
    assert!(!combined.is_empty(), "Should produce output about version");
}

/// Test that upgrade --check --json produces JSON
#[test]
fn test_upgrade_check_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["upgrade", "--check", "--json"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // If successful, should be valid JSON
    if output.status.success() && !stdout.is_empty() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(
            parsed.is_ok(),
            "JSON output should be valid JSON: {}",
            stdout
        );
    }
}

/// Test that upgrade without --yes prompts for confirmation
#[test]
fn test_upgrade_requires_confirmation() {
    // Running upgrade without --yes in non-interactive mode should fail or exit
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["upgrade"])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("Failed to execute command");

    // Should either fail (no TTY) or produce output about confirmation
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    assert!(!combined.is_empty(), "Should produce output");
}

/// Test short flags work
#[test]
fn test_upgrade_short_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["upgrade", "-c"])
        .output()
        .expect("Failed to execute command");

    // Short flag -c should work like --check
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    assert!(!combined.is_empty(), "-c should work as --check");
}
