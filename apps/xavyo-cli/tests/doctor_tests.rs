//! Integration tests for doctor command
//!
//! Tests cover:
//! - Basic doctor diagnostics
//! - JSON output format
//! - Help documentation

use std::process::Command;

/// Test that doctor command runs and provides output
#[test]
fn test_doctor_basic() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["doctor"])
        .output()
        .expect("Failed to execute command");

    // Doctor should run (may succeed or fail depending on config/network)
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    // Should produce some diagnostic output
    assert!(
        !combined.is_empty(),
        "Doctor should produce diagnostic output"
    );
}

/// Test that doctor command supports JSON output
#[test]
fn test_doctor_json_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["doctor", "--json"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // If successful, should be valid JSON
    if output.status.success() && !stdout.is_empty() {
        // Try to parse as JSON
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(
            parsed.is_ok(),
            "JSON output should be valid JSON: {}",
            stdout
        );
    }
}

/// Test that doctor help shows options
#[test]
fn test_doctor_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["doctor", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Help should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Diagnose") || stdout.contains("diagnose"),
        "Help should mention diagnostics"
    );
    assert!(stdout.contains("--json"), "Help should mention --json flag");
}
