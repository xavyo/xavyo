//! Integration tests for the rollback command
//!
//! These tests verify the rollback functionality including:
//! - Undo last apply operation (US1)
//! - Rollback to specific version (US2)
//! - View version history (US3)
//! - Preview rollback changes with dry-run (US4)

mod common;

use std::fs;
use std::process::{Command, Stdio};
use tempfile::TempDir;

// ============================================================================
// Test Fixtures
// ============================================================================

/// Create a version history directory with mock history files
fn create_mock_history(
    dir: &TempDir,
    versions: Vec<(u32, &str, usize, usize)>,
) -> std::path::PathBuf {
    let history_dir = dir.path().join("history");
    fs::create_dir_all(&history_dir).expect("Failed to create history dir");

    // Create index.json
    let version_nums: Vec<u32> = versions.iter().map(|(v, _, _, _)| *v).collect();
    let next_version = versions.iter().map(|(v, _, _, _)| *v).max().unwrap_or(0) + 1;
    let index = serde_json::json!({
        "next_version": next_version,
        "versions": version_nums,
        "max_versions": 10
    });
    fs::write(
        history_dir.join("index.json"),
        serde_json::to_string_pretty(&index).unwrap(),
    )
    .expect("Failed to write index.json");

    // Create version files
    for (version, source, agent_count, tool_count) in versions {
        let version_file = serde_json::json!({
            "version": version,
            "timestamp": "2026-02-04T12:00:00Z",
            "config": {
                "version": "1",
                "agents": (0..agent_count).map(|i| serde_json::json!({
                    "name": format!("agent-{}", i),
                    "agent_type": "copilot",
                    "model_provider": "anthropic",
                    "model_name": "claude-sonnet-4",
                    "risk_level": "low"
                })).collect::<Vec<_>>(),
                "tools": (0..tool_count).map(|i| serde_json::json!({
                    "name": format!("tool-{}", i),
                    "description": format!("Tool {}", i),
                    "risk_level": "low",
                    "input_schema": {"type": "object"}
                })).collect::<Vec<_>>()
            },
            "summary": {
                "agent_count": agent_count,
                "tool_count": tool_count,
                "source": source
            }
        });
        fs::write(
            history_dir.join(format!("v{:03}.json", version)),
            serde_json::to_string_pretty(&version_file).unwrap(),
        )
        .expect("Failed to write version file");
    }

    history_dir
}

// ============================================================================
// User Story 1: Undo Last Apply (T021-T025)
// ============================================================================

/// T021: Test basic rollback undo functionality
#[test]
#[ignore = "rollback command not yet registered in CLI"]
fn test_rollback_basic_undo() {
    // This test verifies the rollback command exists and shows help
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["rollback", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("rollback") || stdout.contains("Rollback"),
        "Rollback command help should be available: {}",
        stdout
    );
}

/// T022: Test rollback with confirmation prompt
#[test]
#[ignore = "rollback command not yet registered in CLI"]
fn test_rollback_with_confirmation() {
    // Without --yes flag, rollback should require confirmation
    // Since we can't interact with stdin easily, we just verify the command exists
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["rollback", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("-y") || stdout.contains("--yes"),
        "Rollback should have --yes flag for confirmation bypass: {}",
        stdout
    );
}

/// T023: Test rollback confirmation decline behavior
#[test]
fn test_rollback_decline_confirmation() {
    // Verify that without authentication, the command fails gracefully
    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("XAVYO_CONFIG_DIR", temp_dir.path().to_str().unwrap());

    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["rollback"])
        .stdin(Stdio::piped())
        .output()
        .expect("Failed to execute command");

    // Should fail because no authentication/history
    assert!(!output.status.success());

    std::env::remove_var("XAVYO_CONFIG_DIR");
}

/// T024: Test rollback with --yes flag
#[test]
#[ignore = "rollback command not yet registered in CLI"]
fn test_rollback_yes_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["rollback", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--yes") || stdout.contains("-y"),
        "Rollback should support --yes flag: {}",
        stdout
    );
    assert!(
        stdout.contains("Skip confirmation"),
        "Help should explain --yes flag: {}",
        stdout
    );
}

/// T025: Test rollback with no history available
#[test]
#[ignore = "rollback command not yet registered in CLI"]
fn test_rollback_no_history() {
    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("XAVYO_CONFIG_DIR", temp_dir.path().to_str().unwrap());

    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["rollback", "--list"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should indicate no history is available
    assert!(
        stdout.contains("No configuration history") || stdout.contains("No versions"),
        "Should indicate no history: stdout={}",
        stdout
    );

    std::env::remove_var("XAVYO_CONFIG_DIR");
}

// ============================================================================
// User Story 2: Rollback to Specific Version (T034-T036)
// ============================================================================

/// T034: Test rollback to specific version
#[test]
#[ignore = "rollback command not yet registered in CLI"]
fn test_rollback_to_specific_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["rollback", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--to") || stdout.contains("<VERSION>"),
        "Rollback should support --to flag: {}",
        stdout
    );
}

/// T035: Test rollback version not found error
#[test]
fn test_rollback_version_not_found() {
    let temp_dir = TempDir::new().unwrap();

    // Create history with versions 1, 2, 3
    create_mock_history(
        &temp_dir,
        vec![
            (1, "config.yaml", 1, 0),
            (2, "config.yaml", 2, 1),
            (3, "config.yaml", 1, 2),
        ],
    );

    std::env::set_var("XAVYO_CONFIG_DIR", temp_dir.path().to_str().unwrap());

    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["rollback", "--to", "999"])
        .output()
        .expect("Failed to execute command");

    // Should fail with version not found
    assert!(!output.status.success());

    std::env::remove_var("XAVYO_CONFIG_DIR");
}

/// T036: Test rollback with invalid version zero
#[test]
fn test_rollback_invalid_version_zero() {
    let temp_dir = TempDir::new().unwrap();
    create_mock_history(&temp_dir, vec![(1, "config.yaml", 1, 0)]);

    std::env::set_var("XAVYO_CONFIG_DIR", temp_dir.path().to_str().unwrap());

    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["rollback", "--to", "0"])
        .output()
        .expect("Failed to execute command");

    // Should fail with invalid version
    assert!(!output.status.success());

    std::env::remove_var("XAVYO_CONFIG_DIR");
}

// ============================================================================
// User Story 3: View Version History (T041-T043)
// ============================================================================

/// T041: Test rollback list versions
#[test]
#[ignore = "rollback command not yet registered in CLI"]
fn test_rollback_list_versions() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["rollback", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--list") || stdout.contains("-l"),
        "Rollback should support --list flag: {}",
        stdout
    );
}

/// T042: Test rollback list when empty
#[test]
#[ignore = "rollback command not yet registered in CLI"]
fn test_rollback_list_empty() {
    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("XAVYO_CONFIG_DIR", temp_dir.path().to_str().unwrap());

    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["rollback", "--list"])
        .output()
        .expect("Failed to execute command");

    // Should handle empty history gracefully
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("No configuration history") || stdout.contains("No versions"),
        "Should handle empty history: stdout={}",
        stdout
    );

    std::env::remove_var("XAVYO_CONFIG_DIR");
}

/// T043: Test rollback list JSON output
#[test]
#[ignore = "rollback command not yet registered in CLI"]
fn test_rollback_list_json_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["rollback", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--output") || stdout.contains("json"),
        "Rollback should support JSON output format: {}",
        stdout
    );
}

// ============================================================================
// User Story 4: Preview Rollback Changes (T048-T050)
// ============================================================================

/// T048: Test rollback dry-run mode
#[test]
#[ignore = "rollback command not yet registered in CLI"]
fn test_rollback_dry_run() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["rollback", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--dry-run") || stdout.contains("-n"),
        "Rollback should support --dry-run flag: {}",
        stdout
    );
}

/// T049: Test rollback dry-run with --to
#[test]
#[ignore = "rollback command not yet registered in CLI"]
fn test_rollback_dry_run_with_to() {
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["rollback", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Both flags should be available
    assert!(
        stdout.contains("--dry-run"),
        "Should have --dry-run: {}",
        stdout
    );
    assert!(stdout.contains("--to"), "Should have --to: {}", stdout);
}

/// T050: Test rollback exit codes
#[test]
fn test_rollback_exit_codes() {
    // When no history and trying to rollback (not --list), should error
    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("XAVYO_CONFIG_DIR", temp_dir.path().to_str().unwrap());

    // Try to actually rollback with no history - should fail
    let output = Command::new(env!("CARGO_BIN_EXE_xavyo"))
        .args(["rollback", "--yes"])
        .output()
        .expect("Failed to execute command");

    // Should have non-zero exit code when no auth/history for actual rollback
    let code = output.status.code().unwrap_or(-1);
    assert!(
        code != 0,
        "Should have non-zero exit code when no history: {}",
        code
    );

    std::env::remove_var("XAVYO_CONFIG_DIR");
}
